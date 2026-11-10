// Testes do código dos nós "Code", sem precisar do n8n, do GLPI nem do Telegram.
// Uso:  node tests/testar-codigo.js
// Cada nó é executado com versões simuladas de $input, $('Nome do nó') e $env.
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const SRC = path.join(__dirname, '..', 'src');
const AMOSTRAS = path.join(__dirname, 'amostras');
const ler = (nome) => fs.readFileSync(path.join(SRC, nome), 'utf8');
const amostra = (nome) => fs.readFileSync(path.join(AMOSTRAS, nome), 'utf8');

const ENV = { PHISHING_TELEGRAM_CHAT_ID: '-1001234567890', PHISHING_ANALISTAS: '111111, 222222' };

function executar(arquivo, bibliotecas, entrada, outrosNos = {}, env = ENV, trocas = {}) {
  let codigo = [...bibliotecas.map((b) => ler(`lib/${b}`)), ler(arquivo)].join('\n');
  for (const [de, para] of Object.entries(trocas)) codigo = codigo.split(de).join(para);
  const itens = (x) => (Array.isArray(x) ? x : [x]).map((json) => ({ json }));
  const $input = { first: () => itens(entrada)[0], all: () => itens(entrada) };
  const $ = (nome) => {
    if (!(nome in outrosNos)) throw new Error(`Nó "${nome}" não executado`);
    const lista = itens(outrosNos[nome]);
    return { first: () => lista[0], last: () => lista[lista.length - 1], all: () => lista };
  };
  const saida = new Function('$input', '$', '$env', 'require', 'Buffer', codigo)($input, $, env, require, Buffer);
  return saida.map((i) => i.json);
}
// Carrega só as bibliotecas, para testar funções soltas.
function biblioteca(...nomes) {
  const codigo = nomes.map((b) => ler(`lib/${b}`)).join('\n');
  const exportar = 'return { decodificarEntidades, htmlParaTexto, esc, desarmar, analisarMime, endereco, autenticacao, ipsDosRecebidos, decodificarPalavras, extrairUrls, extrairLinksHtml, marcaImitada, interacaoDoUsuario, base64Url, dominioRegistravel, cabecalhosColados, encaminhamentoColado };';
  return new Function(codigo + '\n' + exportar)();
}

let total = 0;
let falhas = 0;
function teste(nome, fn) {
  total++;
  try {
    fn();
    console.log(`  ok   ${nome}`);
  } catch (erro) {
    falhas++;
    console.log(`  FALHA ${nome}\n        ${erro.stack.split('\n').slice(0, 3).join('\n        ')}`);
  }
}

const L = biblioteca('ip.js', 'texto.js', 'email.js', 'indicadores.js');
const CFG = {
  prefixoRedis: 'phishing:', glpiTela: 'http://127.0.0.1:8080/front/ticket.form.php?id=',
  categoria: 'Segurança > Phishing e e-mail suspeito', grupo: 'Segurança da Informação',
  cotaDiaria: 20, maxVirusTotal: 4, maxAnexos: 4,
  tipoPhishing: 'Phishing confirmado', tipoLegitimo: 'Contato legítimo', tipoSpam: 'Spam (não malicioso)', grupoN2: 'SOC N2',
};

// ---------------------------------------------------------------- Bibliotecas
console.log('Bibliotecas');
teste('conteúdo do GLPI (tags escapadas) vira texto', () => {
  assert.strictEqual(L.htmlParaTexto('&lt;p&gt;Recebi &amp;quot;isso&amp;quot;&lt;/p&gt;&lt;p&gt;linha 2&lt;/p&gt;'), 'Recebi "isso"\nlinha 2');
});
teste('entidades com acento (&atilde;, &ccedil;)', () => assert.strictEqual(L.decodificarEntidades('N&atilde;o &Eacute; a&ccedil;&atilde;o'), 'Não É ação'));
teste('script e estilo somem do texto', () => assert.strictEqual(L.htmlParaTexto('<style>x{}</style><script>alert(1)</script><b>oi</b>'), 'oi'));
teste('esc neutraliza HTML', () => assert.strictEqual(L.esc('<a href="x">&'), '&lt;a href=&quot;x&quot;&gt;&amp;'));
teste('desarma URL, e-mail, domínio e IP', () => {
  assert.strictEqual(L.desarmar('https://mal.example/x?a=1'), 'hxxps://mal[.]example/x?a=1');
  assert.strictEqual(L.desarmar('http://a.b.example'), 'hxxp://a[.]b[.]example');
  assert.strictEqual(L.desarmar('golpe@falso.example'), 'golpe[@]falso[.]example');
  assert.strictEqual(L.desarmar('1.2.3.4'), '1.2.3[.]4');
});
teste('assunto codificado (RFC 2047) é decodificado', () => assert.strictEqual(L.decodificarPalavras('=?UTF-8?B?U3VhIGNvbnRhIHNlcsOhIGJsb3F1ZWFkYQ==?='), 'Sua conta será bloqueada'));
teste('remetente real é o último <...> (nome de exibição com e-mail falso)', () => {
  const e = L.endereco('"Itau Unibanco <atendimento@itau.com.br>" <alerta@itau-seguranca.example>');
  assert.strictEqual(e.email, 'alerta@itau-seguranca.example');
  assert.strictEqual(e.dominio, 'itau-seguranca.example');
  assert.ok(e.nome.includes('atendimento@itau.com.br'));
  assert.deepStrictEqual(L.endereco('a@b.example'), { nome: '', email: 'a@b.example', dominio: 'b.example' });
});
teste('lê o .eml: textos, anexo e cabeçalhos', () => {
  const m = L.analisarMime(amostra('phishing-banco.eml'));
  assert.strictEqual(m.textos.length, 2);
  assert.ok(m.textos[0].conteudo.includes('será bloqueada em 24 horas. Atualize seu cadastro'));
  assert.ok(m.textos[1].conteudo.includes('href="http://itau-seguranca.example/atualizar?id=9"'));
  assert.strictEqual(m.anexos.length, 1);
  assert.strictEqual(m.anexos[0].nome, 'boleto.pdf.html');
  assert.strictEqual(String.fromCharCode(...m.anexos[0].bytes), '<p>teste</p>');
});
teste('só vale o Authentication-Results de cima (o de baixo pode ser forjado)', () => {
  const a = L.autenticacao(L.analisarMime(amostra('phishing-banco.eml')).cabecalhos);
  assert.deepStrictEqual([a.spf, a.dkim, a.dmarc], ['fail', 'none', 'fail']);
});
teste('IPs de origem: só públicos, do remetente para cá', () => {
  assert.deepStrictEqual(L.ipsDosRecebidos(L.analisarMime(amostra('phishing-banco.eml')).cabecalhos), ['93.184.216.34']);
});
teste('e-mail encaminhado como anexo é lido por dentro', () => {
  const m = L.analisarMime(amostra('encaminhado-como-anexo.eml'));
  assert.strictEqual(m.internas.length, 1);
  assert.strictEqual(L.endereco(m.internas[0].cabecalhos.find((c) => c.nome === 'from').valor).email, 'diretor.presidente@gmail.com');
});
teste('extrai URLs e desfaz o desarme (hxxp, [.])', () => {
  assert.deepStrictEqual(L.extrairUrls('veja hxxps://mal[.]example/a. e www.site.example/x)'), ['https://mal.example/a', 'http://www.site.example/x']);
});
teste('links do HTML: endereço real x texto mostrado', () => {
  assert.deepStrictEqual(L.extrairLinksHtml('<a href="http://mal.example/x">https://www.itau.com.br</a>'), [{ href: 'http://mal.example/x', texto: 'https://www.itau.com.br' }]);
});
teste('marca imitada e domínio parecido', () => {
  assert.strictEqual(L.marcaImitada('itau-seguranca.example', '').marca, 'Itaú');
  assert.ok(L.marcaImitada('micros0ft.example', '').sosia);
  assert.strictEqual(L.marcaImitada('loja.example', 'Microsoft 365').marca, 'Microsoft');
  assert.strictEqual(L.marcaImitada('itau.com.br', 'Itaú'), null);
  assert.strictEqual(L.marcaImitada('mail.microsoft.com', 'Microsoft'), null);
  assert.strictEqual(L.marcaImitada('loja.example', 'Loja Exemplo'), null);
});
teste('interação do usuário, com negação', () => {
  const i = L.interacaoDoUsuario('Recebi o e-mail, cliquei no link e digitei minha senha. Não abri o anexo.');
  assert.deepStrictEqual([i.clicou, i.senha, i.anexo, i.algum], [true, true, false, true]);
  const n = L.interacaoDoUsuario('Não cliquei em nada e nem respondi.');
  assert.deepStrictEqual([n.clicou, n.respondeu, n.algum], [false, false, false]);
});
teste('ID de URL do VirusTotal', () => assert.strictEqual(L.base64Url('http://a.example/'), 'aHR0cDovL2EuZXhhbXBsZS8'));
teste('cabeçalhos colados no chamado e encaminhamento do Outlook', () => {
  const c = L.cabecalhosColados('Oi, segue:\nReceived: from x (x [93.184.216.34])\nFrom: a@b.example\nSubject: teste');
  assert.ok(c.some((h) => h.nome === 'from'));
  const e = L.encaminhamentoColado('De: Banco <x@golpe.example>\nEnviado em: quinta\nAssunto: Bloqueio');
  assert.deepStrictEqual([e.de, e.assunto], ['Banco <x@golpe.example>', 'Bloqueio']);
});

// ---------------------------------------------------------------- Fluxo 1
console.log('Fluxo 1 - analisa relatos');
teste('monta a busca com categoria, grupo e status aberto', () => {
  const r = executar('montar-busca.js', [], {}, {
    'Configuração': CFG,
    'Lê as categorias': { body: [{ id: 3, completename: 'Segurança > Malware' }, { id: 12, completename: 'Segurança > Phishing e e-mail suspeito' }] },
    'Lê os grupos': { body: [{ id: 1, name: 'SOC N1' }, { id: 5, name: 'Segurança da Informação' }] },
  })[0];
  assert.strictEqual(r.categoria_id, 12);
  assert.strictEqual(r.grupo_id, 5);
  const q = decodeURIComponent(r.consulta);
  assert.ok(q.includes('criteria[0][field]=7&criteria[0][searchtype]=equals&criteria[0][value]=12'));
  assert.ok(q.includes('criteria[1][value]=5') && q.includes('criteria[2][value]=notold'));
});
teste('sem a categoria no GLPI: erro explicando o que fazer', () => {
  assert.throws(() => executar('montar-busca.js', [], {}, { 'Configuração': CFG, 'Lê as categorias': { body: [] }, 'Lê os grupos': { body: [] } }), /preparar-glpi/);
});
teste('candidatos e escolha do primeiro ainda não analisado', () => {
  const c = executar('listar-candidatos.js', [], { body: { totalcount: 2, data: [{ 2: 7 }, { 2: 9 }] } }, { 'Configuração': CFG });
  assert.deepStrictEqual(c.map((x) => x.chave_reserva), ['phishing:relato:7', 'phishing:relato:9']);
  const p = executar('escolher-proximo.js', [], [{ reserva: '1' }, { reserva: null }], { 'Lista os candidatos': c, 'Configuração': CFG })[0];
  assert.strictEqual(p.chamado_id, 9);
  assert.match(p.chave_cota, /^phishing:cota:\d{4}-\d{2}-\d{2}$/);
  assert.deepStrictEqual(executar('escolher-proximo.js', [], [{ reserva: '1' }], { 'Lista os candidatos': [c[0]], 'Configuração': CFG }), [{ nenhum: true }]);
});
teste('anexos: .eml é baixado; PDF/imagem não (só o hash)', () => {
  const docs = executar('escolher-downloads.js', [], [
    { body: { id: 1, filename: 'email.eml', mime: 'message/rfc822', sha1sum: 'a'.repeat(40) } },
    { body: { id: 2, filename: 'fatura.pdf', mime: 'application/pdf', sha1sum: 'b'.repeat(40) } },
  ], { 'Lista os anexos': [{ documento_id: 1 }, { documento_id: 2 }] });
  assert.deepStrictEqual(docs.map((d) => d.baixar), [true, false]);
  assert.deepStrictEqual(executar('listar-anexos.js', [], { body: [] }, { 'Configuração': CFG }), [{ sem_anexo: true }]);
});

const RELATO = '&lt;p&gt;Recebi este e-mail do banco, cliquei no link e digitei minha senha. N&amp;atilde;o abri o anexo.&lt;/p&gt;';
function nosDoChamado(conteudoEml, nomeArquivo = 'email.eml', relato = RELATO) {
  return {
    'Configuração': CFG,
    'Escolhe o próximo': { chamado_id: 42 },
    'Lê o chamado': { body: { id: 42, name: 'E-mail suspeito do banco', date: '2026-11-06 14:32:00', content: relato } },
    'Lê os requerentes': { body: [{ type: 1, users_id: 'maria.financeiro' }, { type: 2, users_id: 'dilione' }] },
    'Lê os acompanhamentos': { body: [{ content: '&lt;p&gt;🤖 Análise automática de phishing (analisador-phishing)&lt;/p&gt;' }] },
    ...(conteudoEml === null ? {} : {
      'Escolhe o que baixar': [{ documento_id: 1, nome: nomeArquivo, mime: 'message/rfc822', sha1: '', baixar: true }, { documento_id: 2, nome: 'print.png', mime: 'image/png', sha1: 'c'.repeat(40), baixar: false }],
      'Baixa os anexos': [{ statusCode: 200, body: conteudoEml }, { statusCode: 200, body: '{}' }],
    }),
  };
}
const extrair = (nos) => executar('extrair-evidencias.js', ['ip.js', 'texto.js', 'email.js', 'indicadores.js'], {}, nos)[0];
const EV = extrair(nosDoChamado(amostra('phishing-banco.eml')));
const ids = (ev) => ev.sinais.map((s) => s.id);
teste('evidências do e-mail de phishing', () => {
  assert.strictEqual(EV.email.de.email, 'alerta@itau-seguranca.example');
  assert.strictEqual(EV.email.responder.email, 'suporte.cliente.itau@gmail.com');
  assert.strictEqual(EV.email.assunto, 'Sua conta será bloqueada');
  assert.deepStrictEqual(EV.chamado.requerentes, ['maria.financeiro']);
  for (const id of ['spf', 'dmarc', 'reply-to', 'nome-falso', 'marca', 'link-disfarcado', 'dupla-extensao', 'urgencia', 'credenciais']) {
    assert.ok(ids(EV).includes(id), `faltou o sinal ${id}: ${ids(EV).join(', ')}`);
  }
  assert.ok(!EV.relato.includes('analisador-phishing'), 'a própria análise não pode voltar como relato');
});
teste('o usuário disse que clicou e digitou a senha (e não abriu o anexo)', () => {
  assert.deepStrictEqual([EV.interacao.clicou, EV.interacao.senha, EV.interacao.anexo], [true, true, false]);
});
teste('anexo dentro do e-mail ganha SHA-256; o print não é consultado', () => {
  const anexo = EV.anexos.find((a) => a.nome === 'boleto.pdf.html');
  assert.match(anexo.sha256, /^[0-9a-f]{64}$/);
  assert.ok(EV.anexos.find((a) => a.nome === 'print.png').print);
  assert.ok(EV.consultas.virustotal.every((c) => !c.caminho.includes('c'.repeat(40))));
});
teste('consultas de reputação com limite e prioridade', () => {
  const v = EV.consultas.virustotal;
  assert.ok(v.length <= 4);
  assert.ok(v[0].caminho.startsWith('files/'));
  assert.ok(v.some((c) => c.caminho === 'urls/' + L.base64Url('http://itau-seguranca.example/atualizar?id=9')));
  assert.ok(v.some((c) => c.caminho === 'domains/itau-seguranca.example'));
  assert.ok(!EV.consultas.urlhaus.includes('www.itau.com.br'), 'domínio oficial não vai para o URLhaus');
  assert.ok(EV.consultas.rdap.includes('itau-seguranca.example'));
  assert.ok(!EV.consultas.rdap.includes('gmail.com'));
});
teste('IOCs: só o que é do atacante; oficial, webmail e compartilhado ficam fora com o motivo', () => {
  assert.ok(EV.iocs.dominios.includes('itau-seguranca.example'));
  assert.ok(!EV.iocs.dominios.includes('gmail.com') && !EV.iocs.dominios.includes('itau.com.br'), EV.iocs.dominios.join(', '));
  assert.ok(!EV.iocs.urls.some((u) => /itau\.com\.br/.test(u)), 'link verdadeiro do Itaú não é IOC');
  assert.ok(EV.iocs.urls.includes('http://itau-seguranca.example/atualizar?id=9'));
  assert.ok(EV.iocs.remetente.includes('suporte.cliente.itau@gmail.com'), 'endereço do golpista no Gmail continua IOC');
  const motivo = (v) => (EV.iocs_fora.find((x) => x.valor === v) ?? {}).motivo ?? '';
  assert.match(motivo('gmail.com'), /webmail/);
  assert.match(motivo('itau.com.br'), /oficial de Itaú/);
});
teste('IOCs: domínio da organização (dominiosConfiaveis) nunca entra', () => {
  const nos = nosDoChamado(amostra('phishing-banco.eml'));
  nos['Configuração'] = { ...CFG, dominiosConfiaveis: 'itau-seguranca.example' };
  const ev = extrair(nos);
  assert.ok(!ev.iocs.dominios.includes('itau-seguranca.example') && !ev.iocs.remetente.includes('alerta@itau-seguranca.example'));
  assert.ok(ev.iocs_fora.some((x) => /organização/.test(x.motivo)));
});
teste('e-mail legítimo: autenticação ok e poucos sinais', () => {
  const ev = extrair(nosDoChamado(amostra('legitimo-loja.eml'), 'email.eml', '&lt;p&gt;É legítimo? Não cliquei.&lt;/p&gt;'));
  assert.ok(ids(ev).includes('autenticado'));
  assert.ok(!ids(ev).some((i) => ['marca', 'link-disfarcado', 'reply-to', 'dmarc'].includes(i)), ids(ev).join(', '));
  assert.strictEqual(ev.interacao.algum, false);
});
teste('BEC encaminhado como anexo: analisa a mensagem de dentro', () => {
  const ev = extrair(nosDoChamado(amostra('encaminhado-como-anexo.eml')));
  assert.strictEqual(ev.email.de.email, 'diretor.presidente@gmail.com');
  assert.ok(ids(ev).includes('bec') && ids(ev).includes('webmail'), ids(ev).join(', '));
});
teste('sem anexo: usa o encaminhamento colado e os links do relato', () => {
  const ev = extrair(nosDoChamado(null, '', '&lt;p&gt;De: Correios &amp;lt;rastreio@correios-entrega.example&amp;gt;&lt;br&gt;Assunto: Taxa pendente&lt;br&gt;Link: hxxps://correios-entrega[.]example/pagar&lt;/p&gt;'));
  assert.strictEqual(ev.email.de.email, 'rastreio@correios-entrega.example');
  assert.ok(ev.urls.some((u) => u.url === 'https://correios-entrega.example/pagar'));
  assert.ok(ids(ev).includes('marca'));
});

const dossie = (vt = [], urlhaus = [], rdap = [], ev = EV) => executar('montar-dossie.js', ['texto.js'], {}, {
  'Extrai as evidências': ev, 'Resume o VirusTotal': { virustotal: vt }, 'Resume o URLhaus': { urlhaus }, 'Resume o RDAP': { rdap },
})[0];
const D = dossie([{ tipo: 'url', valor: 'http://itau-seguranca.example/atualizar?id=9', encontrado: true, maliciosos: 7, suspeitos: 1, total: 94 }], [], [{ dominio: 'itau-seguranca.example', idade_dias: 3, criado_em: '2026-11-03' }]);
teste('dossiê: VirusTotal 7/94 é evidência forte e domínio novo pesa', () => {
  assert.strictEqual(D.sugestao_automatica, 'phishing');
  assert.ok(D.fortes.length === 1 && D.pontuacao === 100);
  assert.ok(D.sinais.some((s) => s.id === 'dominio-novo'));
  assert.ok(D.dossie.length <= 14000 && D.dossie.includes('relato_do_usuario'));
});
teste('resumos das fontes (VirusTotal 404/429, URLhaus, RDAP)', () => {
  const vt = executar('resumir-virustotal.js', ['texto.js'], [{ statusCode: 404 }, { statusCode: 429 }, { statusCode: 200, body: { data: { attributes: { last_analysis_stats: { malicious: 3, harmless: 60 }, last_analysis_results: { X: { category: 'malicious', result: 'phishing' } } } } } }],
    { 'Fila do VirusTotal': [{ tipo: 'url', valor: 'a' }, { tipo: 'url', valor: 'b' }, { tipo: 'url', valor: 'c' }] })[0].virustotal;
  assert.deepStrictEqual([vt[0].encontrado, /cota/.test(vt[1].erro), vt[2].maliciosos, vt[2].total], [false, true, 3, 63]);
  const uh = executar('resumir-urlhaus.js', ['texto.js'], { statusCode: 200, body: { query_status: 'ok', urls: [{ url_status: 'online', threat: 'malware_download', tags: ['phishing'] }] } }, { 'Fila do URLhaus': [{ valor: 'h.example' }] })[0].urlhaus[0];
  assert.deepStrictEqual([uh.listado, uh.online, uh.tags[0]], [true, 1, 'phishing']);
  const rd = executar('resumir-rdap.js', ['texto.js'], { statusCode: 200, body: { events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 5 * 86400000).toISOString() }] } }, { 'Fila do RDAP': [{ valor: 'novo.example' }] })[0].rdap[0];
  assert.strictEqual(rd.idade_dias, 5);
});

const parecer = (output, d = D, ev = EV) => executar('parecer-final.js', ['texto.js'], output === null ? { error: 'timeout' } : { output }, { 'Monta o dossiê': d, 'Extrai as evidências': ev })[0].parecer;
teste('trava: IA diz "legítimo" com evidência forte -> continua phishing', () => {
  const p = parecer(JSON.stringify({ classificacao: 'legitimo', confianca: 90, gravidade: 'baixa', resumo: 'Parece seguro.' }));
  assert.strictEqual(p.classificacao, 'phishing');
  assert.ok(p.avisos.some((a) => a.includes('evidência forte')));
});
teste('gravidade crítica quando o usuário digitou a senha; ações obrigatórias primeiro', () => {
  const p = parecer('```json\n' + JSON.stringify({ classificacao: 'phishing', confianca: 92, gravidade: 'media', mitre: ['T1566.002', 'xss'], acoes_soc: ['Bloquear o domínio'] }) + '\n```');
  assert.strictEqual(p.gravidade, 'critica');
  assert.ok(p.acoes_soc[0].startsWith('Trocar a senha'));
  assert.deepStrictEqual(p.mitre, ['T1566.002']);
});
teste('IA fora do ar: vale o parecer automático', () => {
  const p = parecer(null);
  assert.deepStrictEqual([p.origem, p.classificacao], ['automatica', 'phishing']);
  assert.ok(p.mitre.includes('T1566.002'));
});
teste('IA diz "legítimo" com nota alta -> inconclusivo', () => {
  const d = { ...D, fortes: [], pontuacao: 70, sugestao_automatica: 'phishing' };
  assert.strictEqual(parecer(JSON.stringify({ classificacao: 'legitimo', confianca: 80 }), d).classificacao, 'inconclusivo');
});

const P = parecer(JSON.stringify({ classificacao: 'phishing', confianca: 92, gravidade: 'alta', tipo_ataque: 'roubo de credenciais <b>', resumo: 'Página falsa do Itaú <script>alert(1)</script>', evidencias: ['DMARC=fail'], acoes_soc: ['Bloquear'] }));
const aviso = (env = ENV) => executar('montar-aviso.js', ['texto.js'], { parecer: P }, { 'Configuração': CFG, 'Extrai as evidências': EV, 'Monta o dossiê': D }, env)[0];
const A = aviso();
teste('mensagem do Telegram: cabe, tem botões e nada do e-mail vira HTML', () => {
  assert.ok(A.telegram.text.length <= 4096);
  assert.ok(A.telegram_configurado);
  assert.deepStrictEqual(A.telegram.reply_markup.inline_keyboard.flat().map((b) => b.callback_data), ['ph|42|p', 'ph|42|l', 'ph|42|s', 'ph|42|e']);
  assert.ok(!A.telegram.text.includes('<script>') && A.telegram.text.includes('&lt;script&gt;'));
  assert.ok(!/https?:\/\/itau-seguranca/.test(A.telegram.text), 'IOC precisa estar desarmado');
  assert.ok(A.telegram.text.includes('hxxp://itau-seguranca[.]example'));
  assert.ok(A.telegram.text.includes('O usuário disse que clicou no link, digitou senha ou dados'));
});
teste('acompanhamento no GLPI é privado, escapado e marcado', () => {
  assert.strictEqual(A.acompanhamento.input.is_private, 1);
  assert.ok(A.acompanhamento.input.content.includes('analisador-phishing'));
  assert.ok(!A.acompanhamento.input.content.includes('<script>'));
  assert.strictEqual(A.chave_analise, 'phishing:analise:42');
  assert.strictEqual(A.registro.sugestao, 'phishing');
});
teste('sem grupo configurado, o aviso fica marcado como não configurado', () => assert.strictEqual(aviso({}).telegram_configurado, false));
teste('mensagem gigante é encurtada sem cortar HTML', () => {
  const grande = { ...P, evidencias: Array(6).fill('x'.repeat(290)), acoes_soc: Array(8).fill('y'.repeat(290)), contra_evidencias: Array(4).fill('z'.repeat(290)) };
  const t = executar('montar-aviso.js', ['texto.js'], { parecer: grande }, { 'Configuração': CFG, 'Extrai as evidências': EV, 'Monta o dossiê': D })[0].telegram.text;
  assert.ok(t.length <= 4096, String(t.length));
  assert.strictEqual((t.match(/<blockquote/g) ?? []).length, (t.match(/<\/blockquote>/g) ?? []).length);
});

// ---------------------------------------------------------------- Fluxo 2
console.log('Fluxo 2 - decisões do analista');
const grupo = { id: -1001234567890 };
const clique = (uid, de, dados, chat = grupo) => ({ update_id: uid, callback_query: { id: 'cb' + uid, from: { id: de, first_name: 'Ana', username: 'ana_soc' }, data: dados, message: { message_id: 500, chat } } });
const msg = (uid, de, texto, chat = grupo) => ({ update_id: uid, message: { message_id: 600 + uid, from: { id: de, first_name: 'Ana' }, chat, text: texto } });
const lerMsgs = (updates, env = ENV) => executar('ler-mensagens.js', ['texto.js'], { statusCode: 200, body: { ok: true, result: updates } }, {}, env);
teste('clique de analista autorizado vira decisão', () => {
  const r = lerMsgs([clique(10, 111111, 'ph|42|p')])[0];
  assert.strictEqual(r.offset, 11);
  assert.deepStrictEqual([r.acoes[0].tipo, r.acoes[0].decisao, r.acoes[0].chamado_id, r.acoes[0].mensagem_id], ['decidir', 'phishing', 42, 500]);
});
teste('quem não está em PHISHING_ANALISTAS não decide', () => {
  const r = lerMsgs([clique(10, 999, 'ph|42|l')])[0].acoes[0];
  assert.deepStrictEqual([r.tipo, r.alerta], ['responder', true]);
  assert.ok(r.texto.includes('999'));
});
teste('clique vindo de outro chat ou com dado estranho é recusado', () => {
  assert.strictEqual(lerMsgs([clique(10, 111111, 'ph|42|p', { id: -5 })])[0].acoes[0].tipo, 'responder');
  assert.strictEqual(lerMsgs([clique(10, 111111, 'ph|42|z;rm')])[0].acoes[0].tipo, 'responder');
});
teste('sem configuração nada é aceito', () => assert.strictEqual(lerMsgs([clique(10, 111111, 'ph|42|p')], {})[0].acoes[0].tipo, 'responder'));
teste('dois cliques no mesmo chamado na mesma leitura: só o primeiro decide', () => {
  const r = lerMsgs([clique(10, 111111, 'ph|42|p'), clique(11, 222222, 'ph|42|l')])[0].acoes;
  assert.deepStrictEqual(r.map((a) => a.tipo), ['decidir', 'responder']);
});
teste('comandos /nota, /reanalisar e /ajuda (com @bot)', () => {
  const r = lerMsgs([msg(1, 111111, '/nota@phishing_bot 42 usuário confirmou que não clicou'), msg(2, 111111, '/reanalisar #42'), msg(3, 999, '/ajuda'), msg(4, 999, 'oi'), msg(5, 111111, '/nota 42')])[0].acoes;
  assert.deepStrictEqual(r.map((a) => a.tipo), ['nota', 'reanalisar', 'responder', 'responder']);
  assert.strictEqual(r[0].texto, 'usuário confirmou que não clicou');
});
teste('Telegram com erro (409) ou vazio: nada a fazer', () => {
  assert.deepStrictEqual(executar('ler-mensagens.js', ['texto.js'], { statusCode: 409, body: { ok: false } }, {}), []);
  assert.deepStrictEqual(lerMsgs([]), []);
});

const REGISTRO = JSON.stringify(A.registro);
function montarAcoes(acoes, analises, travas) {
  const separadas = executar('separar-acoes.js', [], {}, { 'Configuração': CFG, 'Lê as mensagens': { acoes } });
  return executar('montar-acoes.js', ['texto.js'], travas.map((t, k) => ({ [separadas[k].chave_trava]: t })), {
    'Configuração': CFG, 'Separa as ações': separadas, 'Lê a análise': analises.map((analise) => ({ analise })),
    'Lê os tipos de solução': { body: [{ id: 7, name: 'Phishing confirmado' }, { id: 8, name: 'Contato legítimo' }, { id: 9, name: 'Spam (não malicioso)' }] },
    'Lê os grupos (decisões)': { body: [{ id: 2, name: 'SOC N2' }] },
  });
}
const analista = { id: '111111', nome: 'Ana', usuario: 'ana_soc' };
const decidir = (decisao) => ({ update_id: 10, tipo: 'decidir', chamado_id: 42, decisao, callback_id: 'cb10', mensagem_id: 500, analista });
teste('decisão "phishing": nota interna + solução com texto fixo', () => {
  const s = montarAcoes([decidir('phishing')], [REGISTRO], [1]);
  assert.deepStrictEqual(s.map((x) => x.caminho), ['ITILFollowup', 'ITILSolution']);
  assert.strictEqual(s[0].corpo.input.is_private, 1);
  assert.ok(s[0].corpo.input.content.includes('o analista concordou'));
  assert.strictEqual(s[1].corpo.input.solutiontypes_id, 7);
  assert.ok(s[1].corpo.input.content.includes('confirmamos que é PHISHING'));
  assert.ok(!s[1].corpo.input.content.includes('Página falsa'), 'texto da IA não vai para o usuário');
  assert.strictEqual(s[0].chave_metrica, 'phishing:metricas:ia_phishing:analista_phishing');
  assert.deepStrictEqual(s[0].sucesso.map((m) => m.tg_metodo), ['editMessageReplyMarkup', 'sendMessage', 'answerCallbackQuery']);
});
teste('usuário clicou e digitou a senha: troca de senha IMEDIATA no topo da resposta', () => {
  assert.deepStrictEqual(A.registro.interacao_tipos, ['clicou', 'senha']);
  const t = montarAcoes([decidir('phishing')], [REGISTRO], [1])[1].corpo.input.content;
  assert.ok(t.includes('Você nos contou que clicou no link, digitou sua senha ou seus dados'));
  assert.ok(t.indexOf('Troque a sua senha IMEDIATAMENTE') < t.indexOf('Apague a mensagem'), 'a troca de senha vem antes do resto');
  assert.ok(!t.includes('Desconecte o computador'), 'não abriu o anexo: sem o passo de isolar a máquina');
});
teste('mensagem do grupo: seções espaçadas e /nota explicado com exemplo', () => {
  const t = montarAcoes([decidir('phishing')], [REGISTRO], [1])[0].sucesso.find((m) => m.tg_metodo === 'sendMessage').tg_corpo.text;
  assert.ok(t.includes('Comece por: trocar a senha do usuário'));
  assert.ok(t.includes('1. Bloquear o remetente') && /\n\n2\. /.test(t), 'passos separados por linha em branco');
  assert.ok(t.includes('<code>/nota 42 bloqueei o domínio') && t.includes('só a equipe técnica vê'));
  assert.ok(A.telegram.text.includes('<code>/reanalisar 42</code>') && A.telegram.text.length <= 4096);
});
teste('sem interação: resposta mantém o aviso condicional de troca de senha', () => {
  const r = JSON.stringify({ ...A.registro, interacao: [], interacao_tipos: [] });
  const t = montarAcoes([decidir('phishing')], [r], [1])[1].corpo.input.content;
  assert.ok(!t.includes('Você nos contou') && t.includes('troque a sua senha imediatamente'));
});
teste('registro antigo (só rótulos) e anexo aberto: deduz os tipos e manda isolar a máquina', () => {
  const r = JSON.stringify({ ...A.registro, interacao: ['abriu ou baixou o anexo'], interacao_tipos: undefined });
  const t = montarAcoes([decidir('phishing')], [r], [1])[1].corpo.input.content;
  assert.ok(t.includes('Desconecte o computador da rede agora') && !t.includes('IMEDIATAMENTE'));
});
teste('escalar N2 com senha digitada: o usuário também é orientado a trocar já', () => {
  assert.ok(montarAcoes([decidir('escalar')], [REGISTRO], [1])[2].corpo.input.content.includes('Troque a sua senha IMEDIATAMENTE'));
});
teste('decisão "legítimo" contra a IA conta como discordância', () => {
  const s = montarAcoes([decidir('legitimo')], [REGISTRO], [1]);
  assert.strictEqual(s[1].corpo.input.solutiontypes_id, 8);
  assert.ok(s[0].corpo.input.content.includes('DISCORDOU'));
  assert.strictEqual(s[0].chave_metrica, 'phishing:metricas:ia_phishing:analista_legitimo');
});
teste('escalar N2: inclui o grupo e avisa o usuário, sem solucionar', () => {
  const s = montarAcoes([decidir('escalar')], [REGISTRO], [1]);
  assert.deepStrictEqual(s.map((x) => x.caminho), ['ITILFollowup', 'Group_Ticket', 'ITILFollowup']);
  assert.deepStrictEqual(s[1].corpo.input, { tickets_id: 42, groups_id: 2, type: 2 });
  assert.strictEqual(s[2].corpo.input.is_private, 0);
});
teste('chamado já decidido: só avisa quem clicou', () => {
  const s = montarAcoes([decidir('spam')], [REGISTRO], [2]);
  assert.deepStrictEqual([s.length, s[0].destino, s[0].tg_metodo], [1, 'telegram', 'answerCallbackQuery']);
});
teste('sem análise guardada: avisa e libera a trava', () => {
  const s = montarAcoes([decidir('phishing')], [null], [1]);
  assert.deepStrictEqual([s[0].destino, s[0].apagar_chave], ['telegram', 'phishing:decisao:42']);
});
teste('/nota e /reanalisar', () => {
  const s = montarAcoes([{ update_id: 1, tipo: 'nota', chamado_id: 42, texto: '<b>ok</b>', mensagem_id: 601, analista }, { update_id: 2, tipo: 'reanalisar', chamado_id: 42, mensagem_id: 602, analista }], [REGISTRO, REGISTRO], [1, 1]);
  assert.strictEqual(s[0].caminho, 'ITILFollowup');
  assert.ok(s[0].corpo.input.content.includes('&lt;b&gt;ok&lt;/b&gt;'));
  assert.deepStrictEqual([s[1].destino, s[1].apagar_chave], ['telegram', 'phishing:relato:42']);
});
teste('mesma mensagem do Telegram duas vezes: ignorada', () => {
  assert.deepStrictEqual(montarAcoes([{ update_id: 1, tipo: 'nota', chamado_id: 42, texto: 'x', mensagem_id: 601, analista }], [REGISTRO], [2]), []);
});
teste('confere o GLPI: sucesso manda mensagens; falha libera a trava', () => {
  const passos = montarAcoes([decidir('phishing')], [REGISTRO], [1]);
  const ok = executar('conferir-glpi.js', ['texto.js'], [{ statusCode: 201, body: { id: 1 } }, { statusCode: 201, body: { id: 2 } }], { 'Monta as ações': passos });
  assert.deepStrictEqual(ok.map((m) => m.tg_metodo), ['editMessageReplyMarkup', 'sendMessage', 'answerCallbackQuery']);
  assert.strictEqual(ok[0].chave_metrica, 'phishing:metricas:ia_phishing:analista_phishing');
  const ruim = executar('conferir-glpi.js', ['texto.js'], [{ statusCode: 201, body: {} }, { statusCode: 400, body: ['ERROR'] }], { 'Monta as ações': passos });
  assert.deepStrictEqual([ruim.length, ruim[0].tg_metodo, ruim[0].apagar_chave], [1, 'answerCallbackQuery', 'phishing:decisao:42']);
});

// ---------------------------------------------------------------- Fluxos gerados
console.log('Fluxos gerados');
for (const arquivo of ['analisador-phishing-glpi-ia.json']) {
  teste(`${arquivo}: JSON válido e Code com sintaxe correta`, () => {
    const f = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'workflow', arquivo), 'utf8'));
    for (const n of f.nodes.filter((x) => x.type === 'n8n-nodes-base.code')) {
      try { new Function('$input', '$', '$env', 'require', n.parameters.jsCode); } catch (erro) { throw new Error(`${n.name}: ${erro.message}`); }
    }
    assert.ok(!JSON.stringify(f).match(/\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/), 'token do Telegram no JSON!');
  });
  // As duas rotinas estão no mesmo fluxo: um nó só pode ler $('outro nó') se esse outro já rodou
  // antes dele na MESMA execução (está antes dele nas ligações). O gatilho é a exceção ($('A cada minuto').isExecuted).
  teste(`${arquivo}: toda referência $('nó') aponta para um nó anterior do mesmo ramo`, () => {
    const f = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'workflow', arquivo), 'utf8'));
    const antes = new Map(f.nodes.map((n) => [n.name, new Set()]));
    for (const [origem, saidas] of Object.entries(f.connections)) {
      for (const lista of Object.values(saidas)) for (const grupo of lista) for (const d of grupo) antes.get(d.node).add(origem);
    }
    const anteriores = (nome, vistos = new Set()) => {
      for (const o of antes.get(nome)) if (!vistos.has(o)) { vistos.add(o); anteriores(o, vistos); }
      return vistos;
    };
    const gatilhos = new Set(f.nodes.filter((n) => n.type.endsWith('scheduleTrigger')).map((n) => n.name));
    const erros = [];
    let total = 0;
    for (const n of f.nodes) {
      const texto = (n.parameters.jsCode ?? '') + JSON.stringify({ ...n.parameters, jsCode: '' });
      const ok = anteriores(n.name);
      for (const [, citado] of texto.matchAll(/(?:\$|\blista|\bcorpoDe|\btodos)\('([^']+)'\)/g)) {
        total++;
        if (!ok.has(citado) && !gatilhos.has(citado)) erros.push(`${n.name} -> ${citado}`);
      }
    }
    assert.ok(total > 20, String(total));
    assert.deepStrictEqual([...new Set(erros)], []);
  });
}

console.log(`\n${total - falhas}/${total} testes passaram`);
process.exit(falhas ? 1 : 0);
