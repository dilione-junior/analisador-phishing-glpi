// Avalia o analisador contra o CONJUNTO DE REFERÊNCIA (tests/corpus): cada .eml passa pelo mesmo código dos nós
// do n8n (Extrai as evidências -> Monta o dossiê -> Parecer final), sem n8n, sem GLPI e sem internet.
// A reputação (VirusTotal, URLhaus, RDAP) e a resposta do leitor de QR Code vêm simuladas do gabarito (a leitura
// de verdade é conferida por tests/conferir-leitor-qr.js contra o contêiner); a IA fica DESLIGADA: mede-se a parte
// determinística (regras + travas), que é a rede de segurança quando a IA falha ou é enganada.
//
// Uso:  node tests/avaliar-corpus.js            relatório na tela
//       node tests/avaliar-corpus.js --ci       idem, e sai com erro se houver regressão (usado no CI)
//       node tests/avaliar-corpus.js --json f   grava o resultado completo em f (para comparar versões)
//       node tests/avaliar-corpus.js --caso 06  mostra o detalhe de um caso (sinais, IOCs, parecer)
//
// O que é regressão (quebra o CI):
//  - um caso SEM "lacuna" no gabarito com classificação errada;
//  - falso positivo (legítimo/spam classificado como phishing), em qualquer caso;
//  - sinal obrigatório ausente ou sinal proibido presente;
//  - item proibido nas listas de bloqueio (bloquear domínio oficial/da casa para a empresa): SEMPRE.
// Casos com "lacuna" documentam o que o analisador ainda não sabe: o erro aparece no relatório, mas não quebra o CI.
// Quando uma melhoria resolve a lacuna, o relatório avisa e a lacuna sai do gabarito (gerar-corpus.py).
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'src');
const CORPUS = path.join(__dirname, 'corpus');
const args = process.argv.slice(2);
const opcao = (nome) => (args.includes(nome) ? args[args.indexOf(nome) + 1] ?? true : null);

const ler = (nome) => fs.readFileSync(path.join(SRC, nome), 'utf8');
// Os IPs do atacante no corpus são de documentação (RFC 5737), que o analisador descarta como "não públicos".
// Só aqui, durante o teste, eles passam a valer como públicos (é o papel que fazem nos e-mails).
const ipComTestNet = ler('lib/ip.js').split('\n').filter((l) => !/'(192\.0\.2|198\.51\.100|203\.0\.113)\.0'/.test(l)).join('\n');
const biblioteca = (nome) => (nome === 'ip.js' ? ipComTestNet : ler(`lib/${nome}`));

function executar(arquivo, bibliotecas, entrada, outrosNos) {
  const codigo = [...bibliotecas.map(biblioteca), ler(arquivo)].join('\n');
  const itens = (x) => (Array.isArray(x) ? x : [x]).map((json) => ({ json }));
  const $input = { first: () => itens(entrada)[0], all: () => itens(entrada) };
  const $ = (nome) => {
    if (!(nome in outrosNos)) throw new Error(`Nó "${nome}" não executado`);
    const lista = itens(outrosNos[nome]);
    return { first: () => lista[0], last: () => lista[lista.length - 1], all: () => lista };
  };
  return new Function('$input', '$', '$env', 'require', 'Buffer', codigo)($input, $, {}, require, Buffer).map((i) => i.json);
}

const CFG = {
  prefixoRedis: 'phishing:', glpiTela: 'http://127.0.0.1:8080/front/ticket.form.php?id=',
  categoria: 'Segurança > Phishing e e-mail suspeito', grupo: 'Segurança da Informação',
  cotaDiaria: 20, maxVirusTotal: 4, maxAnexos: 4, dominiosConfiaveis: 'cybersecurity.local',
  leitorQr: 'http://leitor-qr:8080/ler', maxArquivosQr: 4,
  // Pessoas-chave da organização fictícia do conjunto (diretoria e financeiro), como o lab configuraria.
  nomesInternos: 'Carla Mendes, Ana Ribeiro, Maria Souza',
};
// O GLPI guarda o conteúdo do chamado com as tags escapadas.
const comoGlpi = (texto) => `<p>${texto}</p>`.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function analisar(c, numero) {
  const eml = fs.readFileSync(path.join(CORPUS, c.arquivo), 'utf8');
  const nos = {
    'Configuração': CFG,
    'Escolhe o próximo': { chamado_id: 9000 + numero },
    'Lê o chamado': { body: { id: 9000 + numero, name: c.titulo.slice(0, 60), date: '2026-11-20 10:00:00', content: comoGlpi(c.relato) } },
    'Lê os requerentes': { body: [{ type: 1, users_id: c.requerente.split(' ')[0] }] },
    'Lê os acompanhamentos': { body: [] },
    'Escolhe o que baixar': [{ documento_id: 1, nome: path.basename(c.arquivo), mime: 'message/rfc822', sha1: '', baixar: true }],
    'Baixa os anexos': [{ statusCode: 200, body: eml }],
  };
  // QR Code: o nó que separa imagens/PDFs roda de verdade; o leitor-qr responde o que o gabarito diz que há no arquivo.
  const pedidos = executar('listar-arquivos-qr.js', ['ip.js', 'texto.js', 'email.js', 'indicadores.js', 'qr.js'], {}, nos);
  nos['Lista imagens e PDFs (QR)'] = pedidos;
  if (!pedidos[0].nenhum) {
    nos['Lê os QR Codes'] = pedidos.map((p) => ({ statusCode: 200, body: {
      codigos: (c.qr?.[p.nome] ?? []).map((texto) => ({ texto, formato: 'QRCode', pagina: 1 })), protegido: false, erro: '' } }));
  }
  const ev = executar('extrair-evidencias.js', ['ip.js', 'texto.js', 'email.js', 'indicadores.js', 'tecnicas.js', 'qr.js'], {}, nos)[0];
  const rep = c.reputacao ?? {};
  const vt = ev.consultas.virustotal.map((q) => (rep.virustotal?.[q.valor] ? { tipo: q.tipo, valor: q.valor, encontrado: true, ...rep.virustotal[q.valor] } : { tipo: q.tipo, valor: q.valor, encontrado: false }));
  const urlhaus = ev.consultas.urlhaus.map((h) => (rep.urlhaus?.[h] ? { host: h, listado: true, urls: 3, online: 2, ameacas: ['phishing'], tags: ['phishing'] } : { host: h, listado: false }));
  const rdap = ev.consultas.rdap.map((d) => (rep.rdap?.[d] !== undefined ? { dominio: d, idade_dias: rep.rdap[d], criado_em: '' } : { dominio: d, erro: 'HTTP 404' }));
  const d = executar('montar-dossie.js', ['texto.js'], {}, {
    'Extrai as evidências': ev, 'Resume o VirusTotal': { virustotal: vt }, 'Resume o URLhaus': { urlhaus }, 'Resume o RDAP': { rdap },
  })[0];
  const p = executar('parecer-final.js', ['texto.js'], { error: 'IA desligada na avaliação' }, { 'Monta o dossiê': d, 'Extrai as evidências': ev })[0].parecer;
  return { ev, d, p };
}

function avaliar(c, numero) {
  const { ev, d, p } = analisar(c, numero);
  const esperado = c.esperado.classificacao;
  const obtido = p.classificacao;
  let resultado;
  if (esperado === 'phishing') resultado = obtido === 'phishing' ? 'acerto' : obtido === 'inconclusivo' ? 'parcial' : 'erro';
  else if (esperado === 'legitimo') resultado = obtido === 'legitimo' ? 'acerto' : obtido === 'inconclusivo' ? 'parcial' : 'erro';
  else resultado = obtido === 'phishing' ? 'erro' : 'acerto'; // spam: as regras não separam spam de legítimo; só não pode virar phishing
  const falsoPositivo = esperado !== 'phishing' && obtido === 'phishing';
  const falsoNegativo = esperado === 'phishing' && obtido === 'legitimo';

  const ids = ev.sinais.map((s) => s.id).concat(d.sinais.map((s) => s.id));
  const faltando = c.sinais_obrigatorios.filter((s) => !ids.includes(s));
  const proibidos = (c.sinais_proibidos ?? []).filter((s) => ids.includes(s));
  const listas = [...ev.bloqueio.dominios, ...ev.iocs.dominios].map((x) => x.toLowerCase());
  const bloqueioFaltando = c.bloqueio.deve_ter.filter((x) => !listas.includes(x));
  const bloqueioProibido = c.bloqueio.nao_pode_ter.filter((x) => listas.includes(x));
  const todosIocs = JSON.stringify([ev.iocs, ev.bloqueio]);
  const escondidoAchado = c.ioc_escondido ? todosIocs.includes(c.ioc_escondido) : null;

  const problemas = [];
  if (resultado !== 'acerto' && !c.lacuna) problemas.push(`classificação ${obtido} (esperado ${esperado})`);
  if (falsoPositivo && c.lacuna) problemas.push('falso positivo');
  if (faltando.length) problemas.push(`sinal obrigatório ausente: ${faltando.join(', ')}`);
  if (proibidos.length) problemas.push(`sinal proibido presente: ${proibidos.join(', ')}`);
  if (bloqueioFaltando.length && !c.lacuna) problemas.push(`faltou no bloqueio: ${bloqueioFaltando.join(', ')}`);
  if (bloqueioProibido.length) problemas.push(`PROIBIDO no bloqueio: ${bloqueioProibido.join(', ')}`);
  // A lacuna só conta como resolvida quando a classificação acerta E aparecem os sinais que ela pede
  // (ex.: 'html-smuggling') E o IOC escondido (dentro do QR Code, do SVG...) foi achado.
  const futurosFaltando = (c.sinais_futuros ?? []).filter((s) => !ids.includes(s));
  const lacunaResolvida = Boolean(c.lacuna) && resultado === 'acerto' && !futurosFaltando.length && escondidoAchado !== false;

  return {
    id: c.id, esperado, obtido, resultado, falsoPositivo, falsoNegativo, lacuna: Boolean(c.lacuna), lacunaResolvida,
    nota: d.pontuacao, gravidade: p.gravidade, gravidadeEsperada: c.esperado.gravidade,
    sinais: ev.sinais.concat(d.sinais.filter((s) => !ev.sinais.some((e) => e.id === s.id))).map((s) => `${s.peso > 0 ? '+' : ''}${s.peso} ${s.id}`),
    bloqueio: ev.bloqueio, iocsFora: ev.iocs_fora.map((x) => x.valor), escondidoAchado, problemas,
    detalhe: { ev, parecer: p },
  };
}

const { casos } = JSON.parse(fs.readFileSync(path.join(CORPUS, 'casos.json'), 'utf8'));
const resultados = casos.map((c, i) => avaliar(c, i + 1));

const filtro = opcao('--caso');
if (filtro) {
  for (const r of resultados.filter((x) => x.id.startsWith(String(filtro)))) {
    const c = casos.find((x) => x.id === r.id);
    console.log(`\n=== ${r.id}: ${c.titulo}\nTécnica: ${c.tecnica}\nEsperado: ${r.esperado} | obtido: ${r.obtido} (nota ${r.nota}) | gravidade ${r.gravidade} (esperada ${r.gravidadeEsperada})`);
    console.log('Sinais:', r.sinais.join(' | ') || '(nenhum)');
    console.log('Bloqueio:', JSON.stringify(r.bloqueio), '\nFora do bloqueio:', r.iocsFora.join(', ') || '(nada)');
    console.log('Interação:', r.detalhe.ev.interacao.rotulos.join(', ') || '(nenhuma)');
    if (c.lacuna) console.log('Lacuna:', c.lacuna);
    if (r.problemas.length) console.log('PROBLEMAS:', r.problemas.join('; '));
  }
  process.exit(0);
}

const marca = { acerto: 'ok     ', parcial: 'parcial', erro: 'ERRO   ' };
console.log('Conjunto de referência: só regras + travas (IA desligada), reputação simulada\n');
for (const r of resultados) {
  const extra = [r.lacuna ? (r.lacunaResolvida ? 'lacuna RESOLVIDA? revise o gabarito' : 'lacuna conhecida') : '',
    r.escondidoAchado === false ? 'IOC escondido não achado' : '', ...r.problemas].filter(Boolean).join('; ');
  console.log(`  ${marca[r.resultado]} ${r.id.padEnd(40)} esperado ${r.esperado.padEnd(8)} obtido ${r.obtido.padEnd(12)} nota ${String(r.nota).padStart(3)}  ${extra}`);
}
const conta = (f) => resultados.filter(f).length;
const phishing = resultados.filter((r) => r.esperado === 'phishing');
const outros = resultados.filter((r) => r.esperado !== 'phishing');
console.log(`\nPhishing (${phishing.length}): ${conta((r) => r.esperado === 'phishing' && r.resultado === 'acerto')} detectados, `
  + `${conta((r) => r.esperado === 'phishing' && r.resultado === 'parcial')} inconclusivos (vão ao analista), `
  + `${conta((r) => r.falsoNegativo)} falsos negativos (saem como legítimo)`);
console.log(`Legítimos/spam (${outros.length}): ${conta((r) => r.esperado !== 'phishing' && r.resultado === 'acerto')} certos, `
  + `${conta((r) => r.esperado !== 'phishing' && r.resultado === 'parcial')} inconclusivos, ${conta((r) => r.falsoPositivo)} falsos positivos`);
console.log(`Lacunas conhecidas: ${conta((r) => r.lacuna)} (${conta((r) => r.lacunaResolvida)} parecem resolvidas)`);
const regressoes = resultados.filter((r) => r.problemas.length);
console.log(regressoes.length ? `\n${regressoes.length} caso(s) com REGRESSÃO.` : '\nSem regressão.');

const saidaJson = opcao('--json');
if (saidaJson && saidaJson !== true) {
  fs.writeFileSync(saidaJson, JSON.stringify(resultados.map(({ detalhe, ...r }) => r), null, 1));
  console.log(`Resultado gravado em ${saidaJson}`);
}
if (args.includes('--ci') && regressoes.length) process.exit(1);
