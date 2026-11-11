// Nó "Extrai as evidências": junta o relato do usuário (chamado + acompanhamentos) e o e-mail
// suspeito (anexo .eml/.msg ou cabeçalhos colados no chamado) e tira dali, SEM abrir nada:
//  - quem mandou de verdade (From, Reply-To, Return-Path, IP de origem, SPF/DKIM/DMARC);
//  - links (endereço real x texto mostrado), domínios, IPs, e-mails e anexos (nome, extensão, hash);
//  - sinais clássicos de phishing, cada um com peso e explicação;
//  - se o usuário disse que clicou, digitou senha, abriu anexo, respondeu ou pagou;
//  - o que consultar nas bases de reputação (com limite, por causa das cotas gratuitas).
const cfg = $('Configuração').first().json;
const todos = (nome) => { try { return $(nome).all().map((i) => i.json); } catch (erro) { return []; } };
const corpoDe = (nome) => { try { return $(nome).first().json.body; } catch (erro) { return null; } };

const chamadoId = Number($('Escolhe o próximo').first().json.chamado_id);
const chamado = corpoDe('Lê o chamado') ?? {};
const MARCADOR = 'analisador-phishing';

// ---------------- Relato do usuário ----------------
const requerentes = (Array.isArray(corpoDe('Lê os requerentes')) ? corpoDe('Lê os requerentes') : [])
  .filter((u) => Number(u.type) === 1)
  .map((u) => linha(typeof u.users_id === 'string' ? u.users_id : u.alternative_email || `usuário ${u.users_id}`, 80));
const acompanhamentos = (Array.isArray(corpoDe('Lê os acompanhamentos')) ? corpoDe('Lê os acompanhamentos') : [])
  .map((f) => htmlParaTexto(f.content))
  .filter((t) => t && !t.includes(MARCADOR));
const relatoBruto = String(chamado.content ?? '');
const relato = [htmlParaTexto(relatoBruto), ...acompanhamentos].filter(Boolean).join('\n\n---\n\n');

// ---------------- E-mail suspeito ----------------
const escolhidos = todos('Escolhe o que baixar');
const baixados = todos('Baixa os anexos');
const documentos = escolhidos.map((d, i) => ({ ...d, conteudo: d.baixar ? String(baixados[i]?.body ?? baixados[i]?.data ?? '') : '' }));

let mime = null;
let fonte = 'nenhuma';
const urlsExtras = [];
const emailsExtras = [];
let cabsColados = [];
for (const d of documentos) {
  if (!d.conteudo) continue;
  const ext = d.nome.toLowerCase().split('.').pop();
  if (ext === 'msg' || d.mime === 'application/vnd.ms-outlook') {
    // .msg do Outlook é binário (UTF-16): tirando os zeros, links e cabeçalhos aparecem como texto.
    const texto = d.conteudo.replace(/\u0000/g, '');
    urlsExtras.push(...extrairUrls(texto));
    emailsExtras.push(...extrairEmails(texto));
    if (!cabsColados.length) cabsColados = cabecalhosColados(texto);
    if (fonte === 'nenhuma') fonte = `anexo .msg (${d.nome})`;
    continue;
  }
  const leitura = analisarMime(d.conteudo);
  if (!mime && leitura.cabecalhos.some((c) => ['from', 'received', 'subject'].includes(c.nome))) {
    mime = leitura;
    // E-mail encaminhado COMO ANEXO dentro do .eml: o suspeito é o de dentro.
    while (mime.internas.length) mime = mime.internas[0];
    fonte = `anexo .eml (${d.nome})`;
  } else if (/^text\/|html|plain/.test(d.mime) || ['txt', 'htm', 'html'].includes(ext)) {
    urlsExtras.push(...extrairUrls(d.conteudo));
    urlsExtras.push(...extrairLinksHtml(d.conteudo).map((l) => l.href));
  }
}
if (!mime) {
  const colados = cabsColados.length ? cabsColados : cabecalhosColados(relato);
  if (colados.length) {
    mime = { cabecalhos: colados, textos: [], anexos: [], internas: [] };
    if (fonte === 'nenhuma') fonte = 'cabeçalhos colados no chamado';
  }
}
const cabs = mime?.cabecalhos ?? [];
const encaminhado = encaminhamentoColado(relato);
if (!mime && (encaminhado.de || encaminhado.assunto)) fonte = 'e-mail encaminhado / colado no chamado';

const de = endereco(cabecalho(cabs, 'from') || encaminhado.de);
const responder = endereco(cabecalho(cabs, 'reply-to') || encaminhado.responder);
const retorno = endereco(cabecalho(cabs, 'return-path'));
const auth = autenticacao(cabs);
const ipsOrigem = ipsDosRecebidos(cabs);
const textos = mime?.textos ?? [];
const html = textos.filter((t) => t.tipo === 'text/html').map((t) => t.conteudo).join('\n');
const textoPlano = textos.filter((t) => t.tipo === 'text/plain').map((t) => t.conteudo).join('\n') || htmlParaTexto(html);
const linksHtml = extrairLinksHtml(html);

const email = {
  fonte,
  de, responder, retorno,
  assunto: linha(decodificarPalavras(cabecalho(cabs, 'subject')) || encaminhado.assunto, 200),
  data: linha(cabecalho(cabs, 'date') || encaminhado.data, 80),
  message_id: linha(cabecalho(cabs, 'message-id'), 200),
  mailer: linha(cabecalho(cabs, 'x-mailer') || cabecalho(cabs, 'user-agent'), 100),
  autenticacao: auth,
  ips_origem: ipsOrigem.slice(0, 5),
  lista_descadastro: Boolean(cabecalho(cabs, 'list-unsubscribe')),
  corpo: curto(textoPlano, 3500),
};

// ---------------- Conteúdo dos anexos (catálogo de técnicas) ----------------
// Anexos HTML/SVG lidos como texto e .zip pelo índice: nada é executado nem descompactado.
const confiaveis = String(cfg.dominiosConfiaveis ?? '').toLowerCase().split(/[\s,;]+/).filter(Boolean);
const bytesDeTexto = (s) => Array.from(unescape(encodeURIComponent(String(s).slice(0, 2000000))), (c) => c.charCodeAt(0));
const inspecoes = [
  ...(mime?.anexos ?? []).map((a) => inspecionarAnexo(linha(a.nome, 120), a.tipo, a.bytes)),
  ...documentos.filter((d) => d.conteudo && !fonte.includes(d.nome) && /html|svg/i.test(d.mime + ' ' + d.nome))
    .map((d) => inspecionarAnexo(linha(d.nome, 120), d.mime, bytesDeTexto(d.conteudo))),
];

// ---------------- QR Codes (serviço leitor-qr do laboratório) ----------------
// Pedidos em "Lista imagens e PDFs (QR)" e respostas em "Lê os QR Codes", na mesma ordem.
// Leitor fora do ar: a análise segue sem o QR e o parecer avisa.
const pedidosQr = todos('Lista imagens e PDFs (QR)').filter((p) => !p.nenhum);
const respostasQr = todos('Lê os QR Codes');
const qr = { arquivos: pedidosQr.length, falhou: false, lidos: [], pix: [], protegidos: [] };
pedidosQr.forEach((p, k) => {
  const r = respostasQr[k] ?? {};
  const corpo = r.body && typeof r.body === 'object' ? r.body : null;
  if (!corpo || Number(r.statusCode) !== 200) { qr.falhou = true; return; }
  if (corpo.protegido) qr.protegidos.push(p.nome);
  for (const c of (Array.isArray(corpo.codigos) ? corpo.codigos : []).slice(0, 5)) {
    const texto = String(c.texto ?? '').slice(0, 2000);
    const pix = lerPix(texto);
    qr.lidos.push({ arquivo: p.nome, desenhado: Boolean(p.desenhado), pagina: Number(c.pagina) || 1, texto: linha(texto, 300), urls: pix ? [] : extrairUrls(texto, 5), pix });
    if (pix) qr.pix.push({ ...pix, arquivo: p.nome });
  }
});
const urlsDoQr = new Set(qr.lidos.flatMap((l) => l.urls));

// ---------------- Indicadores ----------------
const hostPermitido = (host) => host && host !== 'localhost' && !host.endsWith('.local') && !(ehIPv4(host) && ipBloqueado(host));
const urlsBase = unicos([
  ...linksHtml.map((l) => l.href),
  ...extrairUrls(textoPlano),
  ...urlsExtras,
  ...inspecoes.flatMap((i) => i.urls),
  ...urlsDoQr,
  ...extrairUrls(relato),
], 40);
const urlsDosAnexos = new Set(inspecoes.flatMap((i) => i.urls));
// O redirect_uri de um link de consentimento OAuth é o servidor do atacante: entra como link (vira IOC).
const urlsOAuth = new Set(destinosOAuth(urlsBase, confiaveis));
const todasUrls = unicos([...urlsBase, ...urlsOAuth], 45)
  .filter((u) => hostPermitido(partesDaUrl(u).host) && !u.startsWith(cfg.glpiTela.split('/front')[0]));

const urls = todasUrls.map((u) => {
  const { host, usuario } = partesDaUrl(u);
  const dominio = ehIPv4(host) ? host : dominioRegistravel(host);
  const link = linksHtml.find((l) => l.href === u);
  // Texto do link mostra um endereço, mas o link leva para outro host: truque clássico.
  const mostrado = link ? partesDaUrl(extrairUrls(link.texto)[0] ?? '').host : '';
  const disfarce = Boolean(mostrado && dominioRegistravel(mostrado) !== dominio);
  return {
    url: u, host, dominio,
    sinais: [
      usuario && 'usa "usuário@" para esconder o destino',
      ehIPv4(host) && 'endereço IP no lugar do nome',
      ENCURTADORES.has(host) && 'encurtador de link',
      noDominio(host, HOSPEDAGEM_ABUSADA) && 'serviço gratuito muito usado para hospedar phishing',
      host.startsWith('xn--') || host.includes('.xn--') ? 'domínio com caracteres internacionais (punycode)' : false,
      disfarce && `o texto do link mostra "${mostrado}", mas leva para "${host}"`,
      urlsDosAnexos.has(u) && 'achado dentro de um anexo (HTML/SVG)',
      urlsDoQr.has(u) && 'lido de um QR Code (link escondido em imagem)',
      urlsOAuth.has(u) && 'destino do consentimento OAuth (redirect_uri): servidor que recebe o acesso',
    ].filter(Boolean),
    texto_do_link: link ? link.texto : '',
  };
});

const anexos = [];
let hash = null;
try { const crypto = require('crypto'); hash = (bytes) => crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex'); } catch (erro) { hash = null; }
for (const a of mime?.anexos ?? []) {
  const exts = extensoes(a.nome);
  anexos.push({
    nome: linha(a.nome, 120), tipo: a.tipo, tamanho: a.tamanho, origem: 'dentro do e-mail',
    sha256: hash && a.bytes?.length ? hash(a.bytes) : '', sha1: '', extensoes: exts,
  });
}
// O que estava DENTRO dos anexos: nomes do .zip e a carga contrabandeada (HTML smuggling), com hash para bloquear.
for (const i of inspecoes) {
  const dono = anexos.find((a) => a.nome === i.nome);
  if (dono && i.internos.length) dono.conteudo = i.internos.slice(0, 10).map((n) => linha(n, 100));
  for (const [k, carga] of i.cargas.slice(0, 2).entries()) {
    if (!hash) break;
    anexos.push({ nome: `carga escondida ${k + 1} em ${i.nome}`, tipo: ehZip(carga) ? 'application/zip' : 'application/octet-stream', tamanho: carga.length,
      origem: 'escondido no anexo', sha256: hash(carga), sha1: '', extensoes: ehZip(carga) ? ['zip'] : [] });
  }
}
for (const d of documentos) {
  if (d.conteudo && fonte.includes(d.nome)) continue; // o próprio e-mail
  if (/^image\//.test(d.mime)) { anexos.push({ nome: linha(d.nome, 120), tipo: d.mime, origem: 'print no chamado', sha1: d.sha1, sha256: '', extensoes: extensoes(d.nome), print: true }); continue; }
  anexos.push({ nome: linha(d.nome, 120), tipo: d.mime, origem: 'anexo do chamado', sha1: d.sha1, sha256: '', extensoes: extensoes(d.nome) });
}
for (const a of anexos) {
  const ultima = a.extensoes[a.extensoes.length - 1] ?? '';
  a.perigosa = EXTENSOES_PERIGOSAS.has(ultima);
  a.compactada = EXTENSOES_COMPACTADAS.has(ultima);
  a.dupla_extensao = a.extensoes.length >= 2 && (a.perigosa || a.compactada) && /^(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt)$/.test(a.extensoes[a.extensoes.length - 2]);
}

const emails = unicos([de.email, responder.email, retorno.email, ...extrairEmails(textoPlano), ...emailsExtras].filter(Boolean), 15);
const ips = unicos([...ipsOrigem, ...urls.filter((u) => ehIPv4(u.host)).map((u) => u.host), ...extrairIPs(textoPlano)], 10);

// ---------------- Sinais (heurísticas) ----------------
const sinais = [];
const sinal = (id, peso, descricao) => sinais.push({ id, peso, descricao });
const ruim = (r) => ['fail', 'softfail', 'permerror', 'none'].includes(r);
if (auth.presente) {
  if (['fail', 'softfail'].includes(auth.spf)) sinal('spf', 15, `SPF = ${auth.spf}: o servidor que enviou não está autorizado pelo domínio ${de.dominio || '(remetente)'}`);
  if (auth.dkim === 'fail') sinal('dkim', 10, 'DKIM = fail: assinatura do e-mail inválida (pode ter sido alterado ou forjado)');
  if (auth.dmarc === 'fail') sinal('dmarc', 20, `DMARC = fail: o e-mail NÃO prova que veio de ${de.dominio || 'quem diz ser'}`);
  // Em webmail gratuito qualquer um cria a conta: passar na autenticação não diz nada sobre quem escreveu.
  if (auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass') {
    if (WEBMAIL_GRATUITO.has(dominioRegistravel(de.dominio))) sinal('autenticado', 0, `SPF, DKIM e DMARC passaram, mas ${de.dominio} é webmail gratuito: qualquer pessoa cria uma conta (não conta a favor)`);
    else sinal('autenticado', -15, `SPF, DKIM e DMARC passaram: o e-mail saiu mesmo de ${de.dominio} (isso não garante que o domínio seja confiável)`);
  }
  else if (!['fail', 'softfail'].includes(auth.spf) && ruim(auth.dkim) && ruim(auth.dmarc) && auth.dmarc) sinal('sem-autenticacao', 5, 'e-mail sem DKIM/DMARC válidos');
}
if (responder.dominio && de.dominio && dominioRegistravel(responder.dominio) !== dominioRegistravel(de.dominio)) {
  sinal('reply-to', 15, `as respostas vão para ${responder.email}, outro domínio que não o do remetente (${de.dominio})`);
}
if (retorno.dominio && de.dominio && dominioRegistravel(retorno.dominio) !== dominioRegistravel(de.dominio)) {
  sinal('return-path', 5, `Return-Path (${retorno.dominio}) diferente do remetente; comum em plataformas de envio, mas some aos outros sinais`);
}
const emailNoNome = (de.nome.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i) ?? [''])[0].toLowerCase();
if (emailNoNome && emailNoNome !== de.email) sinal('nome-falso', 20, `o nome de exibição mostra "${emailNoNome}", mas o endereço real é ${de.email}`);
const imitada = marcaImitada(de.dominio, de.nome, email.assunto);
if (imitada) {
  sinal('marca', imitada.sosia ? 25 : 20, `${imitada.sosia ? 'domínio parecido com' : 'usa o nome de'} ${imitada.marca}, mas o remetente é ${de.dominio} (oficiais: ${imitada.oficiais.join(', ')})`);
}
if (de.dominio && WEBMAIL_GRATUITO.has(de.dominio) && (imitada || /\b(banco|suporte|equipe|financeiro|rh|ti|seguran[cç]a|atendimento|diretor|ceo|presidente)\b/i.test(de.nome))) {
  sinal('webmail', 10, `fala em nome de empresa/cargo ("${linha(de.nome, 40)}"), mas usa e-mail gratuito (${de.dominio})`);
}
if ((de.dominio || '').startsWith('xn--') || (de.dominio || '').includes('.xn--')) sinal('punycode-remetente', 15, `domínio do remetente com caracteres internacionais: ${de.dominio}`);
const marcasNosLinks = urls.map((u) => ({ u, m: marcaImitada(u.host, u.texto_do_link) })).filter((x) => x.m);
if (marcasNosLinks.length) sinal('marca-link', 20, `link imita ${marcasNosLinks[0].m.marca}: ${desarmar(marcasNosLinks[0].u.host)}`);
const disfarcados = urls.filter((u) => u.sinais.some((s) => s.startsWith('o texto do link')));
if (disfarcados.length) sinal('link-disfarcado', 25, disfarcados[0].sinais.find((s) => s.startsWith('o texto do link')));
if (urls.some((u) => u.sinais.includes('usa "usuário@" para esconder o destino'))) sinal('url-usuario', 20, 'link com "usuário@" escondendo o destino real');
if (urls.some((u) => ehIPv4(u.host))) sinal('url-ip', 20, 'link aponta direto para um endereço IP');
if (urls.some((u) => ENCURTADORES.has(u.host))) sinal('encurtador', 10, 'link encurtado esconde o destino');
if (urls.some((u) => noDominio(u.host, HOSPEDAGEM_ABUSADA))) sinal('hospedagem', 8, 'link em serviço gratuito muito usado para hospedar páginas falsas (formulários, drives, páginas estáticas)');
if (urls.some((u) => u.host.includes('xn--'))) sinal('url-punycode', 15, 'link com domínio em punycode (pode imitar letras de outro alfabeto)');
if (/<form\b/i.test(html)) sinal('formulario', 15, 'o próprio e-mail tem um formulário (pede dados sem abrir site)');
for (const a of anexos.filter((x) => !x.print)) {
  if (a.dupla_extensao) sinal('dupla-extensao', 25, `anexo com extensão dupla para enganar: ${a.nome}`);
  else if (a.perigosa) sinal('anexo-perigoso', 25, `anexo de tipo que executa código ou abre página: ${a.nome}`);
  else if (a.compactada) sinal('anexo-compactado', 10, `anexo compactado (pode esconder executável): ${a.nome}`);
  if (/\.(docm|xlsm|pptm)$/i.test(a.nome)) sinal('macro', 15, `documento Office com macro: ${a.nome}`);
}
const textoAnalisado = [email.assunto, textoPlano].join('\n');
for (const s of SINAIS_TEXTO) if (s.re.test(textoAnalisado)) sinal(s.id, s.peso, `texto do e-mail: ${s.rotulo}`);
// Catálogo de técnicas (src/lib/tecnicas.js): cada achado vira sinal; os "fortes" viram evidência forte no dossiê.
const nomesInternos = String(cfg.nomesInternos ?? '').split(/[,;\n]+/).map((n) => n.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/\s+/g, ' ').trim()).filter(Boolean);
const tecnicas = detectarTecnicas({
  de, responder, assunto: email.assunto, texto: textoPlano, relato, urls, inspecoes, qr,
  emailsTexto: extrairEmails(textoPlano), confiaveis, nomesInternos, sinaisIds: sinais.map((s) => s.id),
  autenticado: auth.dmarc === 'pass' || (auth.spf === 'pass' && auth.dkim === 'pass'),
});
for (const t of tecnicas) sinal(t.id, t.peso, `${t.forte ? '[técnica forte] ' : ''}${t.descricao}`);
if (email.lista_descadastro && !sinais.some((s) => s.peso >= 15)) sinal('descadastro', -5, 'tem link de descadastro (List-Unsubscribe), típico de e-mail de marketing');

// ---------------- O usuário interagiu? ----------------
const interacao = interacaoDoUsuario(relato);

// ---------------- O que consultar nas bases de reputação ----------------
const conhecido = (d) => MARCAS.some((m) => noDominio(d, m.oficiais)) || WEBMAIL_GRATUITO.has(d) || noDominio(d, HOSPEDAGEM_ABUSADA);
const prioridade = (u) => (u.sinais.length ? 0 : 1);
const urlsOrdenadas = [...urls].sort((a, b) => prioridade(a) - prioridade(b));
const maxVT = Number(cfg.maxVirusTotal) || 4;
const virustotal = [];
for (const a of anexos.filter((x) => !x.print && (x.sha256 || x.sha1))) {
  if (virustotal.length >= Math.min(2, maxVT)) break;
  virustotal.push({ tipo: 'arquivo', valor: a.nome, caminho: `files/${a.sha256 || a.sha1}` });
}
for (const u of urlsOrdenadas) {
  if (virustotal.length >= maxVT - (de.dominio && !conhecido(de.dominio) ? 1 : 0)) break;
  virustotal.push({ tipo: 'url', valor: u.url, caminho: `urls/${base64Url(u.url)}` });
}
if (de.dominio && !conhecido(de.dominio) && virustotal.length < maxVT) {
  virustotal.push({ tipo: 'domínio do remetente', valor: de.dominio, caminho: `domains/${encodeURIComponent(dominioRegistravel(de.dominio))}` });
}
const urlhaus = unicos(urls.map((u) => u.host).filter((h) => !conhecido(dominioRegistravel(h)) && !noDominio(h, [...ENCURTADORES])), 5);
const rdap = unicos([de.dominio, responder.dominio, ...urls.map((u) => u.dominio)]
  .filter((d) => d && !ehIPv4(d))
  .map((d) => dominioRegistravel(d))
  .filter((d) => !conhecido(d) && !ENCURTADORES.has(d)), 3);

// ---------------- IOCs para bloqueio ----------------
// Só entra o que é do atacante. Bloquear gmail.com, itau.com.br ou um serviço compartilhado pararia a empresa:
// esses ficam fora da lista, com o motivo, para o analista ver por que não entraram.
function motivoLegitimo(host) {
  const h = String(host ?? '').toLowerCase();
  if (!h) return null;
  if (noDominio(h, confiaveis)) return { tipo: 'casa', motivo: 'domínio da própria organização' };
  if (WEBMAIL_GRATUITO.has(h) || WEBMAIL_GRATUITO.has(dominioRegistravel(h))) return { tipo: 'webmail', motivo: 'webmail gratuito: bloqueie só o endereço, não o domínio' };
  if (noDominio(h, HOSPEDAGEM_ABUSADA)) return { tipo: 'compartilhado', motivo: 'serviço compartilhado: bloqueie só a URL, não o domínio' };
  if (ENCURTADORES.has(h) || ENCURTADORES.has(dominioRegistravel(h))) return { tipo: 'compartilhado', motivo: 'encurtador de links: bloqueie só a URL, não o domínio' };
  const marca = MARCAS.find((m) => noDominio(h, m.oficiais));
  if (marca) return { tipo: 'oficial', motivo: `domínio oficial de ${marca.nome}` };
  return null;
}
const iocsFora = [];
const fora = (valor, motivo) => { if (!iocsFora.some((x) => x.valor === valor)) iocsFora.push({ valor, motivo }); };
// Endereço e URL saem só se forem de um domínio oficial ou da casa (endereço forjado / link verdadeiro da marca).
const filtra = (lista, hostDe) => lista.filter((valor) => {
  const m = motivoLegitimo(hostDe(valor));
  if (m && (m.tipo === 'oficial' || m.tipo === 'casa')) { fora(valor, m.motivo); return false; }
  return true;
});
const iocs = {
  remetente: filtra(unicos([de.email, responder.email, retorno.email].filter(Boolean), 5), (x) => x.split('@')[1]),
  urls: filtra(unicos(urls.map((u) => u.url), 15), (x) => partesDaUrl(x).host),
  dominios: unicos([de.dominio, responder.dominio, ...urls.map((u) => u.dominio)].filter(Boolean), 15).filter((d) => {
    const m = motivoLegitimo(d);
    if (m) { fora(d, m.motivo); return false; }
    return true;
  }),
  ips: ips.slice(0, 10),
  hashes: anexos.filter((a) => !a.print && (a.sha256 || a.sha1)).map((a) => `${a.sha256 || a.sha1} (${a.nome})`),
  telefones: tecnicas.filter((t) => t.telefone).map((t) => t.telefone),
  // PIX lido de QR: não vai para o bloqueio do Wazuh; serve para o financeiro/banco (golpe do boleto).
  pix: qr.pix.map((p) => [p.recebedor && `recebedor ${p.recebedor}`, p.chave && `chave ${p.chave}`, p.url && `cobrança ${p.url}`, p.valor && `R$ ${p.valor}`].filter(Boolean).join(' · ')).filter(Boolean),
};

// O que pode ir para as listas do Wazuh (botão "Bloquear IOCs"): domínios e hosts dos links que não são
// legítimos nem compartilhados, IPs que aparecem DENTRO dos links (públicos) e os hashes dos anexos.
// O IP do servidor que enviou o e-mail fica de fora: num phishing mandado pelo Gmail, ele é do Google.
const hostsLinks = unicos(urls.map((u) => u.host).filter(Boolean), 30);
const bloqueio = {
  dominios: unicos([...iocs.dominios, ...hostsLinks.filter((h) => !ehIPv4(h) && (!motivoLegitimo(h) || subdominioDeCliente(h)))].map((d) => d.toLowerCase()), 30),
  ips: hostsLinks.filter((h) => ehIPv4(h) && !ipBloqueado(h)),
  hashes: unicos(anexos.filter((a) => !a.print).flatMap((a) => [a.sha256, a.sha1]).filter(Boolean).map((h) => String(h).toLowerCase()), 20),
};

return [{ json: {
  chamado: {
    id: chamadoId,
    titulo: linha(chamado.name, 150),
    aberto_em: String(chamado.date ?? ''),
    requerentes,
    link: cfg.glpiTela + chamadoId,
  },
  relato: curto(relato, 3000),
  email,
  urls: urls.slice(0, 20),
  emails,
  ips,
  anexos,
  sinais,
  tecnicas: tecnicas.map(({ id, nome, forte, abusaServico, mitre, orientacao, descricao }) => ({ id, nome, forte, abusaServico, mitre, orientacao, descricao })),
  interacao,
  qr: { arquivos: qr.arquivos, falhou: qr.falhou, lidos: qr.lidos.slice(0, 8).map(({ urls, ...l }) => l), protegidos: qr.protegidos },
  iocs,
  iocs_fora: iocsFora.slice(0, 15),
  bloqueio,
  tem_email: fonte !== 'nenhuma',
  consultas: { virustotal, urlhaus, rdap },
} }];
