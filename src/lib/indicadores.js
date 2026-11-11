// ---- Biblioteca: indicadores (IOCs) e sinais clássicos de phishing ----
// Listas curtas e explicáveis: cada sinal vira uma frase que o analista entende e pode contestar.

const SEGUNDO_NIVEL = new Set([
  'com', 'net', 'org', 'gov', 'edu', 'mil', 'co', 'ac', 'or', 'ne', 'go', 'gob', 'nom', 'ltd', 'plc', 'sch',
  'art', 'blog', 'app', 'dev', 'eco', 'emp', 'ind', 'inf', 'adv', 'eng', 'med', 'tur', 'tv', 'arq', 'jus', 'leg', 'mp',
]);

// "www.loja.exemplo.com.br" -> "exemplo.com.br" (aproximação da Public Suffix List).
function dominioRegistravel(host) {
  const rotulos = String(host ?? '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (rotulos.length <= 2) return rotulos.join('.');
  const tld = rotulos[rotulos.length - 1];
  const tamanho = tld.length === 2 && SEGUNDO_NIVEL.has(rotulos[rotulos.length - 2]) ? 3 : 2;
  return rotulos.slice(-tamanho).join('.');
}

const MARCAS = [
  { nome: 'Itaú', chaves: ['itau', 'itaú'], oficiais: ['itau.com.br', 'itau.com', 'itaubba.com'] },
  { nome: 'Bradesco', chaves: ['bradesco'], oficiais: ['bradesco.com.br', 'bradesco'] },
  { nome: 'Santander', chaves: ['santander'], oficiais: ['santander.com.br', 'santander.com'] },
  { nome: 'Caixa', chaves: ['caixa econ', 'caixa.gov', 'caixatem', 'caixa tem'], oficiais: ['caixa.gov.br'] },
  { nome: 'Banco do Brasil', chaves: ['banco do brasil', 'bancodobrasil'], oficiais: ['bb.com.br'] },
  { nome: 'Nubank', chaves: ['nubank'], oficiais: ['nubank.com.br', 'nu.com.br'] },
  { nome: 'Banco Inter', chaves: ['bancointer', 'banco inter'], oficiais: ['bancointer.com.br', 'inter.co'] },
  { nome: 'Mercado Livre / Mercado Pago', chaves: ['mercadolivre', 'mercado livre', 'mercadopago', 'mercado pago'], oficiais: ['mercadolivre.com.br', 'mercadopago.com.br', 'mercadolibre.com'] },
  { nome: 'Microsoft', chaves: ['microsoft', 'office365', 'office 365', 'outlook', 'onedrive', 'sharepoint'], oficiais: ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'microsoftonline.com', 'office365.com', 'sharepoint.com', 'sharepointonline.com', 'onmicrosoft.com', 'microsoft365.com'] },
  { nome: 'Google', chaves: ['google', 'gmail'], oficiais: ['google.com', 'gmail.com', 'google.com.br', 'googlemail.com', 'googleusercontent.com', 'withgoogle.com'] },
  { nome: 'Apple', chaves: ['apple', 'icloud'], oficiais: ['apple.com', 'icloud.com'] },
  { nome: 'PayPal', chaves: ['paypal'], oficiais: ['paypal.com', 'paypal.com.br'] },
  { nome: 'Correios', chaves: ['correios'], oficiais: ['correios.com.br'] },
  { nome: 'Receita Federal / gov.br', chaves: ['receita federal', 'gov.br', 'serpro'], oficiais: ['gov.br', 'serpro.gov.br'] },
  { nome: 'Serasa', chaves: ['serasa'], oficiais: ['serasa.com.br', 'serasaexperian.com.br'] },
  { nome: 'Netflix', chaves: ['netflix'], oficiais: ['netflix.com'] },
  { nome: 'Amazon', chaves: ['amazon'], oficiais: ['amazon.com', 'amazon.com.br', 'amazonses.com', 'amazonaws.com'] },
  { nome: 'Meta (WhatsApp/Facebook/Instagram)', chaves: ['whatsapp', 'facebook', 'instagram'], oficiais: ['whatsapp.com', 'facebook.com', 'facebookmail.com', 'instagram.com', 'meta.com'] },
  { nome: 'DocuSign', chaves: ['docusign'], oficiais: ['docusign.com', 'docusign.net'] },
  { nome: 'DHL', chaves: ['dhl'], oficiais: ['dhl.com', 'dhl.com.br'] },
  { nome: 'LinkedIn', chaves: ['linkedin'], oficiais: ['linkedin.com'] },
];

const ENCURTADORES = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly', 'buff.ly',
  'shorturl.at', 'tiny.cc', 'encurtador.com.br', 'l1nq.com', 'rebrand.ly', 's.id', 'v.gd', 't.ly', 'bit.do', 'lnkd.in', 'qrco.de']);

// Serviços legítimos muito usados para HOSPEDAR páginas de phishing (o domínio em si não é malicioso).
const HOSPEDAGEM_ABUSADA = ['drive.google.com', 'docs.google.com', 'forms.gle', 'sites.google.com', 'firebaseapp.com', 'web.app',
  'pages.dev', 'workers.dev', 'r2.dev', 'github.io', 'netlify.app', 'vercel.app', 'glitch.me', 'weebly.com', 'wixsite.com',
  '000webhostapp.com', 'blogspot.com', 'dropbox.com', '1drv.ms', 'onedrive.live.com', 'notion.site', 'ipfs.io', 'ngrok-free.app',
  'ngrok.io', 'trycloudflare.com', 'typeform.com', 'jotform.com', 'canva.site', 'webflow.io', 'framer.app'];

// Hospedagens em que cada SUBDOMÍNIO é de um único cliente (golpe.pages.dev é só do atacante): o subdomínio pode ir
// para o bloqueio; o domínio do serviço (pages.dev) nunca.
const HOSPEDAGEM_POR_SUBDOMINIO = ['firebaseapp.com', 'web.app', 'pages.dev', 'workers.dev', 'r2.dev', 'github.io', 'netlify.app',
  'vercel.app', 'glitch.me', 'weebly.com', 'wixsite.com', '000webhostapp.com', 'blogspot.com', 'notion.site', 'ngrok-free.app',
  'ngrok.io', 'trycloudflare.com', 'canva.site', 'webflow.io', 'framer.app'];
function subdominioDeCliente(host) {
  const h = String(host ?? '').toLowerCase();
  return !h.startsWith('www.') && HOSPEDAGEM_POR_SUBDOMINIO.some((d) => h.endsWith('.' + d));
}

const WEBMAIL_GRATUITO =new Set(['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'yahoo.com.br', 'bol.com.br',
  'uol.com.br', 'terra.com.br', 'icloud.com', 'proton.me', 'protonmail.com', 'gmx.com', 'aol.com', 'zoho.com', 'mail.com', 'yandex.com']);

const EXTENSOES_PERIGOSAS = new Set(['exe', 'scr', 'com', 'pif', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'bat', 'cmd', 'ps1',
  'lnk', 'iso', 'img', 'vhd', 'vhdx', 'msi', 'msix', 'appx', 'jar', 'html', 'htm', 'shtml', 'xhtml', 'svg', 'one', 'docm', 'xlsm',
  'pptm', 'xlam', 'dotm', 'xll', 'chm', 'reg', 'cpl', 'url', 'library-ms', 'search-ms', 'application']);
const EXTENSOES_COMPACTADAS = new Set(['zip', 'rar', '7z', 'gz', 'tgz', 'cab', 'ace', 'arj', 'xz', 'bz2', 'z']);

const SINAIS_TEXTO = [
  { id: 'urgencia', peso: 10, rotulo: 'linguagem de urgência ou ameaça', re: /(conta|acesso|cart[aã]o|cpf|cadastro)\s+(ser[aá]|foi|est[aá]|ser[aã]o)\s+(bloquead|suspens|cancelad|encerrad|desativad)|\b(urgente|imediatamente|[uú]ltimas?\s+horas|em\s+(24|48|72)\s*h(oras)?|prazo\s+final|evite\s+o\s+bloqueio)\b|\b(urgent|immediately|account (will be )?(suspended|locked|closed))\b/i },
  { id: 'credenciais', peso: 10, rotulo: 'pede para confirmar senha, dados ou identidade', re: /\b(confirm|atualiz|valid|verifiqu|recadastr|regulariz)\w*\s+(a\s+|o\s+|sua\s+|seu\s+|seus\s+|suas\s+)?(senha|dados|cadastro|identidade|conta|credenciais|token|chave)|\bsenha\s+(expir|vence|ir[aá]\s+expirar)|\b(acesse|entre|logue|fa[cç]a\s+(o\s+)?login)\s+(com\s+)?(o\s+|a\s+)?(seu|sua)\s+(usu[aá]rio|login|e-?mail|matr[ií]cula)\s+e\s+senha|\b(verify your (account|identity)|password (expires|expired)|unusual sign.?in|confirm your (password|account))\b/i },
  { id: 'pagamento', peso: 10, rotulo: 'fala de pagamento, boleto, PIX, multa ou prêmio', re: /\b(boleto|fatura em aberto|pagamento pendente|d[eé]bito pendente|pix|multa|intima[cç][aã]o|restitui[cç][aã]o|pr[eê]mio|voc[eê] ganhou|sorteio|reembolso|invoice|payment (due|overdue)|wire transfer)\b/i },
  { id: 'bec', peso: 15, rotulo: 'padrão de fraude do "chefe" (BEC): pedido de transferência, troca de conta ou cartão-presente', re: /\b(novos dados banc[aá]rios|mudan[cç]a (de|da) conta banc[aá]ria|alterar (a )?conta (para|de) pagamento|preciso de um favor|cart(ão|oes|ões)[- ]presente|gift ?cards?|transfer[eê]ncia urgente|n[aã]o comente com ningu[eé]m)\b/i },
  { id: 'qrcode', peso: 10, rotulo: 'pede para ler QR Code (quishing)', re: /\b(qr ?code|c[oó]digo qr)\b/i },
];

// Remove o "desarme" que o usuário ou outro analista possa ter feito: hxxp, [.], (.), [:]
function rearmar(texto) {
  return String(texto ?? '').replace(/\bhxxp(s?)/gi, 'http$1').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':').replace(/\[@\]/g, '@');
}

function limparUrl(url) {
  return String(url).replace(/[.,;:!?'")\]}>]+$/, '').replace(/&amp;/g, '&');
}

function extrairUrls(texto, maximo = 40) {
  const achadas = [];
  for (const m of rearmar(texto).matchAll(/\b(?:https?:\/\/|www\.)[^\s<>"'`\])}]+/gi)) {
    let url = limparUrl(m[0]);
    if (/^www\./i.test(url)) url = 'http://' + url;
    if (url.length > 8) achadas.push(url.slice(0, 2000));
  }
  return unicos(achadas, maximo);
}

// Links de um HTML: o endereço real (href) e o texto que o usuário vê.
function extrairLinksHtml(html, maximo = 60) {
  const links = [];
  for (const m of String(html ?? '').matchAll(/<a\b[^>]*?\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi)) {
    const href = limparUrl(decodificarEntidades((m[2] ?? m[3] ?? m[4] ?? '').trim()));
    if (!/^https?:\/\//i.test(href)) continue;
    links.push({ href, texto: linha(htmlParaTexto(m[5]), 200) });
    if (links.length >= maximo) break;
  }
  return links;
}

// Host de uma URL e sinais da própria URL (usuário@ escondendo o destino, IP no lugar do nome).
function partesDaUrl(url) {
  const m = String(url).match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i);
  if (!m) return { host: '', usuario: false };
  const autoridade = m[1];
  const usuario = autoridade.includes('@');
  const host = autoridade.slice(autoridade.lastIndexOf('@') + 1).replace(/:\d+$/, '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  return { host, usuario };
}

function extrairEmails(texto, maximo = 30) {
  return unicos(Array.from(rearmar(texto).matchAll(/\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}\b/gi), (m) => m[0].toLowerCase()), maximo);
}

function extrairIPs(texto, maximo = 20) {
  return unicos(Array.from(rearmar(texto).matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g), (m) => m[0]).filter((ip) => ehIPv4(ip) && !ipBloqueado(ip)), maximo);
}

function noDominio(host, dominios) {
  const h = String(host ?? '').toLowerCase();
  return dominios.some((d) => h === d || h.endsWith('.' + d));
}

function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 3) return 99;
  let anterior = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const atual = [i];
    for (let j = 1; j <= b.length; j++) {
      atual[j] = Math.min(anterior[j] + 1, atual[j - 1] + 1, anterior[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    anterior = atual;
  }
  return anterior[b.length];
}

// Troca caracteres que imitam letras (0->o, 1->l, rn->m, vv->w) para achar domínios parecidos.
function normalizarSosia(texto) {
  return String(texto).toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1!|]/g, 'l')
    .replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/[^a-z]/g, '');
}

// Marca citada (no nome de exibição ou no domínio) que não combina com o domínio de verdade.
function marcaImitada(dominio, ...textos) {
  const d = String(dominio ?? '').toLowerCase();
  if (!d) return null;
  const alvo = textos.join(' ').toLowerCase();
  if (MARCAS.some((m) => noDominio(d, m.oficiais))) return null;
  const rotulo = dominioRegistravel(d).split('.')[0];
  for (const marca of MARCAS) {
    const citada = marca.chaves.some((c) => alvo.includes(c) || d.includes(c.replace(/\s+/g, '')));
    const sosia = marca.chaves.some((c) => {
      const chave = normalizarSosia(c);
      const r = normalizarSosia(rotulo);
      const trocouLetra = r === chave && rotulo.replace(/[^a-z]/g, '') !== chave; // micros0ft, itaú com 1 no lugar de l...
      return chave.length >= 4 && (trocouLetra || (r !== chave && (levenshtein(r, chave) <= (chave.length >= 7 ? 2 : 1) || r.includes(chave))));
    });
    if (citada || sosia) return { marca: marca.nome, oficiais: marca.oficiais.slice(0, 3), sosia };
  }
  return null;
}

// O usuário disse no chamado que clicou, digitou senha, abriu anexo, respondeu ou pagou?
// Frases com "não" logo antes ("não cliquei") contam como negadas.
const INTERACOES = [
  { id: 'clicou', rotulo: 'clicou no link', re: /\b(cliquei|clicou|clicamos|acessei|acessou|abri o link|entrei no (link|site)|cliquei no)\b/gi },
  { id: 'senha', rotulo: 'digitou senha ou dados', re: /\b(digitei|digitou|informei|informou|coloquei|colocou|inseri|inseriu|preenchi|preencheu|passei)\b[^.\n]{0,40}?\b(senha|credenciais|login|dados|cart[aã]o|c[oó]digo|token|cpf)\b/gi },
  { id: 'anexo', rotulo: 'abriu ou baixou o anexo', re: /\b(abri|abriu|baixei|baixou|executei|executou|instalei|instalou|habilitei (as )?macros?)\b[^.\n]{0,30}?\b(anexo|arquivo|documento|programa|planilha|pdf|macros?)\b/gi },
  { id: 'respondeu', rotulo: 'respondeu ao remetente', re: /\b(respondi|respondeu|respondemos)\b/gi },
  { id: 'pagou', rotulo: 'fez pagamento ou transferência', re: /\b(paguei|pagou|fiz o pix|fez o pix|transferi|transferiu|fiz a transfer[eê]ncia)\b/gi },
];

function interacaoDoUsuario(texto) {
  const t = String(texto ?? '');
  const saida = {};
  const trechos = [];
  for (const i of INTERACOES) {
    saida[i.id] = false;
    for (const m of t.matchAll(i.re)) {
      const antes = t.slice(Math.max(0, m.index - 25), m.index).toLowerCase();
      if (/\b(n[aã]o|nem|nunca|sem)\s+(\w+\s+){0,2}$/.test(antes)) continue;
      saida[i.id] = true;
      trechos.push(linha(t.slice(Math.max(0, m.index - 40), m.index + m[0].length + 40), 140));
      break;
    }
  }
  saida.algum = INTERACOES.some((i) => saida[i.id]);
  saida.rotulos = INTERACOES.filter((i) => saida[i.id]).map((i) => i.rotulo);
  saida.trechos = trechos.slice(0, 3);
  return saida;
}

// ID de URL do VirusTotal: base64url da URL, sem "=" no final (feito à mão: a sandbox pode não ter Buffer).
function base64Url(texto) {
  const tabela = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const bytes = [];
  for (const c of String(texto)) {
    const codigo = c.charCodeAt(0);
    if (codigo < 0x80) bytes.push(codigo);
    else for (const b of unescape(encodeURIComponent(c))) bytes.push(b.charCodeAt(0));
  }
  let saida = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    saida += tabela[(n >> 18) & 63] + tabela[(n >> 12) & 63];
    if (i + 1 < bytes.length) saida += tabela[(n >> 6) & 63];
    if (i + 2 < bytes.length) saida += tabela[n & 63];
  }
  return saida;
}

function extensoes(nome) {
  return String(nome ?? '').toLowerCase().split('.').slice(1).map((e) => e.trim());
}
// ---- fim da biblioteca ----
