// ---- Biblioteca: CATÁLOGO DE TÉCNICAS de phishing ----
// Cada técnica é um detector determinístico que só LÊ o e-mail (nada é aberto nem executado):
//  - anexos HTML/SVG lidos como texto (HTML smuggling, script, formulário de senha, redirecionamento);
//  - base64 escondido nos anexos decodificado (acha a URL de destino e a carga contrabandeada);
//  - nomes dos arquivos DENTRO do .zip lidos do índice do zip (sem descompactar);
//  - links de consentimento OAuth / código de dispositivo da Microsoft e do Google;
//  - golpe por telefone, fraude de conta salário, domínio sósia da conversa ou da própria organização;
//  - o relato do usuário ("pediu a senha numa página de outro endereço").
// Campos de cada técnica:
//  peso          soma na nota automática (0 a 100);
//  forte         artefato que não aparece em e-mail legítimo: vira "evidência forte" (a IA não consegue rebaixar);
//  abusaServico  o golpe usa um serviço ou conta legítimos: "SPF/DKIM/DMARC passaram" deixa de contar a favor;
//  orientacao    ação OBRIGATÓRIA para o SOC quando a técnica aparece (vai para o parecer).
// Para incluir uma técnica: entrada em TECNICAS + regra em detectarTecnicas() + caso no conjunto de referência.

const TECNICAS = {
  'html-smuggling': {
    nome: 'HTML smuggling (anexo HTML monta e baixa um arquivo sozinho)', mitre: ['T1027.006', 'T1566.001'], peso: 40, forte: true,
    orientacao: 'Procurar no computador do usuário o arquivo baixado pelo anexo (pasta Downloads) e bloquear o hash; se foi aberto, isolar a máquina',
  },
  'svg-script': {
    nome: 'SVG com script (imagem que executa código ou redireciona)', mitre: ['T1027.006', 'T1566.001'], peso: 40, forte: true,
  },
  'html-login-local': {
    nome: 'anexo HTML com tela de login (pede a senha sem abrir site)', mitre: ['T1566.001', 'T1056.003'], peso: 35,
  },
  'html-redireciona': {
    nome: 'anexo HTML que redireciona para um site externo', mitre: ['T1566.001'], peso: 30,
  },
  'zip-conteudo-perigoso': {
    nome: 'arquivo compactado com executável/atalho/script dentro', mitre: ['T1566.001', 'T1204.002'], peso: 40, forte: true,
    orientacao: 'Confirmar se o usuário abriu o arquivo de dentro do .zip; se abriu, isolar a máquina e fazer varredura (EDR)',
  },
  'zip-com-senha': {
    nome: 'arquivo compactado protegido por senha (esconde o conteúdo do antivírus)', mitre: ['T1027.013'], peso: 15,
  },
  'oauth-consentimento': {
    nome: 'consentimento OAuth (app do atacante pede acesso a e-mails/arquivos)', mitre: ['T1528', 'T1566.002'], peso: 35, abusaServico: true,
    orientacao: 'Se o usuário aceitou: revogar o consentimento do aplicativo no Entra ID (Aplicativos empresariais > Permissões) e encerrar as sessões; trocar a senha NÃO remove o acesso do app',
  },
  'device-code': {
    nome: 'phishing por código de dispositivo (login da Microsoft com código enviado pelo atacante)', mitre: ['T1528', 'T1566.002'], peso: 35, abusaServico: true,
    orientacao: 'Se o usuário digitou o código: revogar as sessões e os tokens de atualização da conta no Entra ID e rever os logins (sign-in logs) por "device code"',
  },
  'aitm-isca': {
    nome: 'link personalizado com o e-mail da vítima escondido (kit de phishing/AiTM)', mitre: ['T1566.002', 'T1557'], peso: 20,
  },
  'compartilhamento-falso': {
    nome: '"arquivo compartilhado" fora das plataformas de compartilhamento', mitre: ['T1566.002'], peso: 20,
  },
  'imita-organizacao': {
    nome: 'domínio que imita o da própria organização', mitre: ['T1566', 'T1656', 'T1583.001'], peso: 25,
  },
  'dominio-sosia-conversa': {
    nome: 'remetente com domínio quase igual ao de quem já está na conversa', mitre: ['T1566', 'T1656', 'T1583.001'], peso: 35,
    orientacao: 'Avisar o fornecedor/cliente verdadeiro por telefone conhecido (não o do e-mail) e não alterar dados bancários sem essa confirmação',
  },
  'callback-telefone': {
    nome: 'golpe por telefone (callback): cobrança falsa com número para "cancelar"', mitre: ['T1566.004', 'T1656'], peso: 40, abusaServico: true,
    orientacao: 'Perguntar ao usuário se ligou para o número: se ligou, verificar se instalou programa de acesso remoto (AnyDesk, TeamViewer...) e isolar a máquina',
  },
  'bec-conta-salario': {
    nome: 'fraude de conta salário (pedido de troca dos dados bancários da folha)', mitre: ['T1656', 'T1566'], peso: 30,
    orientacao: 'Não alterar a conta salário: confirmar com o funcionário pessoalmente ou pelo telefone do cadastro',
  },
  'bec-pretexto': {
    nome: 'desculpa para fugir do canal oficial (e-mail pessoal, sem VPN, em reunião)', mitre: ['T1656'], peso: 15,
  },
  'bec-executivo-webmail': {
    nome: 'executivo/diretor escrevendo de e-mail gratuito', mitre: ['T1656', 'T1585.002'], peso: 20,
  },
  'bec-nome-interno': {
    nome: 'nome de pessoa da organização com endereço de fora', mitre: ['T1656', 'T1585.002'], peso: 30,
    orientacao: 'Confirmar com a pessoa citada por um canal interno (Teams, telefone do ramal) antes de qualquer pagamento ou compra',
  },
  'qrcode-decodificado': {
    nome: 'QR Code com link para site de fora (quishing)', mitre: ['T1566.002', 'T1027'], peso: 20,
    orientacao: 'Perguntar se o usuário leu o QR com o CELULAR: o acesso sai do celular (fora do proxy/EDR); se digitou a senha, trocar a senha e revogar as sessões',
  },
  'qrcode-desenhado': {
    nome: 'QR Code "desenhado" com tabela/caracteres (fuga de filtro de imagem)', mitre: ['T1027', 'T1566.002'], peso: 30,
  },
  'pdf-com-senha': {
    nome: 'PDF protegido por senha (esconde o conteúdo dos filtros)', mitre: ['T1027.013'], peso: 15,
  },
  'relato-pagina-falsa': {
    nome: 'o usuário relata página de login em endereço estranho', mitre: ['T1566.002', 'T1056.003'], peso: 25, abusaServico: true,
  },
};

const PLATAFORMAS_COMPARTILHAMENTO = ['sharepoint.com', 'onedrive.live.com', '1drv.ms', 'drive.google.com', 'docs.google.com',
  'dropbox.com', 'box.com', 'docusign.net', 'docusign.com', 'wetransfer.com', 'we.tl', 'acrobat.adobe.com'];
// Marcas cujos e-mails autênticos carregam texto escrito por terceiros (fatura, convite, compartilhamento, mensagem de vendedor).
const MARCAS_QUE_REPASSAM_TERCEIROS = ['PayPal', 'DocuSign', 'Microsoft', 'Google', 'Amazon', 'Mercado Livre / Mercado Pago', 'LinkedIn', 'Meta (WhatsApp/Facebook/Instagram)'];
const PROVEDORES_OAUTH =['login.microsoftonline.com', 'login.microsoft.com', 'login.windows.net', 'login.live.com', 'accounts.google.com'];
// Escopos que dão ao app acesso ao conteúdo da conta (e-mail, arquivos, contatos, diretório). User.Read/openid/profile não entram.
const ESCOPOS_ARRISCADOS = /^(mail\.|files\.|sites\.|contacts\.|calendars\.readwrite|mailboxsettings|notes\.|directory\.|user\.readwrite\.all|full_access_as_user|ews\.|imap\.|smtp\.|https:\/\/mail\.google\.com|https:\/\/www\.googleapis\.com\/auth\/(gmail|drive|contacts))/i;
// Endereços de esquema XML que aparecem em todo SVG/HTML e não são destino de nada.
const HOSTS_DE_ESQUEMA = ['www.w3.org', 'w3.org', 'schemas.microsoft.com', 'schemas.openxmlformats.org', 'purl.org', 'ns.adobe.com', 'xmlns.com'];
const EXTENSOES_HTML = new Set(['html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml', 'svg']);
const RE_EMAIL_INTEIRO = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,24}$/i;

const semAcento = (t) => String(t ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const rotuloDe = (d) => dominioRegistravel(d).split('.')[0] ?? '';

// Índice de um .zip -> nomes dos arquivos de dentro e se há criptografia (bit 0 do "general purpose flag").
// Lê o diretório central (fim do arquivo); se não houver, percorre os cabeçalhos locais. Não descompacta nada.
function lerZip(b) {
  const u16 = (i) => (b[i] | (b[i + 1] << 8)) >>> 0;
  const u32 = (i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
  const nome = (ini, tam, flags) => {
    const pedaco = b.slice(ini, ini + tam);
    return flags & 0x800 ? utf8(pedaco) : pedaco.map((c) => String.fromCharCode(c)).join('');
  };
  const nomes = [];
  let protegido = false;
  let fim = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (u32(i) === 0x06054b50) { fim = i; break; }
  if (fim >= 0) {
    let p = u32(fim + 16);
    for (let k = 0; k < u16(fim + 10) && k < 500 && p + 46 <= b.length && u32(p) === 0x02014b50; k++) {
      const flags = u16(p + 8);
      const tam = u16(p + 28);
      nomes.push(nome(p + 46, tam, flags));
      if (flags & 1) protegido = true;
      p += 46 + tam + u16(p + 30) + u16(p + 32);
    }
  }
  if (!nomes.length) {
    for (let p = 0; p + 30 <= b.length && nomes.length < 500 && u32(p) === 0x04034b50;) {
      const flags = u16(p + 6);
      const tam = u16(p + 26);
      nomes.push(nome(p + 30, tam, flags));
      if (flags & 1) protegido = true;
      if (flags & 8) break; // tamanho só no fim do dado: não dá para pular com segurança
      p += 30 + tam + u16(p + 28) + u32(p + 18);
    }
  }
  return { nomes: nomes.filter((n) => n && !n.endsWith('/')).slice(0, 100), protegido };
}

const ehZip = (b) => b.length > 22 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4;
const pareceTexto = (b) => b.length > 0 && b.slice(0, 400).every((c) => c === 9 || c === 10 || c === 13 || c >= 32);

function nomeArriscado(nome) {
  const exts = extensoes(String(nome).split(/[\\/]/).pop());
  const ultima = exts[exts.length - 1] ?? '';
  const dupla = exts.length >= 2 && /^(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp3|wav)$/.test(exts[exts.length - 2]);
  if (!EXTENSOES_PERIGOSAS.has(ultima)) return null;
  return { dupla, executavel: !EXTENSOES_HTML.has(ultima) };
}

// Destinos que um anexo HTML/SVG manda abrir: links, formulário, redirecionamento, chamadas de rede.
function destinosNoHtml(t) {
  const achados = extrairLinksHtml(t).map((l) => l.href);
  const padroes = [
    /<form\b[^>]*\baction\s*=\s*["']?([^"'\s>]+)/gi,
    /(?:location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\(|window\.open\s*\(|fetch\s*\(|\.open\s*\(\s*["'](?:POST|GET)["']\s*,|\$\.(?:post|ajax|get)\s*\(|\burl\s*:)\s*["'`]([^"'`]+)/gi,
    /content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*([^"'>\s]+)/gi,
  ];
  for (const re of padroes) for (const m of t.matchAll(re)) achados.push(decodificarEntidades(m[1]));
  return achados.filter((u) => /^https?:\/\//i.test(u));
}

// Lê um anexo (bytes) sem executar: o que há de perigoso, para onde ele leva e o que carrega escondido.
function inspecionarAnexo(nome, tipo, bytes) {
  const r = { nome, achados: [], urls: [], emails: [], internos: [], cargas: [], protegido: false };
  if (!bytes?.length) return r;
  if (ehZip(bytes)) {
    const z = lerZip(bytes);
    r.internos = z.nomes;
    r.protegido = z.protegido;
    return r;
  }
  const ext = extensoes(nome).pop() ?? '';
  const ehHtml = EXTENSOES_HTML.has(ext) || /html|svg/i.test(tipo);
  if (!ehHtml) return r;
  const t = utf8(bytes.slice(0, 2000000));
  const svg = ext === 'svg' || /svg/i.test(tipo);

  // Base64 escondido em strings do script: decodifica, procura URL/e-mail e separa a carga binária (para o hash).
  // Só vira carga (hash para bloqueio) o que é .zip, executável (MZ) ou o arquivo de um smuggling confirmado:
  // uma fonte ou imagem embutida em base64 não pode virar IOC.
  let baixa = '';
  const binarios = [];
  for (const m of t.matchAll(/["'`]([A-Za-z0-9+/]{16,}={0,2})["'`]/g)) {
    if (binarios.length + r.urls.length > 30) break;
    const dados = bytesDeBase64(m[1]);
    if (ehZip(dados)) {
      r.internos.push(...lerZip(dados).nomes);
      binarios.push({ dados, certo: true });
    } else if (pareceTexto(dados)) {
      const texto = utf8(dados);
      if (RE_EMAIL_INTEIRO.test(texto.trim())) r.emails.push(texto.trim().toLowerCase());
      r.urls.push(...extrairUrls(texto));
    } else if (dados.length >= 64) {
      binarios.push({ dados, certo: dados[0] === 0x4d && dados[1] === 0x5a });
    }
  }
  const acao = (t.match(/<form\b[^>]*\baction\s*=\s*["']?(https?:\/\/[^"'\s>]+)/i) ?? [])[1];
  for (const m of t.matchAll(/["'`]([^"'`\\/<>]{1,80}\.(zip|rar|7z|iso|img|vhdx?|exe|msi|js|hta|lnk|vbs|html?|one))["'`]/gi)) { baixa = m[1]; break; }
  r.urls.push(...destinosNoHtml(t));
  r.urls = unicos(r.urls.filter((u) => !noDominio(partesDaUrl(u).host, HOSTS_DE_ESQUEMA)), 15);

  const smuggling = /atob\s*\(|base64/i.test(t) && /new\s+Blob\b|createObjectURL|msSaveOrOpenBlob|msSaveBlob/.test(t)
    && /\.download\s*=|\bdownload\s*=|\.click\s*\(|msSaveOrOpenBlob|msSaveBlob/.test(t);
  if (smuggling) r.achados.push({ id: 'html-smuggling', detalhe: `${nome} monta um arquivo escondido em base64 e o baixa sozinho${baixa ? ` ("${baixa}")` : ''}` });
  r.cargas = binarios.filter((x) => x.certo || smuggling).map((x) => x.dados).slice(0, 3);
  if (svg && /<script\b|\son[a-z]+\s*=|javascript:|<foreignObject\b|<iframe\b|<embed\b|<object\b/i.test(t)) {
    r.achados.push({ id: 'svg-script', detalhe: `${nome} é uma imagem SVG com código (script/evento)${r.urls.length ? `; leva para ${desarmar(partesDaUrl(r.urls[0]).host)}` : ''}` });
  }
  if (!svg && /<input\b[^>]*\btype\s*=\s*["']?password/i.test(t)) {
    const destino = acao ? partesDaUrl(decodificarEntidades(acao)).host : '';
    r.achados.push({ id: 'html-login-local', detalhe: `${nome} abre uma tela de login local${destino ? ` que envia a senha para ${desarmar(destino)}` : ''}` });
  }
  if (!svg && !smuggling && r.urls.length && /location(\.href)?\s*=|location\.(replace|assign)\s*\(|http-equiv\s*=\s*["']?refresh/i.test(t)) {
    r.achados.push({ id: 'html-redireciona', detalhe: `${nome} redireciona sozinho para ${desarmar(partesDaUrl(r.urls[0]).host)}` });
  }
  return r;
}

// Parâmetros de uma URL (query e fragmento), decodificados.
function parametrosDaUrl(url) {
  const saida = {};
  const [semFrag, frag = ''] = String(url).split('#');
  const query = semFrag.includes('?') ? semFrag.slice(semFrag.indexOf('?') + 1) : '';
  for (const par of query.split('&')) {
    if (!par) continue;
    const i = par.indexOf('=');
    const chave = (i >= 0 ? par.slice(0, i) : par).toLowerCase();
    let valor = i >= 0 ? par.slice(i + 1) : '';
    try { valor = decodeURIComponent(valor.replace(/\+/g, ' ')); } catch (erro) { /* mantém cru */ }
    saida[chave] = valor;
  }
  return { query: saida, fragmento: (() => { try { return decodeURIComponent(frag); } catch (erro) { return frag; } })() };
}

// Link de consentimento OAuth: provedor oficial, escopos que dão acesso ao conteúdo e destino (redirect_uri) de fora.
function analisarOAuth(url, confiaveis) {
  const { host } = partesDaUrl(url);
  if (!PROVEDORES_OAUTH.includes(host)) return null;
  const caminho = String(url).split(/[?#]/)[0].toLowerCase();
  if (!/oauth2\/(v2\.0\/)?authorize|\/o\/oauth2\/(v2\/)?auth|oauth20_authorize/.test(caminho)) return null;
  const { query } = parametrosDaUrl(url);
  const escopos = String(query.scope ?? '').split(/[\s,]+/).filter(Boolean);
  const arriscados = escopos.filter((e) => ESCOPOS_ARRISCADOS.test(e));
  const destino = partesDaUrl(query.redirect_uri ?? '').host;
  const destinoDeFora = Boolean(destino) && !noDominio(destino, confiaveis) && !PROVEDORES_OAUTH.includes(destino)
    && !MARCAS.some((m) => (m.nome === 'Microsoft' || m.nome === 'Google') && noDominio(destino, m.oficiais));
  return {
    provedor: host.includes('google') ? 'Google' : 'Microsoft',
    app: linha(query.client_id ?? '', 60), escopos, arriscados, consentimento: /consent/i.test(query.prompt ?? ''),
    redirect: query.redirect_uri ?? '', destino, destinoDeFora,
  };
}

// URL do redirect_uri dos links de consentimento OAuth arriscados: é o servidor do atacante (vira IOC).
function destinosOAuth(urls, confiaveis) {
  return urls.map((u) => analisarOAuth(u, confiaveis)).filter((o) => o && o.arriscados.length && o.destinoDeFora && /^https?:\/\//i.test(o.redirect)).map((o) => o.redirect);
}

function base64ParaTexto(valor) {
  const v = String(valor ?? '').trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]{12,}={0,2}$/.test(v)) return '';
  const b = bytesDeBase64(v);
  return pareceTexto(b) ? utf8(b) : '';
}

// ctx: { de, responder, assunto, texto, relato, urls[{url,host}], inspecoes[], emailsTexto[], confiaveis[], nomesInternos[], sinaisIds[], autenticado }
function detectarTecnicas(ctx) {
  const achadas = [];
  const add = (id, descricao, extra = {}) => {
    if (achadas.some((a) => a.id === id)) return;
    const t = TECNICAS[id];
    achadas.push({ id, nome: t.nome, peso: extra.peso ?? t.peso, forte: extra.forte ?? Boolean(t.forte), abusaServico: Boolean(t.abusaServico), mitre: t.mitre, orientacao: t.orientacao ?? '', descricao });
  };
  const confiaveis = ctx.confiaveis ?? [];
  const deFora = (dominio) => Boolean(dominio) && !noDominio(dominio, confiaveis);
  const oficial = (h) => MARCAS.some((m) => noDominio(h, m.oficiais));
  const texto = [ctx.assunto, ctx.texto].join('\n');
  const hosts = ctx.urls.map((u) => u.host).filter(Boolean);

  // ---- Anexos ----
  for (const i of ctx.inspecoes) {
    for (const a of i.achados) add(a.id, a.detalhe);
    const arriscados = i.internos.map((n) => ({ n, r: nomeArriscado(n) })).filter((x) => x.r);
    if (arriscados.length) {
      const pior = arriscados.find((x) => x.r.executavel) ?? arriscados[0];
      add('zip-conteudo-perigoso', `dentro de ${i.nome} há ${pior.r.dupla ? 'arquivo com extensão dupla' : 'arquivo perigoso'}: ${linha(pior.n, 80)}${arriscados.length > 1 ? ` (+${arriscados.length - 1})` : ''}`,
        pior.r.executavel ? {} : { forte: false, peso: 25 });
    }
    if (i.protegido) add('zip-com-senha', `${i.nome} é protegido por senha: o antivírus não consegue olhar o conteúdo`);
  }

  // ---- Links ----
  for (const u of ctx.urls) {
    const o = analisarOAuth(u.url, confiaveis);
    if (o && o.arriscados.length && (o.destinoDeFora || o.consentimento)) {
      add('oauth-consentimento', `link oficial da ${o.provedor}, mas pede para autorizar o app ${o.app || '(sem id)'} a acessar ${o.arriscados.slice(0, 4).join(', ')}`
        + `${o.destinoDeFora ? ` e devolve o acesso para ${desarmar(o.destino)}` : ''}${o.consentimento ? ' (prompt=consent)' : ''}`);
    }
    const caminho = u.url.split(/[?#]/)[0].toLowerCase();
    if ((noDominio(u.host, ['microsoft.com']) && /\/devicelogin/.test(caminho)) || (u.host === 'aka.ms' && /\/devicelogin/.test(caminho))
      || (PROVEDORES_OAUTH.includes(u.host) && /\/deviceauth|\/devicecode|\/oauth2\/.*\/device/.test(caminho))) {
      if (/\bc[oó]digo\b|\bcode\b/i.test(texto)) add('device-code', `manda abrir a página oficial de login por código (${desarmar(u.host)}) com um código enviado no próprio e-mail`);
    }
    const { query, fragmento } = parametrosDaUrl(u.url);
    const valores = [...Object.values(query), fragmento];
    const escondido = valores.map(base64ParaTexto).find((v) => RE_EMAIL_INTEIRO.test(v.trim()));
    const noFragmento = RE_EMAIL_INTEIRO.test(fragmento.trim()) ? fragmento.trim() : '';
    if ((escondido || noFragmento) && !oficial(u.host) && deFora(u.host)) {
      add('aitm-isca', `o link para ${desarmar(u.host)} leva o e-mail ${desarmar((escondido || noFragmento).trim())} ${escondido ? 'escondido em base64' : 'no fragmento (#)'}: a página falsa já abre preenchida para a vítima`);
    }
  }
  for (const i of ctx.inspecoes) {
    if (i.emails.length) add('aitm-isca', `o anexo ${i.nome} carrega o e-mail ${desarmar(i.emails[0])} escondido em base64 para preencher a página falsa`);
  }
  const textoCompartilha = /compartilhou\s+(um|o|este|esse|uma|a)?\s*(arquivo|documento|pasta|planilha)|shared\s+(a|this|the)\s+(file|document|folder)|enviou\s+(um|o)\s+(documento|arquivo)\s+para\s+(voc[eê]|sua|a\s+sua)\s+(revisar|assinar|assinatura|revis[aã]o)|sent\s+you\s+a\s+document\s+to\s+(review|sign)|(documento|arquivo)[^.\n]{0,80}\b(enviado|dispon[ií]vel)\s+para\s+(sua\s+|a\s+sua\s+)?(assinatura|revis[aã]o|visualiza)/i;
  if (textoCompartilha.test(texto) && hosts.length && !hosts.some((h) => noDominio(h, PLATAFORMAS_COMPARTILHAMENTO))) {
    const h = hosts.find((x) => !noDominio(x, confiaveis)) ?? hosts[0];
    add('compartilhamento-falso', `diz que compartilhou um documento, mas o link vai para ${desarmar(h)}, que não é SharePoint/OneDrive/Google Drive/Dropbox/DocuSign`);
  }

  // ---- Domínios sósia ----
  const rotulosCasa = unicos(confiaveis.map(rotuloDe).filter((r) => r.length >= 5), 10);
  for (const h of unicos([ctx.de.dominio, ctx.responder.dominio, ...hosts].filter(Boolean), 30)) {
    if (!deFora(h) || oficial(h) || WEBMAIL_GRATUITO.has(dominioRegistravel(h))) continue;
    const r = rotuloDe(h);
    const pedacos = h.toLowerCase().split(/[.-]/);
    const casa = rotulosCasa.find((c) => pedacos.includes(c) || r.includes(c) || (normalizarSosia(r) !== r.replace(/[^a-z]/g, '') && normalizarSosia(r) === c)
      || (r !== c && levenshtein(normalizarSosia(r), c) <= (c.length >= 8 ? 2 : 1)));
    if (casa) { add('imita-organizacao', `${desarmar(h)} imita o domínio da organização (${confiaveis.find((d) => rotuloDe(d) === casa)}), mas não é dela`); break; }
  }
  const daConversa = unicos([...(ctx.emailsTexto ?? []).map((e) => e.split('@')[1]), ...hosts].filter(Boolean).map((d) => dominioRegistravel(d)), 30)
    .filter((d) => deFora(d) && !oficial(d) && !WEBMAIL_GRATUITO.has(d));
  for (const quem of [ctx.de.dominio, ctx.responder.dominio].filter(Boolean)) {
    const d = dominioRegistravel(quem);
    if (!deFora(d) || oficial(d) || WEBMAIL_GRATUITO.has(d)) continue;
    const r = rotuloDe(d);
    const par = daConversa.find((o) => {
      const ro = rotuloDe(o);
      return o !== d && r.length >= 5 && ro.length >= 5 && ro !== r
        && (normalizarSosia(ro) === normalizarSosia(r) || levenshtein(r, ro) <= (ro.length >= 8 ? 2 : 1));
    });
    if (par) { add('dominio-sosia-conversa', `o remetente usa ${desarmar(d)}, quase igual a ${desarmar(par)}, que aparece na própria conversa: domínio sósia registrado para se passar pelo contato`); break; }
  }

  // ---- Golpe por telefone (callback / TOAD) ----
  // O golpista escreve o telefone em serviços que publicam texto de terceiros (fatura do PayPal, convite, compartilhamento).
  // Remetente AUTENTICADO de marca que não faz isso (banco, Correios...) com telefone é a própria central: não conta.
  const marcaRemetente = MARCAS.find((m) => noDominio(ctx.de.dominio, m.oficiais));
  const centralPropria = ctx.autenticado && marcaRemetente && !MARCAS_QUE_REPASSAM_TERCEIROS.includes(marcaRemetente.nome);
  const isca =/renova[cç][aã]o\s+autom|renovad[ao]\s+automaticamente|assinatura\s+(anual|mensal|renovada|do\s+(norton|mcafee|antiv))|plano\s+anual|subscription|auto.?renew|norton|mcafee|geek\s?squad|avast|kaspersky|bitdefender|antiv[ií]rus|windows\s+defender/i;
  if (!centralPropria && isca.test(texto)) {
    for (const m of texto.matchAll(/\b(ligue|ligar|liga[cç][aã]o|telefone|central de cancelamento|suporte de cancelamento|call|phone)\b/gi)) {
      const tel = texto.slice(m.index, m.index + 160).match(/(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,5}[\s.-]?\d{4}\b/);
      if (tel && tel[0].replace(/\D/g, '').length >= 8) {
        add('callback-telefone', `cobrança de assinatura/renovação inesperada com telefone para "cancelar" (${tel[0].trim()}): o golpe acontece na ligação, não no link`);
        achadas.find((a) => a.id === 'callback-telefone').telefone = tel[0].trim();
        break;
      }
    }
  }

  // ---- Fraude do "chefe"/do funcionário (BEC) ----
  const externo = deFora(ctx.de.dominio);
  if (externo && /conta\s+(sal[aá]rio|onde\s+recebo|para\s+(dep[oó]sito|cr[eé]dito)\s+do\s+(meu\s+)?sal[aá]rio)|recebo\s+(o\s+)?(meu\s+)?sal[aá]rio|dados\s+banc[aá]rios\s+(para|da)\s+(a\s+)?folha|troquei\s+de\s+banco|mudei\s+de\s+banco|direct\s+deposit|payroll\s+(account|change)/i.test(texto)) {
    add('bec-conta-salario', `pedido de troca da conta salário vindo de fora da organização (${desarmar(ctx.de.email || ctx.de.dominio)})`);
  }
  if (externo && /(meu|minha)\s+e-?mail\s+(pessoal|particular)|sem\s+acesso\s+(a|à|ao)\s+(vpn|e-?mail|rede|sistema)|n[aã]o\s+consigo\s+(atender|falar|ligar)|estou\s+(em\s+(uma\s+)?reuni[aã]o|viajando|em\s+(um\s+)?voo|sem\s+celular)|celular\s+novo|n[uú]mero\s+novo/i.test(texto)) {
    add('bec-pretexto', 'dá uma desculpa para não usar o canal oficial (e-mail pessoal, sem VPN, em reunião, sem poder atender)');
  }
  const assinatura = [ctx.de.nome, String(ctx.texto ?? '').slice(-400)].join('\n');
  if (WEBMAIL_GRATUITO.has(dominioRegistravel(ctx.de.dominio)) && !(ctx.sinaisIds ?? []).includes('webmail')
    && /\b(diretor[a]?|ceo|cfo|coo|presidente|vice-presidente|s[oó]ci[oa]|gerente\s+financeir[oa]|head\s+de)\b/i.test(assinatura)) {
    add('bec-executivo-webmail', `assina como executivo/diretor, mas escreve de e-mail gratuito (${desarmar(ctx.de.email)})`);
  }
  const nomeDe = semAcento(ctx.de.nome).replace(/\s+/g, ' ').trim();
  const interno = (ctx.nomesInternos ?? []).find((n) => n.split(' ').length >= 2 && nomeDe.includes(n));
  if (interno && externo) add('bec-nome-interno', `o nome "${linha(ctx.de.nome, 60)}" é de uma pessoa da organização, mas o endereço é de fora (${desarmar(ctx.de.email)})`);

  // ---- QR Code (lido pelo leitor-qr) ----
  const qr = ctx.qr ?? { lidos: [], protegidos: [] };
  for (const l of qr.lidos) {
    const host = l.urls.map((u) => partesDaUrl(u).host).find((h) => h && deFora(h) && !oficial(h));
    if (host) {
      add('qrcode-decodificado', `o QR Code ${l.desenhado ? 'desenhado no corpo' : `em ${l.arquivo}`}${l.pagina > 1 ? ` (página ${l.pagina})` : ''} leva para ${desarmar(host)}: link escondido em imagem, que o filtro de links não vê`);
      break;
    }
  }
  if (qr.lidos.some((l) => l.desenhado)) add('qrcode-desenhado', 'o QR Code foi montado com tabela HTML ou caracteres (█), sem imagem: truque para passar por filtros que leem QR em imagens');
  if (qr.protegidos.length) add('pdf-com-senha', `${qr.protegidos[0]} é um PDF protegido por senha: os filtros não conseguem ler o conteúdo`);

  // ---- Relato do usuário ----
  const relato = String(ctx.relato ?? '');
  if (/\b(pediu|pedia|pedindo|solicitou|apareceu|abriu|coloquei|digitei|informei)\b[^.\n]{0,80}\b(senha|login|tela\s+de\s+(login|entrada|acesso))/i.test(relato)
    && /outro\s+(endere[cç]o|site|link)|(endere[cç]o|site|link)\s+(era\s+|[eé]\s+|estava\s+|meio\s+)?(estranho|diferente|esquisito)|n[aã]o\s+(é|era)\s+o\s+nosso|documento\s+n[aã]o\s+abriu|deu\s+erro|n[aã]o\s+sou\s+rob[oô]|p[aá]gina\s+(estranha|falsa|diferente)/i.test(relato)) {
    add('relato-pagina-falsa', 'o usuário conta que, depois do link, apareceu uma tela pedindo a senha em endereço estranho (ou que "não abriu" depois do login)');
  }
  return achadas;
}
// ---- fim da biblioteca ----
