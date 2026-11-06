// ---- Biblioteca: leitura de e-mail (.eml / MIME) e de cabeçalhos colados no chamado ----
// Feita à mão (sem bibliotecas externas) porque roda dentro do nó Code do n8n.
// Só LÊ o e-mail: nenhum link é aberto e nenhum anexo é executado.

function bytesDeBase64(texto) {
  const tabela = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const limpo = String(texto ?? '').replace(/[^A-Za-z0-9+/]/g, '');
  const bytes = [];
  for (let i = 0; i + 1 < limpo.length; i += 4) {
    const n = (tabela.indexOf(limpo[i]) << 18) | (tabela.indexOf(limpo[i + 1]) << 12)
      | ((i + 2 < limpo.length ? tabela.indexOf(limpo[i + 2]) : 0) << 6) | (i + 3 < limpo.length ? tabela.indexOf(limpo[i + 3]) : 0);
    bytes.push((n >> 16) & 255);
    if (i + 2 < limpo.length) bytes.push((n >> 8) & 255);
    if (i + 3 < limpo.length) bytes.push(n & 255);
  }
  return bytes;
}

function bytesDeQP(texto) {
  const s = String(texto ?? '').replace(/=\r?\n/g, '');
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && /^[0-9a-f]{2}$/i.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      const c = s.charCodeAt(i);
      if (c < 0x80) bytes.push(c);
      else for (const b of unescape(encodeURIComponent(s[i]))) bytes.push(b.charCodeAt(0));
    }
  }
  return bytes;
}

function utf8(bytes) {
  let saida = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    let n = 0;
    let codigo = 0;
    if (b < 0x80) { saida += String.fromCharCode(b); continue; }
    if (b >= 0xc2 && b < 0xe0) { n = 1; codigo = b & 0x1f; }
    else if (b >= 0xe0 && b < 0xf0) { n = 2; codigo = b & 0x0f; }
    else if (b >= 0xf0 && b < 0xf5) { n = 3; codigo = b & 0x07; }
    else { saida += '�'; continue; }
    let ok = i + n < bytes.length;
    for (let k = 1; ok && k <= n; k++) {
      if ((bytes[i + k] & 0xc0) !== 0x80) ok = false;
      else codigo = (codigo << 6) | (bytes[i + k] & 0x3f);
    }
    if (!ok || codigo > 0x10ffff) { saida += '�'; continue; }
    saida += String.fromCodePoint(codigo);
    i += n;
  }
  return saida;
}

// windows-1252/iso-8859-1 e outros: aproximação por latin1 (bom o bastante para português).
function decodificarBytes(bytes, charset) {
  const c = String(charset ?? 'utf-8').toLowerCase();
  if (c === 'utf-8' || c === 'utf8' || c === 'us-ascii' || c === 'ascii') return utf8(bytes);
  return bytes.map((b) => String.fromCharCode(b)).join('');
}

// "=?UTF-8?B?...?=" e "=?ISO-8859-1?Q?...?=" (RFC 2047), usados no assunto e no nome do remetente.
function decodificarPalavras(valor) {
  return String(valor ?? '')
    .replace(/(=\?[^?]+\?[bq]\?[^?]*\?=)\s+(?==\?)/gi, '$1')
    .replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (inteiro, charset, tipo, dados) => {
      const bytes = tipo.toLowerCase() === 'b' ? bytesDeBase64(dados) : bytesDeQP(dados.replace(/_/g, ' '));
      return decodificarBytes(bytes, charset);
    });
}

// Separa cabeçalhos e corpo; junta as linhas dobradas (que começam com espaço).
function separarCabecalhos(bruto) {
  const texto = String(bruto ?? '').replace(/^﻿/, '');
  const fim = texto.search(/\r?\n\r?\n/);
  const parteCabecalhos = fim >= 0 ? texto.slice(0, fim) : texto;
  const corpo = fim >= 0 ? texto.slice(fim).replace(/^\r?\n\r?\n/, '') : '';
  const cabecalhos = [];
  for (const l of parteCabecalhos.split(/\r?\n/)) {
    if (/^[ \t]/.test(l) && cabecalhos.length) cabecalhos[cabecalhos.length - 1].valor += ' ' + l.trim();
    else {
      const m = l.match(/^([!-9;-~]+):[ \t]*(.*)$/);
      if (m) cabecalhos.push({ nome: m[1].toLowerCase(), valor: m[2] });
    }
  }
  return { cabecalhos, corpo };
}

function cabecalho(lista, nome) {
  return lista.find((c) => c.nome === nome)?.valor ?? '';
}

function cabecalhos(lista, nome) {
  return lista.filter((c) => c.nome === nome).map((c) => c.valor);
}

// Parâmetro de um cabeçalho: boundary, charset, filename (inclusive filename*=utf-8''...).
function parametro(valor, nome) {
  const v = String(valor ?? '');
  const estendido = v.match(new RegExp(`(?:^|;)\\s*${nome}\\*=([^']*)'[^']*'([^;]+)`, 'i'));
  if (estendido) {
    try { return decodeURIComponent(estendido[2].trim()); } catch (erro) { return estendido[2].trim(); }
  }
  const m = v.match(new RegExp(`(?:^|;)\\s*${nome}\\s*=\\s*("([^"]*)"|[^;\\s]+)`, 'i'));
  return m ? decodificarPalavras(m[2] ?? m[1]) : '';
}

// Lê uma mensagem MIME. Devolve cabeçalhos, textos (plain/html), anexos (com os bytes) e
// mensagens encaminhadas como anexo (message/rfc822), cada uma lida do mesmo jeito.
function analisarMime(bruto, profundidade = 0) {
  const { cabecalhos: cabs, corpo } = separarCabecalhos(bruto);
  const resultado = { cabecalhos: cabs, textos: [], anexos: [], internas: [] };
  juntarParte(cabs, corpo, resultado, profundidade);
  return resultado;
}

function juntarParte(cabs, corpo, resultado, profundidade) {
  const tipoCompleto = cabecalho(cabs, 'content-type') || 'text/plain';
  const tipo = tipoCompleto.split(';')[0].trim().toLowerCase();
  const codificacao = cabecalho(cabs, 'content-transfer-encoding').trim().toLowerCase();
  const disposicao = cabecalho(cabs, 'content-disposition');
  const nome = parametro(disposicao, 'filename') || parametro(tipoCompleto, 'name');

  if (tipo.startsWith('multipart/') && profundidade < 6) {
    const fronteira = parametro(tipoCompleto, 'boundary');
    if (!fronteira) return;
    const pedacos = corpo.split('--' + fronteira);
    for (const pedaco of pedacos.slice(1)) {
      if (pedaco.startsWith('--')) break;
      const p = separarCabecalhos(pedaco.replace(/^\r?\n/, ''));
      juntarParte(p.cabecalhos, p.corpo, resultado, profundidade + 1);
    }
    return;
  }

  const bytes = codificacao === 'base64' ? bytesDeBase64(corpo) : codificacao === 'quoted-printable' ? bytesDeQP(corpo) : null;
  const conteudo = () => (bytes ? decodificarBytes(bytes, parametro(tipoCompleto, 'charset')) : corpo);

  if (tipo === 'message/rfc822' && profundidade < 6) {
    resultado.internas.push(analisarMime(conteudo(), profundidade + 1));
    return;
  }
  const ehAnexo = /^\s*attachment/i.test(disposicao) || (nome && !/^text\/(plain|html)$/.test(tipo));
  if (!ehAnexo && (tipo === 'text/plain' || tipo === 'text/html')) {
    resultado.textos.push({ tipo, conteudo: conteudo() });
    return;
  }
  const dados = bytes ?? Array.from(corpo, (c) => c.charCodeAt(0) & 255);
  resultado.anexos.push({ nome: nome || '(sem nome)', tipo, tamanho: dados.length, bytes: dados });
}

// '"Banco" <a@b.com>' -> { nome: 'Banco', email: 'a@b.com', dominio: 'b.com' }
// O endereço real é o ÚLTIMO <...>: '"Banco <a@banco.com>" <golpe@falso.com>' é golpe@falso.com.
function endereco(valor) {
  const v = decodificarPalavras(valor).trim();
  const ultimo = v.lastIndexOf('<');
  const m = ultimo >= 0 ? v.slice(ultimo).match(/^<\s*([^>\s]+@[^>\s]+)\s*>/) : null;
  const email = (m ? m[1] : (v.match(/[^\s<>"',;]+@[^\s<>"',;]+/) ?? [''])[0]).toLowerCase().replace(/^mailto:/, '');
  const nome = m ? v.slice(0, ultimo).trim().replace(/^"|"$/g, '').trim() : '';
  return { nome, email, dominio: email.includes('@') ? email.split('@').pop().replace(/[>.]+$/, '') : '' };
}

// Resultado de SPF/DKIM/DMARC. Só vale o Authentication-Results MAIS DE CIMA (escrito pelo servidor
// que recebeu o e-mail): os de baixo podem ter sido forjados pelo próprio remetente.
function autenticacao(cabs) {
  const ar = cabecalhos(cabs, 'authentication-results')[0] ?? cabecalhos(cabs, 'arc-authentication-results')[0] ?? '';
  const pega = (nome) => (ar.match(new RegExp(`\\b${nome}=([a-z]+)`, 'i'))?.[1] ?? '').toLowerCase();
  const spfCab = (cabecalhos(cabs, 'received-spf')[0] ?? '').match(/^\s*([a-z]+)/i)?.[1]?.toLowerCase() ?? '';
  return { spf: pega('spf') || spfCab, dkim: pega('dkim'), dmarc: pega('dmarc'), presente: Boolean(ar || spfCab) };
}

// IPs públicos que aparecem nos cabeçalhos Received (de baixo para cima = do remetente para nós).
function ipsDosRecebidos(cabs) {
  const ips = [];
  for (const r of cabecalhos(cabs, 'received').reverse()) {
    for (const m of r.matchAll(/\[?\b(\d{1,3}(?:\.\d{1,3}){3})\b\]?/g)) {
      if (!ipBloqueado(m[1]) && !ips.includes(m[1])) ips.push(m[1]);
    }
  }
  return ips;
}

// O usuário colou os cabeçalhos completos no chamado? Procura o primeiro cabeçalho técnico e lê dali.
function cabecalhosColados(texto) {
  const t = String(texto ?? '');
  const inicio = t.search(/^(Received|Return-Path|Delivered-To|Authentication-Results|ARC-Seal|DKIM-Signature|Received-SPF|X-Received):/im);
  if (inicio < 0) return [];
  return separarCabecalhos(t.slice(inicio).replace(/\n\s*\n/g, '\n')).cabecalhos;
}

// Encaminhamento colado (Outlook em português ou inglês): "De: ... Enviado em: ... Assunto: ..."
function encaminhamentoColado(texto) {
  const t = String(texto ?? '');
  const pega = (rotulos) => t.match(new RegExp(`^\\s*(?:\\*\\s*)?(?:${rotulos})\\s*:\\s*(.+)$`, 'im'))?.[1]?.trim() ?? '';
  return {
    de: pega('De|From|Remetente'),
    responder: pega('Responder a|Responder para|Reply-To'),
    assunto: pega('Assunto|Subject'),
    data: pega('Enviado em|Enviada em|Enviado|Data|Date|Sent'),
  };
}
// ---- fim da biblioteca ----
