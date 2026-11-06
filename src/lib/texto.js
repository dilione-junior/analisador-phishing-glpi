// ---- Biblioteca: texto seguro ----
// Tudo o que vem do chamado e do e-mail suspeito foi escrito por um usuário ou por um ATACANTE.
// Por isso: esc() antes de ir para o Telegram/GLPI (vira texto, nunca HTML) e desarmar() nos
// indicadores (hxxps://site[.]com), para o analista não abrir um link malicioso sem querer.

const ENTIDADES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ordm: 'º', ordf: 'ª', euro: '€', copy: '©', reg: '®', ndash: '–', mdash: '—', hellip: '…', laquo: '«', raquo: '»' };
// Letras acentuadas do português: &aacute; &Atilde; &ccedil; ...
for (const [letras, acento, base] of [['aeiou', 'acute', 0x301], ['aeiou', 'grave', 0x300], ['aeiou', 'circ', 0x302], ['aon', 'tilde', 0x303], ['aeiou', 'uml', 0x308], ['c', 'cedil', 0x327]]) {
  for (const l of letras) {
    ENTIDADES[l + acento] = (l + String.fromCharCode(base)).normalize('NFC');
    ENTIDADES[l.toUpperCase() + acento] = (l.toUpperCase() + String.fromCharCode(base)).normalize('NFC');
  }
}

function decodificarEntidades(texto) {
  return String(texto ?? '').replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});/gi, (inteiro, e) => {
    if (e[0] === '#') {
      const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return n > 0 && n < 0x110000 && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : inteiro;
    }
    return ENTIDADES[e] ?? ENTIDADES[e.toLowerCase()] ?? inteiro;
  });
}

// HTML -> texto. O GLPI guarda o conteúdo do chamado com as tags escapadas (&lt;p&gt;): desfaz isso antes.
function htmlParaTexto(html) {
  let s = String(html ?? '');
  if (/&lt;\/?[a-z][\s\S]*?&gt;/i.test(s) && !/<\/?[a-z][^>]*>/i.test(s)) s = decodificarEntidades(s);
  s = s.replace(/<(script|style|head|title)\b[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h\d|blockquote|table)\s*>/gi, '\n')
    .replace(/<[^>]*>/g, ' ');
  return decodificarEntidades(s)
    .replace(/[ \t ]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// Escapa para HTML do Telegram e do GLPI (o Telegram só reconhece &, < e >; " protege atributos).
function esc(texto) {
  return String(texto ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Corta o texto e remove caracteres de controle (mantém quebras de linha).
function curto(texto, maximo = 200) {
  const t = String(texto ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f​-‏‪-‮⁦-⁩]/g, '').trim();
  return t.length > maximo ? t.slice(0, maximo - 1) + '…' : t;
}

// Uma linha só (sem quebras), cortada.
function linha(texto, maximo = 200) {
  return curto(String(texto ?? '').replace(/\s+/g, ' '), maximo);
}

// Indicador "desarmado": https://mal.com/x -> hxxps://mal[.]com/x ; a@mal.com -> a[@]mal[.]com ; 1.2.3.4 -> 1.2.3[.]4
function desarmar(ioc) {
  const texto = String(ioc ?? '');
  const url = texto.match(/^([a-z][a-z0-9+.-]*)(:\/\/)([^/?#]*)(.*)$/i);
  if (url) return url[1].replace(/^http/i, (p) => p[0] + 'xx' + p[3]) + url[2] + url[3].replace(/\./g, '[.]').replace(/@/g, '[@]') + url[4];
  return texto.replace(/@/g, '[@]').replace(/\.(?=[^.]*$)/, '[.]');
}

function unicos(lista, maximo = 50) {
  const vistos = new Set();
  const saida = [];
  for (const item of lista) {
    const chave = String(item).toLowerCase();
    if (!item || vistos.has(chave)) continue;
    vistos.add(chave);
    saida.push(item);
    if (saida.length >= maximo) break;
  }
  return saida;
}
// ---- fim da biblioteca ----
