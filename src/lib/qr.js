// ---- Biblioteca: QR Code ----
// A LEITURA do QR é feita pelo serviço leitor-qr do laboratório (imagens e PDFs). Aqui ficam:
//  - QR "desenhado" sem imagem (tabela HTML com células pretas, ou caracteres █ ▀ ▄): vira uma matriz de
//    módulos e depois uma imagem PGM simples, que vai para o mesmo leitor. É truque para fugir de filtro de imagem.
//  - leitura do código PIX ("copia e cola", padrão EMV do Banco Central) que um QR pode trazer no lugar de um link.

const LADO_MINIMO_QR = 21; // QR versão 1

// Cor de fundo de uma célula: bgcolor="#000", style="background:#000000", rgb(0,0,0), black/white.
function celulaEscura(atributos) {
  const a = String(atributos ?? '').toLowerCase();
  const cor = (a.match(/bgcolor\s*=\s*["']?\s*([#a-z0-9]+)/) ?? a.match(/background(?:-color)?\s*:\s*([^;"']+)/) ?? [])[1];
  if (!cor) return false;
  const c = cor.trim();
  if (/^(black|#000|#000000)$/.test(c)) return true;
  if (/^(white|#fff|#ffffff|transparent|none)$/.test(c)) return false;
  let r; let g; let b;
  const hex = c.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/);
  const rgb = c.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
  if (hex) {
    const h = hex[1].length === 3 ? hex[1].split('').map((x) => x + x).join('') : hex[1];
    [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  } else if (rgb) {
    [r, g, b] = rgb.slice(1, 4).map(Number);
  } else {
    return false;
  }
  return 0.299 * r + 0.587 * g + 0.114 * b < 128;
}

function pareceMatrizQr(m) {
  if (m.length < LADO_MINIMO_QR) return false;
  const largura = m[0].length;
  if (largura < LADO_MINIMO_QR || m.some((l) => l.length !== largura) || Math.abs(largura - m.length) > 2) return false;
  const escuros = m.reduce((t, l) => t + l.filter(Boolean).length, 0) / (largura * m.length);
  return escuros > 0.25 && escuros < 0.75;
}

// <table> com uma célula por módulo (cores de fundo). Devolve as matrizes que parecem QR.
function matrizesDeTabelas(html) {
  const achadas = [];
  for (const t of String(html ?? '').matchAll(/<table\b[^>]*>([\s\S]*?)<\/table\s*>/gi)) {
    const linhas = [];
    for (const tr of t[1].matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr\s*>/gi)) {
      const celulas = Array.from(tr[1].matchAll(/<td\b([^>]*)>/gi), (td) => celulaEscura(td[1]));
      if (celulas.length) linhas.push(celulas);
    }
    if (pareceMatrizQr(linhas)) achadas.push(linhas);
    if (achadas.length >= 3) break;
  }
  return achadas;
}

// Linhas feitas só de █ ▀ ▄ e espaço. Meio-bloco (▀ ▄): cada linha de texto = 2 linhas de módulos.
// Só █: cada caractere = 1 módulo; se todo trecho tiver tamanho par ("██"), cada módulo usou 2 caracteres.
function matrizesDeBlocos(texto) {
  const achadas = [];
  const linhas = String(texto ?? '').replace(/ /g, ' ').split(/\r?\n/);
  let bloco = [];
  const fecha = () => {
    if (bloco.length >= 10) {
      const meio = bloco.some((l) => /[▀▄]/.test(l));
      const largura = Math.max(...bloco.map((l) => l.length));
      const cheias = bloco.map((l) => l.padEnd(largura, ' '));
      let m = [];
      if (meio) {
        for (const l of cheias) {
          m.push(Array.from(l, (c) => c === '█' || c === '▀'));
          m.push(Array.from(l, (c) => c === '█' || c === '▄'));
        }
      } else {
        m = cheias.map((l) => Array.from(l, (c) => c === '█'));
        const trechos = cheias.join('\n').match(/█+| +/g) ?? [];
        if (trechos.length && trechos.every((x) => x.length % 2 === 0)) m = m.map((l) => l.filter((_, i) => i % 2 === 0));
      }
      // Tira linhas/colunas vazias da borda (zona de silêncio) para a checagem de formato.
      while (m.length && !m[0].some(Boolean)) m.shift();
      while (m.length && !m[m.length - 1].some(Boolean)) m.pop();
      if (m.length) {
        const ini = Math.min(...m.map((l) => (l.indexOf(true) < 0 ? Infinity : l.indexOf(true))));
        const fim = Math.max(...m.map((l) => l.lastIndexOf(true)));
        m = m.map((l) => l.slice(ini, fim + 1));
      }
      if (pareceMatrizQr(m)) achadas.push(m);
    }
    bloco = [];
  };
  for (const l of linhas) {
    const limpa = l.replace(/\s+$/, '');
    if (limpa.length >= 10 && /^[█▀▄ ]+$/.test(limpa) && /[█▀▄]/.test(limpa)) bloco.push(limpa);
    else fecha();
  }
  fecha();
  return achadas.slice(0, 3);
}

// Matriz -> imagem PGM (P5, tons de cinza), com 4 módulos de margem branca e 6 pixels por módulo.
function matrizParaPgm(m, escala = 6, margem = 4) {
  const lado = (m[0].length + 2 * margem) * escala;
  const alto = (m.length + 2 * margem) * escala;
  const cabecalho = `P5\n${lado} ${alto}\n255\n`;
  const bytes = Array.from(cabecalho, (c) => c.charCodeAt(0));
  for (let y = 0; y < alto; y++) {
    const linha = m[Math.floor(y / escala) - margem];
    for (let x = 0; x < lado; x++) {
      const escuro = linha ? linha[Math.floor(x / escala) - margem] : false;
      bytes.push(escuro ? 0 : 255);
    }
  }
  return bytes;
}

// bytes -> base64 (feito à mão: a sandbox do n8n pode não ter Buffer).
function bytesParaBase64(bytes) {
  const tabela = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const partes = [];
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    partes.push(tabela[(n >> 18) & 63] + tabela[(n >> 12) & 63]
      + (i + 1 < bytes.length ? tabela[(n >> 6) & 63] : '=') + (i + 2 < bytes.length ? tabela[n & 63] : '='));
  }
  return partes.join('');
}

// Código PIX (BR Code / EMV): campos ID(2) + tamanho(2) + valor. Devolve recebedor, chave, valor e cidade.
function lerPix(texto) {
  const t = String(texto ?? '').trim();
  if (!t.startsWith('000201') || !/br\.gov\.bcb\.pix/i.test(t)) return null;
  const campos = (s) => {
    const saida = {};
    for (let i = 0; i + 4 <= s.length;) {
      const id = s.slice(i, i + 2);
      const tam = Number(s.slice(i + 2, i + 4));
      if (!Number.isFinite(tam)) break;
      saida[id] = s.slice(i + 4, i + 4 + tam);
      i += 4 + tam;
    }
    return saida;
  };
  const c = campos(t);
  const conta = campos(c['26'] ?? '');
  const adicional = campos(c['62'] ?? '');
  return {
    recebedor: linha(c['59'] ?? '', 60), cidade: linha(c['60'] ?? '', 40), valor: linha(c['54'] ?? '', 20),
    chave: linha(conta['01'] ?? '', 80), url: linha(conta['25'] ?? '', 120), txid: linha(adicional['05'] ?? '', 40),
  };
}
// ---- fim da biblioteca ----
