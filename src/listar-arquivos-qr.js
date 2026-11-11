// Nó "Lista imagens e PDFs (QR)": separa do e-mail suspeito o que pode ter QR Code, para o leitor-qr do laboratório:
//  - imagens e PDFs anexados ao .eml (inclusive as imagens do corpo, "inline");
//  - QR "desenhado" sem imagem (tabela HTML ou caracteres █ ▀ ▄), convertido aqui em imagem PGM.
// Cada item vira um pedido ao leitor (nó "Lê os QR Codes"). Sem nada para ler: um item marcador, e o fluxo
// segue direto para "Extrai as evidências". Nada é aberto aqui: os bytes só são copiados em base64.
const cfg = $('Configuração').first().json;
const todos = (nome) => { try { return $(nome).all().map((i) => i.json); } catch (erro) { return []; } };
const MAX_ARQUIVOS = Number(cfg.maxArquivosQr) || 4;
const MAX_BYTES = 4 * 1024 * 1024;

const escolhidos = todos('Escolhe o que baixar');
const baixados = todos('Baixa os anexos');
let mime = null;
for (const [i, d] of escolhidos.entries()) {
  const conteudo = d.baixar ? String(baixados[i]?.body ?? baixados[i]?.data ?? '') : '';
  if (!conteudo || /\.msg$/i.test(d.nome)) continue;
  const leitura = analisarMime(conteudo);
  if (leitura.cabecalhos.some((c) => ['from', 'received', 'subject'].includes(c.nome))) {
    mime = leitura;
    while (mime.internas.length) mime = mime.internas[0]; // e-mail encaminhado como anexo: vale o de dentro
    break;
  }
}

const pedidos = [];
if (mime) {
  const ehImagem = (a) => /^image\/(png|jpe?g|gif|bmp|webp|tiff)$/i.test(a.tipo) || /^(png|jpe?g|gif|bmp|webp|tiff?)$/.test(extensoes(a.nome).pop() ?? '');
  const ehPdf = (a) => /pdf/i.test(a.tipo) || extensoes(a.nome).pop() === 'pdf' || String.fromCharCode(...a.bytes.slice(0, 5)) === '%PDF-';
  for (const a of mime.anexos) {
    if (pedidos.length >= MAX_ARQUIVOS) break;
    if (!a.bytes?.length || a.bytes.length < 100 || a.bytes.length > MAX_BYTES || !(ehImagem(a) || ehPdf(a))) continue;
    pedidos.push({ nome: linha(a.nome, 120), tipo: a.tipo, tamanho: a.bytes.length, desenhado: false, dados: bytesParaBase64(a.bytes) });
  }
  const html = mime.textos.filter((t) => t.tipo === 'text/html').map((t) => t.conteudo).join('\n');
  const texto = mime.textos.filter((t) => t.tipo === 'text/plain').map((t) => t.conteudo).join('\n');
  const desenhos = [...matrizesDeTabelas(html), ...matrizesDeBlocos(texto), ...matrizesDeBlocos(htmlParaTexto(html))];
  const vistos = new Set();
  for (const m of desenhos) {
    const chave = m.map((l) => l.map(Number).join('')).join('|');
    if (vistos.has(chave) || pedidos.length >= MAX_ARQUIVOS + 2) continue;
    vistos.add(chave);
    const pgm = matrizParaPgm(m);
    pedidos.push({ nome: `qr-desenhado-${vistos.size}.pgm`, tipo: 'image/x-portable-graymap', tamanho: pgm.length, desenhado: true, dados: bytesParaBase64(pgm) });
  }
}

if (!pedidos.length) return [{ json: { nenhum: true } }];
return pedidos.map((p) => ({ json: p }));
