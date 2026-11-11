// Confere o leitor-qr DE VERDADE contra o conjunto de referência: para cada .eml, roda o nó "Lista imagens e PDFs (QR)",
// manda cada arquivo ao leitor e compara o que ele leu com o gabarito (campo "qr" de tests/corpus/casos.json).
// O avaliador (avaliar-corpus.js) usa o gabarito no lugar do leitor; este script prova que o gabarito bate com a realidade.
//
// O leitor só existe na rede interna do laboratório (sem porta publicada). Rode de dentro dela, ex.:
//   docker run --rm --network ng-soc-automacao_automacao_qr -v "<repo>:/repo:ro" --entrypoint node \
//     n8nio/n8n:2.46.4 /repo/tests/conferir-leitor-qr.js http://leitor-qr:8080/ler
const fs = require('fs');
const path = require('path');

const URL_LEITOR = process.argv[2] || 'http://leitor-qr:8080/ler';
const SRC = path.join(__dirname, '..', 'src');
const CORPUS = path.join(__dirname, 'corpus');
const ler = (nome) => fs.readFileSync(path.join(SRC, nome), 'utf8');

function listar(eml) {
  const codigo = ['ip.js', 'texto.js', 'email.js', 'indicadores.js', 'qr.js'].map((b) => ler(`lib/${b}`)).join('\n') + '\n' + ler('listar-arquivos-qr.js');
  const nos = {
    'Configuração': { maxArquivosQr: 4 },
    'Escolhe o que baixar': [{ documento_id: 1, nome: 'email.eml', mime: 'message/rfc822', baixar: true }],
    'Baixa os anexos': [{ statusCode: 200, body: eml }],
  };
  const $ = (nome) => { const l = (Array.isArray(nos[nome]) ? nos[nome] : [nos[nome]]).map((json) => ({ json })); return { first: () => l[0], all: () => l }; };
  return new Function('$', codigo)($).map((i) => i.json);
}

(async () => {
  const { casos } = JSON.parse(fs.readFileSync(path.join(CORPUS, 'casos.json'), 'utf8'));
  let erros = 0;
  let lidos = 0;
  for (const c of casos) {
    const pedidos = listar(fs.readFileSync(path.join(CORPUS, c.arquivo), 'utf8')).filter((p) => !p.nenhum);
    for (const p of pedidos) {
      const r = await fetch(URL_LEITOR, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nome: p.nome, dados: p.dados }) });
      const corpo = await r.json();
      const obtido = (corpo.codigos ?? []).map((x) => x.texto).sort();
      const esperado = [...(c.qr?.[p.nome] ?? [])].sort();
      const ok = JSON.stringify(obtido) === JSON.stringify(esperado);
      if (!ok) erros++;
      lidos += obtido.length;
      console.log(`${ok ? 'ok  ' : 'ERRO'} ${c.id.padEnd(36)} ${p.nome.padEnd(40)} ${obtido.length ? obtido.map((t) => t.slice(0, 60)).join(' | ') : '(nenhum QR)'}${corpo.erro ? ' [' + corpo.erro + ']' : ''}${ok ? '' : `  esperado: ${esperado.join(' | ') || '(nenhum)'}`}`);
    }
    for (const nome of Object.keys(c.qr ?? {})) {
      if (!pedidos.some((p) => p.nome === nome)) { erros++; console.log(`ERRO ${c.id}: o gabarito tem QR em "${nome}", mas o nó não mandou esse arquivo ao leitor`); }
    }
  }
  console.log(`\n${lidos} QR lido(s); ${erros ? erros + ' divergência(s)' : 'tudo confere com o gabarito'}.`);
  process.exit(erros ? 1 : 0);
})().catch((erro) => { console.error(erro); process.exit(2); });
