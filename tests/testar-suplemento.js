// Testes do suplemento "Reportar phishing" (outlook-suplemento/), sem Outlook.
// Uso:  node tests/testar-suplemento.js
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const RAIZ = path.join(__dirname, '..');
const PASTA = path.join(RAIZ, 'outlook-suplemento');
const Relato = require(path.join(PASTA, 'relato.js'));
const BASE = 'https://dilione-junior.github.io/analisador-phishing-glpi/';

// interacaoDoUsuario() do fluxo, para garantir que as frases do botão ligam os mesmos avisos.
const libs = ['ip.js', 'texto.js', 'email.js', 'indicadores.js'].map((n) => fs.readFileSync(path.join(RAIZ, 'src', 'lib', n), 'utf8'));
const { interacaoDoUsuario } = new Function(libs.join('\n') + '\nreturn { interacaoDoUsuario };')();

let total = 0;
let falhas = 0;
function teste(nome, fn) {
  total++;
  try {
    fn();
    console.log(`ok   ${nome}`);
  } catch (e) {
    falhas++;
    console.log(`FALHA ${nome}\n     ${e.message}`);
  }
}

teste('cada opção marcada é reconhecida pelo fluxo (mesmo id)', () => {
  for (const i of Relato.INTERACOES) {
    const r = interacaoDoUsuario(i.frase);
    assert.ok(r[i.id], `${i.id}: "${i.frase}"`);
    assert.deepStrictEqual(r.rotulos.length, 1, `${i.id} ligou outros: ${r.rotulos}`);
  }
});

teste('"não fiz nada" não liga nenhum aviso', () => {
  assert.strictEqual(interacaoDoUsuario(Relato.FRASE_NADA).algum, false);
});

teste('corpo do relato com todas as opções liga todos os avisos', () => {
  const { corpoHtml } = Relato.montarRelato({ assunto: 'x', interacoes: Relato.INTERACOES.map((i) => i.id) });
  const r = interacaoDoUsuario(corpoHtml.replace(/<[^>]+>/g, '\n'));
  for (const i of Relato.INTERACOES) assert.ok(r[i.id], i.id);
});

teste('corpo do relato sem opção marcada não liga aviso (exceto pelo comentário)', () => {
  const { corpoHtml } = Relato.montarRelato({ assunto: 'Cliquei aqui e ganhe', remetente: 'a@b.c' });
  // O assunto vem do atacante: "Cliquei" nele liga o aviso. Aceito: o assunto aparece também no anexo.
  const semAssunto = corpoHtml.replace(/Cliquei aqui e ganhe/g, '');
  assert.strictEqual(interacaoDoUsuario(semAssunto.replace(/<[^>]+>/g, '\n')).algum, false);
  assert.match(corpoHtml, /Não informado/);
});

teste('assunto leva o marcador e vira uma linha só', () => {
  const r = Relato.montarRelato({ assunto: 'Fatura\r\nBcc: x@y.z\tvencida' });
  assert.strictEqual(r.assunto, '[Relato phishing] Fatura Bcc: x@y.z vencida');
  assert.strictEqual(Relato.montarRelato({ assunto: '' }).assunto, '[Relato phishing] (sem assunto)');
  assert.ok(Relato.montarRelato({ assunto: 'a'.repeat(500) }).assunto.length <= 170);
});

teste('dados do atacante e do usuário são escapados no HTML', () => {
  const r = Relato.montarRelato({
    assunto: '<img src=x onerror=alert(1)>',
    nome: '"><script>alert(1)</script>',
    remetente: 'a@b.c',
    comentario: '<b>oi</b>\nlinha 2',
  });
  assert.ok(!/<script|<img|<b>oi/.test(r.corpoHtml), r.corpoHtml);
  assert.match(r.corpoHtml, /&lt;b&gt;oi&lt;\/b&gt;<br>linha 2/);
});

teste('nome do anexo sem caracteres proibidos em arquivo', () => {
  const r = Relato.montarRelato({ assunto: 'a/b\\c:d*e?f"g<h>i|j' });
  assert.doesNotMatch(r.nomeAnexo, /[\\/:*?"<>|]/);
});

teste('comentário limitado a 1000 caracteres', () => {
  const r = Relato.montarRelato({ assunto: 'x', comentario: 'z'.repeat(5000) });
  assert.ok(!r.corpoHtml.includes('z'.repeat(1001)));
});

teste('manifesto: XML com URLs só do GitHub Pages do projeto e ícones existentes', () => {
  const xml = fs.readFileSync(path.join(PASTA, 'manifest.xml'), 'utf8');
  assert.match(xml, /<Id>[0-9a-f-]{36}<\/Id>/);
  assert.match(xml, /<Permissions>ReadItem<\/Permissions>/);
  const urls = [...xml.matchAll(/DefaultValue="(https:[^"]+)"/g)].map((m) => m[1]);
  assert.ok(urls.length >= 7, String(urls.length));
  for (const u of urls) {
    if (u.startsWith('https://github.com/dilione-junior/')) continue;
    assert.ok(u.startsWith(BASE), u);
    const local = path.join(PASTA, u.slice(BASE.length));
    assert.ok(fs.existsSync(local), `arquivo não existe: ${local}`);
  }
});

teste('manifesto: todo resid usado está declarado e textos curtos cabem em 125', () => {
  const xml = fs.readFileSync(path.join(PASTA, 'manifest.xml'), 'utf8');
  const declarados = new Set([...xml.matchAll(/\bid="([^"]+)"\s+DefaultValue=/g)].map((m) => m[1]));
  for (const [, r] of xml.matchAll(/resid="([^"]+)"/g)) assert.ok(declarados.has(r), r);
  const curtos = xml.split('<bt:ShortStrings>')[1].split('</bt:ShortStrings>')[0];
  for (const [, v] of curtos.matchAll(/DefaultValue="([^"]*)"/g)) assert.ok(v.length <= 125, v);
});

teste('painel: HTML carrega só scripts locais e o office.js oficial', () => {
  const html = fs.readFileSync(path.join(PASTA, 'relatar.html'), 'utf8');
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1]);
  assert.deepStrictEqual(scripts, ['https://appsforoffice.microsoft.com/lib/1/hosted/office.js', 'config.js', 'relato.js', 'relatar.js']);
  assert.doesNotMatch(html.replace(/<script\b[^>]*src="[^"]+"><\/script>/g, ''), /<script/);
  for (const s of scripts.slice(1)) assert.ok(fs.existsSync(path.join(PASTA, s)), s);
  assert.doesNotMatch(fs.readFileSync(path.join(PASTA, 'relatar.js'), 'utf8'), /innerHTML/);
});

console.log(`\n${total - falhas}/${total} testes passaram`);
process.exit(falhas ? 1 : 0);
