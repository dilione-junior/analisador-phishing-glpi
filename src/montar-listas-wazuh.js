// Nó "Monta as listas novas": junta o que já está em cada lista do Wazuh com as entradas novas.
//  - Entradas gravadas pelo analisador ("... em AAAA-MM-DD") com mais de diasNaLista dias saem.
//  - Entrada repetida fica com a data nova (renova o prazo); as outras (ex.: a de teste) ficam como estão.
//  - Se o login ou a leitura de QUALQUER lista falhar, nada é enviado: um item só com { enviar: false, erros }.
//    (Enviar sem ter lido apagaria o que já estava na lista.)
const cfg = $('Configuração').first().json;
const dias = Number(cfg.diasNaLista) || 90;
const pedidos = $('Junta os IOCs para o Wazuh').all().map((i) => i.json);
const lidas = $input.all().map((i) => i.json);
const login = $('Login no Wazuh (listas)').first().json;
const limite = Date.now() - dias * 86400000;

// Resposta em texto com "resposta completa": o n8n põe o conteúdo em "data" (não em "body"; conferido no n8n 2.46).
// Se um dia mudar, a leitura vem vazia e a trava abaixo impede de gravar por cima.
const texto = (r) => (typeof r?.data === 'string' ? r.data : '');
const erros = [];
const token = texto(login).trim();
if (Number(login.statusCode) !== 200 || !/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) {
  erros.push(`login na API do Wazuh: HTTP ${login.statusCode ?? '?'} (confira a credencial "Wazuh API (ngsoc-listas)")`);
}
const listas = pedidos.map((p, k) => {
  const r = lidas[k] ?? {};
  if (!erros.length && Number(r.statusCode) !== 200) {
    erros.push(`leitura da lista ${p.lista}: HTTP ${r.statusCode ?? '?'}${Number(r.statusCode) === 404 ? ' (rode infra/wazuh/regras/instalar-regras.sh no ng-soc-lab)' : ''}`);
  }
  const atuais = new Map();
  for (const bruta of texto(r).split('\n')) {
    const l = bruta.trim();
    const i = l.indexOf(':');
    if (i > 0) atuais.set(l.slice(0, i), l.slice(i + 1));
  }
  // Trava: a lista criada pelo ng-soc-lab nunca fica vazia (tem a entrada de teste). Se veio vazia, a leitura
  // não funcionou; gravar agora apagaria o que está lá.
  if (!erros.length && !atuais.size) erros.push(`a lista ${p.lista} veio vazia na leitura (esperado pelo menos a entrada de teste): nada foi gravado`);
  let vencidas = 0;
  for (const [chave, valor] of atuais) {
    const m = valor.match(/ em (\d{4}-\d{2}-\d{2})$/);
    if (m && Date.parse(m[1]) < limite) { atuais.delete(chave); vencidas++; }
  }
  const adicionadas = [];
  const renovadas = [];
  for (const n of p.novas) {
    (atuais.has(n.chave) ? renovadas : adicionadas).push(n.chave);
    atuais.set(n.chave, n.valor);
  }
  return { ...p, conteudo: [...atuais].map(([c, v]) => `${c}:${v}`).join('\n') + '\n', adicionadas, renovadas, vencidas, total: atuais.size };
});

if (erros.length) return [{ json: { enviar: false, erros } }];
return listas.map((x) => ({ json: { ...x, enviar: true } }));
