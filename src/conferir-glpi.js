// Nó "Confere o GLPI": viu se TODOS os passos de cada ação deram certo no GLPI.
//  - Deu certo: envia as mensagens de sucesso no Telegram (e conta a métrica de acerto da IA).
//  - Falhou: avisa no Telegram e libera a trava, para o analista poder clicar de novo.
// Os itens chegam na mesma ordem em que "Monta as ações" criou os passos do GLPI.
const passos = $('Monta as ações').all().map((i) => i.json).filter((x) => x.destino === 'glpi');
const respostas = $input.all().map((i) => i.json);
const grupos = new Map();
passos.forEach((p, n) => {
  const g = grupos.get(p.acao_indice) ?? { primeiro: null, ok: true, erros: [] };
  if (p.passo === 0) g.primeiro = p;
  const codigo = Number(respostas[n]?.statusCode);
  if (!(codigo >= 200 && codigo < 300)) {
    g.ok = false;
    g.erros.push(`${p.caminho}: HTTP ${respostas[n]?.statusCode ?? '?'} ${linha(JSON.stringify(respostas[n]?.body ?? ''), 160)}`);
  }
  grupos.set(p.acao_indice, g);
});
const saida = [];
for (const g of grupos.values()) {
  if (!g.primeiro) continue;
  if (g.ok) {
    g.primeiro.sucesso.forEach((m, n) => saida.push({ json: { ...m, chave_metrica: n === 0 ? g.primeiro.chave_metrica : '' } }));
  } else {
    g.primeiro.falha.forEach((m) => saida.push({ json: { ...m, apagar_chave: g.primeiro.chave_trava, erros: g.erros } }));
  }
}
return saida;
