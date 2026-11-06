// Nó "Resume o VirusTotal": de cada resposta, só o que importa ao analista.
// 404 = o VirusTotal nunca viu aquele link/arquivo (isso NÃO quer dizer que é seguro).
const fila = $('Fila do VirusTotal').all().map((i) => i.json);
const resultado = $input.all().map((item, i) => {
  const r = item.json;
  const pedido = fila[i] ?? {};
  const base = { tipo: pedido.tipo, valor: pedido.valor };
  if (r.statusCode === 404) return { ...base, encontrado: false };
  const a = r.body?.data?.attributes;
  if (r.statusCode !== 200 || !a) return { ...base, erro: `HTTP ${r.statusCode ?? '?'}${r.statusCode === 429 ? ' (cota do VirusTotal esgotada)' : ''}` };
  const s = a.last_analysis_stats ?? {};
  const motores = Object.entries(a.last_analysis_results ?? {})
    .filter(([, v]) => ['malicious', 'suspicious'].includes(v?.category))
    .map(([nome, v]) => `${nome}: ${v.result ?? v.category}`)
    .slice(0, 5);
  return {
    ...base,
    encontrado: true,
    maliciosos: Number(s.malicious ?? 0),
    suspeitos: Number(s.suspicious ?? 0),
    total: Object.values(s).reduce((t, n) => t + Number(n || 0), 0),
    reputacao: Number(a.reputation ?? 0),
    motores,
    nome_ameaca: String(a.popular_threat_classification?.suggested_threat_label ?? ''),
    categorias: [...new Set(Object.values(a.categories ?? {}))].slice(0, 4),
    criado_em: a.creation_date ? new Date(a.creation_date * 1000).toISOString().slice(0, 10) : '',
  };
});
return [{ json: { virustotal: resultado } }];
