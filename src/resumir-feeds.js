// Nó "Resume os feeds": o que dos IOCs do chamado apareceu nos feeds (OpenPhish, ThreatFox) guardados no Redis.
// Cada item de entrada veio da "Fila dos feeds" com o campo `achado` preenchido pelo Redis (texto JSON ou vazio).
// O primeiro item é sempre o estado dos feeds (quando foram carregados), para o parecer avisar se estiverem velhos.
const lerJson = (t) => { if (t && typeof t === 'object') return t; try { return t ? JSON.parse(t) : null; } catch (erro) { return null; } };
let estado = null;
const achados = [];
let consultadas = 0;
let erro = '';
for (const item of $input.all()) {
  const q = item.json;
  if (q.error) { erro = linha(typeof q.error === 'string' ? q.error : q.error.message ?? JSON.stringify(q.error), 120); continue; }
  const v = lerJson(q.achado);
  if (q.tipo === 'estado') { estado = v; continue; }
  consultadas++;
  if (!v || typeof v !== 'object') continue;
  achados.push({
    tipo: q.tipo, valor: linha(q.valor, 300), onde: q.onde,
    fontes: Array.isArray(v.fontes) ? v.fontes.slice(0, 3) : [],
    origem: v.origem === 'url' ? 'url' : 'ioc',
    ameaca: linha(v.ameaca, 40), malware: linha(v.malware, 60),
    confianca: Number(v.confianca) || 0, visto_em: linha(v.visto_em, 10),
    comprometido: v.comprometido === true,
    exemplo: linha(v.exemplo, 200),
  });
}

// Idade de cada fonte (horas desde a última carga que deu certo): o parecer avisa se passar de 24 h.
const horas = (iso) => (iso ? Math.round((Date.now() - Date.parse(iso)) / 3600000) : null);
const fontes = {};
for (const [nome, f] of Object.entries(estado?.fontes ?? {})) {
  fontes[nome] = { ok: Boolean(f.ok), itens: Number(f.itens) || 0, horas: horas(f.ultimo_ok), erro: linha(f.erro, 120) };
}
return [{ json: { feeds: { carregado: Boolean(estado), consultadas, achados, fontes, erro } } }];
