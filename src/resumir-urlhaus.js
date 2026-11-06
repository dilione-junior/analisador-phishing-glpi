// Nó "Resume o URLhaus": o host está na base de distribuição de malware/phishing da abuse.ch?
const fila = $('Fila do URLhaus').all().map((i) => i.json);
const resultado = $input.all().map((item, i) => {
  const r = item.json;
  const host = fila[i]?.valor;
  const b = r.body ?? {};
  if (r.statusCode !== 200) return { host, erro: `HTTP ${r.statusCode ?? '?'}` };
  if (b.query_status !== 'ok') return { host, listado: false };
  const urls = Array.isArray(b.urls) ? b.urls : [];
  return {
    host,
    listado: true,
    urls: urls.length,
    online: urls.filter((u) => u.url_status === 'online').length,
    ameacas: [...new Set(urls.map((u) => u.threat).filter(Boolean))].slice(0, 3),
    tags: [...new Set(urls.flatMap((u) => u.tags ?? []))].slice(0, 6),
  };
});
return [{ json: { urlhaus: resultado } }];
