// Nós "Fila do VirusTotal / URLhaus / RDAP": um item por consulta (o nó HTTP seguinte roda uma vez por item).
// __FONTE__ é trocado pelo gerador do fluxo (virustotal, urlhaus ou rdap).
const lista = $('Extrai as evidências').first().json.consultas.__FONTE__ ?? [];
return lista.map((consulta) => ({ json: typeof consulta === 'string' ? { valor: consulta } : consulta }));
