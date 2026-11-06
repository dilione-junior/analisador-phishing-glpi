// Nó "Resume o RDAP": quando o domínio foi registrado. Domínio de poucos dias é sinal forte de phishing.
const fila = $('Fila do RDAP').all().map((i) => i.json);
const hoje = Date.now();
const resultado = $input.all().map((item, i) => {
  const r = item.json;
  const dominio = fila[i]?.valor;
  if (r.statusCode !== 200 || !r.body) return { dominio, erro: `HTTP ${r.statusCode ?? '?'}` };
  const eventos = Array.isArray(r.body.events) ? r.body.events : [];
  const criado = eventos.find((e) => e.eventAction === 'registration')?.eventDate ?? '';
  const registrador = (r.body.entities ?? []).find((e) => (e.roles ?? []).includes('registrar'));
  const nomeRegistrador = registrador?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] ?? '';
  const dias = criado ? Math.floor((hoje - Date.parse(criado)) / 86400000) : null;
  return { dominio, criado_em: criado.slice(0, 10), idade_dias: Number.isFinite(dias) ? dias : null, registrador: String(nomeRegistrador).slice(0, 80) };
});
return [{ json: { rdap: resultado } }];
