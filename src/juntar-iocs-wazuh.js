// Nó "Junta os IOCs para o Wazuh": um item por lista CDB (domínios, IPs, hashes), com as entradas novas
// de TODOS os cliques em "Bloquear IOCs" desta rodada. As três listas são sempre lidas e regravadas:
// assim as entradas vencidas (mais de diasNaLista) também saem.
// Valor de cada entrada: "phishing chamado 18 em 2026-11-10" (o chamado e a data, para auditar e vencer).
const cfg = $('Configuração').first().json;
const acoes = $('Monta as ações').all().map((i) => i.json).filter((x) => x.destino === 'wazuh');
const hoje = new Date().toISOString().slice(0, 10);
const LISTAS = { dominios: cfg.listaDominios, ips: cfg.listaIps, hashes: cfg.listaHashes };

return Object.entries(LISTAS).map(([tipo, lista]) => {
  const novas = new Map();
  for (const a of acoes) {
    for (const chave of a.entradas?.[tipo] ?? []) if (!novas.has(chave)) novas.set(chave, `phishing chamado ${a.chamado_id} em ${hoje}`);
  }
  return { json: { tipo, lista, novas: [...novas].map(([chave, valor]) => ({ chave, valor })) } };
});
