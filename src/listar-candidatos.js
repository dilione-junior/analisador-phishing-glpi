// Nó "Lista os candidatos": chamados abertos da busca, do mais antigo para o mais novo.
// Nenhum chamado: devolve lista vazia e a execução para aqui (sem gastar nada).
const corpo = $input.first().json.body ?? {};
const linhas = Array.isArray(corpo.data) ? corpo.data : [];
const prefixo = $('Configuração').first().json.prefixoRedis;
return linhas
  .map((l) => Number(l['2'] ?? l[2]))
  .filter((id) => Number.isInteger(id) && id > 0)
  .slice(0, 10)
  .map((id) => ({ json: { chamado_id: id, chave_reserva: `${prefixo}relato:${id}` } }));
