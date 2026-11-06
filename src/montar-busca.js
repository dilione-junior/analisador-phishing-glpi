// Nó "Monta a busca": acha no GLPI a categoria de phishing e o grupo da Segurança da Informação
// e monta a busca dos chamados AINDA ABERTOS que têm as duas coisas (categoria + grupo atribuído).
// Chamado de outra categoria não entra: se o usuário escolheu errado, o analista corrige a
// categoria no GLPI e o chamado entra na próxima rodada.
const cfg = $('Configuração').first().json;
const lista = (nome) => {
  const corpo = $(nome).first().json.body;
  return Array.isArray(corpo) ? corpo : [];
};
const acha = (itens, campo, valor, oque) => {
  const achado = itens.find((i) => String(i[campo] ?? '').trim() === valor);
  if (!achado) throw new Error(`Não achei no GLPI ${oque} "${valor}". Rode antes: bash glpi/preparar-glpi.sh`);
  return Number(achado.id);
};
const categoriaId = acha(lista('Lê as categorias'), 'completename', cfg.categoria, 'a categoria');
const grupoId = acha(lista('Lê os grupos'), 'name', cfg.grupo, 'o grupo');

// Campos da busca do GLPI: 2 = número, 7 = categoria, 8 = grupo técnico, 12 = status, 15 = abertura.
const parametros = [
  ['criteria[0][field]', 7], ['criteria[0][searchtype]', 'equals'], ['criteria[0][value]', categoriaId],
  ['criteria[1][link]', 'AND'], ['criteria[1][field]', 8], ['criteria[1][searchtype]', 'equals'], ['criteria[1][value]', grupoId],
  ['criteria[2][link]', 'AND'], ['criteria[2][field]', 12], ['criteria[2][searchtype]', 'equals'], ['criteria[2][value]', 'notold'],
  ['forcedisplay[0]', 2], ['forcedisplay[1]', 15], ['sort', 15], ['order', 'ASC'], ['range', '0-19'],
];
return [{ json: {
  categoria_id: categoriaId,
  grupo_id: grupoId,
  consulta: parametros.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(String(v))).join('&'),
} }];
