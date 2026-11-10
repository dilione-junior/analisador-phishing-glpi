// Nó "Separa as ações": um item por ação, com as chaves do Redis que cada uma usa.
//  - trava: decisão = uma por chamado (dois cliques ou dois analistas não encerram duas vezes);
//    outras ações = uma por mensagem do Telegram (não repete se a mesma mensagem chegar de novo).
const prefixo = $('Configuração').first().json.prefixoRedis;
return $('Lê as mensagens').first().json.acoes.map((a, i) => ({ json: {
  ...a,
  chave_analise: `${prefixo}analise:${a.chamado_id ?? 0}`,
  chave_trava: a.tipo === 'decidir' ? `${prefixo}decisao:${a.chamado_id}`
    : a.tipo === 'bloquear' ? `${prefixo}bloqueio:${a.chamado_id}` // um envio ao Wazuh por chamado
      : `${prefixo}update:${a.update_id}`,
}, pairedItem: 0 }));
