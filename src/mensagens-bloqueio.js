// Nó "Mensagens do bloqueio": transforma o resultado de "Confere o Wazuh" em um item por mensagem do
// Telegram (o formato de "Fala no Telegram"). A chave a apagar (falha) vai no primeiro item de cada clique.
return $('Confere o Wazuh').all().flatMap((i) => i.json.mensagens.map((m, n) => ({ json: {
  destino: 'telegram', ...m, apagar_chave: n === 0 ? i.json.apagar_chave : '',
} })));
