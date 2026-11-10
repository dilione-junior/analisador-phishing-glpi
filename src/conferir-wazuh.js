// Nó "Confere o Wazuh": viu se as listas foram gravadas e as regras recarregadas.
// Um item por clique em "Bloquear IOCs", com:
//  - nota: acompanhamento PRIVADO no GLPI (deu certo ou não: fica a auditoria de quem pediu e do que foi);
//  - mensagens: o que dizer no Telegram;
//  - apagar_chave: em caso de falha, libera a trava para o analista poder tentar de novo.
// A API do Wazuh responde HTTP 200 mesmo quando recusa o pedido: o erro vem dentro da resposta.
const cfg = $('Configuração').first().json;
const acoes = $('Monta as ações').all().map((i) => i.json).filter((x) => x.destino === 'wazuh');
const listas = $('Monta as listas novas').all().map((i) => i.json);
const chat = String($env.PHISHING_TELEGRAM_CHAT_ID ?? '').trim();
const agora = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
const dias = Number(cfg.diasNaLista) || 90;

const okApi = (r) => Number(r?.statusCode) === 200 && r?.body?.error === 0 && !((r?.body?.data?.failed_items ?? []).length);
const erros = [...(listas[0]?.erros ?? [])];
let avisoRecarga = '';
if (!erros.length) {
  $('Envia a lista ao Wazuh (phishing)').all().forEach((i, k) => {
    if (!okApi(i.json)) erros.push(`gravação da lista ${listas[k]?.lista}: ${linha(JSON.stringify(i.json.body ?? i.json.statusCode ?? ''), 200)}`);
  });
  const recarga = $('Recarrega as regras (phishing)').first().json;
  if (!erros.length && !okApi(recarga)) {
    // As listas já estão gravadas; valem quando as regras forem recarregadas (ou o manager reiniciar).
    avisoRecarga = `as listas foram gravadas, mas a recarga das regras falhou (${linha(JSON.stringify(recarga.body ?? recarga.statusCode ?? ''), 160)}): valem depois de reiniciar o manager`;
  }
}

const porTipo = Object.fromEntries(listas.map((l) => [l.tipo, l]));
const ROTULO = { dominios: 'Domínios', ips: 'IPs de links', hashes: 'Hashes de anexos' };
const quem = (a) => `${a.analista.nome}${a.analista.usuario ? ' (@' + a.analista.usuario + ')' : ''}`;
const li = (itens) => '<ul>' + itens.map((x) => `<li>${x}</li>`).join('') + '</ul>';

return acoes.map((a) => {
  const id = a.chamado_id;
  const tipos = ['dominios', 'ips', 'hashes'].filter((t) => (a.entradas[t] ?? []).length);
  if (erros.length) {
    const nota = `<p><strong>⚠️ Falha ao enviar os IOCs ao Wazuh</strong></p><p>Pedido por ${esc(quem(a))} (Telegram ID ${esc(a.analista.id)}), ${agora}. ` +
      'Nada foi gravado. O analista pode clicar de novo.</p>' + li(erros.map((e) => esc(e)));
    return { json: {
      nota: { input: { itemtype: 'Ticket', items_id: id, is_private: 1, content: nota } },
      mensagens: [
        { tg_metodo: 'answerCallbackQuery', tg_corpo: { callback_query_id: a.callback_id, show_alert: true,
          text: `Não consegui enviar ao Wazuh: ${erros[0]}`.slice(0, 190) } },
      ],
      apagar_chave: a.chave_trava,
    } };
  }
  const detalhe = (t) => {
    const l = porTipo[t];
    const novas = (a.entradas[t] ?? []).filter((x) => l?.adicionadas.includes(x)).length;
    return `${ROTULO[t]} (${a.entradas[t].length}${novas < a.entradas[t].length ? `, ${a.entradas[t].length - novas} já estavam na lista e tiveram o prazo renovado` : ''})`;
  };
  const itensGlpi = tipos.map((t) => `${detalhe(t)}: ` + a.entradas[t].map((x) => esc(t === 'hashes' ? x : desarmar(x))).join(', '));
  const nota = `<p><strong>🛡️ IOCs enviados ao Wazuh</strong></p><p>Por ${esc(quem(a))} (Telegram ID ${esc(a.analista.id)}), ${agora}. ` +
    `Ficam ${dias} dias nas listas CDB ${esc(tipos.map((t) => porTipo[t]?.lista).join(', '))}; ` +
    'as regras 100170-100172 alertam se aparecerem no ambiente.</p>' + li(itensGlpi) +
    (avisoRecarga ? `<p>⚠️ ${esc(avisoRecarga)}</p>` : '');
  const resumo = tipos.map((t) => `• ${detalhe(t)}`).join('\n');
  return { json: {
    nota: { input: { itemtype: 'Ticket', items_id: id, is_private: 1, content: nota } },
    mensagens: [
      { tg_metodo: 'editMessageReplyMarkup', tg_corpo: { chat_id: chat, message_id: a.mensagem_id,
        reply_markup: { inline_keyboard: [[{ text: `✔️ IOCs no Wazuh · ${a.analista.nome}`.slice(0, 60), callback_data: `ph|${id}|x` }]] } } },
      { tg_metodo: 'sendMessage', tg_corpo: { chat_id: chat, reply_to_message_id: a.mensagem_id, allow_sending_without_reply: true, parse_mode: 'HTML',
        text: `🛡️ <b>Chamado #${id}: IOCs enviados ao Wazuh</b>\nPor ${esc(a.analista.nome)}\n\n${esc(resumo)}\n\n` +
          `Ficam ${dias} dias nas listas do Wazuh. Se aparecerem no ambiente (anexo num endpoint, consulta DNS ao domínio), ` +
          'o Wazuh alerta e o alerta vira chamado no GLPI.' + (avisoRecarga ? `\n\n⚠️ ${esc(avisoRecarga)}` : '') +
          `\n\nRegistrado no chamado #${id} como nota interna.` } },
      { tg_metodo: 'answerCallbackQuery', tg_corpo: { callback_query_id: a.callback_id, text: 'IOCs enviados ao Wazuh ✔' } },
    ],
    apagar_chave: '',
  } };
});
