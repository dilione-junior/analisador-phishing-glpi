// Nó "Monta as ações": para cada ação, os passos no GLPI e as mensagens no Telegram.
// Saída: itens com destino "glpi" (um por chamada à API, em ordem) ou "telegram" (resposta direta).
// Os passos do GLPI levam junto as mensagens de sucesso e de falha; quem as envia é "Confere o GLPI".
//
// SEGURANÇA: a resposta ao USUÁRIO usa só textos fixos deste arquivo. Nada escrito pela IA vai para o
// usuário: um e-mail malicioso poderia "convencer" a IA a escrever um golpe em nome da Segurança.
const cfg = $('Configuração').first().json;
const acoes = $('Separa as ações').all().map((i) => i.json);
const analises = $('Lê a análise').all().map((i) => i.json.analise);
const travas = $input.all().map((i, k) => Number(i.json[acoes[k]?.chave_trava]));
const lista = (nome) => { const b = $(nome).first().json.body; return Array.isArray(b) ? b : []; };
const tipos = lista('Lê os tipos de solução');
const grupos = lista('Lê os grupos (decisões)');
const chat = String($env.PHISHING_TELEGRAM_CHAT_ID ?? '').trim();

const ROTULO = { phishing: 'PHISHING', legitimo: 'LEGÍTIMO', spam: 'SPAM', escalar: 'ESCALADO PARA N2', inconclusivo: 'INCONCLUSIVO' };
const ICONE = { phishing: '🎣', legitimo: '✅', spam: '📨', escalar: '⬆️' };
const TIPO_SOLUCAO = { phishing: cfg.tipoPhishing, legitimo: cfg.tipoLegitimo, spam: cfg.tipoSpam };
const agora = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
const quem = (a) => `${a.nome}${a.usuario ? ' (@' + a.usuario + ')' : ''}`;
const li = (itens) => '<ul>' + itens.map((x) => `<li>${x}</li>`).join('') + '</ul>';

const tg = (metodo, corpo, extra = {}) => ({ json: { destino: 'telegram', tg_metodo: metodo, tg_corpo: corpo, ...extra } });
const responder = (a, texto, alerta = false) => (a.callback_id
  ? tg('answerCallbackQuery', { callback_query_id: a.callback_id, text: texto.slice(0, 190), show_alert: alerta })
  : tg('sendMessage', { chat_id: chat, reply_to_message_id: a.mensagem_id, text: texto, allow_sending_without_reply: true }));

// O que o usuário contou que fez (tipos fixos detectados por regra no relato, nunca texto da IA).
// Registros antigos só têm os rótulos: deduz os tipos deles.
function tiposDeInteracao(registro) {
  if (Array.isArray(registro.interacao_tipos)) return registro.interacao_tipos;
  const r = (Array.isArray(registro.interacao) ? registro.interacao : []).join(' ');
  return [['clicou', /clicou/], ['senha', /senha|dados/], ['anexo', /anexo/], ['respondeu', /respondeu/], ['pagou', /pagamento|transfer/]]
    .filter(([, re]) => re.test(r)).map(([t]) => t);
}

// Bloco URGENTE, no topo da resposta, quando o usuário disse que interagiu com a mensagem.
function blocoUrgente(tipos) {
  const t = new Set(tipos);
  const fez = [t.has('clicou') && 'clicou no link', t.has('senha') && 'digitou sua senha ou seus dados', t.has('anexo') && 'abriu o anexo',
    t.has('pagou') && 'fez um pagamento', t.has('respondeu') && 'respondeu ao remetente'].filter(Boolean);
  if (!fez.length) return '';
  const passos = [];
  if (t.has('clicou') || t.has('senha')) {
    passos.push('<strong>Troque a sua senha IMEDIATAMENTE</strong>, antes de qualquer outra coisa. Abra o site ou o portal digitando o endereço você mesmo (nunca pelo link do e-mail).');
    passos.push('Se você usa a mesma senha em outros serviços (outro e-mail, banco, redes sociais), troque também em todos eles.');
    passos.push('Se aparecer um pedido de aprovação de login (MFA) que você não fez, <strong>recuse</strong> e nos avise.');
  }
  if (t.has('anexo')) passos.push('<strong>Desconecte o computador da rede agora</strong> (tire o cabo ou desligue o Wi-Fi), mas não desligue a máquina: a equipe vai examiná-la.');
  if (t.has('pagou')) passos.push('<strong>Ligue agora para o seu banco</strong> pelo telefone oficial (o do verso do cartão) e peça o bloqueio ou a contestação do pagamento.');
  if (t.has('respondeu')) passos.push('Não envie mais nada ao remetente e desconfie de ligações ou mensagens de quem disser ser dessa empresa.');
  passos.push('<strong>Responda este chamado</strong> confirmando o que já fez' + (t.has('clicou') || t.has('senha') ? ' (por exemplo: "troquei a senha"). Se não conseguir trocar a senha, responda agora: a equipe faz isso por você.' : '.'));
  return `<p>⚠️ <strong>Você nos contou que ${fez.join(', ')}. Faça isto agora:</strong></p>` + li(passos);
}

const RESPOSTA_USUARIO = {
  phishing: (tipos) => '<p>Olá! Obrigado por reportar: você ajudou a proteger todo mundo.</p>' +
    '<p>Analisamos a mensagem e <strong>confirmamos que é PHISHING</strong> (uma tentativa de golpe).</p>' +
    blocoUrgente(tipos) +
    `<p><strong>${tipos.length ? 'Depois disso' : 'O que fazer agora'}:</strong></p>` + li([
      'Não clique nos links, não abra os anexos e não responda ao remetente.',
      'Apague a mensagem (e esvazie a lixeira).',
      ...(tipos.length ? [] : ['Se você clicou no link ou digitou sua senha, <strong>troque a sua senha imediatamente</strong> e responda este chamado. Se abriu o anexo ou fez algum pagamento, responda este chamado agora.']),
    ]) + '<p>A equipe de Segurança da Informação já está bloqueando o remetente e os links.</p>',
  legitimo: '<p>Olá! Obrigado por reportar.</p>' +
    '<p>Analisamos e <strong>o contato é legítimo</strong>: você pode seguir normalmente.</p>' +
    '<p>Continue desconfiando: na dúvida, confirme por um canal oficial (telefone conhecido ou site digitado por você) e reporte de novo. Reportar nunca é incômodo.</p>',
  spam: '<p>Olá! Obrigado por reportar.</p>' +
    '<p>Analisamos e a mensagem é <strong>spam</strong> (propaganda não solicitada), sem sinal de golpe.</p>' +
    '<p>Pode apagar ou marcar como lixo eletrônico. Evite clicar em "descadastrar" de remetentes que você não conhece.</p>',
  escalar: (tipos) => '<p>Olá! Seu relato foi encaminhado para uma análise mais aprofundada da equipe de Segurança da Informação.</p>' +
    blocoUrgente(tipos) +
    '<p>Enquanto isso, <strong>não interaja</strong> com a mensagem (não clique, não abra anexos, não responda). Avisaremos por aqui.</p>',
};

const CHECKLIST_PHISHING = [
  'Bloquear o remetente e o domínio no filtro/gateway de e-mail',
  'Procurar e apagar cópias da mesma mensagem nas outras caixas (ex.: Microsoft Purview, busca de conteúdo e limpeza)',
  'Bloquear os links e domínios no proxy, DNS ou firewall',
  'Ver nos logs de proxy/DNS quem mais acessou esses domínios',
  'Incluir os IOCs na lista de bloqueio (ex.: lista CDB do Wazuh)',
  'Se houve interação: trocar a senha, encerrar as sessões, conferir o MFA e as regras da caixa de e-mail do usuário',
];

const saida = [];
acoes.forEach((a, k) => {
  const trava = travas[k];
  let registro = null;
  try { registro = analises[k] ? JSON.parse(analises[k]) : null; } catch (erro) { registro = null; }

  if (a.tipo === 'responder') { saida.push(responder(a, a.texto, a.alerta)); return; }
  if (trava > 1) {
    // Mesma mensagem do Telegram chegando de novo: ignora. Decisão repetida: avisa quem clicou.
    if (a.tipo === 'decidir') saida.push(responder(a, `O chamado #${a.chamado_id} já foi decidido antes.`));
    return;
  }
  const liberar = a.tipo === 'decidir' ? a.chave_trava : '';
  if (a.tipo === 'reanalisar') {
    saida.push(tg('sendMessage', { chat_id: chat, reply_to_message_id: a.mensagem_id, allow_sending_without_reply: true,
      text: `🔁 Chamado #${a.chamado_id} volta para a fila: será analisado de novo em até 2 minutos (se ainda estiver aberto e na categoria de phishing).` },
    { apagar_chave: `${cfg.prefixoRedis}relato:${a.chamado_id}` }));
    return;
  }
  if (!registro) {
    saida.push({ ...responder(a, `O chamado #${a.chamado_id} não foi analisado por este fluxo (ou a análise expirou). Use /reanalisar ${a.chamado_id}.`, true) });
    if (liberar) saida[saida.length - 1].json.apagar_chave = liberar;
    return;
  }

  const id = a.chamado_id;
  const passos = [];
  let sucesso = [];
  let chaveMetrica = '';
  if (a.tipo === 'nota') {
    passos.push({ caminho: 'ITILFollowup', corpo: { input: { itemtype: 'Ticket', items_id: id, is_private: 1,
      content: `<p><strong>📝 Nota do analista</strong> ${esc(quem(a.analista))} pelo Telegram, ${agora}:</p><p>${esc(a.texto).replace(/\n/g, '<br>')}</p>` } } });
    sucesso = [tg('sendMessage', { chat_id: chat, reply_to_message_id: a.mensagem_id, allow_sending_without_reply: true, text: `📝 Nota registrada no chamado #${id}.` })];
  } else {
    const decisao = a.decisao;
    const concordou = registro.sugestao === decisao;
    chaveMetrica = `${cfg.prefixoRedis}metricas:ia_${registro.sugestao}:analista_${decisao}`;
    const iocs = registro.iocs ?? {};
    const linhasIocs = [...(iocs.remetente ?? []), ...(iocs.urls ?? []), ...(iocs.dominios ?? []), ...(iocs.ips ?? []), ...(iocs.hashes ?? [])]
      .slice(0, 30).map((x) => esc(desarmar(linha(x, 150))));
    const nota = `<p><strong>${ICONE[decisao]} Decisão do analista: ${ROTULO[decisao]}</strong></p>` +
      `<p>Por ${esc(quem(a.analista))} (Telegram ID ${esc(a.analista.id)}), ${agora}. ` +
      `Sugestão da IA: ${ROTULO[registro.sugestao] ?? esc(registro.sugestao)} (${Number(registro.confianca) || 0}%): <strong>${concordou ? 'o analista concordou' : 'o analista DISCORDOU (caso útil para calibrar a IA)'}</strong>.</p>` +
      (decisao === 'phishing' ? '<p><strong>Checklist de resposta</strong> (registre o que fizer com /nota):</p>' + li(CHECKLIST_PHISHING.map(esc)) : '') +
      (decisao === 'phishing' && linhasIocs.length ? '<p><strong>IOCs para bloqueio (desarmados)</strong></p>' + li(linhasIocs) : '');
    passos.push({ caminho: 'ITILFollowup', corpo: { input: { itemtype: 'Ticket', items_id: id, is_private: 1, content: nota } } });

    if (decisao === 'escalar') {
      const n2 = grupos.find((g) => String(g.name ?? '').trim() === cfg.grupoN2);
      if (!n2) { saida.push({ ...responder(a, `Não achei o grupo "${cfg.grupoN2}" no GLPI.`, true) }); saida[saida.length - 1].json.apagar_chave = liberar; return; }
      passos.push({ caminho: 'Group_Ticket', corpo: { input: { tickets_id: id, groups_id: Number(n2.id), type: 2 } } });
      passos.push({ caminho: 'ITILFollowup', corpo: { input: { itemtype: 'Ticket', items_id: id, is_private: 0, content: RESPOSTA_USUARIO.escalar(tiposDeInteracao(registro)) } } });
    } else {
      const tipo = tipos.find((t) => String(t.name ?? '').trim() === TIPO_SOLUCAO[decisao]);
      if (!tipo) { saida.push({ ...responder(a, `Não achei o tipo de solução "${TIPO_SOLUCAO[decisao]}" no GLPI. Rode glpi/preparar-glpi.sh.`, true) }); saida[saida.length - 1].json.apagar_chave = liberar; return; }
      passos.push({ caminho: 'ITILSolution', corpo: { input: { itemtype: 'Ticket', items_id: id, solutiontypes_id: Number(tipo.id),
        content: decisao === 'phishing' ? RESPOSTA_USUARIO.phishing(tiposDeInteracao(registro)) : RESPOSTA_USUARIO[decisao] } } });
    }

    const interacao = Array.isArray(registro.interacao) && registro.interacao.length && decisao !== 'legitimo' && decisao !== 'spam'
      ? `\n⚠️ O usuário disse que ${esc(registro.interacao.join(', '))}: comece por trocar a senha / isolar a máquina.` : '';
    const proximos = decisao === 'phishing'
      ? '\n\n<b>Próximos passos</b>\n' + CHECKLIST_PHISHING.slice(0, 5).map((x, n) => `${n + 1}. ${esc(x)}`).join('\n') + `\nRegistre o que fizer com /nota ${id} texto`
      : '';
    sucesso = [
      tg('editMessageReplyMarkup', { chat_id: chat, message_id: a.mensagem_id,
        reply_markup: { inline_keyboard: [[{ text: `✔️ ${ROTULO[decisao]} · ${a.analista.nome}`.slice(0, 60), callback_data: `ph|${id}|x` }]] } }),
      tg('sendMessage', { chat_id: chat, reply_to_message_id: a.mensagem_id, allow_sending_without_reply: true, parse_mode: 'HTML',
        text: `${ICONE[decisao]} <b>Chamado #${id}: ${ROTULO[decisao]}</b> por ${esc(a.analista.nome)}\n` +
          (decisao === 'escalar' ? 'Grupo SOC N2 incluído no chamado e usuário avisado.' : 'Usuário respondido e chamado solucionado no GLPI.') +
          `\nIA sugeriu ${ROTULO[registro.sugestao] ?? esc(registro.sugestao)} (${Number(registro.confianca) || 0}%): ${concordou ? '👍 concordou' : '👎 discordou'}` +
          interacao + proximos }),
      tg('answerCallbackQuery', { callback_query_id: a.callback_id, text: 'Decisão registrada no GLPI ✔' }),
    ];
  }
  const falha = [responder(a, `Não consegui gravar no GLPI o chamado #${id}. Tente de novo em 1 minuto.`, true)];
  passos.forEach((p, n) => saida.push({ json: {
    destino: 'glpi', acao_indice: k, passo: n, caminho: p.caminho, corpo: p.corpo,
    ...(n === 0 ? { sucesso: sucesso.map((x) => x.json), falha: falha.map((x) => x.json), chave_trava: liberar, chave_metrica: chaveMetrica } : {}),
  } }));
});
return saida;
