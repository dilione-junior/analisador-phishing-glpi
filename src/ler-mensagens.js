// Nó "Lê as mensagens": transforma o que chegou no Telegram em ações.
//  - Clique num botão do relato (ph|<chamado>|p/l/s/e) -> decidir: phishing, legítimo, spam ou escalar N2.
//  - /nota <chamado> <texto>  -> nota interna no chamado (justificativa, contexto, o que foi feito).
//  - /reanalisar <chamado>    -> o fluxo de análise pega o chamado de novo (ex.: o usuário anexou o .eml depois).
//  - /ajuda                   -> lista os comandos.
// Só vale o que vem do grupo configurado (PHISHING_TELEGRAM_CHAT_ID) e, para decidir ou anotar, só
// analistas autorizados (IDs do Telegram em PHISHING_ANALISTAS). Sem configuração, nada é aceito.
const r = $input.first().json;
if (r.statusCode !== 200 || !r.body?.ok) return []; // 409 = outra leitura em andamento; tenta no próximo minuto
const atualizacoes = Array.isArray(r.body.result) ? r.body.result : [];
if (!atualizacoes.length) return [];

const grupo = String($env.PHISHING_TELEGRAM_CHAT_ID ?? '').trim();
const analistas = new Set(String($env.PHISHING_ANALISTAS ?? '').split(/[\s,;]+/).filter((x) => /^\d{3,20}$/.test(x)));
const DECISOES = { p: 'phishing', l: 'legitimo', s: 'spam', e: 'escalar' };
const AJUDA = 'Comandos do grupo de relatos de phishing\n\n' +
  '👆 Botões da ficha: decidem o caso. Respondem ao usuário e encerram (ou escalam para o N2) o chamado no GLPI.\n\n' +
  '📝 /nota NÚMERO TEXTO: registra no chamado o que você fez, como nota interna (só a equipe técnica vê, o usuário não).\n' +
  'Exemplo: /nota 123 bloqueei o domínio no proxy e no filtro de e-mail\n\n' +
  '🔁 /reanalisar NÚMERO: analisa o chamado de novo (ex.: o usuário anexou o e-mail depois).\n' +
  'Exemplo: /reanalisar 123\n\n' +
  'Só analistas autorizados podem decidir e anotar.';
const pessoa = (de) => ({
  id: String(de?.id ?? ''),
  nome: linha([de?.first_name, de?.last_name].filter(Boolean).join(' ') || 'sem nome', 60),
  usuario: linha(de?.username ?? '', 40),
});

const acoes = [];
const decididosAgora = new Set();
for (const u of atualizacoes) {
  const base = { update_id: Number(u.update_id) };
  const cb = u.callback_query;
  if (cb) {
    const analista = pessoa(cb.from);
    const resposta = (texto, alerta = false) => acoes.push({ ...base, tipo: 'responder', callback_id: String(cb.id), texto, alerta, analista });
    const m = String(cb.data ?? '').match(/^ph\|(\d{1,9})\|([plsex])$/);
    if (!grupo || String(cb.message?.chat?.id ?? '') !== grupo || !m) { resposta('Botão inválido ou de outro grupo.'); continue; }
    if (m[2] === 'x') { resposta('Este relato já foi decidido.'); continue; }
    if (!analistas.has(analista.id)) { resposta(`Sem permissão para decidir. Peça para incluir o seu ID do Telegram (${analista.id}) em PHISHING_ANALISTAS.`, true); continue; }
    const chamado = Number(m[1]);
    if (decididosAgora.has(chamado)) { resposta(`Chamado #${chamado} já está sendo decidido.`); continue; }
    decididosAgora.add(chamado);
    acoes.push({ ...base, tipo: 'decidir', chamado_id: chamado, decisao: DECISOES[m[2]], callback_id: String(cb.id), mensagem_id: Number(cb.message.message_id), analista });
    continue;
  }
  const msg = u.message;
  if (!grupo || !msg || String(msg.chat?.id ?? '') !== grupo) continue; // outras conversas: ignora em silêncio
  const cmd = String(msg.text ?? '').trim().match(/^\/(nota|reanalisar|ajuda|help|start)(?:@\w+)?(?:\s+#?(\d{1,9}))?(?:\s+([\s\S]+))?$/i);
  if (!cmd) continue;
  const analista = pessoa(msg.from);
  const comum = { ...base, mensagem_id: Number(msg.message_id), analista };
  const responder = (texto) => acoes.push({ ...comum, tipo: 'responder', texto });
  const nome = cmd[1].toLowerCase();
  if (['ajuda', 'help', 'start'].includes(nome)) { responder(AJUDA); continue; }
  if (!analistas.has(analista.id)) { responder(`Sem permissão. Peça para incluir o seu ID do Telegram (${analista.id}) em PHISHING_ANALISTAS.`); continue; }
  if (!cmd[2]) { responder(`Informe o número do chamado. Ex.: /${nome} 123${nome === 'nota' ? ' texto da nota' : ''}`); continue; }
  if (nome === 'nota' && !String(cmd[3] ?? '').trim()) { responder(`Escreva o texto da nota. Ex.: /nota ${cmd[2]} usuário confirmou que não clicou`); continue; }
  acoes.push({ ...comum, tipo: nome, chamado_id: Number(cmd[2]), texto: curto(cmd[3] ?? '', 2000) });
}

return [{ json: {
  offset: Math.max(...atualizacoes.map((u) => Number(u.update_id))) + 1,
  acoes: acoes.slice(0, 20),
} }];
