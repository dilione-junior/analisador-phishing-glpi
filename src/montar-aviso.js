// Nó "Monta o registro e o aviso": prepara
//  1. o acompanhamento PRIVADO no GLPI (só técnicos veem) com a análise completa;
//  2. a mensagem para o grupo "Relatos de Phishing" no Telegram, com os botões de decisão;
//  3. o registro guardado no Redis, que o fluxo das decisões usa quando o analista clica.
// Tudo que veio do e-mail/chamado passa por esc() e os indicadores são DESARMADOS (hxxps://site[.]com).
const cfg = $('Configuração').first().json;
const ev = $('Extrai as evidências').first().json;
const d = $('Monta o dossiê').first().json;
const p = $input.first().json.parecer;
const id = ev.chamado.id;

const ROTULO = { phishing: 'PHISHING', spam: 'SPAM', legitimo: 'LEGÍTIMO', inconclusivo: 'INCONCLUSIVO' };
const ICONE = { phishing: '🔴', spam: '🟡', legitimo: '🟢', inconclusivo: '⚪' };
const GRAV = { baixa: 'Baixa', media: 'Média', alta: 'Alta', critica: 'Crítica' };
const ICONE_GRAV = { baixa: '🟢', media: '🟡', alta: '🟠', critica: '🔴' };
const quando = (iso) => {
  const t = Date.parse(String(iso).replace(' ', 'T'));
  return Number.isFinite(t) ? String(iso).slice(8, 10) + '/' + String(iso).slice(5, 7) + ' ' + String(iso).slice(11, 16) : '';
};
const e = ev.email;
const autent = e.autenticacao.presente ? `SPF ${e.autenticacao.spf || '?'} · DKIM ${e.autenticacao.dkim || '?'} · DMARC ${e.autenticacao.dmarc || '?'}` : 'sem resultado de SPF/DKIM/DMARC';
const remetente = (x) => (x.email ? `${x.nome ? linha(x.nome, 60) + ' ' : ''}<${desarmar(x.email)}>` : '');

const reputacao = [];
for (const v of d.reputacao.virustotal) {
  if (v.erro) reputacao.push(`VirusTotal (${v.tipo}): ${v.erro}`);
  else if (!v.encontrado) reputacao.push(`VirusTotal: ${v.tipo} ${desarmar(linha(v.valor, 80))} nunca analisado (não prova que é seguro)`);
  else reputacao.push(`VirusTotal: ${v.tipo} ${desarmar(linha(v.valor, 80))}: ${v.maliciosos}/${v.total} malicioso${v.suspeitos ? `, ${v.suspeitos} suspeito` : ''}${v.nome_ameaca ? ` (${v.nome_ameaca})` : ''}`);
}
for (const u of d.reputacao.urlhaus) if (u.listado) reputacao.push(`URLhaus: ${desarmar(u.host)} LISTADO (${u.online} URL no ar${u.tags.length ? '; ' + u.tags.join(', ') : ''})`);
for (const r of d.reputacao.rdap) if (r.idade_dias !== null && r.idade_dias !== undefined) reputacao.push(`Domínio ${desarmar(r.dominio)} criado em ${r.criado_em} (${r.idade_dias} dias)`);

// IOCs já separados em "Extrai as evidências": domínios oficiais, webmail e serviços compartilhados ficam fora.
const iocs = ev.iocs;
const linhasIocs = [
  ...iocs.remetente.map((x) => 'remetente: ' + desarmar(x)),
  ...iocs.urls.map((x) => 'url: ' + desarmar(linha(x, 150))),
  ...iocs.dominios.map((x) => 'domínio: ' + desarmar(x)),
  ...iocs.ips.map((x) => 'ip: ' + desarmar(x)),
  ...iocs.hashes.map((x) => 'hash: ' + x),
  ...(iocs.telefones ?? []).map((x) => 'telefone do golpe: ' + x),
  ...(iocs.pix ?? []).map((x) => 'PIX lido do QR (para o banco; não vai ao Wazuh): ' + x),
];
// Catálogo de técnicas (achados determinísticos lidos no .eml): curto, vai sempre no aviso.
const tecnicas = ev.tecnicas ?? [];
const linhasTecnicas = tecnicas.map((t) => `${t.forte ? '🔴 ' : ''}${t.nome}`);
const linhasFora = (ev.iocs_fora ?? []).map((x) => `${desarmar(linha(x.valor, 100))}: ${x.motivo}`);

// ---------------- Telegram (HTML do Telegram: b, i, a, code, blockquote) ----------------
const blocos = [];
blocos.push(`🎣 <b>Relato de phishing · Chamado #${id}</b>\n<a href="${esc(ev.chamado.link)}">Abrir no GLPI</a>` +
  `${quando(ev.chamado.aberto_em) ? ' · ' + quando(ev.chamado.aberto_em) : ''}${ev.chamado.requerentes.length ? ' · por <b>' + esc(ev.chamado.requerentes.join(', ')) + '</b>' : ''}` +
  `\n<i>${esc(linha(ev.chamado.titulo, 120))}</i>`);
blocos.push(`<b>Sugestão da IA:</b> ${ICONE[p.classificacao]} <b>${ROTULO[p.classificacao]}</b> · confiança ${p.confianca}%\n` +
  `<b>Gravidade:</b> ${ICONE_GRAV[p.gravidade]} ${GRAV[p.gravidade]}${p.tipo_ataque ? ' · ' + esc(p.tipo_ataque) : ''}${p.mitre.length ? ' · MITRE ' + esc(p.mitre.join(', ')) : ''}\n` +
  `<b>Nota automática:</b> ${p.nota_automatica}/100${p.origem === 'automatica' ? ' (IA indisponível: parecer automático)' : ''}`);
if (ev.interacao.algum) {
  blocos.push(`⚠️ <b>O usuário disse que ${esc(ev.interacao.rotulos.join(', '))}</b>` +
    (ev.interacao.trechos.length ? `\n<blockquote>${esc(ev.interacao.trechos[0])}</blockquote>` : ''));
}
if (ev.tem_email) {
  blocos.push(`📧 <b>E-mail</b> <i>(${esc(e.fonte)})</i>\n` +
    [e.de.email && 'De: ' + esc(remetente(e.de)),
      e.responder.email && e.responder.email !== e.de.email && 'Responder para: ' + esc(remetente(e.responder)),
      e.retorno.email && e.retorno.email !== e.de.email && 'Return-Path: ' + esc(desarmar(e.retorno.email)),
      e.assunto && 'Assunto: ' + esc(e.assunto),
      esc(autent) + (e.ips_origem.length ? ' · IP de origem ' + esc(desarmar(e.ips_origem[0])) : ''),
    ].filter(Boolean).join('\n'));
} else {
  blocos.push('📧 <b>E-mail não anexado</b>: só o relato do usuário foi analisado.');
}
if (linhasTecnicas.length) blocos.push(`🧪 <b>Técnicas detectadas</b> <i>(🔴 = não aparece em e-mail legítimo)</i>\n${linhasTecnicas.slice(0, 5).map((x) => '• ' + esc(x)).join('\n')}`);
blocos.push(`🧠 <b>Análise</b>\n${esc(p.resumo)}`);
// O Telegram não tem espaçamento de linha: frases longas ganham uma linha em branco entre si; IOCs ficam juntos (para copiar).
const itens = (titulo, lista, expandir = true, espacado = true) => (lista.length
  ? `${titulo}\n<blockquote${expandir ? ' expandable' : ''}>${lista.map((x) => '• ' + esc(x)).join(espacado ? '\n\n' : '\n')}</blockquote>` : '');
const opcionais = [
  itens('🔎 <b>Evidências</b>', p.evidencias, false),
  itens('✅ <b>Sinais de legitimidade</b>', p.contra_evidencias),
  itens('🌐 <b>Reputação</b>', reputacao),
  p.acoes_soc.length ? `🛡️ <b>Ações recomendadas</b>\n\n${p.acoes_soc.map((a, k) => `${k + 1}. ${esc(a)}`).join('\n\n')}` : '',
  itens('❓ <b>Perguntar ao usuário</b>', p.perguntas_ao_usuario),
  itens('ℹ️ <b>Avisos</b>', p.avisos),
  itens('🧾 <b>IOCs para bloqueio (desarmados)</b>', linhasIocs, true, false),
  itens('🚫 <b>Fora do bloqueio (legítimos ou compartilhados)</b>', linhasFora, true, false),
].filter(Boolean);
const rodape = '👇 <b>Decida nos botões abaixo.</b> A decisão responde ao usuário e encerra (ou escala) o chamado no GLPI.\n\n' +
  `📝 <b>Anotar o que você fez</b>: envie <code>/nota ${id}</code> seguido do texto. Ex.: <code>/nota ${id} bloqueei o domínio no proxy</code>\n` +
  'Vira nota interna no chamado (só a equipe técnica vê).\n\n' +
  `🔁 <b>Analisar de novo</b> (ex.: o usuário anexou o e-mail depois): <code>/reanalisar ${id}</code>`;

// Limite do Telegram: 4096 caracteres. Tira os blocos opcionais do fim até caber (nunca corta HTML no meio).
let texto = [...blocos, ...opcionais, rodape].join('\n\n');
while (texto.length > 4000 && opcionais.length) {
  opcionais.pop();
  texto = [...blocos, ...opcionais, '<i>(detalhes completos no acompanhamento do GLPI)</i>', rodape].join('\n\n');
}
if (texto.length > 4000) texto = [blocos[0], blocos[1], '<i>(análise completa no acompanhamento do GLPI)</i>', rodape].join('\n\n');

const chatId = String($env.PHISHING_TELEGRAM_CHAT_ID ?? '').trim();
const botao = (rotulo, acao) => ({ text: rotulo, callback_data: `ph|${id}|${acao}` });
const telegram = {
  chat_id: chatId,
  text: texto,
  parse_mode: 'HTML',
  disable_web_page_preview: true,
  reply_markup: { inline_keyboard: [
    [botao('🎣 É phishing', 'p'), botao('✅ É legítimo', 'l')],
    [botao('📨 Spam (sem risco)', 's'), botao('⬆️ Escalar N2', 'e')],
  ] },
};

// ---------------- Acompanhamento PRIVADO no GLPI (HTML) ----------------
const li = (lista) => (lista.length ? '<ul>' + lista.map((x) => `<li>${esc(x)}</li>`).join('') + '</ul>' : '<p>—</p>');
const html = [
  `<p><strong>🤖 Análise automática de phishing</strong> (analisador-phishing) · ${esc(new Date().toISOString().slice(0, 16).replace('T', ' '))} UTC</p>`,
  `<p><strong>Sugestão:</strong> ${ROTULO[p.classificacao]} · confiança ${p.confianca}% · gravidade ${GRAV[p.gravidade]}` +
    `${p.tipo_ataque ? ' · ' + esc(p.tipo_ataque) : ''}${p.mitre.length ? ' · MITRE ATT&amp;CK ' + esc(p.mitre.join(', ')) : ''}<br>` +
    `Nota automática ${p.nota_automatica}/100 · parecer ${p.origem === 'ia' ? 'da IA (com travas)' : 'automático'}. <em>Aguardando decisão do analista no Telegram.</em></p>`,
  ev.interacao.algum ? `<p><strong>⚠️ O usuário disse que ${esc(ev.interacao.rotulos.join(', '))}.</strong></p>` : '',
  `<p><strong>E-mail</strong> (${esc(e.fonte)})</p>` + li([
    e.de.email && 'De: ' + remetente(e.de),
    e.responder.email && 'Responder para: ' + remetente(e.responder),
    e.retorno.email && 'Return-Path: ' + desarmar(e.retorno.email),
    e.assunto && 'Assunto: ' + e.assunto,
    e.data && 'Data: ' + e.data,
    autent,
    e.ips_origem.length && 'IPs de origem: ' + e.ips_origem.map(desarmar).join(', '),
  ].filter(Boolean)),
  `<p><strong>Análise</strong></p><p>${esc(p.resumo)}</p>`,
  tecnicas.length ? '<p><strong>Técnicas detectadas (catálogo)</strong></p>' + li(tecnicas.map((t) => `${t.forte ? '[forte] ' : ''}${t.nome}: ${t.descricao}`)) : '',
  '<p><strong>Evidências</strong></p>' + li(p.evidencias),
  p.contra_evidencias.length ? '<p><strong>Sinais de legitimidade</strong></p>' + li(p.contra_evidencias) : '',
  '<p><strong>Reputação</strong></p>' + li(reputacao),
  '<p><strong>Sinais automáticos (peso)</strong></p>' + li(d.sinais.map((s) => `${s.peso > 0 ? '+' : ''}${s.peso} ${s.descricao}`)),
  '<p><strong>Ações recomendadas</strong></p>' + li(p.acoes_soc),
  p.perguntas_ao_usuario.length ? '<p><strong>Perguntar ao usuário</strong></p>' + li(p.perguntas_ao_usuario) : '',
  p.avisos.length ? '<p><strong>Avisos</strong></p>' + li(p.avisos) : '',
  '<p><strong>IOCs para bloqueio (desarmados)</strong></p>' + li(linhasIocs),
  linhasFora.length ? '<p><strong>Fora do bloqueio (legítimos ou compartilhados)</strong></p>' + li(linhasFora) : '',
].filter(Boolean).join('\n');

return [{ json: {
  telegram,
  telegram_configurado: /^-?\d{5,20}$/.test(chatId),
  acompanhamento: { input: { itemtype: 'Ticket', items_id: id, is_private: 1, content: html } },
  chave_analise: `${cfg.prefixoRedis}analise:${id}`,
  registro: {
    chamado_id: id,
    titulo: ev.chamado.titulo,
    requerentes: ev.chamado.requerentes,
    sugestao: p.classificacao,
    confianca: p.confianca,
    gravidade: p.gravidade,
    tipo_ataque: p.tipo_ataque,
    orientacao_usuario: p.orientacao_usuario,
    interacao: ev.interacao.rotulos,
    // Tipos fixos (clicou, senha, anexo, respondeu, pagou), detectados por regra no relato: a resposta ao usuário usa estes.
    interacao_tipos: ['clicou', 'senha', 'anexo', 'respondeu', 'pagou'].filter((t) => ev.interacao[t]),
    iocs,
    bloqueio: ev.bloqueio ?? null, // o que o botão "Bloquear IOCs no Wazuh" envia
    analisado_em: new Date().toISOString(),
  },
} }];
