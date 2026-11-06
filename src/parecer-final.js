// Nó "Parecer final": lê a resposta da IA (JSON) e aplica TRAVAS antes de mostrar ao analista.
//  - Evidência forte (VirusTotal 3+ motores, URLhaus) não pode virar "legítimo" nem "spam".
//  - Nota automática alta não pode virar "legítimo": no máximo "inconclusivo".
//  - A gravidade sobe conforme o que o USUÁRIO fez (digitou senha, abriu anexo, pagou...).
//  - Se a IA falhar ou responder fora do formato, vale a sugestão automática.
// A IA só SUGERE. Quem decide é o analista, pelo botão no Telegram.
const d = $('Monta o dossiê').first().json;
const ev = $('Extrai as evidências').first().json;
const resposta = $input.first().json;

const CLASSES = ['phishing', 'spam', 'legitimo', 'inconclusivo'];
const GRAVIDADES = ['baixa', 'media', 'alta', 'critica'];
const lista = (x, maximo, tamanho = 300) => (Array.isArray(x) ? x : [])
  .map((i) => linha(typeof i === 'string' ? i : JSON.stringify(i), tamanho)).filter(Boolean).slice(0, maximo);
const sem = (t) => String(t ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();

let ia = null;
let erroIA = '';
if (typeof resposta.output === 'string' && resposta.output.trim()) {
  const t = resposta.output;
  try { ia = JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1)); } catch (erro) { erroIA = 'a IA respondeu fora do formato combinado'; }
} else {
  erroIA = linha(resposta.error?.message ?? resposta.error ?? 'a IA não respondeu', 160);
}

const avisos = [];
const automatica = d.sugestao_automatica;
let origem = 'automatica';
let classe = automatica;
let confianca = automatica === 'phishing' ? Math.min(95, 55 + Math.round(d.pontuacao / 3)) : automatica === 'legitimo' ? 60 : 40;
let p = {};
if (ia && typeof ia === 'object' && CLASSES.includes(sem(ia.classificacao))) {
  origem = 'ia';
  p = ia;
  classe = sem(ia.classificacao);
  confianca = Math.max(0, Math.min(100, Math.round(Number(ia.confianca)) || 50));
} else {
  avisos.push(`Parecer automático (${erroIA || 'resposta da IA inválida'}).`);
}

if (d.fortes.length && classe !== 'phishing') {
  avisos.push(`A IA sugeriu "${classe}", mas há evidência forte (${d.fortes.join('; ')}): mantido como phishing.`);
  classe = 'phishing';
  confianca = Math.max(confianca, 85);
}
if ((classe === 'legitimo' || classe === 'spam') && d.pontuacao >= 50) {
  avisos.push(`A IA sugeriu "${classe}", mas a nota automática é ${d.pontuacao}/100: rebaixado para inconclusivo.`);
  classe = 'inconclusivo';
}
if (!ev.tem_email && !ev.urls.length) {
  confianca = Math.min(confianca, 50);
  avisos.push('O chamado não traz o e-mail (nem cabeçalhos, nem links): peça ao usuário para anexar o e-mail como arquivo (.eml/.msg).');
}

const i = ev.interacao;
let gravidade = GRAVIDADES.includes(sem(p.gravidade)) ? sem(p.gravidade) : classe === 'phishing' ? 'media' : 'baixa';
const minimo = (g) => { if (GRAVIDADES.indexOf(gravidade) < GRAVIDADES.indexOf(g)) gravidade = g; };
if (classe === 'phishing' || classe === 'inconclusivo') {
  if (classe === 'phishing') minimo('media');
  if (i.clicou) minimo('alta');
  if (i.senha || i.anexo || i.pagou) minimo(classe === 'phishing' ? 'critica' : 'alta');
}
if (classe === 'legitimo' || classe === 'spam') gravidade = 'baixa';

// Ações obrigatórias de resposta a incidente, conforme o que o usuário disse que fez.
const obrigatorias = [];
if (classe !== 'legitimo' && classe !== 'spam') {
  if (i.senha) obrigatorias.push('Trocar a senha do usuário AGORA, encerrar as sessões abertas (revogar tokens) e conferir se o MFA continua só com os dispositivos dele');
  if (i.anexo) obrigatorias.push('Isolar a máquina do usuário e fazer varredura (antivírus/EDR) antes de devolvê-la à rede');
  if (i.pagou) obrigatorias.push('Acionar o financeiro e o banco imediatamente para tentar bloquear/estornar o pagamento (no PIX: pedir o MED)');
  if (i.clicou && !i.senha) obrigatorias.push('Confirmar com o usuário se ele digitou algum dado na página e procurar o acesso ao domínio nos logs de proxy/DNS');
  if (i.respondeu) obrigatorias.push('Ver o que o usuário respondeu: se enviou dados, tratar como vazamento');
}
const acoes = [...obrigatorias, ...lista(p.acoes_soc, 6)].filter((a, k, todas) => todas.findIndex((b) => sem(b) === sem(a)) === k).slice(0, 8);
if (!acoes.length && classe === 'phishing') {
  acoes.push('Bloquear o remetente e o domínio no filtro de e-mail', 'Procurar e apagar cópias do mesmo e-mail nas outras caixas', 'Bloquear os links/domínios no proxy ou DNS');
}

const mitre = [...new Set(lista(p.mitre, 5, 20).map((t) => t.toUpperCase()).filter((t) => /^T\d{4}(\.\d{3})?$/.test(t)))];
if (classe === 'phishing' && !mitre.length) {
  if (ev.anexos.some((a) => a.perigosa || a.dupla_extensao)) mitre.push('T1566.001');
  if (ev.urls.length) mitre.push('T1566.002');
  if (!mitre.length) mitre.push('T1566');
}

return [{ json: {
  parecer: {
    classificacao: classe,
    confianca,
    gravidade,
    tipo_ataque: linha(p.tipo_ataque, 80) || (classe === 'phishing' ? 'phishing' : ''),
    mitre,
    resumo: curto(p.resumo, 700) || `Sugestão automática pela nota ${d.pontuacao}/100 (${d.sinais.filter((s) => s.peso > 0).length} sinais de risco).`,
    evidencias: lista(p.evidencias, 6).length ? lista(p.evidencias, 6) : d.sinais.filter((s) => s.peso > 0).sort((a, b) => b.peso - a.peso).slice(0, 6).map((s) => s.descricao),
    contra_evidencias: lista(p.contra_evidencias, 4).length ? lista(p.contra_evidencias, 4) : d.sinais.filter((s) => s.peso < 0).map((s) => s.descricao),
    acoes_soc: acoes,
    orientacao_usuario: curto(p.orientacao_usuario, 600),
    perguntas_ao_usuario: lista(p.perguntas_ao_usuario, 3),
    origem,
    sugestao_automatica: d.sugestao_automatica,
    nota_automatica: d.pontuacao,
    avisos,
  },
} }];
