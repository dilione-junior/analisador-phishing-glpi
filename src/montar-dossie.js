// Nó "Monta o dossiê": junta evidências + reputação, calcula a NOTA AUTOMÁTICA (0 a 100) e monta o
// texto que vai para a IA. A nota automática é a rede de segurança: se a IA falhar ou for enganada
// pelo texto do e-mail, a decisão sugerida nunca fica abaixo do que as evidências mostram.
const ev = $('Extrai as evidências').first().json;
const resumo = (no, campo) => { try { return $(no).first().json[campo] ?? []; } catch (erro) { return null; } };
const vt = resumo('Resume o VirusTotal', 'virustotal');
const urlhaus = resumo('Resume o URLhaus', 'urlhaus');
const rdap = resumo('Resume o RDAP', 'rdap');

const sinais = [...ev.sinais];
const fortes = [];
for (const v of vt ?? []) {
  if (!v.encontrado) continue;
  if (v.maliciosos >= 3) {
    sinais.push({ id: 'vt', peso: 40, descricao: `VirusTotal: ${v.tipo} ${desarmar(v.valor)} marcado como malicioso por ${v.maliciosos} de ${v.total} motores` });
    fortes.push(`VirusTotal ${v.maliciosos}/${v.total} (${v.tipo})`);
  } else if (v.maliciosos + v.suspeitos >= 1) {
    sinais.push({ id: 'vt-fraco', peso: 12, descricao: `VirusTotal: ${v.tipo} ${desarmar(v.valor)} com ${v.maliciosos + v.suspeitos} motor(es) alertando (pode ser falso positivo)` });
  } else if (v.total > 0) {
    sinais.push({ id: 'vt-limpo', peso: -5, descricao: `VirusTotal: ${v.tipo} ${desarmar(v.valor)} sem alertas (${v.total} motores)` });
  }
}
for (const u of urlhaus ?? []) {
  if (!u.listado) continue;
  sinais.push({ id: 'urlhaus', peso: 40, descricao: `URLhaus: ${desarmar(u.host)} listado (${u.urls} URL(s), ${u.online} no ar${u.tags.length ? ', ' + u.tags.join(', ') : ''})` });
  fortes.push(`URLhaus (${u.host})`);
}
for (const r of rdap ?? []) {
  if (r.idade_dias === null || r.idade_dias === undefined) continue;
  if (r.idade_dias < 30) sinais.push({ id: 'dominio-novo', peso: 20, descricao: `domínio ${desarmar(r.dominio)} registrado há só ${r.idade_dias} dia(s) (${r.criado_em})` });
  else if (r.idade_dias < 180) sinais.push({ id: 'dominio-recente', peso: 8, descricao: `domínio ${desarmar(r.dominio)} registrado há ${r.idade_dias} dias` });
}

// Catálogo de técnicas: artefato que não aparece em e-mail legítimo (smuggling, SVG com script, .lnk no .zip) é evidência forte.
const tecnicas = ev.tecnicas ?? [];
for (const t of tecnicas.filter((x) => x.forte)) fortes.push(`técnica: ${t.nome}`);

// "SPF/DKIM/DMARC passaram" só prova de onde o e-mail saiu. Não conta a favor quando o golpe usa um serviço
// ou conta legítimos (OAuth, callback, conta invadida) nem quando o domínio do remetente acabou de ser criado.
const doRemetente = String(ev.email?.de?.dominio ?? '').toLowerCase();
const remetenteNovo = (rdap ?? []).find((r) => r.dominio && (doRemetente === r.dominio || doRemetente.endsWith('.' + r.dominio))
  && r.idade_dias !== null && r.idade_dias !== undefined && r.idade_dias < 30);
const remetente = remetenteNovo?.dominio ?? doRemetente;
const abuso = tecnicas.find((t) => t.abusaServico);
const autenticado = sinais.find((s) => s.id === 'autenticado' && s.peso < 0);
if (autenticado && (abuso || remetenteNovo)) {
  autenticado.peso = 0;
  autenticado.descricao = abuso
    ? `SPF/DKIM/DMARC passaram, mas não contam a favor: o golpe usa um serviço ou conta legítimos (${abuso.nome})`
    : `SPF/DKIM/DMARC passaram, mas o domínio ${desarmar(remetente)} foi criado há ${remetenteNovo.idade_dias} dia(s): é o próprio domínio do atacante`;
}
// Imitação (marca, organização, contato da conversa) + domínio criado há menos de 30 dias: perfil típico de phishing.
const imitacao = sinais.find((s) => ['marca', 'marca-link', 'punycode-remetente', 'url-punycode', 'imita-organizacao', 'dominio-sosia-conversa'].includes(s.id));
const novo = sinais.find((s) => s.id === 'dominio-novo');
if (imitacao && novo) sinais.push({ id: 'imitacao-dominio-novo', peso: 15, descricao: 'imita marca/organização/contato E usa domínio criado há menos de 30 dias: combinação típica de phishing' });

const pontuacao = Math.max(0, Math.min(100, sinais.reduce((t, s) => t + s.peso, 0)));
let sugestao;
if (fortes.length || pontuacao >= 60) sugestao = 'phishing';
else if (pontuacao >= 25 || !ev.tem_email) sugestao = 'inconclusivo';
else sugestao = 'legitimo';

const fontes = {
  virustotal: vt === null ? 'não consultado' : vt,
  urlhaus: urlhaus === null ? 'não consultado' : urlhaus,
  rdap: rdap === null ? 'não consultado' : rdap,
};
const dossie = {
  chamado: { id: ev.chamado.id, titulo: ev.chamado.titulo, requerentes: ev.chamado.requerentes },
  relato_do_usuario: ev.relato,
  usuario_interagiu: { clicou: ev.interacao.clicou, digitou_dados: ev.interacao.senha, abriu_anexo: ev.interacao.anexo, respondeu: ev.interacao.respondeu, pagou: ev.interacao.pagou, trechos: ev.interacao.trechos },
  email: { ...ev.email, corpo: curto(ev.email.corpo, 2500) },
  urls: ev.urls.slice(0, 12).map((u) => ({ url: linha(u.url, 300), texto_do_link: u.texto_do_link, sinais: u.sinais })),
  anexos: ev.anexos.map((a) => ({ nome: a.nome, tipo: a.tipo, origem: a.origem, perigosa: a.perigosa, dupla_extensao: a.dupla_extensao, sha256: a.sha256, sha1: a.sha1, ...(a.conteudo ? { arquivos_dentro: a.conteudo } : {}) })),
  tecnicas_detectadas: tecnicas.map((t) => `${t.forte ? '[forte] ' : ''}${t.nome}: ${t.descricao}`),
  telefones_do_golpe: ev.iocs?.telefones ?? [],
  qr_codes: (ev.qr?.lidos ?? []).map((l) => `${l.desenhado ? 'QR desenhado no corpo' : l.arquivo}${l.pagina > 1 ? ` p.${l.pagina}` : ''}: ${l.pix ? 'PIX ' : ''}${l.texto}`),
  ...(ev.qr?.falhou ? { qr_aviso: 'o leitor de QR Code não respondeu: imagens e PDFs não foram lidos' } : {}),
  sinais_automaticos: sinais.map((s) => `${s.peso > 0 ? '+' : ''}${s.peso} ${s.descricao}`),
  reputacao: fontes,
  nota_automatica: pontuacao,
  sugestao_automatica: sugestao,
  evidencia_forte: fortes,
};

return [{ json: {
  dossie: JSON.stringify(dossie, null, 1).slice(0, 14000),
  sinais,
  fortes,
  pontuacao,
  sugestao_automatica: sugestao,
  reputacao: { virustotal: vt ?? [], urlhaus: urlhaus ?? [], rdap: rdap ?? [] },
} }];
