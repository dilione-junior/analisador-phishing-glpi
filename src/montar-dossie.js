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
  anexos: ev.anexos.map((a) => ({ nome: a.nome, tipo: a.tipo, origem: a.origem, perigosa: a.perigosa, dupla_extensao: a.dupla_extensao, sha256: a.sha256, sha1: a.sha1 })),
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
