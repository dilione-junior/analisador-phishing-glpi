// Nó "Prepara os IOCs dos feeds" (rotina 3, a cada 6 horas): transforma o que veio do OpenPhish e do ThreatFox
// em chaves do Redis (uma por IOC), cada uma com validade de `feedDias`. Um IOC que continua no feed tem a
// validade renovada a cada carga; o que sumiu do feed vence sozinho. Nada vai para o Wazuh: o feed só vira
// evidência na análise, e o bloqueio continua dependendo do clique do analista.
//
// Saída: um item por chave { chave, valor, ttl } e, por último, o estado das fontes (feed:estado).
// Se uma fonte falhar, as chaves dela da carga anterior continuam valendo até vencer, e o estado registra o erro.
const cfg = $('Configuração').first().json;
const dias = Math.max(1, Number(cfg.feedDias) || 7);
const ttl = dias * 86400;
const confiaveis = String(cfg.dominiosConfiaveis ?? '').toLowerCase().split(/[\s,;]+/).filter(Boolean);
const agora = new Date().toISOString();
const MAXIMO_POR_FONTE = 20000;
const CONFIANCA_MINIMA = 50; // ThreatFox: abaixo disso o próprio relator não tem certeza

let anterior = {};
try { anterior = JSON.parse($('Lê o estado dos feeds').first().json.estado || '{}') || {}; } catch (erro) { anterior = {}; }
const fontesAntes = anterior.fontes ?? {};

const mapa = new Map();
const poe = (chave, info) => {
  if (!chave || chave.length > FEED_TAMANHO_CHAVE + 20) return;
  const ja = mapa.get(chave);
  if (!ja) { mapa.set(chave, { ...info, fontes: [info.fonte] }); return; }
  if (!ja.fontes.includes(info.fonte)) ja.fontes.push(info.fonte);
  ja.confianca = Math.max(ja.confianca ?? 0, info.confianca ?? 0);
  ja.comprometido = Boolean(ja.comprometido && info.comprometido); // basta uma fonte dizer que é do atacante
  if (ja.origem !== 'ioc' && info.origem === 'ioc') { ja.origem = 'ioc'; ja.ameaca = info.ameaca; ja.malware = info.malware; }
};

// URL do feed: a própria URL e, quando o host é do atacante, o host inteiro (outras páginas do mesmo kit).
function porUrl(url, base) {
  const n = normalizarUrlFeed(url);
  if (!n) return false;
  poe(`feed:url:${n}`, { ...base, tipo: 'url', origem: 'ioc' });
  const { host } = partesDaUrl(url);
  const caminho = n.slice(n.indexOf('/') >= 0 ? n.indexOf('/') : n.length);
  const invadido = Boolean(base.comprometido) || FEED_CAMINHO_INVADIDO.test(caminho + '/');
  if (ehIPv4(host)) {
    if (!ipBloqueado(host)) poe(`feed:ip:${host}`, { ...base, tipo: 'ip', origem: 'url', exemplo: url.slice(0, 300) });
  } else if (hostDoAtacanteFeed(host, confiaveis)) {
    poe(`feed:host:${host}`, { ...base, tipo: 'host', origem: 'url', comprometido: invadido, exemplo: url.slice(0, 300) });
  }
  return true;
}

const textoDe = (r) => (typeof r?.body === 'string' ? r.body : typeof r?.data === 'string' ? r.data : '');
const pega = (nome) => { try { return $(nome).first().json; } catch (erro) { return null; } };
const fontes = {};
const registra = (nome, ok, itens, erro) => {
  fontes[nome] = {
    ok, itens, erro: ok ? '' : linha(erro, 160),
    ultimo_ok: ok ? agora : (fontesAntes[nome]?.ultimo_ok ?? null),
    tentativa: agora,
  };
};

// ---------------- OpenPhish (feed comunitário: só URLs de phishing, atualizado a cada 12 h) ----------------
const op = pega('Baixa o OpenPhish');
if (!op || Number(op.statusCode) !== 200) {
  registra('openphish', false, 0, `HTTP ${op?.statusCode ?? 'sem resposta'}${op?.error ? ' ' + JSON.stringify(op.error).slice(0, 80) : ''}`);
} else {
  const linhas = textoDe(op).split(/\r?\n/).map((l) => l.trim()).filter((l) => /^https?:\/\/\S+$/i.test(l)).slice(0, MAXIMO_POR_FONTE);
  let n = 0;
  for (const url of linhas) if (porUrl(url, { fonte: 'openphish', ameaca: 'phishing', malware: '', confianca: 100, visto_em: agora.slice(0, 10) })) n++;
  if (!n) registra('openphish', false, 0, 'feed veio vazio ou em formato inesperado');
  else registra('openphish', true, n);
}

// ---------------- ThreatFox (abuse.ch: IOCs do último dia; URLs, domínios, IP:porta e hashes) ----------------
const tf = pega('Baixa o ThreatFox');
const corpo = tf?.body && typeof tf.body === 'object' ? tf.body : null;
if (!tf || Number(tf.statusCode) !== 200 || !corpo) {
  registra('threatfox', false, 0, `HTTP ${tf?.statusCode ?? 'sem resposta'}${typeof tf?.body === 'string' ? ' ' + tf.body.slice(0, 80) : ''}`);
} else if (corpo.query_status === 'no_result') {
  registra('threatfox', true, 0);
} else if (corpo.query_status !== 'ok' || !Array.isArray(corpo.data)) {
  registra('threatfox', false, 0, `query_status=${corpo.query_status ?? '?'}`);
} else {
  let n = 0;
  for (const i of corpo.data.slice(0, MAXIMO_POR_FONTE)) {
    if (Number(i.confidence_level) < CONFIANCA_MINIMA) continue;
    const ioc = String(i.ioc ?? '').trim();
    const base = {
      fonte: 'threatfox', ameaca: linha(i.threat_type, 40), malware: linha(i.malware_printable, 60),
      confianca: Number(i.confidence_level) || 0, visto_em: String(i.first_seen ?? '').slice(0, 10), comprometido: i.is_compromised === true,
    };
    const tipo = String(i.ioc_type ?? '');
    if (tipo === 'url') { if (porUrl(ioc, base)) n++; }
    else if (tipo === 'domain') {
      const h = ioc.toLowerCase().replace(/\.$/, '');
      if (hostDoAtacanteFeed(h, confiaveis)) { poe(`feed:host:${h}`, { ...base, tipo: 'host', origem: 'ioc' }); n++; }
    } else if (tipo === 'ip:port') {
      const ip = ioc.replace(/:\d+$/, '');
      if (ehIPv4(ip) && !ipBloqueado(ip)) { poe(`feed:ip:${ip}`, { ...base, tipo: 'ip', origem: 'ioc' }); n++; }
    } else if (tipo === 'sha256_hash' && /^[a-f0-9]{64}$/i.test(ioc)) { poe(`feed:sha256:${ioc.toLowerCase()}`, { ...base, tipo: 'sha256', origem: 'ioc' }); n++; }
    else if (tipo === 'md5_hash' && /^[a-f0-9]{32}$/i.test(ioc)) { poe(`feed:md5:${ioc.toLowerCase()}`, { ...base, tipo: 'md5', origem: 'ioc' }); n++; }
  }
  registra('threatfox', true, n);
}

const itens = [...mapa.entries()].map(([chave, info]) => {
  const { fonte, ...resto } = info;
  return { json: { chave, valor: JSON.stringify(resto), ttl } };
});
const estado = { atualizado_em: agora, dias, chaves: itens.length, fontes };
itens.push({ json: { chave: FEED_ESTADO, valor: JSON.stringify(estado), ttl: 30 * 86400, estado: true } });
return itens;
