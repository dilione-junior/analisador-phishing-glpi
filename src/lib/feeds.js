// ---- Biblioteca: feeds de IOC (OpenPhish, ThreatFox) guardados no Redis ----
// Usada por "Prepara os IOCs dos feeds" (grava) e "Extrai as evidências" (monta as chaves a procurar).
// As DUAS pontas usam as mesmas funções: uma URL só "bate" se for normalizada do mesmo jeito.
// Precisa de indicadores.js e ip.js antes (partesDaUrl, dominioRegistravel, noDominio, listas, ehIPv4).

// Chaves no Redis (o prefixo "phishing:" vem da Configuração):
//   feed:url:<host/caminho?consulta>   URL exata (sem esquema, porta e #fragmento)
//   feed:host:<host>                   host inteiro do atacante (domínio do ThreatFox ou host de URL do OpenPhish)
//   feed:ip:<ip>                       IP (ThreatFox ip:port; a porta é descartada)
//   feed:sha256:<hash> / feed:md5:<hash>
//   feed:estado                        quando cada fonte foi carregada e quantos itens trouxe
const FEED_ESTADO = 'feed:estado';
const FEED_TAMANHO_CHAVE = 400;

// Caminhos típicos de site INVADIDO (o dono é legítimo; o atacante só pendurou a página): o host não é do atacante.
const FEED_CAMINHO_INVADIDO = /\/(wp-content|wp-includes|wp-admin|wp-json|~[^/]+|cgi-bin|\.well-known|administrator|components|modules|sites\/default|vendor)\//i;

function normalizarUrlFeed(url) {
  const texto = String(url ?? '').trim();
  const m = texto.match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^#]*)/i);
  if (!m) return '';
  const { host } = partesDaUrl(texto);
  if (!host) return '';
  let resto = m[1] || '/';
  const q = resto.indexOf('?');
  let caminho = q >= 0 ? resto.slice(0, q) : resto;
  const consulta = q >= 0 ? resto.slice(q + 1) : '';
  if (!caminho.startsWith('/')) caminho = '/' + caminho;
  if (!consulta) caminho = caminho.replace(/\/+$/, '');
  return (host + caminho + (consulta ? '?' + consulta : '')).slice(0, FEED_TAMANHO_CHAVE);
}

// O host pode ser marcado INTEIRO? Só se for do atacante: nunca marca, webmail, encurtador, serviço compartilhado
// (HOSPEDAGEM_ABUSADA de indicadores.js, a mesma lista que protege o bloqueio do Wazuh) nem a própria organização.
// Subdomínio de cliente (golpe.pages.dev) pode; o domínio do serviço (pages.dev), não.
function hostDoAtacanteFeed(host, confiaveis = []) {
  const h = String(host ?? '').toLowerCase().replace(/\.$/, '');
  if (!h || !h.includes('.') || h === 'localhost' || h.endsWith('.local') || ehIPv4(h)) return false;
  if (noDominio(h, confiaveis)) return false;
  if (WEBMAIL_GRATUITO.has(h) || WEBMAIL_GRATUITO.has(dominioRegistravel(h))) return false;
  if (ENCURTADORES.has(h) || ENCURTADORES.has(dominioRegistravel(h))) return false;
  if (MARCAS.some((m) => noDominio(h, m.oficiais))) return false;
  if (noDominio(h, HOSPEDAGEM_ABUSADA) && !subdominioDeCliente(h)) return false;
  return true;
}

// Host e os "pais" até o domínio registrável: login.golpe.example -> [login.golpe.example, golpe.example].
// Assim um domínio listado no ThreatFox pega qualquer subdomínio dele no e-mail.
function hostsParaConsulta(host) {
  const h = String(host ?? '').toLowerCase().replace(/\.$/, '');
  if (!h || ehIPv4(h)) return [];
  const base = dominioRegistravel(h);
  const saida = [h];
  let atual = h;
  while (atual !== base && atual.includes('.')) {
    atual = atual.slice(atual.indexOf('.') + 1);
    saida.push(atual);
  }
  return saida;
}

// Chaves a procurar para um chamado. Cada item: { chave, tipo, valor, onde }.
function chavesDosFeeds({ urls = [], hosts = [], ips = [], hashes = [], confiaveis = [] }, maximo = 60) {
  const lista = [{ chave: FEED_ESTADO, tipo: 'estado', valor: '', onde: '' }];
  const vistos = new Set([FEED_ESTADO]);
  const poe = (chave, tipo, valor, onde) => {
    if (!chave || vistos.has(chave) || lista.length >= maximo) return;
    vistos.add(chave);
    lista.push({ chave, tipo, valor, onde });
  };
  for (const h of hashes) {
    const v = String(h ?? '').toLowerCase();
    if (/^[a-f0-9]{64}$/.test(v)) poe(`feed:sha256:${v}`, 'sha256', v, 'anexo');
    else if (/^[a-f0-9]{32}$/.test(v)) poe(`feed:md5:${v}`, 'md5', v, 'anexo');
  }
  for (const u of urls) {
    const url = typeof u === 'string' ? u : u.url;
    const n = normalizarUrlFeed(url);
    if (n && !noDominio(partesDaUrl(url).host, confiaveis)) poe(`feed:url:${n}`, 'url', url, 'link');
  }
  const consultaHost = (host, onde) => {
    const h = String(host ?? '').toLowerCase();
    if (!h || noDominio(h, confiaveis)) return;
    if (ehIPv4(h)) { if (!ipBloqueado(h)) poe(`feed:ip:${h}`, 'ip', h, onde); return; }
    for (const x of hostsParaConsulta(h)) poe(`feed:host:${x}`, 'host', x, onde);
  };
  for (const u of urls) consultaHost(partesDaUrl(typeof u === 'string' ? u : u.url).host, 'link');
  for (const { host, onde } of hosts) consultaHost(host, onde);
  for (const ip of ips) consultaHost(ip, 'origem');
  return lista;
}
// ---- fim da biblioteca ----
