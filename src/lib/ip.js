// ---- Biblioteca: endereços IP que não são públicos (privados, locais, reservados, documentação) ----
// Usada para ignorar IPs internos nos cabeçalhos Received e nos links (não são indicadores de ataque).

// Converte "a.b.c.d" em número (0 a 2^32-1). Devolve null se não for IPv4 válido.
function ipv4ParaNumero(ip) {
  const partes = String(ip).split('.');
  if (partes.length !== 4) return null;
  let numero = 0;
  for (const parte of partes) {
    if (!/^\d{1,3}$/.test(parte)) return null;
    const valor = Number(parte);
    if (valor > 255) return null;
    numero = numero * 256 + valor;
  }
  return numero;
}

// Faixas IPv4 privadas, locais, reservadas ou de documentação.
const FAIXAS_IPV4_BLOQUEADAS = [
  ['0.0.0.0', 8],       // "esta rede"
  ['10.0.0.0', 8],      // privada
  ['100.64.0.0', 10],   // CGNAT
  ['127.0.0.0', 8],     // loopback
  ['169.254.0.0', 16],  // link-local (inclui metadados de nuvem 169.254.169.254)
  ['172.16.0.0', 12],   // privada (inclui as redes do Docker)
  ['192.0.0.0', 24],    // IETF
  ['192.0.2.0', 24],    // documentação
  ['192.88.99.0', 24],  // 6to4 relay
  ['192.168.0.0', 16],  // privada
  ['198.18.0.0', 15],   // testes de desempenho
  ['198.51.100.0', 24], // documentação
  ['203.0.113.0', 24],  // documentação
  ['224.0.0.0', 4],     // multicast
  ['240.0.0.0', 4],     // reservada e broadcast
];

function ipv4Bloqueado(ip) {
  const numero = ipv4ParaNumero(ip);
  if (numero === null) return true;
  return FAIXAS_IPV4_BLOQUEADAS.some(([base, bits]) => {
    const mascara = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((numero & mascara) >>> 0) === ((ipv4ParaNumero(base) & mascara) >>> 0);
  });
}

// Expande um IPv6 para 8 grupos numéricos. Devolve null se for inválido.
function expandirIPv6(ip) {
  let texto = String(ip).replace(/^\[|\]$/g, '').toLowerCase();
  const zona = texto.indexOf('%');
  if (zona >= 0) texto = texto.slice(0, zona);
  const comIPv4 = texto.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (comIPv4) {
    const numero = ipv4ParaNumero(comIPv4[2]);
    if (numero === null) return null;
    texto = comIPv4[1] + (numero >>> 16).toString(16) + ':' + (numero & 0xffff).toString(16);
  }
  const metades = texto.split('::');
  if (metades.length > 2) return null;
  const esquerda = metades[0] ? metades[0].split(':') : [];
  const direita = metades.length === 2 && metades[1] ? metades[1].split(':') : [];
  const faltam = 8 - esquerda.length - direita.length;
  if (metades.length === 1 && faltam !== 0) return null;
  if (metades.length === 2 && faltam < 1) return null;
  const grupos = [...esquerda, ...Array(metades.length === 2 ? faltam : 0).fill('0'), ...direita];
  if (grupos.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return grupos.map((g) => parseInt(g, 16));
}

function ipv6Bloqueado(ip) {
  const g = expandirIPv6(ip);
  if (!g) return true;
  const ipv4Embutido = () => `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  // IPv4 mapeado (::ffff:a.b.c.d) e NAT64 (64:ff9b::a.b.c.d): vale a regra do IPv4 embutido.
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return ipv4Bloqueado(ipv4Embutido());
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return ipv4Bloqueado(ipv4Embutido());
  // Só aceita endereços globais (2000::/3). Isso já exclui ::1, fc00::/7, fe80::/10 e multicast.
  if ((g[0] & 0xe000) !== 0x2000) return true;
  if (g[0] === 0x2001 && (g[1] === 0x0db8 || g[1] === 0)) return true; // documentação e Teredo
  if (g[0] === 0x2002) return true; // 6to4 (embute um IPv4 qualquer)
  return false;
}

function ehIPv4(texto) {
  return ipv4ParaNumero(texto) !== null;
}

function ipBloqueado(ip) {
  return String(ip).includes(':') ? ipv6Bloqueado(ip) : ipv4Bloqueado(ip);
}
// ---- fim da biblioteca ----
