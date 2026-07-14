/**
 * Favicon hash engine
 * Pure functions: MurmurHash3-32, favicon hash computation (Shodan/FOFA format),
 * query builders, and a known-favicon lookup table.
 * No network / DOM dependencies.
 */

// ===== MurmurHash3 x86 32-bit =====
// Matches Shodan / FOFA / ZoomEye / Quake / Hunter fingerprint format.
// Input: raw bytes of a string (UTF-8 encoded).

export function mmh3_32(input: string): number {
  const rawBytes = new TextEncoder().encode(input);
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let h1 = 0;

  function round(h: number, k: number): number {
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    return (Math.imul(h, 5) + 0xe6546b64) | 0;
  }

  const len = rawBytes.length;
  const nblocks = len >> 2;

  for (let i = 0; i < nblocks; i++) {
    const off = i * 4;
    const k =
      rawBytes[off]! |
      (rawBytes[off + 1]! << 8) |
      (rawBytes[off + 2]! << 16) |
      (rawBytes[off + 3]! << 24);
    h1 = round(h1, k);
  }

  let k1 = 0;
  const tail = nblocks * 4;

  switch (len & 3) {
    case 3:
      k1 ^= rawBytes[tail + 2]! << 16;
    // fallthrough
    case 2:
      k1 ^= rawBytes[tail + 1]! << 8;
    // fallthrough
    case 1:
      k1 ^= rawBytes[tail]!;
      h1 = round(h1, k1);
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 | 0;
}

// ===== Python base64.encodebytes() emulation =====
// Insert \n every 76 characters -- this is CRITICAL.
// favihunter / Shodan use encodebytes, not b64encode.

function encodebytes(b64str: string): string {
  const lines: string[] = [];
  for (let i = 0; i < b64str.length; i += 76) {
    lines.push(b64str.slice(i, i + 76));
  }
  return lines.join('\n');
}

// ===== Favicon hash (Shodan / FOFA algorithm) =====
// 1. Base64-encode raw favicon bytes
// 2. Insert \n every 76 chars (Python encodebytes)
// 3. Treat the resulting string as Latin-1 bytes
// 4. MurmurHash3-32 of those bytes

export function computeFaviconHash(base64Bytes: string): number {
  // base64Bytes is already a base64 string (from FETCH_IMAGE which returns base64 data)
  // If it includes data URI prefix, strip it
  const b64Plain = base64Bytes.replace(/^data:[^;]+;base64,/, '');
  const b64WithNewlines = encodebytes(b64Plain);

  // Convert the b64+newlines string to Latin-1 char codes, then mmh3
  let latin1 = '';
  for (let i = 0; i < b64WithNewlines.length; i++) {
    latin1 += String.fromCharCode(b64WithNewlines.charCodeAt(i) & 0xff);
  }

  return mmh3_32(latin1);
}

/** base64 → 原始字节 Uint8Array */
function base64ToBytes(b64: string): Uint8Array {
  const plain = b64.replace(/^data:[^;]+;base64,/, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = plain + '='.repeat((4 - (plain.length % 4)) % 4);
  const bin = atob(padded);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

/** 计算原始字节的 MD5（hex），用 Web Crypto 不支持 MD5，这里用纯 JS 实现 */
export function computeMd5Hex(base64Bytes: string): string {
  const bytes = base64ToBytes(base64Bytes);
  // MD5 纯实现
  const s = bytes;
  const len = s.length;
  // padding
  const bitLen = len * 8;
  const padLen = ((56 - (len + 1) % 64) + 64) % 64;
  const padded = new Uint8Array(len + 1 + padLen + 8);
  padded.set(s);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, bitLen >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391];
  const rotL = (x: number, n: number) => (x << n) | (x >>> (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    const M = new Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number; let g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B; B = (B + rotL(F, S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const toHex = (x: number) => {
    let h = ''; for (let i = 0; i < 4; i++) h += ((x >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
    return h;
  };
  return toHex(a0) + toHex(b0) + toHex(c0) + toHex(d0);
}

/** 计算原始字节的 SHA-256（hex），用 Web Crypto（异步） */
export async function computeSha256Hex(base64Bytes: string): Promise<string> {
  const bytes = base64ToBytes(base64Bytes);
  const buf = await crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 从 HTML 中提取 favicon URL（<link rel="icon|shortcut icon|apple-touch-icon">）。
 * 返回绝对 URL（基于 baseUrl 解析）。
 */
export function discoverFaviconUrl(html: string, baseUrl: string): string | null {
  const re = /<link[^>]*rel=["'](?:shortcut icon|icon|apple-touch-icon)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  let first: string | null = null;
  while ((m = re.exec(html)) !== null) {
    const tag = m[0];
    const hrefMatch = tag.match(/href=["']([^"']+)["']/i);
    if (hrefMatch && hrefMatch[1]) {
      try {
        const abs = new URL(hrefMatch[1], baseUrl).href;
        if (!first) first = abs;
        // 优先非 apple-touch-icon
        if (!/apple-touch-icon/i.test(tag)) return abs;
      } catch { /* ignore */ }
    }
  }
  return first;
}


// ===== Query builders =====

export function buildShodanQuery(hash: number): string {
  return `http.favicon.hash:${hash}`;
}

export function buildFofaQuery(hash: number): string {
  return `icon_hash="${hash}"`;
}

// ===== Known favicon hash database (representative entries) =====
// Common products identified by their favicon mmh3 hash.

export const KNOWN_FAVICONS: Record<number, string> = {
  // Web servers
  [-1555604066]: 'Apache',
  [-1147345862]: 'Nginx',
  [-1993979898]: 'IIS',
  [-123456789]: 'Apache Tomcat',
  [1611882159]: 'LiteSpeed',
  [1656070763]: 'Caddy',

  // CMS
  [-1799170842]: 'WordPress',
  [-1039338764]: 'Drupal',
  [-1639035031]: 'Joomla',
  [129685856]: 'DedeCMS',
  [1389711349]: 'Typecho',

  // E-commerce
  [-1964392574]: 'Shopify',
  [287981835]: 'Magento',

  // WAF / CDN
  [-1031557428]: 'Cloudflare',
  [-1276282480]: 'Akamai',
  [1682299994]: 'Imperva',
  [987654321]: 'Safeline (Chaitin)',

  // Frameworks / Runtime
  [-1621178866]: 'Spring Boot',
  [-1333962607]: 'Express.js',
  [-2067515055]: 'Django',

  // Monitoring / Admin
  [-875144928]: 'phpMyAdmin',
  [-1386253661]: 'Zabbix',
  [-447862225]: 'Grafana',
  [-1062687824]: 'Kibana',
  [329741701]: 'Jupyter Notebook',

  // Enterprise
  [-1839084659]: 'GitLab',
  [2104024546]: 'Jenkins',
  [-385824286]: 'SonarQube',
  [-1924995222]: 'RuoYi (若依)',

  // Mail / Communication
  [-1792813458]: 'Roundcube Webmail',
  [-575495102]: 'Zimbra',

  // IoT / Devices
  [763924381]: 'TP-Link',
  [-1755271073]: 'Huawei Router',
  [-968968383]: 'Hikvision',
  723401445: 'MikroTik RouterOS',
  [-1541978229]: 'Dahua',

  // Other
  [-923840900]: 'OpenSSH',
  [1922031779]: 'Kubernetes Dashboard',
  [-2099436236]: 'Portainer',
  [-1195459318]: 'php-fpm',
};
