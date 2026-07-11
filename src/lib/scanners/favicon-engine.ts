/**
 * Favicon hash engine -- 灵眸 v6.0
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
