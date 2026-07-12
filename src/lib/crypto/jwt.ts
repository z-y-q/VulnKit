/**
 * JWT 解析与漏洞检测 — 灵眸 v6.0
 * 从 vk-jwt.js 提取的纯逻辑（解码 + 算法混淆检测 + 敏感 claim 分析）
 * 签名验证依赖 Web Crypto API（crypto.subtle）
 */

export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  jku?: string;
  x5u?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface JwtFinding {
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail: string;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
  token: string;
  findings: JwtFinding[];
}

/** Base64URL → UTF-8 字符串 */
export function base64UrlDecode(str: string): string {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** Base64URL → Uint8Array（用于签名验证） */
export function base64UrlToUint8(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const raw = atob(padded);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

/** 算法 → Web Crypto 参数映射 */
export const JWT_ALGO_MAP: Record<string, { hash: string; name: string; curve?: string }> = {
  HS256: { hash: 'SHA-256', name: 'HMAC' },
  HS384: { hash: 'SHA-384', name: 'HMAC' },
  HS512: { hash: 'SHA-512', name: 'HMAC' },
  RS256: { hash: 'SHA-256', name: 'RSASSA-PKCS1-v1_5' },
  RS384: { hash: 'SHA-384', name: 'RSASSA-PKCS1-v1_5' },
  RS512: { hash: 'SHA-512', name: 'RSASSA-PKCS1-v1_5' },
  ES256: { hash: 'SHA-256', name: 'ECDSA', curve: 'P-256' },
  ES384: { hash: 'SHA-384', name: 'ECDSA', curve: 'P-384' },
  ES512: { hash: 'SHA-512', name: 'ECDSA', curve: 'P-521' },
  EdDSA: { hash: 'SHA-512', name: 'EdDSA', curve: 'Ed25519' },
  PS256: { hash: 'SHA-256', name: 'RSASSA-PSS' },
  PS384: { hash: 'SHA-384', name: 'RSASSA-PSS' },
  PS512: { hash: 'SHA-512', name: 'RSASSA-PSS' },
};

/** 敏感 claim 列表 */
export const SENSITIVE_CLAIMS = [
  'email', 'password', 'secret', 'token', 'api_key', 'apikey', 'admin', 'role',
  'privilege', 'credit_card', 'ssn', 'phone', 'jwk', 'x5u', 'x5c', 'kid',
  'act', 'cnf', 'nonce', 'aud', 'azp', 'authorization_endpoint',
  'token_endpoint', 'session_id', 'refresh_token',
];

/** 解析 JWT token（不验证签名） */
export function decode(token: string): DecodedJwt | null {
  const parts = token.trim().split('.');
  if (parts.length < 2) return null;

  try {
    const header = JSON.parse(base64UrlDecode(parts[0])) as JwtHeader;
    const payload = JSON.parse(base64UrlDecode(parts[1])) as JwtPayload;
    const signature = parts[2] || '';

    const findings: JwtFinding[] = [
      ...detectAlgorithmConfusion(header, payload),
      ...analyzeClaims(header, payload),
    ];

    return { header, payload, signature, token, findings };
  } catch {
    return null;
  }
}

/** 检测算法混淆与配置漏洞 */
export function detectAlgorithmConfusion(header: JwtHeader, payload: JwtPayload): JwtFinding[] {
  const findings: JwtFinding[] = [];
  const alg = (header.alg || '').toLowerCase();

  // alg: none 无签名攻击
  if (alg === 'none' || alg === 'non' || alg === 'nil') {
    findings.push({
      severity: 'critical',
      title: 'alg: none 无签名攻击',
      detail: 'JWT 使用 "none" 算法，意味着无签名验证。攻击者可伪造任意 payload。',
    });
  }

  // jku 外部密钥 URL
  if (header.jku) {
    findings.push({
      severity: 'high',
      title: 'jku 外部密钥 URL',
      detail: `Header 包含 "jku" (JWK Set URL)，可能指向攻击者控制的密钥服务器。URL: ${header.jku}`,
    });
  }

  // x5u 外部证书 URL
  if (header.x5u) {
    findings.push({
      severity: 'high',
      title: 'x5u 外部证书 URL',
      detail: `Header 包含 "x5u" (X.509 URL)，可能指向攻击者控制的证书。URL: ${header.x5u}`,
    });
  }

  // kid SQL 注入风险
  if (header.kid && typeof header.kid === 'string' && /['";\\]/.test(header.kid)) {
    findings.push({
      severity: 'high',
      title: 'kid SQL 注入风险',
      detail: `Header "kid" 参数包含可疑字符，可能存在 SQL 注入漏洞。kid: ${header.kid}`,
    });
  }

  // kid 路径遍历风险
  if (header.kid && typeof header.kid === 'string' && /^(path|file|\/|\.\.)/i.test(header.kid)) {
    findings.push({
      severity: 'high',
      title: 'kid 路径遍历风险',
      detail: `Header "kid" 参数疑似文件路径，可能存在路径遍历漏洞。kid: ${header.kid}`,
    });
  }

  // 缺少 alg
  if (!header.alg) {
    findings.push({
      severity: 'medium',
      title: '缺少 alg 声明',
      detail: 'JWT Header 未声明签名算法，可能导致验证时使用不安全的默认算法。',
    });
  }

  const now = Math.floor(Date.now() / 1000);

  // Token 已过期
  if (payload.exp && payload.exp < now) {
    findings.push({
      severity: 'medium',
      title: 'Token 已过期',
      detail: `exp=${payload.exp} (${new Date(payload.exp * 1000).toLocaleString('zh-CN')})，当前时间戳=${now}`,
    });
  }

  // Token 尚未生效
  if (payload.nbf && payload.nbf > now) {
    findings.push({
      severity: 'medium',
      title: 'Token 尚未生效',
      detail: `nbf=${payload.nbf}，当前时间戳=${now}`,
    });
  }

  // 有效期过长
  if (payload.exp && payload.nbf && payload.exp - payload.nbf > 86400 * 365) {
    findings.push({
      severity: 'low',
      title: 'Token 有效期过长',
      detail: `有效期超过 1 年（${Math.round((payload.exp - payload.nbf) / 86400)} 天），建议缩短有效期。`,
    });
  }

  // 缺少时间控制
  if (!payload.exp && !payload.iat) {
    findings.push({
      severity: 'low',
      title: '缺少时间控制',
      detail: 'Token 没有 exp 和 iat 声明，无法判断有效性和过期时间。',
    });
  }

  return findings;
}

/** 分析 payload 中的敏感 claim */
export function analyzeClaims(_header: JwtHeader, payload: JwtPayload): JwtFinding[] {
  const findings: JwtFinding[] = [];
  const keys = Object.keys(payload || {});

  for (const originalKey of keys) {
    const key = originalKey.toLowerCase();
    if (SENSITIVE_CLAIMS.includes(key)) {
      const val = payload[originalKey];
      const displayVal =
        typeof val === 'string'
          ? val.substring(0, 20) + (val.length > 20 ? '...' : '')
          : JSON.stringify(val);
      findings.push({
        severity:
          key === 'password' || key === 'secret' || key === 'credit_card' || key === 'ssn'
            ? 'high'
            : 'medium',
        title: `敏感 Claim: ${originalKey}`,
        detail: `Payload 包含敏感字段 "${originalKey}"，值: ${displayVal}`,
      });
    }
  }

  // 过多私有 claim
  const registered = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];
  const privateClaims = keys.filter(k => !registered.includes(k));
  if (privateClaims.length > 15) {
    findings.push({
      severity: 'low',
      title: '过多私有 Claim',
      detail: `Payload 包含 ${privateClaims.length} 个非标准 Claim，可能包含冗余敏感数据。`,
    });
  }

  return findings;
}

/** PEM → ArrayBuffer */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN[^-]+-----/, '')
    .replace(/-----END[^-]+-----/, '')
    .replace(/\s/g, '');
  const raw = atob(b64);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}

// ====== 签名验证（Web Crypto） ======

export interface JwtVerifyResult {
  valid: boolean;
  alg: string;
  error?: string;
}

/** JWT ECDSA 签名：原始 r||s（P1363）→ DER SEQUENCE{ INTEGER r, INTEGER s } */
function ecRawSignatureToDer(sig: Uint8Array, partLen: number): Uint8Array {
  const encodeInt = (half: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < half.length - 1 && half[i] === 0) i++; // 去前导 0
    const trimmed = half.subarray(i);
    // 高位为 1 时补 0x00 防止被当作负数
    if (trimmed[0] & 0x80) {
      const padded = new Uint8Array(trimmed.length + 1);
      padded.set(trimmed, 1);
      return padded;
    }
    return trimmed;
  };
  const r = encodeInt(sig.subarray(0, partLen));
  const s = encodeInt(sig.subarray(partLen, partLen * 2));
  // DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
  const totalLen = 2 + r.length + 2 + s.length;
  const out = new Uint8Array(2 + totalLen);
  out[0] = 0x30;
  out[1] = totalLen;
  let o = 2;
  out[o++] = 0x02;
  out[o++] = r.length;
  out.set(r, o); o += r.length;
  out[o++] = 0x02;
  out[o++] = s.length;
  out.set(s, o);
  return out;
}

/** 各 ECDSA 曲线对应的分量字节长度 */
const EC_PART_LEN: Record<string, number> = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

/**
 * 验证 JWT 签名。
 * @param token 完整 JWT
 * @param key   HMAC 为原始密钥字符串；RSA/EC 为 PEM 公钥（SPKI）
 */
export async function verifySignature(token: string, key: string): Promise<JwtVerifyResult> {
  const parts = token.trim().split('.');
  if (parts.length < 3) return { valid: false, alg: '?', error: 'Token 不完整（缺签名段）' };

  const header = JSON.parse(base64UrlDecode(parts[0])) as JwtHeader;
  const alg = (header.alg || '').toUpperCase();
  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlToUint8(parts[2]);
  const params = JWT_ALGO_MAP[alg];

  if (alg === 'NONE' || alg === 'NON' || alg === 'NIL') {
    return { valid: true, alg, error: 'alg=none 无签名，服务端若接受则可伪造' };
  }
  if (!params) return { valid: false, alg, error: `不支持的算法: ${alg || '(空)'}` };
  if (!key) return { valid: false, alg, error: '请提供验证密钥' };

  try {
    if (params.name === 'HMAC') {
      const cryptoKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(key), { name: 'HMAC', hash: params.hash }, false, ['verify'],
      );
      const valid = await crypto.subtle.verify('HMAC', cryptoKey, signature as unknown as ArrayBuffer, data as unknown as ArrayBuffer);
      return { valid, alg };
    }

    if (params.name === 'RSASSA-PKCS1-v1_5' || params.name === 'RSASSA-PSS') {
      const cryptoKey = await crypto.subtle.importKey(
        'spki', pemToArrayBuffer(key),
        params.name === 'RSASSA-PSS'
          ? { name: 'RSASSA-PSS', hash: params.hash }
          : { name: 'RSASSA-PKCS1-v1_5', hash: params.hash },
        false, ['verify'],
      );
      const valid = params.name === 'RSASSA-PSS'
        ? await crypto.subtle.verify({ name: 'RSASSA-PSS' }, cryptoKey, signature as unknown as ArrayBuffer, data as unknown as ArrayBuffer)
        : await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature as unknown as ArrayBuffer, data as unknown as ArrayBuffer);
      return { valid, alg };
    }

    if (params.name === 'ECDSA') {
      const partLen = EC_PART_LEN[params.curve || ''];
      if (!partLen) return { valid: false, alg, error: `不支持的曲线: ${params.curve}` };
      const derSig = ecRawSignatureToDer(signature, partLen);
      const cryptoKey = await crypto.subtle.importKey(
        'spki', pemToArrayBuffer(key),
        { name: 'ECDSA', namedCurve: params.curve },
        false, ['verify'],
      );
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: params.hash }, cryptoKey, derSig as unknown as ArrayBuffer, data as unknown as ArrayBuffer,
      );
      return { valid, alg };
    }

    return { valid: false, alg, error: `暂不支持 ${alg}（Web Crypto 不支持 EdDSA/ES256K）` };
  } catch (e: any) {
    return { valid: false, alg, error: '验证失败: ' + (e.message || String(e)) };
  }
}

/**
 * 构造 alg=none 攻击 PoC：移除签名，便于测试服务端是否接受无签名 token。
 * 返回的 token 仅用于授权测试，不可用于未授权目标。
 */
export function forgeNoneToken(token: string): string {
  const parts = token.trim().split('.');
  if (parts.length < 2) return token;
  const header = JSON.parse(base64UrlDecode(parts[0])) as JwtHeader;
  header.alg = 'none';
  const enc = (obj: unknown) => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${enc(header)}.${parts[1]}.`;
}

