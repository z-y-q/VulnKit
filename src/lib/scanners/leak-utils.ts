/**
 * 泄露检测工具函数
 * 从 vk-leak-utils.js 提取的纯逻辑，无任何依赖
 */

/** Base64URL → 字符串（兼容 Unicode） */
export function b64urlToStr(s: string): string | null {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    const bin = atob(s);
    try {
      return decodeURIComponent(escape(bin));
    } catch {
      return bin;
    }
  } catch {
    return null;
  }
}

/** Luhn 校验（信用卡号） */
export function luhnOk(num: string | number): boolean {
  const d = String(num).replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Shannon 熵（用于检测高熵密钥/token） */
export function shannonEntropy(str: string): number {
  if (!str) return 0;
  const f: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    f[c] = (f[c] || 0) + 1;
  }
  let h = 0;
  const L = str.length;
  for (const k in f) {
    const p = f[k] / L;
    h -= p * Math.log2(p);
  }
  return h;
}

/** 占位符字面量列表 */
export const PLACEHOLDER_LITERALS = [
  'your-api-key', 'your_api_key', 'xxxxxxxx', 'changeme', 'placeholder',
  'example', 'test', 'demo', 'todo', 'replace-me', 'null', 'undefined',
  'password', 'string', '', 'secret', 'apikey', 'token',
  '00000000000000000000', '11111111111111111111',
];

/** 判断是否为占位符/示例值 */
export function isPlaceholder(v: unknown): boolean {
  const s = String(v ?? '').trim().toLowerCase();
  if (PLACEHOLDER_LITERALS.includes(s)) return true;
  if (/^(.)\1+$/.test(s)) return true;           // 全相同字符
  if (/^x+$/i.test(s)) return true;               // 全 x
  if (/^<[^>]+>$/.test(s)) return true;           // <placeholder>
  if (/^(?:abcdef|123456|qwerty)/i.test(s) && s.length < 16) return true;
  return false;
}

/** 判断匹配位置是否处于加密上下文（避免误报加密密钥为泄露） */
export function inCryptoContext(source: string, offset: number, len: number): boolean {
  const w = 300;
  const lo = Math.max(0, offset - w);
  const hi = Math.min(source.length, offset + len + w);
  const ctx = source.slice(lo, hi);
  return /(?:CryptoJS\.(?:AES|DES|TripleDES|RC4)\s*\.\s*(?:encrypt|decrypt)|crypto\.(?:createCipher(?:iv)?|createDecipher(?:iv)?)|crypto\.subtle\.(?:encrypt|decrypt|importKey)|JSEncrypt|forge\.cipher|sm[234]\.(?:encrypt|decrypt|do(?:En|De)crypt))/i.test(ctx);
}
