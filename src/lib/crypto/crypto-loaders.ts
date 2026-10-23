/**
 * 加密算法动态导入封装 — 构建优化 P0
 *
 * 将 crypto-js、sm-crypto、bcryptjs 按需加载，减少主 bundle 体积 ~100KB
 * EncodingPanel 点击对应算法按钮时才加载相应库
 *
 * 注意：此文件内联了 crypto-engine.ts 的逻辑，避免静态依赖导致 code splitting 失效
 */

// ====== 类型定义 ======

export type AesMode = 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR';
export type AesPadding = 'Pkcs7' | 'ZeroPadding' | 'NoPadding' | 'Iso97971';

export interface AesOptions {
  mode: AesMode;
  keySize: 128 | 192 | 256;
  padding: AesPadding;
  key: string;
  iv?: string;
}

export interface DesOptions {
  mode: 'CBC' | 'ECB';
  padding: AesPadding;
  key: string;
  iv?: string;
  triple?: boolean;
}

export interface Sm2Options {
  publicKey?: string;
  privateKey?: string;
  cipherMode?: 0 | 1;
}

export interface Sm4Options {
  key: string;
  mode?: 'ecb' | 'cbc';
  iv?: string;
  padding?: boolean;
}

export type HashAlgo = 'md5' | 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512';

export interface HashOptions {
  algo: HashAlgo;
  output?: 'hex' | 'base64';
  hmac?: boolean;
  hmacKey?: string;
}

export interface BcryptOptions {
  cost?: number;
}

export interface RsaKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

// ====== 通用工具 ======

function padOrTruncate(key: string, len: number): string {
  if (!key) return '';
  if (key.length === len) return key;
  if (key.length > len) return key.slice(0, len);
  return key + '\0'.repeat(len - key.length);
}

function toHex(str: string): string {
  return Array.from(str).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function ab2pem(buffer: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  const b64 = btoa(binary);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----BEGIN [A-Z ]+-----/, '').replace(/-----END [A-Z ]+-----/, '').replace(/\s/g, '');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

// ====== 动态加载库缓存 ======

let cryptoJsCache: typeof import('crypto-js') | null = null;
let smCryptoCache: typeof import('sm-crypto') | null = null;
let bcryptCache: typeof import('bcryptjs') | null = null;

async function loadCryptoJS() {
  if (!cryptoJsCache) {
    const module = await import('crypto-js');
    cryptoJsCache = module.default;
  }
  return cryptoJsCache;
}

async function loadSmCrypto() {
  if (!smCryptoCache) {
    smCryptoCache = await import('sm-crypto');
  }
  return smCryptoCache;
}

async function loadBcrypt() {
  if (!bcryptCache) {
    const module = await import('bcryptjs');
    bcryptCache = module.default;
  }
  return bcryptCache;
}

// ====== AES 加密/解密 ======

export async function aesEncrypt(input: string, options: AesOptions): Promise<string> {
  const CryptoJS = await loadCryptoJS();
  const mode = (CryptoJS.mode as any)[options.mode];
  const padding = (CryptoJS.pad as any)[options.padding];
  if (!mode || !padding) throw new Error(`不支持的 AES 模式/填充: ${options.mode}/${options.padding}`);

  const opts: any = { mode, padding };
  if (options.mode !== 'ECB') {
    opts.iv = CryptoJS.enc.Utf8.parse(padOrTruncate(options.iv || '', 16));
  }
  const keyWA = CryptoJS.enc.Utf8.parse(padOrTruncate(options.key, options.keySize / 8));
  return CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(input), keyWA, opts).toString();
}

export async function aesDecrypt(input: string, options: AesOptions): Promise<string> {
  const CryptoJS = await loadCryptoJS();
  const mode = (CryptoJS.mode as any)[options.mode];
  const padding = (CryptoJS.pad as any)[options.padding];
  if (!mode || !padding) throw new Error(`不支持的 AES 模式/填充: ${options.mode}/${options.padding}`);

  const opts: any = { mode, padding };
  if (options.mode !== 'ECB') {
    opts.iv = CryptoJS.enc.Utf8.parse(padOrTruncate(options.iv || '', 16));
  }
  const keyWA = CryptoJS.enc.Utf8.parse(padOrTruncate(options.key, options.keySize / 8));
  return CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(input, keyWA, opts));
}

// ====== DES/3DES 加密/解密 ======

export async function desEncrypt(input: string, options: DesOptions): Promise<string> {
  const CryptoJS = await loadCryptoJS();
  const mode = (CryptoJS.mode as any)[options.mode];
  const padding = (CryptoJS.pad as any)[options.padding];
  const opts: any = { mode, padding };
  if (options.mode !== 'ECB') {
    opts.iv = CryptoJS.enc.Utf8.parse(padOrTruncate(options.iv || '', 8));
  }
  const keyWA = CryptoJS.enc.Utf8.parse(padOrTruncate(options.key, 8));
  const fn = options.triple ? CryptoJS.TripleDES : CryptoJS.DES;
  return fn.encrypt(CryptoJS.enc.Utf8.parse(input), keyWA, opts).toString();
}

export async function desDecrypt(input: string, options: DesOptions): Promise<string> {
  const CryptoJS = await loadCryptoJS();
  const mode = (CryptoJS.mode as any)[options.mode];
  const padding = (CryptoJS.pad as any)[options.padding];
  const opts: any = { mode, padding };
  if (options.mode !== 'ECB') {
    opts.iv = CryptoJS.enc.Utf8.parse(padOrTruncate(options.iv || '', 8));
  }
  const keyWA = CryptoJS.enc.Utf8.parse(padOrTruncate(options.key, 8));
  const fn = options.triple ? CryptoJS.TripleDES : CryptoJS.DES;
  return CryptoJS.enc.Utf8.stringify(fn.decrypt(input, keyWA, opts));
}

// ====== RC4 加密/解密 ======

export async function rc4Encrypt(input: string, key: string): Promise<string> {
  if (!key) throw new Error('请输入 RC4 密钥');
  const CryptoJS = await loadCryptoJS();
  return CryptoJS.RC4.encrypt(CryptoJS.enc.Utf8.parse(input), key).toString();
}

export async function rc4Decrypt(input: string, key: string): Promise<string> {
  if (!key) throw new Error('请输入 RC4 密钥');
  const CryptoJS = await loadCryptoJS();
  return CryptoJS.enc.Utf8.stringify(CryptoJS.RC4.decrypt(input, key));
}

// ====== 国密 SM2 加密/解密 ======

function normalizePubKey(pubKey: string): string {
  let k = pubKey.trim();
  if (k.length === 128) k = '04' + k;
  if (k.length !== 130 || !k.startsWith('04')) {
    throw new Error('公钥格式错误（需 128/130 位十六进制，04 开头）');
  }
  return k;
}

export async function sm2Encrypt(input: string, options: Sm2Options): Promise<string> {
  if (!options.publicKey) throw new Error('请输入 SM2 公钥');
  const { sm2 } = await loadSmCrypto();
  const pub = normalizePubKey(options.publicKey);
  const bytes = Array.from(new TextEncoder().encode(input));
  return sm2.doEncrypt(bytes, pub, options.cipherMode ?? 1);
}

export async function sm2Decrypt(input: string, options: Sm2Options): Promise<string> {
  if (!options.privateKey) throw new Error('请输入 SM2 私钥');
  const { sm2 } = await loadSmCrypto();
  const decrypted = sm2.doDecrypt(input, options.privateKey.trim(), options.cipherMode ?? 1);
  if (!decrypted) throw new Error('SM2 解密失败，请检查密钥和密文');
  return decrypted;
}

// ====== 国密 SM4 加密/解密 ======

export async function sm4Encrypt(input: string, options: Sm4Options): Promise<string> {
  if (!options.key || options.key.length !== 16) throw new Error('SM4 密钥需 16 字符');
  const { sm4 } = await loadSmCrypto();
  const keyHex = toHex(options.key);
  const opts: any = {
    padding: (options.padding !== false ? 'pkcs#5' : 'none') as 'pkcs#5' | 'none',
    mode: options.mode === 'cbc' ? 'cbc' : undefined,
    iv: options.mode === 'cbc' ? toHex(options.iv || '') : undefined,
  };
  return sm4.encrypt(input, keyHex, opts);
}

export async function sm4Decrypt(input: string, options: Sm4Options): Promise<string> {
  if (!options.key || options.key.length !== 16) throw new Error('SM4 密钥需 16 字符');
  const { sm4 } = await loadSmCrypto();
  const keyHex = toHex(options.key);
  const opts: any = {
    padding: (options.padding !== false ? 'pkcs#5' : 'none') as 'pkcs#5' | 'none',
    mode: options.mode === 'cbc' ? 'cbc' : undefined,
    iv: options.mode === 'cbc' ? toHex(options.iv || '') : undefined,
  };
  return sm4.decrypt(input, keyHex, opts);
}

// ====== Hash + HMAC ======

export async function computeHash(input: string, options: HashOptions): Promise<string> {
  const CryptoJS = await loadCryptoJS();
  const algoName = options.algo.toUpperCase().replace('-', '');
  const output = options.output || 'hex';

  if (options.hmac) {
    if (!options.hmacKey) throw new Error('请输入 HMAC 密钥');
    const keyWA = CryptoJS.enc.Utf8.parse(options.hmacKey);
    const fn = (CryptoJS as any)[`Hmac${algoName}`] || CryptoJS.HmacSHA256;
    const hash = fn(input, keyWA);
    return output === 'hex'
      ? hash.toString(CryptoJS.enc.Hex)
      : CryptoJS.enc.Base64.stringify(hash);
  }

  const fn = (CryptoJS as any)[algoName];
  if (!fn) throw new Error(`不支持的哈希算法: ${options.algo}`);
  const result = fn(input);
  return output === 'hex'
    ? result.toString(CryptoJS.enc.Hex)
    : CryptoJS.enc.Base64.stringify(result);
}

// ====== RSA-OAEP（Web Crypto API）======

export async function rsaGenerateKeyPair(keySize: 2048 | 4096 = 2048): Promise<RsaKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: keySize, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
  const [pub, pri] = await Promise.all([
    crypto.subtle.exportKey('spki', keyPair.publicKey),
    crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
  ]);
  return { publicKeyPem: ab2pem(pub, 'PUBLIC KEY'), privateKeyPem: ab2pem(pri, 'PRIVATE KEY') };
}

export async function rsaEncrypt(input: string, publicKeyPem: string): Promise<string> {
  if (!publicKeyPem) throw new Error('请提供 RSA 公钥 PEM');
  const pubKey = await crypto.subtle.importKey(
    'spki', pemToArrayBuffer(publicKeyPem), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'],
  );
  const buf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, new TextEncoder().encode(input));
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}

export async function rsaDecrypt(b64Cipher: string, privateKeyPem: string): Promise<string> {
  if (!privateKeyPem) throw new Error('请提供 RSA 私钥 PEM');
  const priKey = await crypto.subtle.importKey(
    'pkcs8', pemToArrayBuffer(privateKeyPem), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt'],
  );
  const bin = atob(b64Cipher);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  const out = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priKey, buf);
  return new TextDecoder().decode(out);
}

// ====== Bcrypt ======

export async function bcryptHash(password: string, cost = 10): Promise<string> {
  if (!password) throw new Error('请输入要哈希的口令');
  if (cost < 4 || cost > 31) throw new Error('Bcrypt cost 需在 4-31 之间');
  const bcrypt = await loadBcrypt();
  const salt = bcrypt.genSaltSync(cost);
  return bcrypt.hashSync(password, salt);
}

export async function bcryptVerify(password: string, hash: string): Promise<boolean> {
  if (!password || !hash) throw new Error('请输入口令与哈希');
  const bcrypt = await loadBcrypt();
  try {
    return bcrypt.compareSync(password, hash);
  } catch {
    throw new Error('哈希格式无效（需 $2a$/$2b$/$2y$ 开头的 Bcrypt 哈希）');
  }
}

// ====== 弱算法警告 ======

export const WEAK_ALGO_WARNINGS: Record<string, string> = {
  DES: 'DES 密钥仅 56 位有效长度，已被认为不安全，仅用于验证遗留系统',
  '3DES': '3DES 性能差且逐渐被弃用，建议迁移到 AES',
  RC4: 'RC4 存在已知漏洞（ biases ），已被 RFC 7465 禁止在 TLS 中使用',
  MD5: 'MD5 已被攻破（碰撞攻击），不可用于安全场景',
  SHA1: 'SHA-1 已被攻破，不建议用于安全场景',
  'AES-ECB': 'ECB 模式相同明文块产生相同密文块，泄漏明文模式',
};
