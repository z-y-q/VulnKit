/**
 * 加密/解密引擎 — 灵眸 v6.0
 * 对齐 v5 vk-crypto.js 的全部算法：AES / DES / RC4 / SM2 / SM4 / RSA / Hash+HMAC
 * - 对称/流密码/哈希：crypto-js
 * - 国密 SM2/SM4：sm-crypto
 * - RSA-OAEP + 密钥对生成：Web Crypto API
 */

import CryptoJS from 'crypto-js';
import { sm2, sm4 } from 'sm-crypto';
import bcrypt from 'bcryptjs';

// ====== 通用工具 ======

/** 密钥填充/截断到指定字节长度（null 字节填充，对齐 v5 padOrTruncate） */
export function padOrTruncate(key: string, len: number): string {
  if (!key) return '';
  if (key.length === len) return key;
  if (key.length > len) return key.slice(0, len);
  return key + '\0'.repeat(len - key.length);
}

/** 字符串转十六进制（每字符 UTF-16 码元） */
export function toHex(str: string): string {
  return Array.from(str).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

/** ArrayBuffer → PEM */
export function ab2pem(buffer: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  const b64 = btoa(binary);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

/** PEM → ArrayBuffer */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----BEGIN [A-Z ]+-----/, '').replace(/-----END [A-Z ]+-----/, '').replace(/\s/g, '');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

// ====== AES ======

export type AesMode = 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR';
export type AesPadding = 'Pkcs7' | 'ZeroPadding' | 'NoPadding' | 'Iso97971';

export interface AesOptions {
  mode: AesMode;
  keySize: 128 | 192 | 256;
  padding: AesPadding;
  key: string;
  iv?: string;
}

function aesOpts(o: AesOptions) {
  const mode = (CryptoJS.mode as any)[o.mode];
  const padding = (CryptoJS.pad as any)[o.padding];
  if (!mode || !padding) throw new Error(`不支持的 AES 模式/填充: ${o.mode}/${o.padding}`);
  const opts: any = { mode, padding };
  if (o.mode !== 'ECB') opts.iv = CryptoJS.enc.Utf8.parse(padOrTruncate(o.iv || '', 16));
  return { keyWA: CryptoJS.enc.Utf8.parse(padOrTruncate(o.key, o.keySize / 8)), opts };
}

export function aesEncrypt(input: string, o: AesOptions): string {
  const p = aesOpts(o);
  return CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(input), p.keyWA, p.opts).toString();
}

export function aesDecrypt(input: string, o: AesOptions): string {
  const p = aesOpts(o);
  return CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(input, p.keyWA, p.opts));
}

// ====== DES / 3DES ======

export interface DesOptions {
  mode: 'CBC' | 'ECB';
  padding: AesPadding;
  key: string;
  iv?: string;
  triple?: boolean; // true=3DES
}

function desOpts(o: DesOptions) {
  const mode = (CryptoJS.mode as any)[o.mode];
  const padding = (CryptoJS.pad as any)[o.padding];
  const opts: any = { mode, padding };
  if (o.mode !== 'ECB') opts.iv = CryptoJS.enc.Utf8.parse(padOrTruncate(o.iv || '', 8));
  return { keyWA: CryptoJS.enc.Utf8.parse(padOrTruncate(o.key, 8)), opts };
}

export function desEncrypt(input: string, o: DesOptions): string {
  const p = desOpts(o);
  const fn = o.triple ? CryptoJS.TripleDES : CryptoJS.DES;
  return fn.encrypt(CryptoJS.enc.Utf8.parse(input), p.keyWA, p.opts).toString();
}

export function desDecrypt(input: string, o: DesOptions): string {
  const p = desOpts(o);
  const fn = o.triple ? CryptoJS.TripleDES : CryptoJS.DES;
  return CryptoJS.enc.Utf8.stringify(fn.decrypt(input, p.keyWA, p.opts));
}

// ====== RC4 ======

export function rc4Encrypt(input: string, key: string): string {
  if (!key) throw new Error('请输入 RC4 密钥');
  return CryptoJS.RC4.encrypt(CryptoJS.enc.Utf8.parse(input), key).toString();
}

export function rc4Decrypt(input: string, key: string): string {
  if (!key) throw new Error('请输入 RC4 密钥');
  return CryptoJS.enc.Utf8.stringify(CryptoJS.RC4.decrypt(input, key));
}

// ====== SM2 国密非对称 ======

export interface Sm2Options {
  publicKey?: string; // 130 位十六进制（04 开头）或 128 位
  privateKey?: string; // 64 位十六进制
  cipherMode?: 0 | 1; // 0=C1C3C2, 1=C1C2C3（默认 1）
}

function normalizePubKey(pubKey: string): string {
  let k = pubKey.trim();
  if (k.length === 128) k = '04' + k;
  if (k.length !== 130 || !k.startsWith('04')) throw new Error('公钥格式错误（需 128/130 位十六进制，04 开头）');
  return k;
}

export function sm2Encrypt(input: string, o: Sm2Options): string {
  if (!o.publicKey) throw new Error('请输入 SM2 公钥');
  const pub = normalizePubKey(o.publicKey);
  const bytes = Array.from(new TextEncoder().encode(input));
  return sm2.doEncrypt(bytes, pub, o.cipherMode ?? 1);
}

export function sm2Decrypt(input: string, o: Sm2Options): string {
  if (!o.privateKey) throw new Error('请输入 SM2 私钥');
  const decrypted = sm2.doDecrypt(input, o.privateKey.trim(), o.cipherMode ?? 1);
  if (!decrypted) throw new Error('SM2 解密失败，请检查密钥和密文');
  return decrypted;
}

// ====== SM4 国密对称 ======

export interface Sm4Options {
  key: string; // 16 字符
  mode?: 'ecb' | 'cbc';
  iv?: string; // cbc 模式需要
  padding?: boolean; // true=pkcs#5, false=none
}

function sm4Opts(o: Sm4Options) {
  if (!o.key || o.key.length !== 16) throw new Error('SM4 密钥需 16 字符');
  return {
    keyHex: toHex(o.key),
    opts: {
      padding: (o.padding !== false ? 'pkcs#5' : 'none') as 'pkcs#5' | 'none',
      mode: o.mode === 'cbc' ? 'cbc' : undefined,
      iv: o.mode === 'cbc' ? toHex(o.iv || '') : undefined,
    } as any,
  };
}

export function sm4Encrypt(input: string, o: Sm4Options): string {
  const p = sm4Opts(o);
  return sm4.encrypt(input, p.keyHex, p.opts);
}

export function sm4Decrypt(input: string, o: Sm4Options): string {
  const p = sm4Opts(o);
  return sm4.decrypt(input, p.keyHex, p.opts);
}

// ====== Hash + HMAC ======

export type HashAlgo = 'md5' | 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512';

export interface HashOptions {
  algo: HashAlgo;
  output?: 'hex' | 'base64'; // 默认 hex
  hmac?: boolean;
  hmacKey?: string;
}

export function computeHash(input: string, o: HashOptions): string {
  const algoName = o.algo.toUpperCase().replace('-', '');
  const output = o.output || 'hex';
  if (o.hmac) {
    if (!o.hmacKey) throw new Error('请输入 HMAC 密钥');
    const keyWA = CryptoJS.enc.Utf8.parse(o.hmacKey);
    const fn = (CryptoJS as any)[`Hmac${algoName}`] || CryptoJS.HmacSHA256;
    const hash = fn(input, keyWA);
    return output === 'hex'
      ? hash.toString(CryptoJS.enc.Hex)
      : CryptoJS.enc.Base64.stringify(hash);
  }
  const fn = (CryptoJS as any)[algoName];
  if (!fn) throw new Error(`不支持的哈希算法: ${o.algo}`);
  const result = fn(input);
  return output === 'hex'
    ? result.toString(CryptoJS.enc.Hex)
    : CryptoJS.enc.Base64.stringify(result);
}

// ====== RSA-OAEP（Web Crypto） ======

export interface RsaKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

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

// ====== Bcrypt（口令哈希，对齐 v5） ======

/** 生成 Bcrypt 口令哈希。cost 为成本因子（4-31），默认 10 */
export function bcryptHash(password: string, cost = 10): string {
  if (!password) throw new Error('请输入要哈希的口令');
  if (cost < 4 || cost > 31) throw new Error('Bcrypt cost 需在 4-31 之间');
  const salt = bcrypt.genSaltSync(cost);
  return bcrypt.hashSync(password, salt);
}

/** 验证口令是否匹配 Bcrypt 哈希 */
export function bcryptVerify(password: string, hash: string): boolean {
  if (!password || !hash) throw new Error('请输入口令与哈希');
  try {
    return bcrypt.compareSync(password, hash);
  } catch {
    throw new Error('哈希格式无效（需 $2a$/$2b$/$2y$ 开头的 Bcrypt 哈希）');
  }
}

// ====== 弱算法警告（对齐 v5） ======

export const WEAK_ALGO_WARNINGS: Record<string, string> = {
  DES: 'DES 密钥仅 56 位有效长度，已被认为不安全，仅用于验证遗留系统',
  '3DES': '3DES 性能差且逐渐被弃用，建议迁移到 AES',
  RC4: 'RC4 存在已知漏洞（ biases ），已被 RFC 7465 禁止在 TLS 中使用',
  MD5: 'MD5 已被攻破（碰撞攻击），不可用于安全场景',
  SHA1: 'SHA-1 已被攻破，不建议用于安全场景',
  'AES-ECB': 'ECB 模式相同明文块产生相同密文块，泄漏明文模式',
};
