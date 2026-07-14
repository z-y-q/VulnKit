import { describe, it, expect, beforeAll } from 'vitest';
import { sm2 } from 'sm-crypto';
import {
  padOrTruncate,
  toHex,
  ab2pem,
  pemToArrayBuffer,
  aesEncrypt,
  aesDecrypt,
  desEncrypt,
  desDecrypt,
  rc4Encrypt,
  rc4Decrypt,
  sm2Encrypt,
  sm2Decrypt,
  sm4Encrypt,
  sm4Decrypt,
  computeHash,
  rsaGenerateKeyPair,
  rsaEncrypt,
  rsaDecrypt,
  bcryptHash,
  bcryptVerify,
  WEAK_ALGO_WARNINGS,
} from '@/lib/crypto/crypto-engine';

// ====== 通用工具 ======

describe('crypto-engine: padOrTruncate', () => {
  it('空 key → 空串', () => {
    expect(padOrTruncate('', 16)).toBe('');
  });
  it('等长 → 原样', () => {
    expect(padOrTruncate('abc', 3)).toBe('abc');
  });
  it('超长 → 截断', () => {
    expect(padOrTruncate('abcdef', 3)).toBe('abc');
  });
  it('不足 → null 字节填充', () => {
    expect(padOrTruncate('ab', 4)).toBe('ab\0\0');
    expect(padOrTruncate('ab', 4).length).toBe(4);
  });
});

describe('crypto-engine: toHex', () => {
  it('ASCII 字符串转十六进制（UTF-16 码元）', () => {
    expect(toHex('abc')).toBe('616263');
  });
  it('空串 → 空串', () => {
    expect(toHex('')).toBe('');
  });
});

describe('crypto-engine: ab2pem / pemToArrayBuffer', () => {
  it('round trip 保持字节一致', () => {
    const original = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 253]).buffer;
    const pem = ab2pem(original, 'TEST KEY');
    expect(pem).toContain('-----BEGIN TEST KEY-----');
    expect(pem).toContain('-----END TEST KEY-----');
    const back = new Uint8Array(pemToArrayBuffer(pem));
    expect(Array.from(back)).toEqual([0, 1, 2, 3, 250, 251, 252, 253]);
  });
});

// ====== AES ======

describe('crypto-engine: AES round trip', () => {
  const modes = ['CBC', 'ECB', 'CFB', 'OFB', 'CTR'] as const;
  for (const mode of modes) {
    it(`${mode} / 128 / Pkcs7 round trip`, () => {
      const o = { mode, keySize: 128 as const, padding: 'Pkcs7' as const, key: '0123456789abcdef', iv: '0123456789abcdef' };
      const cipher = aesEncrypt('hello 灵眸', o);
      expect(cipher).toBeTruthy();
      expect(aesDecrypt(cipher, o)).toBe('hello 灵眸');
    });
  }
  it('ECB 无需 iv 也能 round trip', () => {
    const o = { mode: 'ECB' as const, keySize: 256 as const, padding: 'Pkcs7' as const, key: '0123456789abcdef0123456789abcdef' };
    expect(aesDecrypt(aesEncrypt('data', o), o)).toBe('data');
  });
  it('空输入 round trip', () => {
    const o = { mode: 'CBC' as const, keySize: 128 as const, padding: 'Pkcs7' as const, key: '0123456789abcdef', iv: '0123456789abcdef' };
    expect(aesDecrypt(aesEncrypt('', o), o)).toBe('');
  });
  it('不同 keySize（192/256）round trip', () => {
    for (const keySize of [192, 256] as const) {
      const key = 'k'.repeat(keySize / 8);
      const o = { mode: 'CBC' as const, keySize, padding: 'Pkcs7' as const, key, iv: '0123456789abcdef' };
      expect(aesDecrypt(aesEncrypt('payload', o), o)).toBe('payload');
    }
  });
  it('非法密文（非 base64）解密返回空串而非抛错', () => {
    const o = { mode: 'CBC' as const, keySize: 128 as const, padding: 'Pkcs7' as const, key: '0123456789abcdef', iv: '0123456789abcdef' };
    expect(aesDecrypt('!!!not-base64!!!', o)).toBe('');
  });
  it('不支持的 mode/padding 抛错', () => {
    const o = { mode: 'WRONG' as any, keySize: 128 as const, padding: 'Pkcs7' as const, key: '0123456789abcdef' };
    expect(() => aesEncrypt('x', o)).toThrow(/不支持/);
  });
});

// ====== DES / 3DES ======

describe('crypto-engine: DES / 3DES round trip', () => {
  it('DES-CBC round trip', () => {
    const o = { mode: 'CBC' as const, padding: 'Pkcs7' as const, key: '01234567', iv: '01234567' };
    expect(desDecrypt(desEncrypt('secret', o), o)).toBe('secret');
  });
  it('3DES（triple）round trip', () => {
    const o = { mode: 'ECB' as const, padding: 'Pkcs7' as const, key: '0123456789abcdef01234567', triple: true };
    expect(desDecrypt(desEncrypt('triple-data', o), o)).toBe('triple-data');
  });
});

// ====== RC4 ======

describe('crypto-engine: RC4', () => {
  it('round trip', () => {
    const cipher = rc4Encrypt('stream-data', 'rc4key');
    expect(rc4Decrypt(cipher, 'rc4key')).toBe('stream-data');
  });
  it('空密钥抛错', () => {
    expect(() => rc4Encrypt('x', '')).toThrow('请输入 RC4 密钥');
    expect(() => rc4Decrypt('x', '')).toThrow('请输入 RC4 密钥');
  });
});

// ====== SM2 ======

describe('crypto-engine: SM2', () => {
  let keypair: { publicKey: string; privateKey: string };
  beforeAll(() => {
    keypair = sm2.generateKeyPairHex();
    expect(keypair.publicKey).toMatch(/^04[0-9a-f]{128}$/);
    expect(keypair.privateKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('round trip（130 位 04 开头公钥）', () => {
    const cipher = sm2Encrypt('sm2-payload', { publicKey: keypair.publicKey });
    expect(cipher).toBeTruthy();
    expect(sm2Decrypt(cipher, { privateKey: keypair.privateKey })).toBe('sm2-payload');
  });

  it('128 位公钥自动补 04 前缀', () => {
    const pubNoPrefix = keypair.publicKey.slice(2); // 去掉 04
    expect(pubNoPrefix.length).toBe(128);
    const cipher = sm2Encrypt('x', { publicKey: pubNoPrefix });
    expect(sm2Decrypt(cipher, { privateKey: keypair.privateKey })).toBe('x');
  });

  it('无 publicKey 抛错', () => {
    expect(() => sm2Encrypt('x', {})).toThrow('请输入 SM2 公钥');
  });
  it('无 privateKey 抛错', () => {
    expect(() => sm2Decrypt('x', {})).toThrow('请输入 SM2 私钥');
  });
  it('公钥格式错误抛错', () => {
    expect(() => sm2Encrypt('x', { publicKey: 'zzz' })).toThrow(/公钥格式错误/);
    expect(() => sm2Encrypt('x', { publicKey: '05' + '0'.repeat(128) })).toThrow(/公钥格式错误/);
  });
  it('解密失败抛错（错误密文）', () => {
    expect(() => sm2Decrypt('invalid-cipher-text', { privateKey: keypair.privateKey })).toThrow(/SM2 解密失败/);
  });
});

// ====== SM4 ======

describe('crypto-engine: SM4 round trip', () => {
  it('ECB mode round trip', () => {
    const o = { key: '0123456789abcdef', mode: 'ecb' as const };
    expect(sm4Decrypt(sm4Encrypt('sm4-data', o), o)).toBe('sm4-data');
  });
  it('CBC mode round trip', () => {
    const o = { key: '0123456789abcdef', mode: 'cbc' as const, iv: '0123456789abcdef' };
    expect(sm4Decrypt(sm4Encrypt('sm4-cbc', o), o)).toBe('sm4-cbc');
  });
  it('padding=false（none）round trip（明文须为 16 字节整块）', () => {
    const o = { key: '0123456789abcdef', mode: 'ecb' as const, padding: false };
    const plain = '0123456789abcdef'; // 16 字节
    expect(sm4Decrypt(sm4Encrypt(plain, o), o)).toBe(plain);
  });
  it('非法 key 长度抛错', () => {
    expect(() => sm4Encrypt('x', { key: 'short' })).toThrow(/SM4 密钥需 16 字符/);
    expect(() => sm4Encrypt('x', { key: '0123456789abcdef0' })).toThrow(/SM4 密钥需 16 字符/);
    expect(() => sm4Encrypt('x', { key: '' })).toThrow(/SM4 密钥需 16 字符/);
  });
});

// ====== Hash + HMAC ======

describe('crypto-engine: computeHash', () => {
  it('MD5 空串 → d41d8cd9...（对齐 RFC 1321）', () => {
    expect(computeHash('', { algo: 'md5' })).toBe('d41d8cd98f00b204e9800998ecf8427e');
  });
  it('SHA-256 确定性', () => {
    const h = computeHash('abc', { algo: 'sha256' });
    expect(h).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    // 两次相同输入
    expect(computeHash('abc', { algo: 'sha256' })).toBe(h);
  });
  it('base64 输出', () => {
    const b64 = computeHash('abc', { algo: 'sha256', output: 'base64' });
    expect(b64).toBe('ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=');
  });
  it('各哈希算法均产生非空 hex', () => {
    for (const algo of ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'] as const) {
      const h = computeHash('test', { algo });
      expect(h.length).toBeGreaterThan(0);
      expect(/^[0-9a-f]+$/.test(h)).toBe(true);
    }
  });
  it('HMAC-SHA256 round trip 一致', () => {
    const a = computeHash('msg', { algo: 'sha256', hmac: true, hmacKey: 'secret' });
    const b = computeHash('msg', { algo: 'sha256', hmac: true, hmacKey: 'secret' });
    expect(a).toBe(b);
    expect(a.length).toBe(64);
  });
  it('HMAC 缺 key 抛错', () => {
    expect(() => computeHash('msg', { algo: 'sha256', hmac: true, hmacKey: '' })).toThrow('请输入 HMAC 密钥');
  });
  it('不支持的哈希算法抛错', () => {
    expect(() => computeHash('x', { algo: 'sha999' as any })).toThrow(/不支持的哈希算法/);
  });
});

// ====== RSA-OAEP（Web Crypto） ======

describe('crypto-engine: RSA-OAEP', () => {
  let keypair: { publicKeyPem: string; privateKeyPem: string };
  beforeAll(async () => {
    keypair = await rsaGenerateKeyPair(2048);
  });

  it('生成的 PEM 格式正确', () => {
    expect(keypair.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(keypair.privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
  });

  it('encrypt → decrypt round trip', async () => {
    const cipher = await rsaEncrypt('rsa-secret', keypair.publicKeyPem);
    expect(cipher).toBeTruthy();
    expect(await rsaDecrypt(cipher, keypair.privateKeyPem)).toBe('rsa-secret');
  });

  it('空 PEM 抛错', async () => {
    await expect(rsaEncrypt('x', '')).rejects.toThrow('请提供 RSA 公钥 PEM');
    await expect(rsaDecrypt('x', '')).rejects.toThrow('请提供 RSA 私钥 PEM');
  });

  it('非法 PEM → WebCrypto reject', async () => {
    await expect(rsaEncrypt('x', '-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----')).rejects.toThrow();
  });

  it('错误私钥解密 → reject', async () => {
    const cipher = await rsaEncrypt('x', keypair.publicKeyPem);
    // 用另一对私钥解密应失败
    const other = await rsaGenerateKeyPair(2048);
    await expect(rsaDecrypt(cipher, other.privateKeyPem)).rejects.toThrow();
  });
});

// ====== Bcrypt ======

describe('crypto-engine: Bcrypt', () => {
  it('hash → verify 通过', () => {
    const hash = bcryptHash('password123', 4);
    expect(hash).toMatch(/^\$2[aby]\$/);
    expect(bcryptVerify('password123', hash)).toBe(true);
  });
  it('错误口令 verify 失败', () => {
    const hash = bcryptHash('correct', 4);
    expect(bcryptVerify('wrong', hash)).toBe(false);
  });
  it('相同口令每次哈希不同（含盐）', () => {
    expect(bcryptHash('same', 4)).not.toBe(bcryptHash('same', 4));
  });
  it('空口令抛错', () => {
    expect(() => bcryptHash('', 4)).toThrow('请输入要哈希的口令');
  });
  it('非法 cost 抛错', () => {
    expect(() => bcryptHash('p', 3)).toThrow(/Bcrypt cost/);
    expect(() => bcryptHash('p', 32)).toThrow(/Bcrypt cost/);
  });
  it('非法哈希格式返回 false（bcryptjs 内部容错不抛错）', () => {
    expect(bcryptVerify('p', 'not-a-bcrypt-hash')).toBe(false);
  });
  it('空口令/空哈希抛错', () => {
    expect(() => bcryptVerify('', 'x')).toThrow('请输入口令与哈希');
    expect(() => bcryptVerify('p', '')).toThrow('请输入口令与哈希');
  });
});

// ====== 弱算法警告表 ======

describe('crypto-engine: WEAK_ALGO_WARNINGS', () => {
  it('覆盖关键弱算法', () => {
    for (const algo of ['DES', '3DES', 'RC4', 'MD5', 'SHA1', 'AES-ECB']) {
      expect(WEAK_ALGO_WARNINGS[algo]).toBeTruthy();
    }
  });
});
