import { describe, it, expect } from 'vitest';
import {
  decode,
  base64UrlDecode,
  base64UrlToUint8,
  detectAlgorithmConfusion,
  analyzeClaims,
  JWT_ALGO_MAP,
} from '@/lib/crypto/jwt';

describe('JWT 解析', () => {
  it('base64UrlDecode 支持 URL 安全字符', () => {
    // "hello" 的 base64url
    expect(base64UrlDecode('aGVsbG8')).toBe('hello');
  });

  it('base64UrlDecode 兼容填充缺失', () => {
    // "{ }" 的 base64url = e30
    expect(base64UrlDecode('e30')).toBe('{}');
  });

  it('base64UrlToUint8 返回字节数组', () => {
    const arr = base64UrlToUint8('aGVsbG8'); // hello
    expect(arr).toBeInstanceOf(Uint8Array);
    expect(arr.length).toBe(5);
    expect(arr[0]).toBe(104); // 'h'
  });

  it('decode 正常 JWT', () => {
    // header {"alg":"HS256","typ":"JWT"} + payload {"sub":"123","name":"test"}
    const token =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoidGVzdCJ9.signature';
    const decoded = decode(token);
    expect(decoded).not.toBeNull();
    expect(decoded!.header.alg).toBe('HS256');
    expect(decoded!.payload.sub).toBe('123');
    expect(decoded!.payload.name).toBe('test');
  });

  it('decode 无效 token 返回 null', () => {
    expect(decode('not.a.jwt')).toBeNull();
    expect(decode('invalid')).toBeNull();
  });
});

describe('JWT 算法映射', () => {
  it('包含主流算法', () => {
    expect(JWT_ALGO_MAP.HS256.name).toBe('HMAC');
    expect(JWT_ALGO_MAP.RS256.name).toBe('RSASSA-PKCS1-v1_5');
    expect(JWT_ALGO_MAP.ES256.curve).toBe('P-256');
    expect(JWT_ALGO_MAP.EdDSA.name).toBe('EdDSA');
  });
});

describe('JWT 漏洞检测', () => {
  it('检测 alg: none（critical）', () => {
    const findings = detectAlgorithmConfusion({ alg: 'none' }, {});
    const noneFinding = findings.find(f => f.title.includes('none'));
    expect(noneFinding).toBeDefined();
    expect(noneFinding!.severity).toBe('critical');
  });

  it('检测 jku 外部密钥 URL（high）', () => {
    const findings = detectAlgorithmConfusion({ alg: 'HS256', jku: 'https://evil.com/jwks.json' }, {});
    expect(findings.some(f => f.title.includes('jku'))).toBe(true);
  });

  it('检测 kid SQL 注入风险', () => {
    const findings = detectAlgorithmConfusion({ alg: 'HS256', kid: "x' OR '1'='1" }, {});
    expect(findings.some(f => f.title.includes('SQL 注入'))).toBe(true);
  });

  it('检测 kid 路径遍历风险', () => {
    const findings = detectAlgorithmConfusion({ alg: 'HS256', kid: '../../../etc/passwd' }, {});
    expect(findings.some(f => f.title.includes('路径遍历'))).toBe(true);
  });

  it('检测过期 token', () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const findings = detectAlgorithmConfusion({ alg: 'HS256' }, { exp: past });
    expect(findings.some(f => f.title.includes('已过期'))).toBe(true);
  });

  it('检测有效期过长', () => {
    const now = Math.floor(Date.now() / 1000);
    const findings = detectAlgorithmConfusion(
      { alg: 'HS256' },
      { nbf: now, exp: now + 86400 * 400 } // > 1 年
    );
    expect(findings.some(f => f.title.includes('有效期过长'))).toBe(true);
  });

  it('检测缺少 alg 声明', () => {
    const findings = detectAlgorithmConfusion({}, {});
    expect(findings.some(f => f.title.includes('缺少 alg'))).toBe(true);
  });
});

describe('JWT 敏感 claim 分析', () => {
  it('检测 password claim（high）', () => {
    const findings = analyzeClaims({}, { password: 'secret123' });
    const pwd = findings.find(f => f.title.includes('password'));
    expect(pwd).toBeDefined();
    expect(pwd!.severity).toBe('high');
  });

  it('检测 email claim（medium）', () => {
    const findings = analyzeClaims({}, { email: 'test@example.com' });
    expect(findings.some(f => f.title.includes('email'))).toBe(true);
  });

  it('检测过多私有 claim', () => {
    const payload: Record<string, string> = {};
    for (let i = 0; i < 20; i++) payload[`custom${i}`] = 'val';
    const findings = analyzeClaims({}, payload);
    expect(findings.some(f => f.title.includes('过多私有'))).toBe(true);
  });

  it('普通 claim 不报警', () => {
    const findings = analyzeClaims({}, { iss: 'test', sub: 'user' });
    expect(findings.length).toBe(0);
  });
});
