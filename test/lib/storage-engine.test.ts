import { describe, it, expect } from 'vitest';
import {
  isSensitiveStorageKey,
  classifyStorageValue,
  truncate,
  escapeHtml,
} from '@/lib/scanners/storage-engine';

describe('storage-engine: isSensitiveStorageKey', () => {
  it('标记 token 为敏感', () => {
    expect(isSensitiveStorageKey('access_token')).toBe(true);
    expect(isSensitiveStorageKey('token')).toBe(true);
    expect(isSensitiveStorageKey('refresh_token')).toBe(true);
  });

  it('标记 password 为敏感', () => {
    expect(isSensitiveStorageKey('password')).toBe(true);
    expect(isSensitiveStorageKey('db_password')).toBe(true);
    expect(isSensitiveStorageKey('passwd')).toBe(true);
  });

  it('标记 session 为敏感', () => {
    expect(isSensitiveStorageKey('session_id')).toBe(true);
    expect(isSensitiveStorageKey('session')).toBe(true);
  });

  it('标记 jwt 为敏感', () => {
    expect(isSensitiveStorageKey('id_token')).toBe(true);
    expect(isSensitiveStorageKey('jwt_token')).toBe(true);
  });

  it('标记 csrf/xsrf 为敏感', () => {
    expect(isSensitiveStorageKey('csrf-token')).toBe(true);
    expect(isSensitiveStorageKey('xsrf-token')).toBe(true);
  });

  it('不标记普通键为敏感', () => {
    expect(isSensitiveStorageKey('theme')).toBe(false);
    expect(isSensitiveStorageKey('lang')).toBe(false);
    expect(isSensitiveStorageKey('layout')).toBe(false);
    expect(isSensitiveStorageKey('version')).toBe(false);
  });

  it('大小写不敏感', () => {
    expect(isSensitiveStorageKey('TOKEN')).toBe(true);
    expect(isSensitiveStorageKey('Api_Key')).toBe(true);
  });
});

describe('storage-engine: classifyStorageValue', () => {
  it('JWT Token 值返回 high', () => {
    const result = classifyStorageValue('data', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature');
    expect(result.isSensitive).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.patterns.some(p => p.includes('JWT'))).toBe(true);
  });

  it('Bearer Token 值返回 high', () => {
    const result = classifyStorageValue('auth', 'Bearer eyJhbGciOiJ9.test');
    expect(result.isSensitive).toBe(true);
    expect(result.severity).toBe('high');
  });

  it('AWS Key 值返回 high', () => {
    const result = classifyStorageValue('key', 'AKIAIOSFODNN7EXAMPLE');
    expect(result.isSensitive).toBe(true);
    expect(result.severity).toBe('high');
  });

  it('数据库连接字符串返回 high', () => {
    const result = classifyStorageValue('db', 'mysql://root:pass@localhost:3306/mydb');
    expect(result.isSensitive).toBe(true);
    expect(result.severity).toBe('high');
  });

  it('敏感键 + 普通值返回 medium', () => {
    const result = classifyStorageValue('token', 'abc');
    expect(result.isSensitive).toBe(true);
    expect(result.severity).toBe('medium');
  });

  it('普通键 + 普通值不敏感', () => {
    const result = classifyStorageValue('theme', 'dark');
    expect(result.isSensitive).toBe(false);
    expect(result.severity).toBe('low');
  });

  it('Long Base64 值返回 medium', () => {
    const longB64 = 'a'.repeat(200) + '==';
    const result = classifyStorageValue('data', longB64);
    expect(result.isSensitive).toBe(true);
    expect(result.severity).toBe('medium');
  });

  it('匹配多个模式合并', () => {
    const result = classifyStorageValue('access_token', 'Bearer eyJhbG.test');
    // token 键匹配 + Bearer 值匹配 + JWT 值匹配
    expect(result.patterns.length).toBeGreaterThanOrEqual(2);
    expect(result.severity).toBe('high');
  });
});

describe('storage-engine: truncate', () => {
  it('短值不截断', () => {
    expect(truncate('hello', 10)).toBe('hello');
  });

  it('等长值不截断', () => {
    expect(truncate('hello', 5)).toBe('hello');
  });

  it('超长值截断并加 ...', () => {
    const result = truncate('hello world', 5);
    expect(result).toBe('hello...');
    expect(result.length).toBe(8); // 5 + 3
  });

  it('空字符串不变', () => {
    expect(truncate('', 10)).toBe('');
  });
});

describe('storage-engine: escapeHtml', () => {
  it('转义 HTML 特殊字符', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    );
  });

  it('转义 &', () => {
    expect(escapeHtml('a&b')).toBe('a&amp;b');
  });

  it('无特殊字符不变', () => {
    expect(escapeHtml('hello')).toBe('hello');
  });
});
