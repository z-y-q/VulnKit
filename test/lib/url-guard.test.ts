import { describe, it, expect } from 'vitest';
import { isAllowedUrl, validateProbeUrl } from '@/lib/core/url-guard';

describe('isAllowedUrl', () => {
  it('允许普通 http/https 公网域名', () => {
    expect(isAllowedUrl('https://example.com/path')).toBe(true);
    expect(isAllowedUrl('http://sub.example.com:8080/x')).toBe(true);
  });

  it('拒绝 loopback', () => {
    expect(isAllowedUrl('http://127.0.0.1/admin')).toBe(false);
    expect(isAllowedUrl('http://localhost/x')).toBe(false);
    expect(isAllowedUrl('http://[::1]/x')).toBe(false);
  });

  it('拒绝私网段', () => {
    expect(isAllowedUrl('http://192.168.1.1/')).toBe(false);
    expect(isAllowedUrl('http://10.0.0.1/')).toBe(false);
    expect(isAllowedUrl('http://172.16.0.1/')).toBe(false);
    expect(isAllowedUrl('http://172.31.255.255/')).toBe(false);
  });

  it('允许 172.15/172.32（公网段）', () => {
    expect(isAllowedUrl('http://172.15.0.1/')).toBe(true);
    expect(isAllowedUrl('http://172.32.0.1/')).toBe(true);
  });

  it('拒绝链路本地 169.254', () => {
    expect(isAllowedUrl('http://169.254.169.254/latest/meta-data/')).toBe(false);
  });

  it('拒绝 .local / .internal 后缀（mDNS/内网）', () => {
    expect(isAllowedUrl('http://printer.local/')).toBe(false);
    expect(isAllowedUrl('http://svc.internal/')).toBe(false);
  });

  it('拒绝纯数字主机名（十进制 IP 绕过）', () => {
    expect(isAllowedUrl('http://2130706433/')).toBe(false); // 127.0.0.1 的十进制
  });

  it('拒绝非 http(s) 协议', () => {
    expect(isAllowedUrl('file:///etc/passwd')).toBe(false);
    expect(isAllowedUrl('ftp://example.com/')).toBe(false);
    expect(isAllowedUrl('javascript:alert(1)')).toBe(false);
  });

  it('拒绝畸形 URL', () => {
    expect(isAllowedUrl('not-a-url')).toBe(false);
    expect(isAllowedUrl('')).toBe(false);
  });
});

describe('validateProbeUrl', () => {
  it('合法 https 返回 parsed', () => {
    const r = validateProbeUrl('https://example.com/a?b=1');
    expect('parsed' in r).toBe(true);
    if ('parsed' in r) {
      expect(r.parsed.hostname).toBe('example.com');
    }
  });

  it('非法协议返回 error', () => {
    const r = validateProbeUrl('ftp://x');
    expect('error' in r).toBe(true);
  });

  it('畸形 URL 返回 error', () => {
    const r = validateProbeUrl(':::broken');
    expect('error' in r).toBe(true);
  });
});
