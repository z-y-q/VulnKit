import { describe, it, expect } from '@jest/globals';
import { extractBaseDomain } from '../src/popup/vk-subdomain.js';

// ---------------------------------------------------------------------------
// extractBaseDomain
// ---------------------------------------------------------------------------
describe('extractBaseDomain', () => {
  // --- Simple (two-part) TLDs ---
  it('returns two-part domain as-is for example.com', () => {
    expect(extractBaseDomain('example.com')).toBe('example.com');
  });

  it('strips subdomains from normal domains', () => {
    expect(extractBaseDomain('a.b.example.com')).toBe('example.com');
  });

  it('strips single subdomain', () => {
    expect(extractBaseDomain('www.example.com')).toBe('example.com');
  });

  it('handles three-level normal domain', () => {
    expect(extractBaseDomain('a.b.c.example.com')).toBe('example.com');
  });

  it('returns single label as-is', () => {
    expect(extractBaseDomain('localhost')).toBe('localhost');
  });

  // --- Multi-part TLDs ---
  it('handles co.uk', () => {
    expect(extractBaseDomain('www.example.co.uk')).toBe('example.co.uk');
  });

  it('handles co.uk with deep subdomains', () => {
    expect(extractBaseDomain('x.y.z.example.co.uk')).toBe('example.co.uk');
  });

  it('handles com.cn', () => {
    expect(extractBaseDomain('a.b.example.com.cn')).toBe('example.com.cn');
  });

  it('handles co.jp', () => {
    expect(extractBaseDomain('a.b.example.co.jp')).toBe('example.co.jp');
  });

  it('handles com.au', () => {
    expect(extractBaseDomain('sub.example.com.au')).toBe('example.com.au');
  });

  it('handles com.br', () => {
    expect(extractBaseDomain('sub.example.com.br')).toBe('example.com.br');
  });

  it('handles com.tw', () => {
    expect(extractBaseDomain('sub.example.com.tw')).toBe('example.com.tw');
  });

  it('handles com.hk', () => {
    expect(extractBaseDomain('sub.example.com.hk')).toBe('example.com.hk');
  });

  it('handles gov.cn', () => {
    expect(extractBaseDomain('sub.example.gov.cn')).toBe('example.gov.cn');
  });

  it('handles ac.uk', () => {
    expect(extractBaseDomain('sub.example.ac.uk')).toBe('example.ac.uk');
  });

  it('handles co.za', () => {
    expect(extractBaseDomain('sub.example.co.za')).toBe('example.co.za');
  });

  // --- Case insensitivity ---
  it('is case-insensitive', () => {
    expect(extractBaseDomain('A.B.Example.COM')).toBe('example.com');
  });

  it('handles mixed case with multi-part TLD', () => {
    expect(extractBaseDomain('WWW.Example.CO.UK')).toBe('example.co.uk');
  });

  // --- Edge cases ---
  it('handles org.cn multi-part TLD', () => {
    expect(extractBaseDomain('sub.example.org.cn')).toBe('example.org.cn');
  });

  it('handles net.cn multi-part TLD', () => {
    expect(extractBaseDomain('sub.example.net.cn')).toBe('example.net.cn');
  });

  it('handles gov.uk multi-part TLD', () => {
    expect(extractBaseDomain('sub.example.gov.uk')).toBe('example.gov.uk');
  });

  it('handles com.sg multi-part TLD', () => {
    expect(extractBaseDomain('sub.example.com.sg')).toBe('example.com.sg');
  });
});
