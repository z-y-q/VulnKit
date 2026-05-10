import { describe, it, expect } from '@jest/globals';
import { padOrTruncate, toHex, pemToArrayBuffer, ab2pem } from '../src/popup/vk-crypto.js';

// ---------------------------------------------------------------------------
// padOrTruncate
// ---------------------------------------------------------------------------
describe('padOrTruncate', () => {
  it('pads "abc" to length 6 with 3 null chars', () => {
    const result = padOrTruncate('abc', 6);
    expect(result.length).toBe(6);
    expect(result).toBe('abc\0\0\0');
  });

  it('truncates "abcdefgh" to length 4', () => {
    const result = padOrTruncate('abcdefgh', 4);
    expect(result).toBe('abcd');
  });

  it('returns "abc" unchanged when length matches', () => {
    const result = padOrTruncate('abc', 3);
    expect(result).toBe('abc');
  });

  it('returns falsy input (empty string) as-is', () => {
    expect(padOrTruncate('', 3)).toBe('');
  });
});

// ---------------------------------------------------------------------------
// toHex
// ---------------------------------------------------------------------------
describe('toHex', () => {
  it('toHex("AB") returns "4142"', () => {
    expect(toHex('AB')).toBe('4142');
  });

  it('toHex("") returns ""', () => {
    expect(toHex('')).toBe('');
  });

  it('toHex("A") returns "41"', () => {
    expect(toHex('A')).toBe('41');
  });
});

// ---------------------------------------------------------------------------
// pemToArrayBuffer + ab2pem roundtrip
// ---------------------------------------------------------------------------
describe('pemToArrayBuffer', () => {
  it('converts PEM string to ArrayBuffer', () => {
    const pem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA\n-----END PUBLIC KEY-----';
    const buffer = pemToArrayBuffer(pem);
    expect(buffer).toBeInstanceOf(ArrayBuffer);
    expect(buffer.byteLength).toBeGreaterThan(0);
  });
});

describe('ab2pem', () => {
  it('converts ArrayBuffer to PEM string with correct headers', () => {
    const pem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA\n-----END PUBLIC KEY-----';
    const buffer = pemToArrayBuffer(pem);
    const result = ab2pem(buffer, 'PUBLIC KEY');
    expect(result).toContain('-----BEGIN PUBLIC KEY-----');
    expect(result).toContain('-----END PUBLIC KEY-----');
  });

  it('roundtrip: ab2pem(pemToArrayBuffer(pem), label) contains BEGIN/END', () => {
    const originalPem =
      '-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpEgcSTAMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRlc3Rj\n-----END CERTIFICATE-----';
    const buffer = pemToArrayBuffer(originalPem);
    const roundTripped = ab2pem(buffer, 'CERTIFICATE');
    expect(roundTripped).toContain('-----BEGIN CERTIFICATE-----');
    expect(roundTripped).toContain('-----END CERTIFICATE-----');

    // Verify the base64 body matches (after stripping headers and whitespace)
    const extractBody = (pem) =>
      pem
        .replace(/-----BEGIN[^-]+-----/, '')
        .replace(/-----END[^-]+-----/, '')
        .replace(/\s/g, '');
    expect(extractBody(roundTripped)).toBe(extractBody(originalPem));
  });
});
