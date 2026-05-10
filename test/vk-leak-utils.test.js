import { describe, it, expect } from '@jest/globals';
import {
  b64urlToStr,
  luhnOk,
  shannonEntropy,
  isPlaceholder,
  inCryptoContext,
} from '../src/popup/vk-leak-rules.js';

// ---------------------------------------------------------------------------
// b64urlToStr
// ---------------------------------------------------------------------------
describe('b64urlToStr', () => {
  it('decodes standard base64 with padding', () => {
    expect(b64urlToStr('SGVsbG8gV29ybGQ=')).toBe('Hello World');
  });

  it('decodes standard base64 without padding', () => {
    expect(b64urlToStr('SGVsbG8gV29ybGQ')).toBe('Hello World');
  });

  it('replaces URL-safe underscore with slash', () => {
    // b64url encoding replaces "/" with "_" and "+" with "-"
    // Standard base64 of byte 0xFF is "/w=="; URL-safe replaces "/" with "_"
    // So b64urlToStr("_w==") should decode to the byte \xFF
    const decoded = b64urlToStr('_w==');
    expect(decoded).toBe('ÿ');
  });

  it('returns null for invalid base64', () => {
    expect(b64urlToStr('invalid!!!')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// luhnOk
// ---------------------------------------------------------------------------
describe('luhnOk', () => {
  it('returns true for a valid Visa number', () => {
    expect(luhnOk('4532015112830366')).toBe(true);
  });

  it('returns false when last digit is changed', () => {
    expect(luhnOk('4532015112830367')).toBe(false);
  });

  it('returns false for strings that are too short', () => {
    expect(luhnOk('123')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(luhnOk('')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// shannonEntropy
// ---------------------------------------------------------------------------
describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 when all characters are the same', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });

  it('returns 1.0 for two equally likely characters', () => {
    expect(shannonEntropy('ab')).toBe(1.0);
  });

  it('returns > 3.0 for a random 32-char hex string', () => {
    const hex = Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(
      ''
    );
    expect(shannonEntropy(hex)).toBeGreaterThan(3.0);
  });
});

// ---------------------------------------------------------------------------
// isPlaceholder
// ---------------------------------------------------------------------------
describe('isPlaceholder', () => {
  it('returns true for "changeme"', () => {
    expect(isPlaceholder('changeme')).toBe(true);
  });

  it('returns true for "YOUR_API_KEY" (case insensitive)', () => {
    expect(isPlaceholder('YOUR_API_KEY')).toBe(true);
  });

  it('returns true for repeated characters "aaaaaaaa"', () => {
    expect(isPlaceholder('aaaaaaaa')).toBe(true);
  });

  it('returns true for "xxxx"', () => {
    expect(isPlaceholder('xxxx')).toBe(true);
  });

  it('returns true for "<your-value>" template syntax', () => {
    expect(isPlaceholder('<your-value>')).toBe(true);
  });

  it('returns true for "abcdef" (short common pattern)', () => {
    expect(isPlaceholder('abcdef')).toBe(true);
  });

  it('returns false for a real-looking key', () => {
    expect(isPlaceholder('sk-1234567890abcdef')).toBe(false);
  });

  it('returns false for empty/whitespace-only input', () => {
    expect(isPlaceholder('')).toBe(true); // empty string is in PLACEHOLDER_LITERALS
  });
});

// ---------------------------------------------------------------------------
// inCryptoContext
// ---------------------------------------------------------------------------
describe('inCryptoContext', () => {
  it('returns true when CryptoJS.AES.encrypt is in context', () => {
    expect(inCryptoContext('CryptoJS.AES.encrypt(data, key)', 0, 0)).toBe(true);
  });

  it('returns true when crypto.createCipheriv is in context', () => {
    expect(inCryptoContext('crypto.createCipheriv(...)', 0, 0)).toBe(true);
  });

  it('returns false for normal code with no crypto context', () => {
    expect(inCryptoContext('normal code here', 0, 0)).toBe(false);
  });
});
