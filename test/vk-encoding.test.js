import { describe, it, expect } from '@jest/globals';
import { encodingTools } from '../src/popup/vk-encoding.js';

describe('encodingTools.base64', () => {
  it('encode("Hello World") returns btoa-compatible result', () => {
    const result = encodingTools.base64.encode('Hello World');
    expect(result).toBe(btoa(unescape(encodeURIComponent('Hello World'))));
  });

  it('decode(encode("Hello World")) roundtrips correctly', () => {
    const encoded = encodingTools.base64.encode('Hello World');
    const decoded = encodingTools.base64.decode(encoded);
    expect(decoded).toBe('Hello World');
  });

  it('encode("") returns ""', () => {
    expect(encodingTools.base64.encode('')).toBe('');
  });

  it('encode Unicode "中文" roundtrips correctly', () => {
    const encoded = encodingTools.base64.encode('中文');
    const decoded = encodingTools.base64.decode(encoded);
    expect(decoded).toBe('中文');
  });

  it('decode invalid base64 returns "Error: invalid Base64"', () => {
    expect(encodingTools.base64.decode('!!!not-valid!!!')).toBe('Error: invalid Base64');
  });
});

describe('encodingTools.url', () => {
  it('encode("hello world&foo=bar") returns encodeURIComponent result', () => {
    const result = encodingTools.url.encode('hello world&foo=bar');
    expect(result).toBe(encodeURIComponent('hello world&foo=bar'));
  });

  it('decode roundtrips correctly', () => {
    const encoded = encodingTools.url.encode('hello world&foo=bar');
    const decoded = encodingTools.url.decode(encoded);
    expect(decoded).toBe('hello world&foo=bar');
  });

  it('encode("中文") roundtrips correctly', () => {
    const encoded = encodingTools.url.encode('中文');
    const decoded = encodingTools.url.decode(encoded);
    expect(decoded).toBe('中文');
  });
});

describe('encodingTools.hex', () => {
  it('encode("AB") returns "4142"', () => {
    expect(encodingTools.hex.encode('AB')).toBe('4142');
  });

  it('decode("4142") returns "AB"', () => {
    expect(encodingTools.hex.decode('4142')).toBe('AB');
  });

  it('encode("") returns ""', () => {
    expect(encodingTools.hex.encode('')).toBe('');
  });

  it('decode("") returns ""', () => {
    expect(encodingTools.hex.decode('')).toBe('');
  });
});
