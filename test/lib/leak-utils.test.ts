import { describe, it, expect } from 'vitest';
import {
  b64urlToStr,
  luhnOk,
  shannonEntropy,
  isPlaceholder,
  inCryptoContext,
  PLACEHOLDER_LITERALS,
} from '@/lib/scanners/leak-utils';

describe('leak-utils: b64urlToStr', () => {
  it('解码 URL 安全 base64', () => {
    expect(b64urlToStr('aGVsbG8')).toBe('hello');
  });
  it('兼容标准 base64', () => {
    expect(b64urlToStr('aGVsbG8=')).toBe('hello');
  });
  it('无效输入返回 null', () => {
    expect(b64urlToStr('!!!invalid!!!')).toBeNull();
  });
});

describe('leak-utils: luhnOk（信用卡 Luhn 校验）', () => {
  it('合法 Visa 测试卡通过', () => {
    expect(luhnOk('4111111111111111')).toBe(true);
  });
  it('合法 Mastercard 测试卡通过', () => {
    expect(luhnOk('5555555555554444')).toBe(true);
  });
  it('错误卡号不通过', () => {
    expect(luhnOk('4111111111111112')).toBe(false);
  });
  it('过短数字不通过', () => {
    expect(luhnOk('123456')).toBe(false);
  });
  it('支持含空格的输入', () => {
    expect(luhnOk('4111 1111 1111 1111')).toBe(true);
  });
});

describe('leak-utils: shannonEntropy', () => {
  it('空字符串熵为 0', () => {
    expect(shannonEntropy('')).toBe(0);
  });
  it('单一字符熵为 0', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });
  it('随机字符串熵高于重复字符串', () => {
    const random = shannonEntropy('x8f2k9p1q');
    const repeated = shannonEntropy('aaaaaaaa');
    expect(random).toBeGreaterThan(repeated);
  });
  it('高熵密钥特征', () => {
    // 模拟 32 字节随机密钥的 hex
    const key = 'a3f5b8c1d9e702f4a6b8c0d2e4f608a1';
    expect(shannonEntropy(key)).toBeGreaterThan(3.5);
  });
});

describe('leak-utils: isPlaceholder', () => {
  it('识别占位符字面量', () => {
    expect(isPlaceholder('your-api-key')).toBe(true);
    expect(isPlaceholder('changeme')).toBe(true);
    expect(isPlaceholder('example')).toBe(true);
  });
  it('识别全相同字符', () => {
    expect(isPlaceholder('0000000000')).toBe(true);
    expect(isPlaceholder('aaaaaaaa')).toBe(true);
  });
  it('识别全 x', () => {
    expect(isPlaceholder('xxxxxxxxxxxx')).toBe(true);
  });
  it('识别 <placeholder> 格式', () => {
    expect(isPlaceholder('<your-key>')).toBe(true);
  });
  it('真实密钥不是占位符', () => {
    expect(isPlaceholder('sk-abc123def456ghi789jkl012mno345')).toBe(false);
    expect(isPlaceholder('AKIAIOSFODNN7EXAMPLE')).toBe(false);
  });
  it('PLACEHOLDER_LITERALS 非空', () => {
    expect(PLACEHOLDER_LITERALS.length).toBeGreaterThan(10);
  });
});

describe('leak-utils: inCryptoContext', () => {
  const source = 'var x = 1; CryptoJS.AES.encrypt(data, key); var match = "AKIA1234567890";';
  it('加密上下文中的匹配返回 true', () => {
    const offset = source.indexOf('AKIA1234567890');
    expect(inCryptoContext(source, offset, 12)).toBe(true);
  });
  it('非加密上下文返回 false', () => {
    const plain = 'some text AKIA1234567890 more text without crypto nearby';
    const offset = plain.indexOf('AKIA1234567890');
    expect(inCryptoContext(plain, offset, 12)).toBe(false);
  });
});
