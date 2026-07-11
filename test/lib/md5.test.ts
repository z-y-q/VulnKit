import { describe, it, expect } from 'vitest';
import { md5, md5String } from '@/lib/core/md5';

describe('md5', () => {
  // RFC 1321 标准测试向量
  it('空字符串 → d41d8cd98f00b204e9800998ecf8427e', () => {
    expect(md5(new Uint8Array([]))).toBe('d41d8cd98f00b204e9800998ecf8427e');
  });

  it('"a" → 0cc175b9c0f1b6a831c399e269772661', () => {
    expect(md5String('a')).toBe('0cc175b9c0f1b6a831c399e269772661');
  });

  it('"abc" → 900150983cd24fb0d6963f7d28e17f72', () => {
    expect(md5String('abc')).toBe('900150983cd24fb0d6963f7d28e17f72');
  });

  it('"message digest" → f96b697d7cb7938d525a2f31aaf161d0', () => {
    expect(md5String('message digest')).toBe('f96b697d7cb7938d525a2f31aaf161d0');
  });

  it('"abcdefghijklmnopqrstuvwxyz" → c3fcd3d76192e4007dfb496cca67e13b', () => {
    expect(md5String('abcdefghijklmnopqrstuvwxyz')).toBe('c3fcd3d76192e4007dfb496cca67e13b');
  });

  it('较长输入触发多块处理（>56 字节）', () => {
    expect(md5String('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).toBe(
      'd174ab98d277d9f5a5611c2c9f419d9f',
    );
  });

  it('UTF-8 多字节字符正确编码', () => {
    // "灵眸" 的 UTF-8 字节 MD5
    expect(md5String('灵眸')).toBe(md5(new TextEncoder().encode('灵眸')));
  });

  it('两次相同输入产生相同输出（确定性）', () => {
    expect(md5String('test 灵眸 v6')).toBe(md5String('test 灵眸 v6'));
  });
});
