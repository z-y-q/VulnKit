import { describe, it, expect } from 'vitest';

// 灵眸 v6.0 编码工具纯逻辑测试
// 从 EncodingPanel.svelte 提取的转换逻辑，验证核心功能正确

describe('编码工具核心逻辑', () => {
  describe('Base64', () => {
    it('编码 ASCII', () => {
      expect(btoa('hello')).toBe('aGVsbG8=');
    });
    it('编码 UTF-8 需先转字节', () => {
      // 非 ASCII 字符 btoa 不支持，必须先 TextEncoder
      const bytes = new TextEncoder().encode('灵眸');
      const encoded = btoa(String.fromCharCode(...bytes));
      // 验证往返正确
      const decoded = new TextDecoder().decode(
        new Uint8Array(Array.from(atob(encoded), c => c.charCodeAt(0)))
      );
      expect(decoded).toBe('灵眸');
    });
    it('解码', () => {
      expect(atob('aGVsbG8=')).toBe('hello');
    });
    it('编解码往返', () => {
      const text = 'test payload <script>alert(1)</script>';
      expect(atob(btoa(text))).toBe(text);
    });
  });

  describe('URL 编码', () => {
    it('编码特殊字符', () => {
      expect(encodeURIComponent('a b&c=d')).toBe('a%20b%26c%3Dd');
    });
    it('解码', () => {
      expect(decodeURIComponent('a%20b%26c%3Dd')).toBe('a b&c=d');
    });
  });

  describe('HTML 实体', () => {
    it('编码防 XSS', () => {
      const el = document.createElement('span');
      el.textContent = '<script>alert(1)</script>';
      expect(el.innerHTML).toContain('&lt;script&gt;');
    });
  });

  describe('Hex', () => {
    it('编码 ASCII', () => {
      const bytes = Array.from(new TextEncoder().encode('AB'))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
      expect(bytes).toBe('41 42');
    });
    it('解码', () => {
      const decoded = new TextDecoder().decode(
        new Uint8Array('41 42'.trim().split(/\s+/).map(h => parseInt(h, 16)))
      );
      expect(decoded).toBe('AB');
    });
  });
});
