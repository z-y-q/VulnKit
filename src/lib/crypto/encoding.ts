/**
 * 编码/解码工具 — 灵眸 v6.0
 * 从 vk-encoding.js 提取的纯逻辑，无 UI/Chrome 依赖
 */

export type EncodingType = 'base64' | 'url' | 'html' | 'hex';

export const ENCODING_NAMES: Record<EncodingType, string> = {
  base64: 'Base64',
  url: 'URL',
  html: 'HTML',
  hex: 'Hex',
};

/** Base64 — 支持 UTF-8（修复旧版 btoa 不支持中文的问题） */
export const base64 = {
  encode(text: string): string {
    try {
      const bytes = new TextEncoder().encode(text);
      return btoa(String.fromCharCode(...bytes));
    } catch (e) {
      return `Error: ${(e as Error).message}`;
    }
  },
  decode(text: string): string {
    try {
      const raw = atob(text.trim());
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      return new TextDecoder().decode(bytes);
    } catch {
      return 'Error: invalid Base64';
    }
  },
};

/** URL 编码 */
export const url = {
  encode: encodeURIComponent,
  decode: decodeURIComponent,
};

/** HTML 实体编码（防 XSS） */
export const html = {
  encode(text: string): string {
    const el = document.createElement('div');
    el.textContent = text;
    return el.innerHTML;
  },
  decode(text: string): string {
    const el = document.createElement('div');
    el.innerHTML = text;
    return el.textContent || '';
  },
};

/** Hex 编码 */
export const hex = {
  encode(text: string): string {
    return Array.from(new TextEncoder().encode(text))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },
  decode(text: string): string {
    return new TextDecoder().decode(
      new Uint8Array(text.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || [])
    );
  },
};

/** 编码工具注册表 */
export const encodingTools: Record<EncodingType, { encode: (t: string) => string; decode: (t: string) => string }> = {
  base64,
  url,
  html,
  hex,
};

/** 通用转换入口 */
export function transform(type: EncodingType, mode: 'encode' | 'decode', input: string): string {
  const tool = encodingTools[type];
  if (!tool) return 'Error: 未知编码类型';
  return mode === 'encode' ? tool.encode(input) : tool.decode(input);
}
