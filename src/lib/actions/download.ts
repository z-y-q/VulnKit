/**
 * 文件下载
 *
 * 统一各面板手写的 `new Blob + createObjectURL + a.click + setTimeout(revoke)` 模板。
 * 对齐 docs/UX-UI优化建议.md §6.1：文件名规范 lingmou-{module}-{yyyy-mm-dd}.{ext}，
 * revokeObjectURL 在点击后安全延迟释放。
 */

import { toJson } from './serializers';

/** 构造规范文件名：lingmou-{module}-{yyyy-mm-dd}.{ext}（ext 去掉前导点） */
export function buildFilename(module: string, ext: string): string {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const cleanExt = ext.replace(/^\.*/, '');
  return `lingmou-${module}-${yyyy}-${mm}-${dd}.${cleanExt}`;
}

/** 触发文本内容下载。createObjectURL → click，1s 后释放 URL。 */
export function downloadText(
  content: string,
  filename: string,
  mime = 'text/plain;charset=utf-8',
): void {
  const blob = new Blob([content], { type: mime });
  triggerDownload(blob, filename);
}

/** JSON 下载（美化序列化）。 */
export function downloadJson(data: unknown, filename: string): void {
  downloadText(toJson(data), filename, 'application/json;charset=utf-8');
}

/** 通用 Blob 下载（二进制，如 zip）。调用方负责构造 Blob。 */
export function downloadBlob(blob: Blob, filename: string): void {
  triggerDownload(blob, filename);
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    // 延迟释放：部分浏览器需 click 后 URL 仍存活一小段时间才能完成下载
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
