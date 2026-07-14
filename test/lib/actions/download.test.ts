import { describe, it, expect, beforeEach, vi } from 'vitest';
import { buildFilename, downloadText, downloadJson, downloadBlob } from '@/lib/actions/download';

// jsdom 未实现 URL.createObjectURL / revokeObjectURL
beforeEach(() => {
  (URL as any).createObjectURL = vi.fn(() => 'blob:test');
  (URL as any).revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
});

describe('download（§6.1）', () => {
  it('buildFilename 格式 lingmou-{module}-{yyyy-mm-dd}.{ext}', () => {
    expect(buildFilename('xss', 'csv')).toMatch(/^lingmou-xss-\d{4}-\d{2}-\d{2}\.csv$/);
    expect(buildFilename('fuzz', '.csv')).toMatch(/^lingmou-fuzz-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  it('downloadText 创建 Blob + 触发 a.click', () => {
    downloadText('hello', 'test.txt');
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalled();
  });

  it('downloadJson 触发下载（JSON 文本）', () => {
    downloadJson({ a: 1 }, 'test.json');
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalled();
  });

  it('downloadBlob 接收 Blob 并触发下载', () => {
    downloadBlob(new Blob(['x']), 'test.bin');
    expect(URL.createObjectURL).toHaveBeenCalled();
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalled();
  });
});
