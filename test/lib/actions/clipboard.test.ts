import { describe, it, expect, beforeEach, vi } from 'vitest';
import { copyText, copyLines } from '@/lib/actions/clipboard';

let writeTextMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  writeTextMock = vi.fn();
  // jsdom 默认无 navigator.clipboard，手动注入
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: writeTextMock },
    configurable: true,
  });
});

describe('clipboard（§6.1）', () => {
  it('copyText 成功 → 返回 true 且调用 writeText', async () => {
    writeTextMock.mockResolvedValue(undefined);
    const r = await copyText('hi');
    expect(r).toBe(true);
    expect(writeTextMock).toHaveBeenCalledWith('hi');
  });

  it('copyText 失败 → 返回 false（不静默报成功）', async () => {
    writeTextMock.mockRejectedValue(new Error('denied'));
    const r = await copyText('hi');
    expect(r).toBe(false);
    expect(writeTextMock).toHaveBeenCalled();
  });

  it('copyLines 空数组 → 返回 false', async () => {
    const r = await copyLines([]);
    expect(r).toBe(false);
    expect(writeTextMock).not.toHaveBeenCalled();
  });

  it('copyLines 拼接多行并自定义提示', async () => {
    writeTextMock.mockResolvedValue(undefined);
    const r = await copyLines(['a', 'b']);
    expect(r).toBe(true);
    expect(writeTextMock).toHaveBeenCalledWith('a\nb');
  });
});
