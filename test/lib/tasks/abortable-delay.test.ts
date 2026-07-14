import { describe, it, expect } from 'vitest';
import { abortableDelay } from '@/lib/tasks/abortable-delay';

describe('abortableDelay（§2.3）', () => {
  it('到时 resolve', async () => {
    const ac = new AbortController();
    await expect(abortableDelay(20, ac.signal)).resolves.toBeUndefined();
  });

  it('已 abort 的 signal 立即 reject', async () => {
    const ac = new AbortController();
    ac.abort(new Error('cancelled'));
    await expect(abortableDelay(100, ac.signal)).rejects.toThrow('cancelled');
  });

  it('运行中 abort 触发 reject', async () => {
    const ac = new AbortController();
    const p = abortableDelay(100, ac.signal);
    ac.abort(new Error('cancelled'));
    await expect(p).rejects.toThrow('cancelled');
  });

  it('无参 abort reject 默认 AbortError', async () => {
    const ac = new AbortController();
    const p = abortableDelay(100, ac.signal);
    ac.abort();
    await expect(p).rejects.toThrow('aborted');
  });

  it('多个 delay 各自独立，互不干扰', async () => {
    const a = new AbortController();
    const b = new AbortController();
    const pa = abortableDelay(20, a.signal);
    const pb = abortableDelay(80, b.signal);
    b.abort(new Error('b cancelled'));
    await expect(pb).rejects.toThrow('b cancelled');
    await expect(pa).resolves.toBeUndefined();
  });
});
