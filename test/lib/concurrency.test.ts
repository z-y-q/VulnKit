import { describe, it, expect } from 'vitest';
import { runConcurrent } from '@/lib/core/concurrency';

describe('runConcurrent', () => {
  it('处理全部 items 且并发不超过上限', async () => {
    const items = Array.from({ length: 50 }, (_, i) => i);
    let inflight = 0;
    let peak = 0;
    const seen: number[] = [];

    await runConcurrent(items, async (item) => {
      inflight++;
      peak = Math.max(peak, inflight);
      seen.push(item);
      await new Promise<void>(r => setTimeout(r, 5));
      inflight--;
    }, { concurrency: 4 });

    expect(seen.sort((a, b) => a - b)).toEqual(items);
    expect(peak).toBeLessThanOrEqual(4);
  });

  it('cancelled 信号停止派发新任务', async () => {
    let processed = 0;
    let stop = false;
    const items = Array.from({ length: 100 }, () => 0);

    // 处理 3 个后触发取消
    const proc = async () => {
      processed++;
      if (processed >= 3) stop = true;
      await new Promise<void>(r => setTimeout(r, 10));
    };
    await runConcurrent(items, proc, { concurrency: 2, cancelled: () => stop });

    // 并发 2 + 取消时在飞 2 → 最多处理约 3~5 个，远小于 100
    expect(processed).toBeLessThan(10);
    expect(processed).toBeGreaterThanOrEqual(3);
  });

  it('concurrency < 1 视为 1，items 为空不报错', async () => {
    let calls = 0;
    await runConcurrent([], async () => { calls++; }, { concurrency: 0 });
    expect(calls).toBe(0);
    await runConcurrent([1, 2, 3], async () => { calls++; }, { concurrency: -5 });
    expect(calls).toBe(3);
  });

  it('fn 接收正确的 index', async () => {
    const indices: number[] = [];
    await runConcurrent(['a', 'b', 'c'], async (_item, i) => { indices.push(i); }, { concurrency: 3 });
    expect(indices.sort((a, b) => a - b)).toEqual([0, 1, 2]);
  });
});
