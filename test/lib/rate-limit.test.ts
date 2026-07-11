import { describe, it, expect, vi, beforeEach } from 'vitest';

// settings mock：直接控制限流器读到的上限
const settingsState = { maxConcurrentPerHost: 3, minIntervalPerHostMs: 0 };
vi.mock('@/lib/core/settings', () => ({
  loadScanSettings: async () => ({ ...settingsState }),
}));

const storageListeners: Array<(c: any, a: string) => void> = [];
(globalThis as any).browser = {
  storage: {
    onChanged: { addListener: (fn: any) => storageListeners.push(fn) },
  },
};

// 动态导入，确保 mock 生效
const { initRateLimiter, acquire, hostnameOf } = await import('@/lib/background/rate-limit');

describe('rate-limit', () => {
  beforeEach(async () => {
    settingsState.maxConcurrentPerHost = 3;
    settingsState.minIntervalPerHostMs = 0;
    await initRateLimiter();
  });

  it('hostnameOf 解析失败回退到 __unknown__', () => {
    expect(hostnameOf('not-a-url')).toBe('__unknown__');
    expect(hostnameOf('https://example.com/path')).toBe('example.com');
  });

  it('同主机并发不超过上限', async () => {
    let inflight = 0;
    let peak = 0;
    const task = async () => {
      const release = await acquire('host.test');
      inflight++;
      peak = Math.max(peak, inflight);
      // 模拟异步工作
      await new Promise<void>(r => setTimeout(r, 10));
      inflight--;
      release();
    };
    // 启动 20 个任务，上限 3 → peak 应 ≤ 3
    await Promise.all(Array.from({ length: 20 }, () => task()));
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThanOrEqual(1);
  });

  it('不同主机互不阻塞', async () => {
    let done = 0;
    const run = async (host: string) => {
      const release = await acquire(host);
      await new Promise<void>(r => setTimeout(r, 20));
      release();
      done++;
    };
    const t0 = Date.now();
    await Promise.all([run('a.com'), run('b.com'), run('c.com')]);
    const elapsed = Date.now() - t0;
    expect(done).toBe(3);
    // 若互不阻塞，三个并发任务总耗时约等于单个（~20ms），远小于串行（~60ms）
    expect(elapsed).toBeLessThan(55);
  });
});
