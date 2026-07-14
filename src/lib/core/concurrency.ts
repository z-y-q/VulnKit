/**
 * 并发执行器
 *
 * 统一各扫描面板的 worker 循环模板：
 *   并发限流 + 可取消 + 索引自增。
 * 取代各面板手写的 `idx++ / worker() / Promise.all(Array.from(...))` 样板。
 */

export interface ConcurrentOptions {
  /** 并发 worker 数（<1 视为 1） */
  concurrency: number;
  /** 可选取消信号：返回 true 时停止派发新任务（在飞任务自然完成） */
  cancelled?: () => boolean;
  /** 可选暂停信号：返回 true 时 worker 等待（不派发新任务），恢复后继续 */
  paused?: () => boolean;
}

/**
 * 对 items 并发执行 fn，每个 item 由一个 worker 顺序消费，最多 concurrency 个 worker 并行。
 * fn 接收 (item, index)。worker 在派发前检查 cancelled。
 */
export async function runConcurrent<T>(
  items: readonly T[],
  fn: (item: T, index: number) => Promise<void>,
  opts: ConcurrentOptions,
): Promise<void> {
  const n = Math.max(1, Math.floor(opts.concurrency) || 1);
  let idx = 0;

  async function worker() {
    while (idx < items.length) {
      if (opts.cancelled?.()) return;
      while (opts.paused?.()) {
        if (opts.cancelled?.()) return;
        await new Promise<void>(r => setTimeout(r, 200));
      }
      const cur = idx++;
      await fn(items[cur], cur);
    }
  }

  await Promise.all(Array.from({ length: n }, () => worker()));
}
