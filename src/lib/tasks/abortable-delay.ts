/**
 * 可取消延时
 *
 * 对齐 docs/个人版项目优化路线.md §2.3。
 * 替代裸 `setTimeout` + 手动句柄管理：与 AbortSignal 绑定，
 * signal abort 时立即 reject 并清理 timer，避免回调在组件卸载/任务取消后仍执行。
 *
 * 典型用法（配合 TaskController）：
 *   await abortableDelay(3000, ctx.signal);
 *   if (!ctx.isCurrent()) return; // 旧任务结果丢弃
 */

export function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }

    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}
