/**
 * 应用版本统一来源 — 灵眸 v7.3
 *
 * 解决历史版本号漂移：Popup 曾写 v7.0、StatusBar/Options 写 v6.0、
 * 报告元数据写 6.0.0，而 Side Panel 顶栏从 manifest 动态读取。
 *
 * 规则（对齐 docs/UX-UI优化建议.md §7.6 / §10.6）：
 * - runtime UI：优先 `browser.runtime.getManifest().version`；
 * - 非 runtime 纯函数（如 report-builder）：由调用方注入 appVersion；
 * - 报告/备份元数据：写入同一版本；
 * - 代码注释不保留易过时的产品版本号。
 */

let _cached: string | null = null;

/** 返回 manifest 中的版本号；取不到时回退到 '0.0.0'。结果缓存。 */
export function getAppVersion(): string {
  if (_cached) return _cached;
  try {
    // browser 在扩展上下文可用；在纯单测/非扩展环境降级
    const ver = (globalThis as any)?.browser?.runtime?.getManifest?.()?.version;
    _cached = typeof ver === 'string' && ver ? ver : '0.0.0';
  } catch {
    _cached = '0.0.0';
  }
  return _cached;
}
