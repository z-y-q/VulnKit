/**
 * 按主机限流器 — 灵眸 v6.0 background 侧
 *
 * 双重控制：
 *   1. 最大并发（per-host semaphore）—— 同一主机同时在飞的请求上限
 *   2. 最小间隔（per-host pacing）—— 同主机相邻请求至少间隔 N ms
 *
 * 跨面板全局生效：XSS / CORS / Fuzz 同时开打也只会有 maxConcurrentPerHost
 * 个请求落在同一主机上。这是"控制测试强度"（SRC 合规）的机制保障。
 *
 * 设置在 SW 启动时加载，并监听 storage 变更热更新，避免每次请求读 storage。
 */
import { loadScanSettings, type ScanSettings } from '@/lib/core/settings';

interface HostGate {
  running: number;
  queue: Array<{ resolve: () => void }>;
  lastReleasedAt: number;
}

const gates = new Map<string, HostGate>();
let settings: ScanSettings | null = null;

/** SW 启动时调用：加载设置并订阅变更 */
export async function initRateLimiter(): Promise<void> {
  settings = await loadScanSettings();
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.pentestSettings) {
      // 重新加载完整合并 + 范围裁剪
      void loadScanSettings().then(s => {
        settings = s;
      });
    }
  });
}

function getGate(hostname: string): HostGate {
  let g = gates.get(hostname);
  if (!g) {
    g = { running: 0, queue: [], lastReleasedAt: 0 };
    gates.set(hostname, g);
  }
  return g;
}

function currentSettings(): ScanSettings {
  return settings ?? { maxConcurrentPerHost: 6, minIntervalPerHostMs: 0 } as ScanSettings;
}

/**
 * 获取对某主机的访问权（在发起 fetch 前 await）。
 * 返回 release 函数，请求结束后必须调用（用 try/finally）。
 */
export async function acquire(hostname: string): Promise<() => void> {
  const s = currentSettings();
  const gate = getGate(hostname);

  // 并发已满 → 排队
  if (gate.running >= s.maxConcurrentPerHost) {
    await new Promise<void>(resolve => gate.queue.push({ resolve }));
  }
  gate.running++;

  // 最小间隔 pacing：距上次 release 不足 interval 则补齐等待
  if (s.minIntervalPerHostMs > 0 && gate.lastReleasedAt > 0) {
    const elapsed = Date.now() - gate.lastReleasedAt;
    const wait = s.minIntervalPerHostMs - elapsed;
    if (wait > 0) await new Promise<void>(r => setTimeout(r, wait));
  }

  let released = false;
  return () => {
    if (released) return;
    released = true;
    gate.running--;
    gate.lastReleasedAt = Date.now();
    const next = gate.queue.shift();
    if (next) next.resolve();
  };
}

/** 从 URL 提取 hostname；解析失败回退 '__unknown__'（仍受限，避免绕过） */
export function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname || '__unknown__';
  } catch {
    return '__unknown__';
  }
}
