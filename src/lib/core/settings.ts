/**
 * 扫描参数设置
 *
 * 复用 browser.storage.local key `pentestSettings`（contextMenus 已用此 key 存
 * enableContextMenu）。此处扩展扫描相关参数：请求超时、并发数、每主机限流。
 *
 * 设计目标：把"控制测试强度"从口头规则变成机制保障（SRC 合规硬性要求）。
 * background 与 UI 都可使用本模块（纯 storage 访问，无框架依赖）。
 */

const STORAGE_KEY = 'pentestSettings';

/** 扫描参数默认值 */
export const DEFAULT_SCAN_SETTINGS: ScanSettings = {
  requestTimeoutMs: 10000,
  concurrency: 6,
  maxConcurrentPerHost: 6,
  minIntervalPerHostMs: 0, // 0 = 不限速；>0 则同主机相邻请求至少间隔该毫秒
};

/** 合法范围（options UI 与写入校验共用） */
export const SCAN_SETTINGS_BOUNDS = {
  requestTimeoutMs: { min: 3000, max: 60000 },
  concurrency: { min: 1, max: 16 },
  maxConcurrentPerHost: { min: 1, max: 16 },
  minIntervalPerHostMs: { min: 0, max: 5000 },
} as const;

export interface ScanSettings {
  /** 单次 HTTP 请求超时（毫秒） */
  requestTimeoutMs: number;
  /** 单个扫描面板的并发 worker 数 */
  concurrency: number;
  /** 同一主机同时在飞的请求上限（跨面板全局生效，background 令牌桶） */
  maxConcurrentPerHost: number;
  /** 同一主机相邻两次请求的最小间隔（毫秒），用于温和限速 */
  minIntervalPerHostMs: number;
}

export interface PentestSettings extends Partial<ScanSettings> {
  enableContextMenu?: boolean;
}

/** 把任意 partial 合并到默认值上，并做范围裁剪 */
export function normalizeScanSettings(raw: Partial<ScanSettings> | undefined): ScanSettings {
  const clamp = (
    v: number | undefined,
    bound: { min: number; max: number },
    fallback: number,
  ): number => {
    if (typeof v !== 'number' || Number.isNaN(v)) return fallback;
    return Math.min(bound.max, Math.max(bound.min, Math.round(v)));
  };
  return {
    requestTimeoutMs: clamp(
      raw?.requestTimeoutMs,
      SCAN_SETTINGS_BOUNDS.requestTimeoutMs,
      DEFAULT_SCAN_SETTINGS.requestTimeoutMs,
    ),
    concurrency: clamp(
      raw?.concurrency,
      SCAN_SETTINGS_BOUNDS.concurrency,
      DEFAULT_SCAN_SETTINGS.concurrency,
    ),
    maxConcurrentPerHost: clamp(
      raw?.maxConcurrentPerHost,
      SCAN_SETTINGS_BOUNDS.maxConcurrentPerHost,
      DEFAULT_SCAN_SETTINGS.maxConcurrentPerHost,
    ),
    minIntervalPerHostMs: clamp(
      raw?.minIntervalPerHostMs,
      SCAN_SETTINGS_BOUNDS.minIntervalPerHostMs,
      DEFAULT_SCAN_SETTINGS.minIntervalPerHostMs,
    ),
  };
}

/** 从 storage 读取并合并默认值（异步） */
export async function loadScanSettings(): Promise<ScanSettings> {
  try {
    const data = await browser.storage.local.get(STORAGE_KEY);
    const raw = (data[STORAGE_KEY] || {}) as Partial<ScanSettings>;
    return normalizeScanSettings(raw);
  } catch {
    return { ...DEFAULT_SCAN_SETTINGS };
  }
}

/** 写入扫描参数（保留同 key 下其他字段，如 enableContextMenu） */
export async function saveScanSettings(patch: Partial<ScanSettings>): Promise<void> {
  const data = await browser.storage.local.get(STORAGE_KEY);
  const current = (data[STORAGE_KEY] || {}) as PentestSettings;
  const next: PentestSettings = { ...current, ...normalizeScanSettings({ ...current, ...patch }) };
  await browser.storage.local.set({ [STORAGE_KEY]: next });
}
