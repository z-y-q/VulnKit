import { describe, it, expect, beforeEach } from 'vitest';
import {
  normalizeScanSettings,
  DEFAULT_SCAN_SETTINGS,
  SCAN_SETTINGS_BOUNDS,
} from '@/lib/core/settings';

// browser 全局 mock（setup.ts 提供 chrome/wxt mock，这里补 browser.storage）
const storage: Record<string, any> = {};
(globalThis as any).browser = {
  storage: {
    local: {
      get: async (keys: string | string[]) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        const out: any = {};
        for (const k of arr) if (k in storage) out[k] = storage[k];
        return out;
      },
      set: async (obj: any) => {
        Object.assign(storage, obj);
      },
    },
    onChanged: { addListener: () => {} },
  },
};

describe('settings normalize', () => {
  beforeEach(() => {
    for (const k of Object.keys(storage)) delete storage[k];
  });

  it('空输入返回默认值', () => {
    expect(normalizeScanSettings(undefined)).toEqual(DEFAULT_SCAN_SETTINGS);
  });

  it('越界值被裁剪到合法范围', () => {
    const s = normalizeScanSettings({
      requestTimeoutMs: 1,
      concurrency: 999,
      maxConcurrentPerHost: 0,
      minIntervalPerHostMs: -5,
    });
    expect(s.requestTimeoutMs).toBe(SCAN_SETTINGS_BOUNDS.requestTimeoutMs.min);
    expect(s.concurrency).toBe(SCAN_SETTINGS_BOUNDS.concurrency.max);
    expect(s.maxConcurrentPerHost).toBe(SCAN_SETTINGS_BOUNDS.maxConcurrentPerHost.min);
    expect(s.minIntervalPerHostMs).toBe(SCAN_SETTINGS_BOUNDS.minIntervalPerHostMs.min);
  });

  it('合法值原样保留（四舍五入）', () => {
    const s = normalizeScanSettings({
      requestTimeoutMs: 7000,
      concurrency: 4,
      maxConcurrentPerHost: 3,
      minIntervalPerHostMs: 200,
    });
    expect(s).toEqual({
      requestTimeoutMs: 7000,
      concurrency: 4,
      maxConcurrentPerHost: 3,
      minIntervalPerHostMs: 200,
    });
  });

  it('非数字回退到默认', () => {
    const s = normalizeScanSettings({ concurrency: 'abc' as unknown as number });
    expect(s.concurrency).toBe(DEFAULT_SCAN_SETTINGS.concurrency);
  });
});
