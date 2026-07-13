import { describe, it, expect, beforeEach } from 'vitest';

// 内存 storage mock（支持 get(null) 全量 + getManifest；setup.ts 的默认 mock 不持久化且无 getManifest）
const mem: Record<string, any> = {};
(globalThis as any).browser = {
  runtime: {
    getManifest: () => ({ version: '9.9.9' }),
  },
  storage: {
    local: {
      get: async (keys: any) => {
        if (keys === null || keys === undefined) return { ...mem };
        const arr = Array.isArray(keys) ? keys : [keys];
        const out: any = {};
        for (const k of arr) if (k in mem) out[k] = mem[k];
        return out;
      },
      set: async (obj: any) => {
        Object.assign(mem, obj);
      },
      remove: async (keys: any) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        for (const k of arr) delete mem[k];
      },
    },
    onChanged: { addListener: () => {} },
  },
};

const { buildBackup, applyBundle, parseBackup, summarizeBundle } = await import('@/lib/core/backup');

describe('backup 字段白名单（§7.7 / §10.5）', () => {
  beforeEach(() => {
    for (const k of Object.keys(mem)) delete mem[k];
  });

  it('buildBackup 默认排除 secrets / transient / 未知 key', async () => {
    Object.assign(mem, {
      lingmouPrefs: { a: 1 }, // preferences
      panelLayout: { order: [], hidden: [] }, // preferences
      haeCustomRules: 'yaml', // rules
      pentest_scan_history: [{ x: 1 }], // history
      lingmou_zoomeye_key: 'SECRET-KEY', // secrets — 必须排除
      pentest_spoof: { ua: 'x' }, // secrets — 必须排除
      pendingAction: { tabId: 1 }, // transient — 必须排除
      __pendingCopy: 'clip', // transient — 必须排除
      someUnknownKey: 'evil', // 未知 — 必须排除
    });
    const bundle = await buildBackup();
    expect(bundle.data).toHaveProperty('lingmouPrefs');
    expect(bundle.data).toHaveProperty('panelLayout');
    expect(bundle.data).toHaveProperty('haeCustomRules');
    expect(bundle.data).toHaveProperty('pentest_scan_history');
    expect(bundle.data).not.toHaveProperty('lingmou_zoomeye_key');
    expect(bundle.data).not.toHaveProperty('pentest_spoof');
    expect(bundle.data).not.toHaveProperty('pendingAction');
    expect(bundle.data).not.toHaveProperty('__pendingCopy');
    expect(bundle.data).not.toHaveProperty('someUnknownKey');
    // 明文序列化结果不应出现密钥值
    expect(JSON.stringify(bundle.data)).not.toContain('SECRET-KEY');
  });

  it('buildBackup includeSecrets 含 secrets，但仍排除 transient / 未知', async () => {
    Object.assign(mem, {
      lingmou_zoomeye_key: 'SECRET-KEY',
      pentest_spoof: { ua: 'x' },
      pendingAction: { tabId: 1 },
      unknownX: 1,
    });
    const bundle = await buildBackup({ includeSecrets: true });
    expect(bundle.data).toHaveProperty('lingmou_zoomeye_key');
    expect(bundle.data).toHaveProperty('pentest_spoof');
    expect(bundle.data).not.toHaveProperty('pendingAction');
    expect(bundle.data).not.toHaveProperty('unknownX');
  });

  it('buildBackup includeHistory=false 排除历史', async () => {
    mem.pentest_scan_history = [{ x: 1 }];
    const bundle = await buildBackup({ includeHistory: false });
    expect(bundle.data).not.toHaveProperty('pentest_scan_history');
  });

  it('buildBackup 写入 schemaVersion / appVersion / exportedAt / categories', async () => {
    mem.lingmouPrefs = { a: 1 };
    const bundle = await buildBackup();
    expect(bundle.schemaVersion).toBe(1);
    expect(bundle.appVersion).toBe('9.9.9');
    expect(typeof bundle.exportedAt).toBe('number');
    expect(bundle.categories.length).toBeGreaterThan(0);
    expect(bundle.categories.some((c) => c.name === 'preferences')).toBe(true);
  });

  it('applyBundle 默认不写 secrets / transient / 未知 key', async () => {
    const bundle = {
      schemaVersion: 1,
      appVersion: '1',
      exportedAt: 0,
      categories: [],
      data: {
        lingmouPrefs: { a: 1 },
        lingmou_zoomeye_key: 'SECRET',
        pendingAction: { x: 1 },
        unknownKey: 'evil',
      },
    } as any;
    const result = await applyBundle(bundle);
    expect(result.applied).toContain('lingmouPrefs');
    expect(result.applied).not.toContain('lingmou_zoomeye_key');
    expect(result.skipped).toContain('lingmou_zoomeye_key');
    expect(result.skipped).toContain('unknownKey');
    expect(mem.lingmou_zoomeye_key).toBeUndefined();
    expect(mem.lingmouPrefs).toEqual({ a: 1 });
  });

  it('applyBundle includeSecrets 写入 secrets', async () => {
    const bundle = {
      schemaVersion: 1,
      appVersion: '1',
      exportedAt: 0,
      categories: [],
      data: { lingmou_zoomeye_key: 'K' },
    } as any;
    await applyBundle(bundle, { includeSecrets: true });
    expect(mem.lingmou_zoomeye_key).toBe('K');
  });

  it('applyBundle overwrite 清偏好/规则/历史，但不清本机密钥', async () => {
    mem.lingmouPrefs = { old: 1 };
    mem.lingmou_zoomeye_key = 'EXISTING-KEY';
    mem.haeCustomRules = 'oldyaml';
    mem.pentest_scan_history = [{ old: 1 }];
    const bundle = {
      schemaVersion: 1,
      appVersion: '1',
      exportedAt: 0,
      categories: [],
      data: { haeCustomRules: 'newyaml' },
    } as any;
    await applyBundle(bundle, { mode: 'overwrite' });
    expect(mem.haeCustomRules).toBe('newyaml');
    expect(mem.lingmouPrefs).toBeUndefined(); // preferences 被清
    expect(mem.pentest_scan_history).toBeUndefined(); // history 被清
    expect(mem.lingmou_zoomeye_key).toBe('EXISTING-KEY'); // secrets 不清
  });

  it('parseBackup 新格式直接返回，不误判为 legacy', () => {
    const raw = {
      schemaVersion: 1,
      appVersion: '7',
      exportedAt: 1,
      categories: [],
      data: { lingmouPrefs: { a: 1 } },
    };
    const { bundle, legacy, unknownKeys } = parseBackup(raw);
    expect(legacy).toBe(false);
    expect(bundle!.data).toHaveProperty('lingmouPrefs');
    expect(unknownKeys).toEqual([]);
  });

  it('parseBackup 旧格式 {__app, data} 按白名单过滤并收集未知 key', () => {
    const raw = {
      __app: 'lingmou-v6',
      __exportedAt: 123,
      data: { lingmouPrefs: { a: 1 }, pendingAction: { x: 1 }, evilKey: 'x' },
    };
    const { bundle, legacy, unknownKeys } = parseBackup(raw);
    expect(legacy).toBe(true);
    expect(bundle!.data).toHaveProperty('lingmouPrefs');
    expect(bundle!.data).not.toHaveProperty('pendingAction'); // transient 过滤
    expect(unknownKeys).toContain('evilKey');
  });

  it('parseBackup 裸 storage 对象（无 data 包裹）兼容', () => {
    const raw = { lingmouPrefs: { a: 1 }, evilKey: 'x' };
    const { bundle, legacy, unknownKeys } = parseBackup(raw);
    expect(legacy).toBe(true);
    expect(bundle!.data).toHaveProperty('lingmouPrefs');
    expect(unknownKeys).toContain('evilKey');
  });

  it('summarizeBundle 基于 data 重算类别（legacy 也能正确预览）', () => {
    const bundle = {
      schemaVersion: 1,
      appVersion: '1',
      exportedAt: 0,
      categories: [], // legacy 无类别摘要
      data: { lingmouPrefs: { a: 1 }, haeCustomRules: 'y', lingmou_zoomeye_key: 'K' },
    } as any;
    const s = summarizeBundle(bundle);
    expect(s.totalKeys).toBe(3);
    expect(s.hasSecrets).toBe(true);
    const cats = s.categories.map((c) => c.name);
    expect(cats).toContain('preferences');
    expect(cats).toContain('rules');
    expect(cats).toContain('secrets');
  });

  it('parseBackup 无效输入返回 null bundle', () => {
    expect(parseBackup(null).bundle).toBeNull();
    expect(parseBackup('string').bundle).toBeNull();
    expect(parseBackup(undefined).bundle).toBeNull();
  });
});
