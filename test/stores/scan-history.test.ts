import { describe, it, expect, beforeEach } from 'vitest';

// Map 真实回填的 storage.local mock（setup.ts 的默认 mock 不持久化）
const mem: Record<string, any> = {};
(globalThis as any).browser = {
  storage: {
    local: {
      get: async (keys: string | string[]) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        const out: any = {};
        for (const k of arr) if (k in mem) out[k] = mem[k];
        return out;
      },
      set: async (obj: any) => {
        Object.assign(mem, obj);
      },
      remove: async (keys: string | string[]) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        for (const k of arr) delete mem[k];
      },
    },
    onChanged: { addListener: () => {} },
  },
};

const { scanHistoryStore } = await import('@/stores/scan-history');

function finding(title: string, severity: any = 'high') {
  return { title, severity, detail: 'd', evidence: 'e', url: 'https://a.test/x' };
}

describe('scan-history store', () => {
  beforeEach(async () => {
    for (const k of Object.keys(mem)) delete mem[k];
    await scanHistoryStore.clear();
  });

  it('addScan 写入并可读取', async () => {
    await scanHistoryStore.addScan({
      url: 'https://a.test/p',
      module: 'cors',
      findings: [finding('CORS 反射')],
    });
    await scanHistoryStore.refresh();
    let entries: any[] = [];
    const unsub = scanHistoryStore.subscribe(e => (entries = e));
    unsub();
    expect(entries.length).toBe(1);
    expect(entries[0].module).toBe('cors');
    expect(entries[0].summary.total).toBe(1);
  });

  it('L2：同域同模块 1h 内合并而非新增', async () => {
    await scanHistoryStore.addScan({ url: 'https://a.test/p', module: 'cors', findings: [finding('A')] });
    await scanHistoryStore.addScan({ url: 'https://a.test/p', module: 'cors', findings: [finding('B'), finding('C')] });

    await scanHistoryStore.refresh();
    let entries: any[] = [];
    scanHistoryStore.subscribe(e => (entries = e))();
    expect(entries.length).toBe(1); // 合并，不是 2 条
    expect(entries[0].findings.length).toBe(2); // 覆盖为最新 findings
    expect(entries[0].summary.total).toBe(2);
  });

  it('L2：不同模块不合并', async () => {
    await scanHistoryStore.addScan({ url: 'https://a.test/p', module: 'cors', findings: [finding('A')] });
    await scanHistoryStore.addScan({ url: 'https://a.test/p', module: 'xssscan', findings: [finding('B')] });
    await scanHistoryStore.refresh();
    let entries: any[] = [];
    scanHistoryStore.subscribe(e => (entries = e))();
    expect(entries.length).toBe(2);
  });

  it('L2：不同域名不合并', async () => {
    await scanHistoryStore.addScan({ url: 'https://a.test/p', module: 'cors', findings: [finding('A')] });
    await scanHistoryStore.addScan({ url: 'https://b.test/p', module: 'cors', findings: [finding('B')] });
    await scanHistoryStore.refresh();
    let entries: any[] = [];
    scanHistoryStore.subscribe(e => (entries = e))();
    expect(entries.length).toBe(2);
  });

  it('clearDomain 只删该域', async () => {
    await scanHistoryStore.addScan({ url: 'https://a.test/p', module: 'cors', findings: [finding('A')] });
    await scanHistoryStore.addScan({ url: 'https://b.test/p', module: 'cors', findings: [finding('B')] });
    await scanHistoryStore.clearDomain('a.test');
    await scanHistoryStore.refresh();
    let entries: any[] = [];
    scanHistoryStore.subscribe(e => (entries = e))();
    expect(entries.length).toBe(1);
    expect(entries[0].domain).toBe('b.test');
  });
});
