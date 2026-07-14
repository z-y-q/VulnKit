import { describe, it, expect, beforeEach } from 'vitest';

const mem: Record<string, any> = {};
let onChangedListener: ((changes: any, area: string) => void) | null = null;
(globalThis as any).browser = {
  storage: {
    local: {
      get: async (keys: string | string[]) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        const out: any = {};
        for (const k of arr) if (k in mem) out[k] = mem[k];
        return out;
      },
      set: async (obj: any) => { Object.assign(mem, obj); },
      remove: async (keys: string | string[]) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        for (const k of arr) delete mem[k];
      },
    },
    onChanged: { addListener: (fn: any) => { onChangedListener = fn; } },
  },
};

const { recentTargetsStore } = await import('@/stores/recent-targets');

const KEY = 'recentTargets';

function readStore(): any[] {
  let v: any[] = [];
  recentTargetsStore.subscribe((x) => (v = x))();
  return v;
}

describe('recent-targets store', () => {
  beforeEach(async () => {
    for (const k of Object.keys(mem)) delete mem[k];
    await recentTargetsStore.clear();
  });

  it('record 写入并提取 domain', async () => {
    await recentTargetsStore.record('https://a.test/x', 'fuzz');
    const list = readStore();
    expect(list.length).toBe(1);
    expect(list[0].url).toBe('https://a.test/x');
    expect(list[0].domain).toBe('a.test');
    expect(list[0].panel).toBe('fuzz');
  });

  it('record 置顶去重（同 url 覆盖 usedAt）', async () => {
    await recentTargetsStore.record('https://a.test/x', 'fuzz');
    await recentTargetsStore.record('https://b.test/y', 'cors');
    await recentTargetsStore.record('https://a.test/x', 'headers'); // 再次记录 a.test
    const list = readStore();
    expect(list.length).toBe(2); // 去重
    expect(list[0].url).toBe('https://a.test/x'); // 置顶
    expect(list[0].panel).toBe('headers'); // 最新覆盖
  });

  it('record 非 http(s) 拒绝', async () => {
    await recentTargetsStore.record('chrome://settings', 'fuzz');
    await recentTargetsStore.record('not a url', 'fuzz');
    await recentTargetsStore.record('', 'fuzz');
    expect(readStore().length).toBe(0);
  });

  it('record 截断到上限 10', async () => {
    for (let i = 0; i < 12; i++) {
      await recentTargetsStore.record(`https://t${i}.test/`, 'fuzz');
    }
    expect(readStore().length).toBe(10);
    expect(readStore()[0].url).toBe('https://t11.test/'); // 最新在顶
  });

  it('remove 删除指定 url', async () => {
    await recentTargetsStore.record('https://a.test/', 'fuzz');
    await recentTargetsStore.record('https://b.test/', 'cors');
    await recentTargetsStore.remove('https://a.test/');
    const list = readStore();
    expect(list.length).toBe(1);
    expect(list[0].url).toBe('https://b.test/');
  });

  it('clear 清空', async () => {
    await recentTargetsStore.record('https://a.test/', 'fuzz');
    await recentTargetsStore.clear();
    expect(readStore().length).toBe(0);
    expect(mem[KEY]).toEqual([]);
  });

  it('reload 从 storage 恢复', async () => {
    mem[KEY] = [{ url: 'https://old.test/', domain: 'old.test', panel: 'xss', usedAt: 1 }];
    await recentTargetsStore.reload();
    expect(readStore().length).toBe(1);
    expect(readStore()[0].url).toBe('https://old.test/');
  });

  it('reload 规范化：缺 domain 自动补、过滤非法项', async () => {
    mem[KEY] = [
      { url: 'https://c.test/p' }, // 缺 domain/panel/usedAt
      { foo: 'bar' }, // 缺 url，丢弃
      'not-an-object',
    ];
    await recentTargetsStore.reload();
    const list = readStore();
    expect(list.length).toBe(1);
    expect(list[0].domain).toBe('c.test');
  });

  it('onChanged 跨上下文同步', async () => {
    expect(onChangedListener).toBeTruthy();
    onChangedListener!({ [KEY]: { newValue: [{ url: 'https://z.test/', domain: 'z.test', panel: 'cors', usedAt: 5 }] } }, 'local');
    expect(readStore().length).toBe(1);
    expect(readStore()[0].url).toBe('https://z.test/');
  });
});
