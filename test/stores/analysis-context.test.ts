import { describe, it, expect, beforeEach, vi } from 'vitest';

// 有状态 storage.local mock（setup.ts 默认 mock 不持久化）+ 捕获 onChanged listener
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
    onChanged: {
      addListener: (fn: any) => { onChangedListener = fn; },
      removeListener: (fn: any) => { if (onChangedListener === fn) onChangedListener = null; },
    },
  },
};

const { analysisContextStore } = await import('@/stores/analysis-context');
const { activePanelStore } = await import('@/stores/ui');

const KEY = 'lingmou:analysis-context';

function readStore(): any {
  let v: any = null;
  analysisContextStore.subscribe((x) => (v = x))();
  return v;
}
function readActive(): string {
  let v = '';
  activePanelStore.subscribe((x) => (v = x))();
  return v;
}

describe('analysis-context store', () => {
  beforeEach(async () => {
    for (const k of Object.keys(mem)) delete mem[k];
    await analysisContextStore.clear();
    activePanelStore.set('encoding');
  });

  it('handoff 写入 storage 且 store 更新', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'gather',
      sourceLabel: '信息收集',
      targetPanel: 'source-loader',
      payload: { text: 'a.js\nb.js' },
      summary: '2 个脚本',
    });
    expect(mem[KEY]).toBeDefined();
    expect(mem[KEY].targetPanel).toBe('source-loader');
    expect(mem[KEY].payload.text).toBe('a.js\nb.js');
    expect(readStore()?.targetPanel).toBe('source-loader');
  });

  it('handoff navigate=true 切到目标面板', async () => {
    activePanelStore.set('gather');
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'fuzz', payload: { paths: '/admin' },
    }, { navigate: true });
    expect(readActive()).toBe('fuzz');
  });

  it('handoff navigate=false 不切面板', async () => {
    activePanelStore.set('links');
    await analysisContextStore.handoff({
      sourcePanel: 'links', sourceLabel: '链接提取',
      targetPanel: 'multiurl', payload: { text: 'u1' },
    }, { navigate: false });
    expect(readActive()).toBe('links'); // 仍在原面板
    expect(readStore()?.targetPanel).toBe('multiurl'); // 但 context 已写
  });

  it('consume 匹配 target 返回并清除（一次性）', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'source-loader', payload: { text: 'x.js' },
    }, { navigate: false });

    const c = await analysisContextStore.consume('source-loader');
    expect(c?.targetPanel).toBe('source-loader');
    expect(c?.payload.text).toBe('x.js');
    // 已清除
    expect(mem[KEY]).toBeUndefined();
    expect(readStore()).toBeNull();

    const again = await analysisContextStore.consume('source-loader');
    expect(again).toBeNull();
  });

  it('consume 不匹配 target 返回 null 且不清除', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'fuzz', payload: { paths: '/a' },
    }, { navigate: false });

    const c = await analysisContextStore.consume('multiurl');
    expect(c).toBeNull();
    expect(mem[KEY]).toBeDefined(); // 仍在
  });

  it('clear 清除 storage 与 store', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'fuzz', payload: {},
    }, { navigate: false });
    expect(mem[KEY]).toBeDefined();

    await analysisContextStore.clear();
    expect(mem[KEY]).toBeUndefined();
    expect(readStore()).toBeNull();
  });

  it('back 切回来源面板', async () => {
    activePanelStore.set('source-loader');
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'source-loader', payload: { text: 'y.js' },
    }, { navigate: false });
    // 模拟用户在目标面板看到横幅，未 consume 即点返回
    analysisContextStore.back();
    expect(readActive()).toBe('gather');
  });

  it('back 在 context 为空时无效（不抛错）', async () => {
    activePanelStore.set('fuzz');
    expect(() => analysisContextStore.back()).not.toThrow();
    expect(readActive()).toBe('fuzz');
  });

  it('peek 读当前值不删除', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'fuzz', payload: { paths: '/a' },
    }, { navigate: false });
    const c = analysisContextStore.peek();
    expect(c?.targetPanel).toBe('fuzz');
    expect(mem[KEY]).toBeDefined(); // 未删
  });

  it('consumePayload 有 key 返回值并清除', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'history', sourceLabel: '历史档案',
      targetPanel: 'cors', payload: { targetUrl: 'https://a.test/x' },
    }, { navigate: false });
    const v = await analysisContextStore.consumePayload('cors', 'targetUrl');
    expect(v).toBe('https://a.test/x');
    expect(mem[KEY]).toBeUndefined(); // 已清
  });

  it('consumePayload 无 key 返回 null 且不清除', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'history-archive', sourceLabel: 'Wayback',
      targetPanel: 'fuzz', payload: { paths: '/admin' }, // 只有 paths，无 targetUrl
    }, { navigate: false });
    const v = await analysisContextStore.consumePayload('fuzz', 'targetUrl');
    expect(v).toBeNull();
    expect(mem[KEY]).toBeDefined(); // 未清，留给 paths 消费者
  });

  it('consumePayload 不匹配 panel 返回 null', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'history', sourceLabel: '历史',
      targetPanel: 'cors', payload: { targetUrl: 'https://a.test/' },
    }, { navigate: false });
    const v = await analysisContextStore.consumePayload('fuzz', 'targetUrl');
    expect(v).toBeNull();
    expect(mem[KEY]).toBeDefined();
  });

  it('reload 从 storage 恢复', async () => {
    mem[KEY] = {
      id: 'x', sourcePanel: 'links', sourceLabel: '链接提取',
      targetPanel: 'multiurl', payload: { text: 'z' }, createdAt: Date.now(),
    };
    await analysisContextStore.reload();
    expect(readStore()?.targetPanel).toBe('multiurl');
  });

  it('reload 过期 context 视为空并清理磁盘', async () => {
    mem[KEY] = {
      id: 'x', sourcePanel: 'links', sourceLabel: '链接',
      targetPanel: 'multiurl', payload: {},
      createdAt: Date.now() - 10 * 60 * 1000, // 10 分钟前，超过 5 分钟 TTL
    };
    await analysisContextStore.reload();
    expect(readStore()).toBeNull();
    expect(mem[KEY]).toBeUndefined(); // 磁盘残留已清
  });

  it('onChanged 跨上下文同步更新 store', async () => {
    expect(onChangedListener).toBeTruthy();
    const external = {
      id: 'e1', sourcePanel: 'history-archive', sourceLabel: 'Wayback',
      targetPanel: 'fuzz', payload: { paths: '/old' }, createdAt: Date.now(),
    };
    onChangedListener!({ [KEY]: { newValue: external } }, 'local');
    expect(readStore()?.sourcePanel).toBe('history-archive');

    onChangedListener!({ [KEY]: { newValue: undefined } }, 'local');
    expect(readStore()).toBeNull();
  });

  it('onChanged 非 local 或无关 key 不影响 store', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'fuzz', payload: {},
    }, { navigate: false });
    onChangedListener!({ otherKey: { newValue: 1 } }, 'local');
    expect(readStore()?.targetPanel).toBe('fuzz');
    onChangedListener!({ [KEY]: { newValue: { targetPanel: 'x' } } }, 'session');
    expect(readStore()?.targetPanel).toBe('fuzz');
  });

  it('normalize 拒绝缺字段 / 脏 payload', async () => {
    mem[KEY] = { sourcePanel: 'a' }; // 缺 targetPanel
    await analysisContextStore.reload();
    expect(readStore()).toBeNull();

    mem[KEY] = {
      sourcePanel: 'a', targetPanel: 'b',
      payload: { ok: 'str', bad: 123, nest: { x: 1 } }, createdAt: Date.now(),
    };
    await analysisContextStore.reload();
    const c = readStore();
    expect(c).toBeTruthy();
    expect(c.payload.ok).toBe('str');
    expect('bad' in c.payload).toBe(false); // 非字符串已过滤
    expect('nest' in c.payload).toBe(false);
  });

  it('consumePayload 多 key：只删指定 key，保留其他 key（§8.1）', async () => {
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'fuzz', payload: { targetUrl: 'https://a.test/', paths: '/admin' },
    }, { navigate: false });
    const v = await analysisContextStore.consumePayload('fuzz', 'targetUrl');
    expect(v).toBe('https://a.test/');
    expect(mem[KEY]).toBeDefined(); // 未整体清空
    expect(mem[KEY].payload.targetUrl).toBeUndefined();
    expect(mem[KEY].payload.paths).toBe('/admin');
    const p = await analysisContextStore.consumePayload('fuzz', 'paths');
    expect(p).toBe('/admin');
    expect(mem[KEY]).toBeUndefined(); // 全空后整体清
  });

  it('dispose 移除 storage listener（§8.1）', () => {
    expect(onChangedListener).toBeTruthy();
    analysisContextStore.dispose();
    expect(onChangedListener).toBeNull();
  });
});
