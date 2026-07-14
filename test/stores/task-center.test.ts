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

const { taskCenterStore } = await import('@/stores/task-center');

const KEY = 'taskCenter';

function readStore(): any[] {
  let v: any[] = [];
  taskCenterStore.subscribe((x) => (v = x))();
  return v;
}

function flush(): Promise<void> {
  // report 走写队列（异步）；等一个微任务让队列落盘
  return new Promise((r) => setTimeout(r, 0));
}

describe('task-center store', () => {
  beforeEach(async () => {
    for (const k of Object.keys(mem)) delete mem[k];
    await taskCenterStore.clear();
    await flush();
  });

  it('report 置顶写入', async () => {
    taskCenterStore.report({ panel: 'fuzz', label: '目录扫描', status: 'succeeded', summary: '5 个路径' });
    await flush();
    const list = readStore();
    expect(list.length).toBe(1);
    expect(list[0].panel).toBe('fuzz');
    expect(list[0].status).toBe('succeeded');
    expect(list[0].summary).toBe('5 个路径');
    expect(typeof list[0].id).toBe('string');
    expect(typeof list[0].finishedAt).toBe('number');
  });

  it('report 多条按时间倒序（最新在顶）', async () => {
    taskCenterStore.report({ panel: 'cors', label: 'CORS', status: 'failed' });
    await flush();
    taskCenterStore.report({ panel: 'fuzz', label: '目录扫描', status: 'cancelled' });
    await flush();
    const list = readStore();
    expect(list.length).toBe(2);
    expect(list[0].panel).toBe('fuzz'); // 最新在顶
    expect(list[1].panel).toBe('cors');
  });

  it('report 截断到上限 20', async () => {
    for (let i = 0; i < 25; i++) {
      taskCenterStore.report({ panel: 'fuzz', label: `任务${i}`, status: 'succeeded' });
      await flush();
    }
    const list = readStore();
    expect(list.length).toBe(20);
    expect(list[0].label).toBe('任务24'); // 最新
  });

  it('clear 清空', async () => {
    taskCenterStore.report({ panel: 'fuzz', label: 'x', status: 'succeeded' });
    await flush();
    await taskCenterStore.clear();
    await flush();
    expect(readStore().length).toBe(0);
    expect(mem[KEY]).toEqual([]);
  });

  it('reload 从 storage 恢复', async () => {
    mem[KEY] = [{ id: 'a', panel: 'jsarchive', label: 'JS 归档', status: 'partial', finishedAt: 1 }];
    await taskCenterStore.reload();
    expect(readStore().length).toBe(1);
    expect(readStore()[0].panel).toBe('jsarchive');
  });

  it('reload 规范化：过滤非法 status、补 label', async () => {
    mem[KEY] = [
      { id: '1', panel: 'fuzz', status: 'succeeded' }, // 缺 label → 用 panel
      { id: '2', panel: 'cors', status: 'running' }, // 非终态 status → 丢弃
      { id: '3', status: 'failed' }, // 缺 panel → 丢弃
      'bad',
    ];
    await taskCenterStore.reload();
    const list = readStore();
    expect(list.length).toBe(1);
    expect(list[0].label).toBe('fuzz');
  });

  it('onChanged 跨上下文同步', async () => {
    expect(onChangedListener).toBeTruthy();
    onChangedListener!({ [KEY]: { newValue: [{ id: 'x', panel: 'xss', label: 'XSS', status: 'failed', finishedAt: 2 }] } }, 'local');
    expect(readStore().length).toBe(1);
    expect(readStore()[0].panel).toBe('xss');
  });

  it('所有终态 status 都被接受', async () => {
    for (const s of ['succeeded', 'partial', 'cancelled', 'failed'] as const) {
      taskCenterStore.report({ panel: 'p', label: 'l', status: s });
      await flush();
    }
    const list = readStore();
    expect(list.length).toBe(4);
    expect(list.map((r) => r.status).sort()).toEqual(['cancelled', 'failed', 'partial', 'succeeded']);
  });
});
