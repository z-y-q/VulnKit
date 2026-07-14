import { describe, it, expect } from 'vitest';
import { get } from 'svelte/store';
import { createTaskController, type TaskRunContext } from '@/lib/tasks/task-controller';

const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe('task-controller（§3.4 / §10.2）', () => {
  it('start 成功：idle → succeeded，返回 result', async () => {
    const ctrl = createTaskController<string, string>({ run: async () => 'done' });
    const r = await ctrl.start('x');
    expect(r.status).toBe('succeeded');
    expect(r.result).toBe('done');
    expect(get(ctrl.state).status).toBe('succeeded');
  });

  it('validate 抛错 → failed 且 reject', async () => {
    const ctrl = createTaskController({
      validate: () => { throw new Error('bad input'); },
      run: async () => 'never',
    });
    await expect(ctrl.start('x')).rejects.toThrow();
    expect(get(ctrl.state).status).toBe('failed');
    expect(get(ctrl.state).error).toBeDefined();
  });

  it('run 抛错 → failed 且 reject', async () => {
    const ctrl = createTaskController({ run: async () => { throw new Error('boom'); } });
    await expect(ctrl.start('x')).rejects.toThrow();
    expect(get(ctrl.state).status).toBe('failed');
  });

  it('cancel 在 run 中 → signal.aborted 传播且 status=cancelled，result 保留', async () => {
    let ctx!: TaskRunContext;
    const ctrl = createTaskController({
      run: async (_i, c) => { ctx = c; await delay(50); return 'done'; },
    });
    const p = ctrl.start('x');
    await delay(10);
    ctrl.cancel();
    expect(ctx.signal.aborted).toBe(true);
    const r = await p;
    expect(r.status).toBe('cancelled');
    expect(r.result).toBe('done');
    expect(get(ctrl.state).status).toBe('cancelled');
  });

  it('cancel 在 run 边界停止派发，返回部分结果', async () => {
    const ctrl = createTaskController<number[], number[]>({
      run: async (input, c) => {
        const out: number[] = [];
        for (const n of input) {
          if (c.signal.aborted) break;
          await delay(5);
          out.push(n);
        }
        return out;
      },
    });
    const p = ctrl.start([1, 2, 3, 4, 5, 6, 7, 8]);
    await delay(12);
    ctrl.cancel();
    const r = await p;
    expect(r.status).toBe('cancelled');
    expect(Array.isArray(r.result)).toBe(true);
    expect((r.result as number[]).length).toBeLessThan(8);
  });

  it('pause/resume 切换 isPaused 与 status', async () => {
    let ctx!: TaskRunContext;
    const ctrl = createTaskController(
      { run: async (_i, c) => { ctx = c; await delay(60); return 1; } },
      { canPause: true },
    );
    const p = ctrl.start('x');
    await delay(10);
    expect(get(ctrl.state).status).toBe('running');
    ctrl.pause();
    expect(get(ctrl.state).status).toBe('paused');
    expect(ctx.isPaused()).toBe(true);
    ctrl.resume();
    expect(get(ctrl.state).status).toBe('running');
    expect(ctx.isPaused()).toBe(false);
    await p;
  });

  it('reportProgress 合并进度但不改 status', async () => {
    let ctx!: TaskRunContext;
    const ctrl = createTaskController({
      run: async (_i, c) => {
        ctx = c;
        c.reportProgress({ completed: 5, total: 10, phase: 'mid', status: 'succeeded' });
        await delay(10);
        return 1;
      },
    });
    const p = ctrl.start('x');
    await delay(5);
    const s = get(ctrl.state);
    expect(s.completed).toBe(5);
    expect(s.total).toBe(10);
    expect(s.phase).toBe('mid');
    expect(s.status).toBe('running'); // reportProgress 的 status 被忽略
    await p;
  });

  it('防重复 start：运行中再 start 不重入', async () => {
    const ctrl = createTaskController({ run: async () => { await delay(40); return 1; } });
    const p1 = ctrl.start('x');
    const r2 = await ctrl.start('y');
    expect(r2.status).toBe('running');
    await p1;
  });

  it('reset → idle 清空进度与错误', async () => {
    const ctrl = createTaskController({ run: async () => 1 });
    await ctrl.start('x');
    expect(get(ctrl.state).status).toBe('succeeded');
    ctrl.reset();
    expect(get(ctrl.state).status).toBe('idle');
    expect(get(ctrl.state).completed).toBe(0);
    expect(get(ctrl.state).error).toBeUndefined();
  });

  it('canPause=false 时 pause 无效', async () => {
    const ctrl = createTaskController({ run: async () => { await delay(30); return 1; } });
    const p = ctrl.start('x');
    await delay(10);
    ctrl.pause();
    expect(get(ctrl.state).status).toBe('running');
    await p;
  });
});
