/**
 * 统一任务状态机 — 灵眸 v6.0
 *
 * 对齐 docs/UX-UI优化建议.md §3.4 / §10.2。
 * createTaskController(adapter) 在既有 runConcurrent + sendMessage 之上加状态机语义层：
 *   idle → validating → running ↔ paused → succeeded | cancelled | failed
 * 取消通过 AbortController 传播；adapter 在 run 内用 ctx.signal 决定是否继续派发
 * （典型：runConcurrent(..., { cancelled: () => ctx.signal.aborted })）。
 *
 * 任务为会话级（不持久化），state 用 svelte/store writable，UI 用 $derived($ctrl.state) 订阅。
 */

import { writable, get, type Readable } from 'svelte/store';
import { toActionableError, type ActionableError } from '@/lib/errors/actionable-error';

export type TaskStatus =
  | 'idle' | 'validating' | 'running' | 'paused'
  | 'succeeded' | 'partial' | 'cancelled' | 'failed';

export interface TaskState {
  status: TaskStatus;
  /** 当前阶段提示文案（如「抓取远程 JS (3/120)」） */
  phase: string;
  completed: number;
  total?: number;
  succeeded: number;
  failed: number;
  skipped: number;
  startedAt?: number;
  elapsedMs: number;
  canPause: boolean;
  canCancel: boolean;
  error?: ActionableError;
}

export interface TaskRunContext {
  /** 取消信号；aborted 时 adapter 应停止派发后续工作 */
  signal: AbortSignal;
  /** 是否暂停（adapter 可传给 runConcurrent 的 paused 回调） */
  isPaused: () => boolean;
  /** 上报进度（phase/completed/total/succeeded/failed/skipped），不改 status */
  reportProgress(update: Partial<TaskState>): void;
}

export interface TaskAdapter<TInput, TResult> {
  /** 可选输入校验；抛错则进入 failed（不入 running） */
  validate?(input: TInput): Promise<void> | void;
  /** 核心运行；应尊重 ctx.signal.aborted，抛错进入 failed */
  run(input: TInput, ctx: TaskRunContext): Promise<TResult>;
}

/** start 的 resolve 值；status ∈ {succeeded, cancelled}（cancelled 时 result 可能为部分结果） */
export interface StartResult<TResult> {
  status: TaskStatus;
  result?: TResult;
}

export interface TaskController<TInput, TResult> {
  state: Readable<TaskState>;
  /** 启动；failed 时 reject(ActionableError)，否则 resolve */
  start(input: TInput): Promise<StartResult<TResult>>;
  pause(): void;
  resume(): void;
  cancel(): void;
  /** 回到 idle 并清空进度/错误 */
  reset(): void;
}

export interface CreateTaskOptions {
  /** 是否支持暂停（fuzz 等需要；默认 false） */
  canPause?: boolean;
}

export const IDLE: TaskState = {
  status: 'idle',
  phase: '',
  completed: 0,
  succeeded: 0,
  failed: 0,
  skipped: 0,
  elapsedMs: 0,
  canPause: false,
  canCancel: false,
};

export function createTaskController<TInput, TResult>(
  adapter: TaskAdapter<TInput, TResult>,
  opts: CreateTaskOptions = {},
): TaskController<TInput, TResult> {
  const canPauseEnabled = opts.canPause ?? false;
  const store = writable<TaskState>({ ...IDLE });

  let ac: AbortController | null = null;
  let paused = false;
  let startedAt = 0;
  let timer: ReturnType<typeof setInterval> | null = null;

  function patch(p: Partial<TaskState>) {
    store.update((s) => ({ ...s, ...p }));
  }
  function elapsed(): number {
    return startedAt ? Date.now() - startedAt : 0;
  }
  function startTimer() {
    stopTimer();
    timer = setInterval(() => patch({ elapsedMs: elapsed() }), 500);
  }
  function stopTimer() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  function reportProgress(update: Partial<TaskState>) {
    // reportProgress 不改 status（status 由控制器驱动）
    const { status: _omit, ...rest } = update as any;
    patch(rest);
  }

  async function start(input: TInput): Promise<StartResult<TResult>> {
    const cur = get(store);
    if (cur.status === 'running' || cur.status === 'validating' || cur.status === 'paused') {
      // 防重复派发
      return { status: cur.status };
    }

    ac = new AbortController();
    paused = false;
    startedAt = Date.now();
    patch({
      ...IDLE,
      status: 'validating',
      phase: '校验中',
      startedAt,
      canCancel: true,
      canPause: false,
    });

    try {
      if (adapter.validate) await adapter.validate(input);
    } catch (e) {
      stopTimer();
      const err = toActionableError(e);
      patch({ status: 'failed', error: err, elapsedMs: elapsed(), canCancel: false, canPause: false });
      throw err;
    }

    if (ac.signal.aborted) {
      stopTimer();
      patch({ status: 'cancelled', elapsedMs: elapsed(), canCancel: false, canPause: false });
      return { status: 'cancelled' };
    }

    patch({ status: 'running', phase: '运行中', canCancel: true, canPause: canPauseEnabled });
    startTimer();

    let result: TResult | undefined;
    try {
      result = await adapter.run(input, {
        signal: ac.signal,
        isPaused: () => paused,
        reportProgress,
      });
    } catch (e) {
      stopTimer();
      const err = toActionableError(e);
      patch({ status: 'failed', error: err, elapsedMs: elapsed(), canCancel: false, canPause: false });
      throw err;
    }

    stopTimer();
    const finalElapsed = elapsed();

    if (ac.signal.aborted) {
      // 取消：adapter 已停止派发并返回；result 可能含部分结果（面板自行展示/标记 partial）
      patch({ status: 'cancelled', elapsedMs: finalElapsed, canCancel: false, canPause: false });
      return { status: 'cancelled', result };
    }

    patch({ status: 'succeeded', elapsedMs: finalElapsed, canCancel: false, canPause: false });
    return { status: 'succeeded', result };
  }

  function pause() {
    const cur = get(store);
    if (cur.status !== 'running' || !cur.canPause) return;
    paused = true;
    patch({ status: 'paused', canPause: false });
  }

  function resume() {
    if (get(store).status !== 'paused') return;
    paused = false;
    patch({ status: 'running', canPause: canPauseEnabled });
  }

  function cancel() {
    if (ac) ac.abort();
    paused = false;
    // status 由 start 流程在 run 返回后置为 cancelled；此处仅更新按钮可用态供 UI 即时反馈
    const cur = get(store);
    if (cur.status === 'running' || cur.status === 'paused' || cur.status === 'validating') {
      patch({ canCancel: false, canPause: false });
    }
  }

  function reset() {
    if (ac) ac.abort();
    paused = false;
    stopTimer();
    startedAt = 0;
    ac = null;
    patch({ ...IDLE });
  }

  return { state: store, start, pause, resume, cancel, reset };
}
