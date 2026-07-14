/**
 * 统一任务状态机
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
import { taskCenterStore } from '@/stores/task-center';

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
  /** 本次任务轮次 id（每次 start 递增）；adapter 可用于日志/去重 */
  taskId: number;
  /** 是否仍是当前任务（未被后续 start/重跑取代）；旧回调回写状态前应检查，丢弃过期结果 */
  isCurrent(): boolean;
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
  /** 重跑：无参用上次 input（retry 'all'）；传参换 input（retry 'failed' 复用）。仅终态后可调 */
  retry(input?: TInput): Promise<StartResult<TResult>>;
  /** 释放资源：abort 进行中任务 + 停计时器 + 回到 idle。供面板 onDestroy 调用 */
  dispose(): void;
}

export interface CreateTaskOptions {
  /** 是否支持暂停（fuzz 等需要；默认 false） */
  canPause?: boolean;
  /** 上报到 task-center 的面板 id（不传则不上报，向后兼容） */
  centerPanel?: string;
  /** 上报到 task-center 的任务标签（默认用 centerPanel） */
  centerLabel?: string;
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
  const centerPanel = opts.centerPanel;
  const centerLabel = opts.centerLabel ?? opts.centerPanel ?? '';
  const store = writable<TaskState>({ ...IDLE });

  let ac: AbortController | null = null;
  let paused = false;
  let startedAt = 0;
  let timer: ReturnType<typeof setInterval> | null = null;
  let lastInput: TInput | undefined;
  /** 任务轮次 id：每次 start 递增；adapter 据此判断回调是否仍属当前任务 */
  let runId = 0;
  /** 是否已释放（dispose 后）；释放后 start 不再派发 */
  let disposed = false;

  function patch(p: Partial<TaskState>) {
    store.update((s) => ({ ...s, ...p }));
  }
  /** 终态上报到 task-center（仅当配置了 centerPanel，向后兼容） */
  function reportToCenter(status: TaskStatus): void {
    if (!centerPanel) return;
    if (status === 'succeeded' || status === 'partial' || status === 'cancelled' || status === 'failed') {
      taskCenterStore.report({
        panel: centerPanel,
        label: centerLabel,
        status,
        summary: get(store).phase || undefined,
      });
    }
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
    if (disposed) return { status: 'idle' };
    const cur = get(store);
    if (cur.status === 'running' || cur.status === 'validating' || cur.status === 'paused') {
      // 防重复派发
      return { status: cur.status };
    }

    const myRun = ++runId;
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
      reportToCenter('failed');
      throw err;
    }

    if (ac.signal.aborted) {
      stopTimer();
      patch({ status: 'cancelled', elapsedMs: elapsed(), canCancel: false, canPause: false });
      reportToCenter('cancelled');
      return { status: 'cancelled' };
    }

    lastInput = input;
    patch({ status: 'running', phase: '运行中', canCancel: true, canPause: canPauseEnabled });
    startTimer();

    let result: TResult | undefined;
    try {
      result = await adapter.run(input, {
        signal: ac.signal,
        taskId: myRun,
        isCurrent: () => myRun === runId,
        isPaused: () => paused,
        reportProgress,
      });
    } catch (e) {
      stopTimer();
      if (disposed) return { status: 'idle' }; // dispose 已处理状态，旧 run 错误丢弃
      const err = toActionableError(e);
      patch({ status: 'failed', error: err, elapsedMs: elapsed(), canCancel: false, canPause: false });
      reportToCenter('failed');
      throw err;
    }

    stopTimer();
    const finalElapsed = elapsed();

    if (disposed) return { status: 'idle', result }; // dispose 已置 idle，旧 run 结果丢弃

    if (ac.signal.aborted) {
      // 取消：adapter 已停止派发并返回；result 可能含部分结果（面板自行展示/标记 partial）
      patch({ status: 'cancelled', elapsedMs: finalElapsed, canCancel: false, canPause: false });
      reportToCenter('cancelled');
      return { status: 'cancelled', result };
    }

    patch({ status: 'succeeded', elapsedMs: finalElapsed, canCancel: false, canPause: false });
    reportToCenter('succeeded');
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

  function retry(input?: TInput): Promise<StartResult<TResult>> {
    return start(input ?? lastInput!);
  }

  /** 释放资源：abort 进行中任务 + 停计时器 + 回到 idle。供面板 onDestroy 调用，之后 start 不再派发 */
  function dispose(): void {
    disposed = true;
    if (ac) ac.abort();
    paused = false;
    stopTimer();
    startedAt = 0;
    ac = null;
    patch({ ...IDLE });
  }

  return { state: store, start, pause, resume, cancel, reset, retry, dispose };
}
