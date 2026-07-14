<script lang="ts" generics="TInput, TResult">
  // 任务运行控件 — 灵眸 v6.0
  // 对齐 docs/UX-UI优化建议.md §5.1 运行区 / §3.4 状态机：
  // 主按钮随状态切换（开始 → 暂停/继续 + 取消），并委托 ScanProgress 展示
  // controller.state 的 phase/completed/total/failed/elapsed。
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import { toActionableError, type ActionableError } from '@/lib/errors/actionable-error';
  import { IDLE, type TaskController, type TaskState, type StartResult } from '@/lib/tasks/task-controller';

  let {
    controller,
    buildInput,
    runLabel = '开始',
    runIcon = '▶',
    onResult,
    onError,
  }: {
    controller: TaskController<TInput, TResult>;
    /** 点击「开始」时组装输入；返回 Promise 以支持异步取当前 tab 等 */
    buildInput: () => TInput | Promise<TInput>;
    runLabel?: string;
    runIcon?: string;
    /** start 完成（succeeded/cancelled）回调，面板在此写历史/toast */
    onResult?: (r: StartResult<TResult>) => void;
    /** start 失败回调，面板可挂 ErrorState */
    onError?: (e: ActionableError) => void;
  } = $props();

  // controller.state 是 Readable<TaskState>；用 $state + $effect 订阅以在模板里 reactive 使用
  let s = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { s = v; }));
  let busy = $derived(s.status === 'running' || s.status === 'paused' || s.status === 'validating');
  let scanning = $derived(s.status === 'running' || s.status === 'paused');
  let showProgress = $derived(scanning || s.status === 'succeeded' || s.status === 'cancelled' || s.status === 'failed');

  async function handleStart() {
    try {
      const input = await buildInput();
      const r = await controller.start(input);
      onResult?.(r);
    } catch (e) {
      onError?.(toActionableError(e));
    }
  }
</script>

<div class="space-y-2">
  <div class="flex items-center gap-1">
    {#if busy}
      {#if s.status === 'running' && s.canPause}
        <button class="btn btn-sm btn-soft" onclick={() => controller.pause()}>暂停</button>
      {:else if s.status === 'paused'}
        <button class="btn btn-sm btn-primary" onclick={() => controller.resume()}>继续</button>
      {/if}
      <button
        class="btn btn-sm"
        onclick={() => controller.cancel()}
        disabled={!s.canCancel}
      >取消</button>
    {:else}
      <button class="btn btn-sm btn-primary" onclick={handleStart}>
        <span aria-hidden="true">{runIcon}</span> {runLabel}
      </button>
    {/if}
    {#if s.elapsedMs > 0}
      <span class="text-xs text-gray-400 ml-auto tabular-nums">{(s.elapsedMs / 1000).toFixed(1)}s</span>
    {/if}
  </div>
  {#if showProgress}
    <ScanProgress
      scanning={scanning}
      scanned={s.completed}
      total={s.total ?? 0}
      phase={s.phase}
      elapsedMs={s.elapsedMs}
      failed={s.failed}
    />
  {/if}
</div>
