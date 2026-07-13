<script lang="ts">
  // 目标 URL 输入 + 扫描按钮 — bindable value，供带 URL 输入的扫描面板复用。
  // 增强（对齐 docs/UX-UI优化建议.md §5.1 / §8.3）：
  // - 可选显式 label（不靠 placeholder 替代 label）；
  // - Enter 提交，运行中不重复派发；
  // - 可选 onValidate 即时校验，错误通过 aria-describedby 关联，错误时禁用按钮。
  // 所有新增 props 可选 → 现有调用方零改动即可继续工作（向后兼容）。
  let {
    value = $bindable(''),
    scanning = false,
    buttonText = '扫描',
    scanningText = '扫描中...',
    placeholder = '目标 URL (https://...)',
    label = '',
    onscan,
    onValidate,
  }: {
    value?: string;
    scanning?: boolean;
    buttonText?: string;
    scanningText?: string;
    placeholder?: string;
    label?: string;
    onscan?: () => void;
    onValidate?: (v: string) => string | null;
  } = $props();

  // 实例级稳定 id，供 label / aria-describedby 关联（实例生命周期内不变）
  let uid = `urlinput-${Math.random().toString(36).slice(2, 8)}`;

  // 即时校验：仅在调用方提供 onValidate 且 value 非空时执行
  let validationError = $derived(onValidate && value ? onValidate(value) : null);

  let canRun = $derived(!!value && !scanning && !validationError);

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && canRun) {
      e.preventDefault();
      onscan?.();
    }
  }
</script>

<div class={label ? 'space-y-1' : ''}>
  {#if label}
    <label for={uid} class="panel-label">{label}</label>
  {/if}
  <div class="flex gap-1">
    <input
      id={uid}
      class="input flex-1 text-sm"
      {placeholder}
      bind:value
      onkeydown={onKeydown}
      aria-invalid={validationError ? 'true' : undefined}
      aria-describedby={validationError ? `${uid}-err` : undefined}
    />
    <button
      type="button"
      class="btn btn-sm btn-primary shrink-0"
      disabled={!canRun}
      onclick={onscan}
    >
      {scanning ? scanningText : buttonText}
    </button>
  </div>
  {#if validationError}
    <p id={`${uid}-err`} class="text-xs text-red-500 dark:text-red-400">{validationError}</p>
  {/if}
</div>
