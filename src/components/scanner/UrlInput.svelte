<script lang="ts">
  // 目标 URL 输入 + 扫描按钮 — bindable value，供带 URL 输入的扫描面板复用。
  // 增强（对齐 docs/UX-UI优化建议.md §5.1 / §8.3 / §4.1）：
  // - 可选显式 label（不靠 placeholder 替代 label）；
  // - Enter 提交，运行中不重复派发；
  // - 可选 onValidate 即时校验，错误通过 aria-describedby 关联，错误时禁用按钮；
  // - 可选 recordTarget：扫描时把目标记入 recentTargetsStore，focus 时显示候选下拉回填。
  // 所有新增 props 可选 → 现有调用方零改动即可继续工作（向后兼容）。
  import { get } from 'svelte/store';
  import { recentTargetsStore } from '@/stores/recent-targets';
  import { analysisContextStore } from '@/stores/analysis-context';
  import { activePanelStore } from '@/stores/ui';

  let {
    value = $bindable(''),
    scanning = false,
    buttonText = '扫描',
    scanningText = '扫描中...',
    placeholder = '目标 URL (https://...)',
    label = '',
    onscan,
    onValidate,
    recordTarget = false,
  }: {
    value?: string;
    scanning?: boolean;
    buttonText?: string;
    scanningText?: string;
    placeholder?: string;
    label?: string;
    onscan?: () => void;
    onValidate?: (v: string) => string | null;
    recordTarget?: boolean;
  } = $props();

  // 实例级稳定 id，供 label / aria-describedby 关联（实例生命周期内不变）
  let uid = `urlinput-${Math.random().toString(36).slice(2, 8)}`;

  // 即时校验：仅在调用方提供 onValidate 且 value 非空时执行
  let validationError = $derived(onValidate && value ? onValidate(value) : null);

  let canRun = $derived(!!value && !scanning && !validationError);

  // 最近目标候选（跨面板共享）
  let recent = $derived($recentTargetsStore);
  let showRecent = $state(false);
  let candidates = $derived.by(() => {
    const kw = value.trim().toLowerCase();
    const list = kw ? recent.filter((t) => t.url.toLowerCase().includes(kw)) : recent;
    return list.slice(0, 8);
  });

  // 跨面板 handoff 回填 targetUrl（History「回到源面板」等）；无则 noop，不影响普通输入。
  // 用 get 快照读取当前面板 id，effect 无响应式依赖 → 仅 mount 跑一次。
  $effect(() => {
    analysisContextStore.consumePayload(get(activePanelStore), 'targetUrl').then((v) => {
      if (v) value = v;
    }).catch(() => { /* ignore */ });
  });

  async function run() {
    if (!canRun) return;
    if (recordTarget && value) {
      // 乐观记录（失败目标也是用户感兴趣的重试对象）；面板也可在成功后自行 record 覆盖
      await recentTargetsStore.record(value, get(activePanelStore));
    }
    onscan?.();
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && canRun) {
      e.preventDefault();
      run();
    } else if (e.key === 'Escape') {
      showRecent = false;
    }
  }

  function pick(url: string) {
    value = url;
    showRecent = false;
  }
</script>

<div class={label ? 'space-y-1' : ''}>
  {#if label}
    <label for={uid} class="panel-label">{label}</label>
  {/if}
  <div class="flex gap-1">
    <div class="flex-1 relative">
      <input
        id={uid}
        class="input w-full text-sm"
        {placeholder}
        bind:value
        onkeydown={onKeydown}
        onfocus={() => { if (recordTarget) showRecent = true; }}
        onblur={() => setTimeout(() => (showRecent = false), 150)}
        aria-invalid={validationError ? 'true' : undefined}
        aria-describedby={validationError ? `${uid}-err` : undefined}
        aria-expanded={recordTarget && candidates.length ? showRecent : undefined}
        aria-controls={recordTarget && candidates.length ? `${uid}-listbox` : undefined}
        autocomplete="off"
        spellcheck="false"
      />
      {#if recordTarget && showRecent && candidates.length}
        <div
          id={`${uid}-listbox`}
          class="absolute z-30 top-full left-0 right-0 mt-0.5 max-h-56 overflow-y-auto rounded-md border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-lg"
          role="listbox"
          aria-label="最近目标"
        >
          {#each candidates as t (t.url)}
            <button
              type="button"
              class="block w-full text-left px-2 py-1 text-xs hover:bg-blue-50 dark:hover:bg-blue-900/30 font-mono truncate"
              role="option"
              aria-selected="false"
              aria-label={t.url}
              onmousedown={(e: MouseEvent) => { e.preventDefault(); pick(t.url); }}
            >
              <span class="text-gray-400 mr-1">{t.domain}</span>{t.url}
            </button>
          {/each}
        </div>
      {/if}
    </div>
    <button
      type="button"
      class="btn btn-sm btn-primary shrink-0"
      disabled={!canRun}
      onclick={run}
    >
      {scanning ? scanningText : buttonText}
    </button>
  </div>
  {#if validationError}
    <p id={`${uid}-err`} class="text-xs text-red-500 dark:text-red-400">{validationError}</p>
  {/if}
</div>
