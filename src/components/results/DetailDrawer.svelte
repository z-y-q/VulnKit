<script lang="ts" module>
  // 详情抽屉（对齐 docs/UX-UI优化建议.md §5.3）
  // 展示单条发现的完整详情 + 跨面板 handoff 动作 + 上一条/下一条；
  // a11y：role=dialog aria-modal、Escape 关闭、焦点陷阱、关闭后焦点回触发元素。
  // 类型（DetailField/DetailHandoffAction）与 severityTone 抽到 ./detail-drawer-utils.ts，便于单测。
</script>

<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { analysisContextStore } from '@/stores/analysis-context';
  import { severityTone, type DetailField, type DetailHandoffAction } from './detail-drawer-utils';
  import { sheetTransition, scrimFade } from '@/lib/ui/motion';

  let {
    items,
    index,
    onclose,
    onnavigate,
    sourcePanel,
    sourceLabel,
    title,
    severity,
    moduleLabel,
    target,
    fields,
    evidence,
    actions = [],
    children,
  }: {
    /** 全集（供「上一条/下一条」导航与计数） */
    items: T[];
    /** 当前展示项索引；null = 关闭 */
    index: number | null;
    onclose: () => void;
    onnavigate: (index: number) => void;
    /** handoff 来源面板 id + 标签 */
    sourcePanel: string;
    sourceLabel: string;
    title: (item: T) => string;
    severity?: (item: T) => string;
    moduleLabel?: string;
    target?: (item: T) => string;
    fields: (item: T) => DetailField[];
    evidence?: (item: T) => string;
    actions?: DetailHandoffAction<T>[];
    /** 面板自定义补充（验证结果 / rawResponse 等） */
    children?: Snippet<[T]>;
  } = $props();

  let open = $derived(index !== null && index >= 0 && index < items.length);
  let item = $derived(open && index !== null ? items[index] : null);

  let dialogRef: HTMLDivElement | undefined = $state();
  let closeBtn: HTMLButtonElement | undefined = $state();
  let lastFocused: HTMLElement | null = null;

  // 打开：记录触发元素 + 聚焦关闭键；关闭：把焦点还给触发元素（§8 modal 焦点恢复）
  $effect(() => {
    if (open) {
      if (!lastFocused) lastFocused = document.activeElement as HTMLElement | null;
      queueMicrotask(() => closeBtn?.focus());
    } else if (lastFocused) {
      lastFocused?.focus?.();
      lastFocused = null;
    }
  });

  // Escape 关闭 + Tab 焦点陷阱（模式复刻 ConfirmDialog）
  $effect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onclose();
        return;
      }
      if (e.key === 'Tab' && dialogRef) {
        const focusable = dialogRef.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  });

  function onOverlayClick(e: MouseEvent) {
    if (e.target === e.currentTarget) onclose();
  }
  function onOverlayKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onclose();
    }
  }

  let canPrev = $derived(index !== null && index > 0);
  let canNext = $derived(index !== null && index < items.length - 1);

  function prev() {
    if (canPrev && index !== null) onnavigate(index - 1);
  }
  function next() {
    if (canNext && index !== null) onnavigate(index + 1);
  }

  async function doHandoff(a: DetailHandoffAction<T>) {
    if (!item) return;
    const built = a.build(item);
    await analysisContextStore.handoff({
      sourcePanel,
      sourceLabel,
      targetPanel: a.targetPanel,
      payload: built.payload,
      summary: built.summary,
    });
    onclose();
  }

  async function copyField(f: DetailField) {
    await copyText(f.value, `已复制 ${f.label}`);
  }
  async function copyAll() {
    if (!item) return;
    const lines: string[] = [title(item)];
    if (moduleLabel) lines.push(`模块: ${moduleLabel}`);
    const t = target?.(item);
    if (t) lines.push(`目标: ${t}`);
    for (const f of fields(item)) lines.push(`${f.label}: ${f.value}`);
    const ev = evidence?.(item);
    if (ev) lines.push(`证据:\n${ev}`);
    await copyText(lines.join('\n'), '已复制完整详情');
  }
</script>

{#if open && item}
  <div
    class="dd-overlay"
    role="button"
    tabindex="-1"
    aria-label="点击遮罩关闭详情"
    onclick={onOverlayClick}
    onkeydown={onOverlayKeydown}
    transition:scrimFade
  >
    <div
      bind:this={dialogRef}
      class="dd-dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="dd-title"
      transition:sheetTransition
    >
      <!-- 头部 -->
      <div class="dd-header">
        <div class="dd-titlewrap">
          {#if severity?.(item)}
            <span class="dd-sev dd-sev-{severityTone(severity(item))}">{severity(item)}</span>
          {/if}
          <h3 id="dd-title" class="dd-title">{title(item)}</h3>
        </div>
        <button type="button" bind:this={closeBtn} class="dd-close" aria-label="关闭详情" onclick={onclose}>✕</button>
      </div>

      <!-- 可滚动正文 -->
      <div class="dd-body">
        {#if moduleLabel || target?.(item)}
          <div class="dd-meta">
            {#if moduleLabel}<span class="dd-metatag">{moduleLabel}</span>{/if}
            {#if target?.(item)}
              <span class="dd-target" title={target(item)}>{target(item)}</span>
            {/if}
          </div>
        {/if}

        <!-- 字段表 -->
        <dl class="dd-fields">
          {#each fields(item) as f (f.label)}
            <div class="dd-field">
              <dt>{f.label}</dt>
              <dd class={f.mono ? 'mono' : ''}>
                <span class="dd-value" title={f.value}>{f.value || '—'}</span>
                {#if f.value}
                  <button type="button" class="dd-copyfield" aria-label={`复制${f.label}`} onclick={() => copyField(f)}>复制</button>
                {/if}
              </dd>
            </div>
          {/each}
        </dl>

        <!-- 证据 / 原始响应 -->
        {#if evidence?.(item)}
          <div class="dd-section">
            <div class="dd-sectionlabel">证据 / 原始响应</div>
            <pre class="dd-evidence">{evidence(item)}</pre>
          </div>
        {/if}

        <!-- 面板自定义补充（验证结果等） -->
        {#if children}{@render children(item)}{/if}

        <!-- 跨面板 handoff 动作 -->
        {#if actions.length > 0}
          <div class="dd-actions">
            {#each actions as a (a.label)}
              <button type="button" class="dd-action" onclick={() => doHandoff(a)}>{a.label}</button>
            {/each}
          </div>
        {/if}
      </div>

      <!-- 底部：上一条 / 下一条 / 复制全部 -->
      <div class="dd-footer">
        <button type="button" class="dd-nav" disabled={!canPrev} onclick={prev}>‹ 上一条</button>
        <span class="dd-pos">{(index ?? 0) + 1} / {items.length}</span>
        <button type="button" class="dd-nav" disabled={!canNext} onclick={next}>下一条 ›</button>
        <button type="button" class="dd-copyall" onclick={copyAll}>复制全部</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .dd-overlay {
    position: fixed;
    inset: 0;
    z-index: 10050;
    background: rgba(15, 23, 42, 0.45);
    backdrop-filter: blur(2px);
    display: flex;
    justify-content: flex-end;
  }
  .dd-dialog {
    width: 100%;
    max-width: 480px;
    height: 100%;
    background: #fff;
    color: #1f2937;
    /* §12 —— 分层阴影 + 顶部受光高光边，读作真实物体（主题感知 token） */
    box-shadow: var(--vk-glass-highlight), var(--vk-shadow-xl);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  :global(.dark) .dd-dialog {
    background: #1e293b;
    color: #e2e8f0;
  }
  .dd-header {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    border-bottom: 1px solid #e5e7eb;
    flex-shrink: 0;
  }
  :global(.dark) .dd-header {
    border-color: #334155;
  }
  .dd-titlewrap {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 0;
  }
  .dd-title {
    margin: 0;
    font-size: 14px;
    font-weight: 700;
    line-height: 1.4;
    word-break: break-all;
  }
  .dd-sev {
    flex-shrink: 0;
    padding: 1px 7px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
  }
  .dd-sev-danger { background: #fee2e2; color: #b91c1c; }
  .dd-sev-warn { background: #fef3c7; color: #b45309; }
  .dd-sev-low { background: #dbeafe; color: #1d4ed8; }
  .dd-sev-ok { background: #dcfce7; color: #15803d; }
  .dd-sev-info { background: #e0e7ff; color: #4338ca; }
  .dd-sev-muted { background: #f3f4f6; color: #6b7280; }
  :global(.dark) .dd-sev-danger { background: rgba(239,68,68,.2); color: #fca5a5; }
  :global(.dark) .dd-sev-warn { background: rgba(245,158,11,.2); color: #fcd34d; }
  :global(.dark) .dd-sev-low { background: rgba(59,130,246,.2); color: #93c5fd; }
  :global(.dark) .dd-sev-ok { background: rgba(34,197,94,.2); color: #86efac; }
  :global(.dark) .dd-sev-info { background: rgba(99,102,241,.2); color: #a5b4fc; }
  :global(.dark) .dd-sev-muted { background: rgba(148,163,184,.18); color: #cbd5e1; }
  .dd-close {
    flex-shrink: 0;
    width: 28px;
    height: 28px;
    border: none;
    background: transparent;
    color: inherit;
    font-size: 16px;
    cursor: pointer;
    border-radius: 6px;
  }
  .dd-close:hover { background: rgba(0, 0, 0, 0.06); }
  :global(.dark) .dd-close:hover { background: rgba(255, 255, 255, 0.08); }
  .dd-close:focus-visible { outline: 2px solid #4a90e2; outline-offset: 2px; }

  .dd-body {
    flex: 1;
    overflow-y: auto;
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .dd-meta {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    font-size: 11px;
  }
  .dd-metatag {
    padding: 1px 7px;
    border-radius: 6px;
    background: #eef2ff;
    color: #4338ca;
  }
  :global(.dark) .dd-metatag { background: rgba(99,102,241,.18); color: #a5b4fc; }
  .dd-target {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    color: #6b7280;
    word-break: break-all;
  }
  :global(.dark) .dd-target { color: #94a3b8; }

  .dd-fields {
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .dd-field {
    display: grid;
    grid-template-columns: 7.5rem 1fr;
    gap: 8px;
    align-items: start;
    font-size: 12px;
    line-height: 1.5;
  }
  .dd-field dt {
    color: #9ca3af;
    flex-shrink: 0;
  }
  :global(.dark) .dd-field dt { color: #94a3b8; }
  .dd-field dd {
    margin: 0;
    display: flex;
    align-items: start;
    gap: 6px;
    min-width: 0;
  }
  .dd-value {
    word-break: break-all;
    flex: 1;
    min-width: 0;
  }
  .dd-value.mono,
  .dd-field dd.mono .dd-value {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  .dd-copyfield {
    flex-shrink: 0;
    border: none;
    background: transparent;
    color: #6b7280;
    font-size: 11px;
    cursor: pointer;
    padding: 0 2px;
  }
  .dd-copyfield:hover { color: #4a90e2; }
  :global(.dark) .dd-copyfield { color: #94a3b8; }
  :global(.dark) .dd-copyfield:hover { color: #60a5fa; }

  .dd-sectionlabel {
    font-size: 11px;
    color: #9ca3af;
    margin-bottom: 4px;
  }
  :global(.dark) .dd-sectionlabel { color: #94a3b8; }
  .dd-evidence {
    margin: 0;
    padding: 8px;
    background: #f9fafb;
    border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 240px;
    overflow-y: auto;
    color: #4b5563;
  }
  :global(.dark) .dd-evidence { background: rgba(15,23,42,.5); color: #cbd5e1; }

  .dd-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .dd-action {
    padding: 5px 11px;
    border: 1px solid #4a90e2;
    background: transparent;
    color: #4a90e2;
    border-radius: 7px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
  }
  .dd-action:hover { background: #4a90e2; color: #fff; }
  :global(.dark) .dd-action { border-color: #60a5fa; color: #93c5fd; }
  :global(.dark) .dd-action:hover { background: #3b82f6; color: #fff; border-color: #3b82f6; }
  .dd-action:focus-visible { outline: 2px solid #4a90e2; outline-offset: 2px; }

  .dd-footer {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 10px 16px;
    border-top: 1px solid #e5e7eb;
    flex-shrink: 0;
    font-size: 12px;
  }
  :global(.dark) .dd-footer { border-color: #334155; }
  .dd-nav {
    padding: 4px 10px;
    border: 1px solid #e5e7eb;
    background: #f9fafb;
    color: #4b5563;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
  }
  .dd-nav:hover:not(:disabled) { background: #f3f4f6; }
  .dd-nav:disabled { opacity: 0.4; cursor: not-allowed; }
  :global(.dark) .dd-nav { background: #334155; color: #cbd5e1; border-color: #475569; }
  :global(.dark) .dd-nav:hover:not(:disabled) { background: #475569; }
  .dd-nav:focus-visible { outline: 2px solid #4a90e2; outline-offset: 2px; }
  .dd-pos {
    color: #9ca3af;
    font-size: 11px;
  }
  :global(.dark) .dd-pos { color: #94a3b8; }
  .dd-copyall {
    margin-left: auto;
    padding: 4px 12px;
    border: none;
    background: #4a90e2;
    color: #fff;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
  }
  .dd-copyall:hover { background: #357abd; }
  :global(.dark) .dd-copyall { background: #3b82f6; }
  :global(.dark) .dd-copyall:hover { background: #2563eb; }
  .dd-copyall:focus-visible { outline: 2px solid #4a90e2; outline-offset: 2px; }

  /* reduced-motion 由 @/lib/ui/motion 的 transition 构造器统一降级（duration: 0） */
</style>
