<script lang="ts">
  // 确认对话框 — 替代浏览器原生 confirm()（对齐 §4.3.7 / §8）
  // role="dialog" aria-modal，默认焦点「取消」，Escape 关闭，焦点陷阱，遮罩点击关闭，焦点恢复。
  // 全 scoped style 不依赖 UnoCSS，保证任意入口可用。
  import { confirmStore } from '@/stores/confirm';
  import { popTransition, scrimFade } from '@/lib/ui/motion';

  let req = $derived($confirmStore);

  let dialogRef: HTMLDivElement | undefined = $state();
  let cancelBtn: HTMLButtonElement | undefined = $state();
  let lastFocused: HTMLElement | null = null;

  // 打开时记录触发元素 + 聚焦取消（默认焦点在「取消」，防误确认）；
  // 关闭时把焦点还给触发元素（§8 modal 焦点恢复）。
  $effect(() => {
    if (req) {
      if (!lastFocused) lastFocused = document.activeElement as HTMLElement | null;
      queueMicrotask(() => cancelBtn?.focus());
    } else if (lastFocused) {
      lastFocused?.focus?.();
      lastFocused = null;
    }
  });

  // Escape 关闭 + 简单 Tab 焦点陷阱
  $effect(() => {
    if (!req) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        confirmStore.respond(false);
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
    if (e.target === e.currentTarget) confirmStore.respond(false);
  }

  function onOverlayKeydown(e: KeyboardEvent) {
    // Enter/Space 触发关闭；Escape 已由 window 级 keydown 处理
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      confirmStore.respond(false);
    }
  }
</script>

{#if req}
  <!-- 遮罩点击/激活关闭；键盘用户亦可通过 Escape（window 监听）或取消按钮关闭 -->
  <div
    class="vk-confirm-overlay"
    role="button"
    tabindex="-1"
    aria-label="点击遮罩关闭对话框"
    onclick={onOverlayClick}
    onkeydown={onOverlayKeydown}
    transition:scrimFade
  >
    <div
      bind:this={dialogRef}
      class="vk-confirm-dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="vk-confirm-title"
      aria-describedby="vk-confirm-msg"
      transition:popTransition
    >
      <h3 id="vk-confirm-title" class="vk-confirm-title">
        {#if req.variant === 'danger'}<span aria-hidden="true">⚠️</span> {/if}{req.title}
      </h3>
      <p id="vk-confirm-msg" class="vk-confirm-message">{req.message}</p>
      <div class="vk-confirm-actions">
        <button type="button" bind:this={cancelBtn} class="vk-confirm-btn vk-confirm-cancel" onclick={() => confirmStore.respond(false)}>
          {req.cancelLabel || '取消'}
        </button>
        <button
          type="button"
          class="vk-confirm-btn vk-confirm-ok {req.variant === 'danger' ? 'is-danger' : ''}"
          onclick={() => confirmStore.respond(true)}
        >
          {req.confirmLabel || '确认'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .vk-confirm-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    background: rgba(15, 23, 42, 0.45);
    backdrop-filter: blur(2px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
  }
  .vk-confirm-dialog {
    width: 100%;
    max-width: 380px;
    background: #fff;
    color: #1f2937;
    border-radius: 14px;
    /* §12 —— 分层阴影 + 顶部受光高光边（主题感知 token） */
    box-shadow: var(--vk-glass-highlight), var(--vk-shadow-xl);
    padding: 18px 20px 16px;
  }
  :global(.dark) .vk-confirm-dialog {
    background: #1e293b;
    color: #e2e8f0;
  }
  .vk-confirm-title {
    margin: 0 0 8px;
    font-size: 15px;
    font-weight: 700;
    line-height: 1.4;
  }
  .vk-confirm-message {
    margin: 0 0 16px;
    font-size: 13px;
    line-height: 1.6;
    color: #6b7280;
    white-space: pre-line;
    word-break: break-word;
  }
  :global(.dark) .vk-confirm-message {
    color: #94a3b8;
  }
  .vk-confirm-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .vk-confirm-btn {
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 600;
    border-radius: 8px;
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.15s ease;
  }
  .vk-confirm-btn:focus-visible {
    outline: 2px solid #4A90E2;
    outline-offset: 2px;
  }
  .vk-confirm-cancel {
    background: #f3f4f6;
    color: #4b5563;
    border-color: #e5e7eb;
  }
  .vk-confirm-cancel:hover {
    background: #e5e7eb;
  }
  :global(.dark) .vk-confirm-cancel {
    background: #334155;
    color: #cbd5e1;
    border-color: #475569;
  }
  :global(.dark) .vk-confirm-cancel:hover {
    background: #475569;
  }
  .vk-confirm-ok {
    background: #4A90E2;
    color: #fff;
  }
  .vk-confirm-ok:hover {
    background: #357ABD;
  }
  .vk-confirm-ok.is-danger {
    background: #ef4444;
  }
  .vk-confirm-ok.is-danger:hover {
    background: #dc2626;
  }
  /* reduced-motion 由 @/lib/ui/motion 的 transition 构造器统一降级（duration: 0） */
</style>
