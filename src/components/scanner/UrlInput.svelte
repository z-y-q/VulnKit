<script lang="ts">
  // 目标 URL 输入 + 扫描按钮 — bindable value，供带 URL 输入的扫描面板复用
  let {
    value = $bindable(''),
    scanning = false,
    buttonText = '扫描',
    scanningText = '扫描中...',
    placeholder = '目标 URL (https://...)',
    onscan,
  }: {
    value?: string;
    scanning?: boolean;
    buttonText?: string;
    scanningText?: string;
    placeholder?: string;
    onscan?: () => void;
  } = $props();
</script>

<div class="flex gap-1">
  <input class="input flex-1 text-sm" {placeholder} bind:value />
  <button class="btn btn-sm btn-primary shrink-0" disabled={scanning || !value} onclick={onscan}>
    {scanning ? scanningText : buttonText}
  </button>
</div>
