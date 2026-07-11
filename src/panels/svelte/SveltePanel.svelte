<script lang="ts">
  // Svelte/SvelteKit 检测面板 — 灵眸 v6.0
  import { sendToContent } from '@/lib/core/messaging';
  import { toastStore } from '@/stores/ui';

  // —— 类型（匹配 inject/svelte-detect.ts 返回结构）——
  interface SvelteDetectResult {
    detected: boolean;
    version: string;
    variant: string;
    components: string[];
    stores: string[];
    isSvelteKit: boolean;
    routingMode: string;
    signals: string[];
  }

  // —— 状态 ——
  let scanning = $state(false);
  let result = $state<SvelteDetectResult | null>(null);

  // —— 检测 ——
  async function detectSvelte() {
    scanning = true;
    result = null;

    const resp = await sendToContent({ type: 'VK_SVELTE_DETECT' });

    if (!resp) {
      toastStore.show('检测失败: 请刷新目标网页后重试', 'error');
      scanning = false;
      return;
    }

    result = resp as SvelteDetectResult;
    scanning = false;

    if (result.detected) {
      const name = result.variant || 'Svelte';
      toastStore.show(`检测到 ${name}${result.version ? ' ' + result.version : ''}`, 'success');
    } else {
      toastStore.show('未检测到 Svelte', 'info');
    }
  }

  // —— 复制 / 导出 ——
  function copyResults() {
    if (!result) {
      toastStore.show('没有检测结果', 'warning');
      return;
    }
    const lines: string[] = [];
    if (result.detected) {
      const name = result.variant || 'Svelte';
      lines.push(`${name} Detected: ${result.version || 'unknown'}`);
      if (result.isSvelteKit) lines.push('SvelteKit: Yes');
      if (result.routingMode) lines.push('Routing: ' + result.routingMode);
    } else {
      lines.push('Svelte: Not detected');
    }
    if (result.components.length > 0) {
      lines.push('Components: ' + result.components.join(', '));
    }
    if (result.stores.length > 0) {
      lines.push('Stores: ' + result.stores.join(', '));
    }
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      toastStore.show('已复制检测结果', 'success');
    });
  }

  function exportJson() {
    if (!result) {
      toastStore.show('没有可导出的结果', 'warning');
      return;
    }
    const report = { timestamp: new Date().toISOString(), result };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'svelte-analysis-' + Date.now() + '.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('已导出 JSON', 'success');
  }
</script>

<div class="space-y-3">
  <!-- 检测按钮 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">Svelte / SvelteKit 检测</div>
      <button
        class="btn btn-sm btn-primary"
        disabled={scanning}
        onclick={detectSvelte}
      >
        {scanning ? '检测中...' : '检测 Svelte'}
      </button>
    </div>
    <div class="text-xs text-gray-400">
      检测当前页面是否使用 Svelte 框架，识别版本、组件和路由模式
    </div>
  </div>

  <!-- 扫描进度 -->
  {#if scanning}
    <div class="card p-3 text-center">
      <div class="text-xs text-gray-500">正在注入检测脚本并分析页面...</div>
    </div>
  {/if}

  <!-- 未检测到 -->
  {#if !scanning && result && !result.detected}
    <div class="card p-3 text-center space-y-1">
      <div class="text-2xl">&#128270;</div>
      <div class="text-sm">未检测到 Svelte</div>
      <div class="text-xs text-gray-400">当前页面未发现 Svelte/SvelteKit 框架特征</div>
    </div>
  {/if}

  <!-- 检测结果 -->
  {#if !scanning && result && result.detected}
    <div class="card p-3 space-y-2">
      <!-- 标题行 -->
      <div class="flex items-center gap-2 flex-wrap">
        <span class="badge badge-green">已检测到</span>
        <span class="text-sm font-bold">
          {result.variant || 'Svelte'}{result.version ? ' ' + result.version : ''}
        </span>
      </div>

      <!-- SvelteKit -->
      {#if result.isSvelteKit}
        <div class="text-xs">
          <span class="text-gray-500">框架变体:</span>
          <span class="badge badge-blue ml-1">SvelteKit</span>
        </div>
      {/if}

      <!-- 版本 -->
      {#if result.version}
        <div class="text-xs">
          <span class="text-gray-500">版本:</span>
          <span class="font-mono ml-1">{result.version}</span>
        </div>
      {/if}

      <!-- 路由模式 -->
      {#if result.routingMode}
        <div class="text-xs">
          <span class="text-gray-500">路由模式:</span>
          <span class="ml-1">{result.routingMode}</span>
        </div>
      {/if}

      <!-- 组件 -->
      {#if result.components.length > 0}
        <div class="space-y-1">
          <div class="text-xs text-gray-500">组件 ({result.components.length})</div>
          <div class="flex flex-wrap gap-1">
            {#each result.components as c}
              <span class="badge">{c}</span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- Store -->
      {#if result.stores.length > 0}
        <div class="space-y-1">
          <div class="text-xs text-gray-500">Store ({result.stores.length})</div>
          <div class="flex flex-wrap gap-1">
            {#each result.stores as s}
              <span class="badge">{s}</span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- 检测信号 -->
      {#if result.signals.length > 0}
        <div class="space-y-1">
          <div class="text-xs text-gray-500">检测信号</div>
          {#each result.signals as sig}
            <div class="text-xs font-mono text-gray-600 dark:text-gray-400">{sig}</div>
          {/each}
        </div>
      {/if}
    </div>

    <!-- 操作按钮 -->
    <div class="flex gap-1">
      <button class="btn btn-sm flex-1" onclick={copyResults}>复制文本</button>
      <button class="btn btn-sm flex-1" onclick={exportJson}>导出 JSON</button>
    </div>
  {/if}
</div>
