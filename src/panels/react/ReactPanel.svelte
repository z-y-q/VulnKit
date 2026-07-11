<script lang="ts">
  // React 分析面板 — 灵眸 v6.0
  // 检测 React 框架、分析路由/信号、探索 Redux/Zustand/Jotai/Recoil Store
  import { sendToContent } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import {
    type StoreTreeRow,
    flattenStoreTree,
    isSensitiveEntry,
  } from '@/lib/analyzers/vue-analyzer';

  // ===== 类型（与 inject/react-detect.ts 返回值对齐）=====
  interface ReactDetectResult {
    detected: boolean;
    version: string;
    metaframework: string;
    mode: string;
    stateManager: string;
    components: string[];
    routes: string[];
    signals: string[];
  }

  // ===== 类型（与 inject/react-store-explorer.ts 返回值对齐）=====
  interface StoreEntry {
    state: any;
    type: string;
    atomCount?: number;
  }

  interface RouteEntry {
    path: string;
    source: string;
    hasElement?: boolean;
  }

  interface StoreExploreResult {
    stores: Record<string, StoreEntry>;
    routes: RouteEntry[];
    apiEndpoints: string[];
    errors: string[];
  }

  // ===== 状态 =====
  let detecting = $state(false);
  let exploring = $state(false);
  let detectResult = $state<ReactDetectResult | null>(null);
  let storeResult = $state<StoreExploreResult | null>(null);
  let storeFilter = $state('');
  let expandedStores = $state<Set<string>>(new Set());
  let currentUrl = $state('');

  // 自动填充当前 URL
  $effect(() => {
    getActiveTabUrl().then(u => { if (u) currentUrl = u; });
  });

  // ===== 检测 React =====
  async function detectReact() {
    detecting = true;
    detectResult = null;
    storeResult = null;

    const data = await sendToContent({ type: 'VK_REACT_DETECT' });

    if (!data || !(data as ReactDetectResult).detected) {
      detectResult = null;
      detecting = false;
      toastStore.show(
        data ? '未检测到 React 框架' : '无法连接内容脚本（请刷新页面后重试）',
        data ? 'warning' : 'error',
      );
      return;
    }

    detectResult = data as ReactDetectResult;
    detecting = false;
    toastStore.show(`检测到 React ${(data as ReactDetectResult).version || ''}`, 'success');
  }

  // ===== 探索 Store =====
  async function exploreStore() {
    exploring = true;
    storeResult = null;

    const data = await sendToContent({ type: 'VK_REACT_STORE_EXPLORE' });

    if (!data || !(data as StoreExploreResult).stores) {
      storeResult = null;
      exploring = false;
      toastStore.show(
        data ? '未检测到 React Store' : '无法连接内容脚本',
        data ? 'warning' : 'error',
      );
      return;
    }

    storeResult = data as StoreExploreResult;
    exploring = false;
    const storeKeys = Object.keys(storeResult.stores);
    const types = new Set<string>();
    storeKeys.forEach(k => {
      const t = storeResult!.stores[k]?.type || 'unknown';
      types.add(t);
    });
    toastStore.show(`${Array.from(types).join(', ')} | ${storeKeys.length} 个 Store`, 'success');
  }

  // ===== Store 展开/收起 =====
  function toggleStore(storeId: string) {
    if (expandedStores.has(storeId)) {
      expandedStores.delete(storeId);
    } else {
      expandedStores.add(storeId);
    }
    expandedStores = new Set(expandedStores); // trigger reactivity
  }

  // ===== 复制/导出 =====
  function copyDetectJson() {
    if (!detectResult) return;
    navigator.clipboard.writeText(JSON.stringify(detectResult, null, 2)).then(() => {
      toastStore.show('已复制检测结果', 'success');
    });
  }

  function copyStoreJson() {
    if (!storeResult) return;
    navigator.clipboard.writeText(JSON.stringify(storeResult, null, 2)).then(() => {
      toastStore.show('已复制 Store 数据', 'success');
    });
  }

  function exportReport() {
    if (!detectResult) return;
    const report = {
      timestamp: new Date().toISOString(),
      url: currentUrl,
      detect: detectResult,
      store: storeResult || undefined,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `react-analysis-${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('报告已导出', 'success');
  }

  function copyText(text: string, label?: string) {
    navigator.clipboard.writeText(text).then(() => {
      toastStore.show(label ? `已复制: ${label}` : '已复制', 'success');
    });
  }

  // ===== 衍生状态 =====
  let groupedRoutes = $derived(() => {
    if (!storeResult?.routes) return {};
    const g: Record<string, RouteEntry[]> = {};
    for (const r of storeResult.routes) {
      const src = r.source || 'unknown';
      if (!g[src]) g[src] = [];
      g[src].push(r);
    }
    return g;
  });

  // ===== 辅助 =====
  function modeColor(mode: string): string {
    return mode === 'development'
      ? 'text-red-500 dark:text-red-400'
      : 'text-green-600 dark:text-green-500';
  }

  function modeLabel(mode: string): string {
    return mode === 'development' ? '开发模式' : '生产模式';
  }

  function severityColor(sensitive: boolean): string {
    return sensitive ? 'text-red-500 dark:text-red-400' : '';
  }
</script>

<div class="space-y-3">
  <!-- 当前 URL -->
  <div class="card p-2 text-xs text-gray-500">
    <b>目标:</b> <span class="font-mono break-all">{currentUrl || '未获取'}</span>
  </div>

  <!-- React 检测 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">React 检测</div>
      <button
        class="btn btn-sm btn-primary"
        disabled={detecting}
        onclick={detectReact}
      >
        {detecting ? '检测中...' : '检测 React'}
      </button>
    </div>

    {#if detectResult}
      <!-- 基本信息 -->
      <div class="space-y-1 text-xs">
        <div class="flex items-center gap-2">
          <span class="text-gray-500 w-20 shrink-0">状态</span>
          <span class="badge badge-ok">已检测</span>
        </div>
        {#if detectResult.version}
          <div class="flex items-center gap-2">
            <span class="text-gray-500 w-20 shrink-0">版本</span>
            <span class="badge badge-ok">React {detectResult.version}</span>
          </div>
        {/if}
        {#if detectResult.mode}
          <div class="flex items-center gap-2">
            <span class="text-gray-500 w-20 shrink-0">运行模式</span>
            <span class="{modeColor(detectResult.mode)} font-semibold">
              {modeLabel(detectResult.mode)}
            </span>
          </div>
        {/if}
        {#if detectResult.metaframework}
          <div class="flex items-center gap-2">
            <span class="text-gray-500 w-20 shrink-0">元框架</span>
            <span class="badge">{detectResult.metaframework}</span>
          </div>
        {/if}
        {#if detectResult.stateManager}
          <div class="flex items-center gap-2">
            <span class="text-gray-500 w-20 shrink-0">状态管理</span>
            <span class="badge badge-warn">{detectResult.stateManager}</span>
          </div>
        {/if}
      </div>

      <!-- 组件树 -->
      {#if detectResult.components && detectResult.components.length > 0}
        <div class="space-y-1 text-xs mt-2">
          <div class="flex items-center gap-2">
            <span class="text-gray-500">组件树</span>
            <span class="text-gray-400">({detectResult.components.length})</span>
          </div>
          <div class="flex gap-1 flex-wrap">
            {#each detectResult.components as c}
              <span class="badge">{c}</span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- 检测信号 -->
      {#if detectResult.signals && detectResult.signals.length > 0}
        <div class="space-y-1 text-xs mt-2">
          <div class="text-gray-500 mb-1">检测信号</div>
          {#each detectResult.signals as s}
            <div class="text-gray-600 dark:text-gray-400">{s}</div>
          {/each}
        </div>
      {/if}

      <!-- 路由（detect 阶段） -->
      {#if detectResult.routes && detectResult.routes.length > 0}
        <div class="space-y-1 text-xs mt-2">
          <div class="flex items-center gap-2">
            <span class="text-gray-500">路由</span>
            <span class="text-gray-400">({detectResult.routes.length})</span>
          </div>
          <div class="space-y-0.5 max-h-40 overflow-y-auto">
            {#each detectResult.routes as r}
              <div class="font-mono text-gray-600 dark:text-gray-400">{r}</div>
            {/each}
          </div>
        </div>
      {/if}

      <!-- 操作按钮 -->
      <div class="flex gap-1 mt-2">
        <button class="btn btn-sm flex-1" onclick={copyDetectJson}>复制 JSON</button>
        <button class="btn btn-sm flex-1" onclick={exportReport}>导出报告</button>
      </div>
    {/if}
  </div>

  <!-- Store 探索 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">Store 探索</div>
      <button
        class="btn btn-sm btn-primary"
        disabled={exploring}
        onclick={exploreStore}
      >
        {exploring ? '探索中...' : '探索 State'}
      </button>
    </div>

    {#if storeResult}
      <!-- 错误提示 -->
      {#if storeResult.errors && storeResult.errors.length > 0}
        <div class="flex gap-1 flex-wrap text-xs">
          {#each storeResult.errors as err}
            <span class="badge badge-sensitive">{err}</span>
          {/each}
        </div>
      {/if}

      <!-- Store 列表 -->
      {#each Object.entries(storeResult.stores || {}) as [storeId, storeData]}
        {@const isExpanded = expandedStores.has(storeId)}
        <div class="card p-2 space-y-1 text-xs">
          <div class="flex items-center gap-2 cursor-pointer" onclick={() => toggleStore(storeId)}>
            <span class="text-gray-500">{isExpanded ? '▼' : '▶'}</span>
            <span class="font-semibold">{storeId}</span>
            <span class="badge">{storeData.type || 'unknown'}</span>
            {#if storeData.atomCount}
              <span class="badge">{storeData.atomCount} atoms</span>
            {/if}
          </div>

          {#if isExpanded}
            <!-- State 树 -->
            {#if storeData.state && typeof storeData.state === 'object'}
              {@const rows = flattenStoreTree(storeData.state).filter(r =>
                !storeFilter || r.path.toLowerCase().includes(storeFilter.toLowerCase()) || r.key.toLowerCase().includes(storeFilter.toLowerCase())
              )}
              <input
                class="input text-xs w-full"
                placeholder="过滤 State..."
                bind:value={storeFilter}
              />
              <div class="max-h-60 overflow-y-auto">
                {#each rows as row}
                  <div
                    class="flex items-baseline gap-1 py-0.5 border-b border-gray-100 dark:border-gray-800"
                    style="padding-left: {row.depth * 16}px"
                  >
                    <span class="font-mono text-gray-600 dark:text-gray-400 w-32 shrink-0 truncate">{row.key}</span>
                    <span class="text-gray-400 w-12 shrink-0">{row.type}</span>
                    <span class="font-mono break-all flex-1 {row.sensitive ? 'text-red-500 dark:text-red-400' : 'text-gray-700 dark:text-gray-300'}">{row.valuePreview}</span>
                    {#if row.sensitive}
                      <span class="text-red-500 dark:text-red-400 text-[10px] shrink-0">SENSITIVE</span>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          {/if}
        </div>
      {/each}

      <!-- 路由（explore 阶段） -->
      {#if storeResult.routes && storeResult.routes.length > 0}
        <div class="space-y-1 text-xs mt-2">
          <div class="flex items-center gap-2">
            <span class="font-medium">路由</span>
            <span class="text-gray-400">({storeResult.routes.length})</span>
          </div>
          <!-- 按来源分组 -->
          <div class="space-y-1">
            {#each Object.entries(groupedRoutes) as [src, routes]}
              <div>
                <div class="text-gray-500 font-medium">{src} ({routes.length})</div>
                <div class="space-y-0.5 max-h-60 overflow-y-auto">
                  {#each routes as r}
                    <div class="flex items-center gap-1">
                      <code class="font-mono text-xs break-all flex-1">{r.path}</code>
                      {#if r.hasElement}
                        <span class="badge text-[10px]">component</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              </div>
            {/each}
          </div>
          <div class="flex gap-1">
            <button
              class="btn btn-sm flex-1"
              onclick={() => copyText(
                storeResult!.routes.map(r => r.path).join('\n'),
                `${storeResult!.routes.length} 条路由`,
              )}
            >
              复制路由
            </button>
          </div>
        </div>
      {/if}

      <!-- API 端点 -->
      {#if storeResult.apiEndpoints && storeResult.apiEndpoints.length > 0}
        <div class="space-y-1 text-xs mt-2">
          <div class="flex items-center gap-2">
            <span class="font-medium">API 端点</span>
            <span class="text-gray-400">({storeResult.apiEndpoints.length})</span>
          </div>
          <div class="space-y-0.5 max-h-60 overflow-y-auto">
            {#each storeResult.apiEndpoints as ep}
              {@const isAction = ep.startsWith('[Action] ')}
              <div class="flex items-center gap-1">
                <code class="font-mono text-xs break-all flex-1">
                  {isAction ? ep.substring(8) : ep}
                </code>
                {#if isAction}
                  <span class="badge text-[10px]">action</span>
                {/if}
                <button
                  class="btn btn-sm text-[10px] shrink-0"
                  onclick={() => copyText(isAction ? ep.substring(8) : ep)}
                >
                  复制
                </button>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <!-- Store 操作 -->
      {#if Object.keys(storeResult.stores || {}).length > 0}
        <div class="flex gap-1">
          <button class="btn btn-sm flex-1" onclick={copyStoreJson}>复制 Store JSON</button>
        </div>
      {/if}
    {/if}
  </div>
</div>
