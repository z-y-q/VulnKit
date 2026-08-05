<script lang="ts">
  // Angular 分析面板
  // 1. Angular 框架检测（版本/变体/模式/组件/路由/信号）
  // 2. NgRx Store / Angular Signals / Router / API 端点探索
  import { sendToContent } from '@/lib/core/messaging';
  import { toastStore } from '@/stores/ui';
  import { flattenStoreTree } from '@/lib/analyzers/vue-analyzer';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';

  // ===== 类型（与 inject/angular-detect.ts / inject/angular-store-explorer.ts 返回值一致）=====
  interface AngularDetectResult {
    detected: boolean;
    version: string;
    variant: string;
    mode: string;
    modules: string[];
    routes: string[];
    signals: string[];
  }

  interface AngularStoreEntry {
    state: unknown;
    type: string;
  }

  interface AngularSignal {
    name: string;
    component: string;
  }

  interface AngularRoute {
    path: string;
    source: string;
    component?: string;
    lazy?: boolean;
    guards?: string[];
    data?: unknown;
  }

  interface AngularStoreExploreResult {
    stores: Record<string, AngularStoreEntry>;
    signals: AngularSignal[];
    routes: AngularRoute[];
    apiEndpoints: string[];
    errors: string[];
  }

  // ===== 状态 =====
  let detectLoading = $state(false);
  let detectResult = $state<AngularDetectResult | null>(null);
  let detectStatus = $state('');

  let storeLoading = $state(false);
  let storeResult = $state<AngularStoreExploreResult | null>(null);
  let storeStatus = $state('');
  let storeSearch = $state('');
  // 子标签页: 'store' | 'routes' | 'api'
  let activeSubTab = $state<'store' | 'routes' | 'api'>('store');
  let filteredStoreKeys = $derived.by(() => {
    const keys = Object.keys(storeResult?.stores || {});
    if (!storeSearch) return keys;
    const q = storeSearch.toLowerCase();
    return keys.filter(k => k.toLowerCase().includes(q));
  });
  let lastDetectResult = $state<AngularDetectResult | null>(null);

  // ===== 检测 Angular =====
  async function detectAngular() {
    detectLoading = true;
    detectResult = null;
    detectStatus = '正在检测 Angular...';

    const response = await sendToContent({ type: 'VK_ANGULAR_DETECT' });
    detectLoading = false;

    if (!response) {
      detectStatus = '检测失败：请刷新目标网页后重试';
      toastStore.show('检测失败，请刷新页面后重试', 'error');
      return;
    }

    const data = response as AngularDetectResult;
    detectResult = data;
    lastDetectResult = data;

    if (data.detected) {
      detectStatus = `检测到 ${data.variant || 'Angular'}${data.version ? ' ' + data.version : ''}`;
      toastStore.show(`检测到 Angular${data.version ? ' ' + data.version : ''}`, 'success');
    } else {
      detectStatus = '未检测到 Angular';
      toastStore.show('未检测到 Angular 框架', 'info');
    }
    await saveFindings();
  }

  // ===== 探索 Store =====
  async function exploreStore() {
    storeLoading = true;
    storeResult = null;
    storeStatus = '正在探索 Angular Store...';
    activeSubTab = 'store';

    const response = await sendToContent({ type: 'VK_ANGULAR_STORE_EXPLORE' });
    storeLoading = false;

    if (!response) {
      storeStatus = '无响应，请刷新页面后重试';
      toastStore.show('获取 Store 数据失败', 'error');
      return;
    }

    const data = response as AngularStoreExploreResult;
    storeResult = data;

    const storeKeys = Object.keys(data.stores || {});
    const parts: string[] = [];
    if (storeKeys.length > 0) parts.push(`${storeKeys.length} 个 Store`);
    if (data.signals?.length > 0) parts.push(`${data.signals.length} 个 Signal`);
    storeStatus = parts.length > 0 ? parts.join(' | ') : '未检测到 Angular Store';

    if (data.errors?.length > 0) {
      storeStatus += ` | ${data.errors.slice(0, 2).join('; ')}`;
    }

    toastStore.show(
      storeKeys.length > 0 ? `发现 ${storeKeys.length} 个 Store` : '未发现 NgRx Store / Signal',
      storeKeys.length > 0 ? 'success' : 'info',
    );
    await saveFindings();
  }

  // state 树扁平化复用 vue-analyzer 的 flattenStoreTree（含敏感字段检测）

  // ===== 复制 / 导出 =====
  function copyDetectResults() {
    if (!lastDetectResult) {
      toastStore.show('没有检测结果', 'warning');
      return;
    }
    const d = lastDetectResult;
    const lines: string[] = [];
    if (d.detected) {
      lines.push(`${d.variant || 'Angular'} Detected: ${d.version || 'unknown'}`);
      if (d.mode) lines.push(`Mode: ${d.mode}`);
    } else {
      lines.push('Angular: Not detected');
    }
    if (d.modules?.length > 0) lines.push(`Modules: ${d.modules.join(', ')}`);
    if (d.routes?.length > 0) {
      lines.push('Routes:');
      d.routes.forEach((r) => lines.push(`  - ${r}`));
    }
    if (d.signals?.length > 0) {
      lines.push('Signals:');
      d.signals.forEach((s) => lines.push(`  - ${s}`));
    }
    copyText(lines.join('\n'), '已复制检测结果');
  }

  function copyStoreJson() {
    if (!storeResult) {
      toastStore.show('没有 Store 数据', 'warning');
      return;
    }
    const json = JSON.stringify(storeResult.stores || {}, null, 2);
    copyText(json, 'Store JSON 已复制');
  }

  function copyRoutesText() {
    const sr = storeResult;
    if (!sr?.routes?.length) {
      toastStore.show('没有路由数据', 'warning');
      return;
    }
    const text = JSON.stringify(sr.routes, null, 2);
    copyText(text, `已复制 ${sr.routes.length} 个路由（JSON）`);
  }

  function copyEndpoint(url: string) {
    copyText(url, `已复制: ${url}`);
  }

  // —— 导出序列化器（detect + store 合并报告）——
  type AngularReport = { detect: AngularDetectResult | null; store: typeof storeResult };
  function angularJson(items: AngularReport[]): string {
    const r = items[0];
    return JSON.stringify({ detect: r.detect, store: r.store }, null, 2);
  }
  function angularText(items: AngularReport[]): string {
    const r = items[0];
    const lines: string[] = [];
    if (r.detect?.detected) {
      lines.push(`${r.detect.variant || 'Angular'} ${r.detect.version || ''} (${r.detect.mode})`);
    }
    if (r.store?.routes?.length) lines.push(`Routes: ${r.store.routes.length}`);
    if (r.store?.apiEndpoints?.length) lines.push(`API: ${r.store.apiEndpoints.length}`);
    return lines.join('\n') || '无数据';
  }
  let exportItems = $derived<AngularReport[]>([{ detect: lastDetectResult, store: storeResult }]);

  // ===== 渲染辅助 =====
  function modeBadgeColor(mode: string): string {
    return mode === 'development'
      ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300'
      : 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300';
  }

  // ===== Findings 导出 =====
  /** 基于当前扫描结果生成安全发现（对齐 v5 vk-angular getFindings） */
  function getFindings(): ScanFinding[] {
    const findings: ScanFinding[] = [];
    if (!lastDetectResult || !lastDetectResult.detected) return findings;
    if (lastDetectResult.version) {
      findings.push({ severity: 'info', title: 'Angular 版本泄露', detail: '检测到 Angular 版本: ' + lastDetectResult.version });
    }
    if (lastDetectResult.mode === 'development') {
      findings.push({ severity: 'medium', title: 'Angular 开发模式运行', detail: '应用以开发模式运行，可能泄露调试信息和源码映射' });
    }
    if (storeResult?.routes?.length) {
      findings.push({ severity: 'low', title: '客户端路由发现', detail: storeResult.routes.length + ' 个路由' });
    }
    if (storeResult?.apiEndpoints?.length) {
      findings.push({ severity: 'low', title: 'API 端点发现', detail: storeResult.apiEndpoints.length + ' 个端点' });
    }
    return findings;
  }

  /** 将 findings 保存到扫描历史 */
  async function saveFindings() {
    const findings = getFindings();
    if (findings.length > 0) {
      // Angular panel doesn't have its own URL; use tab URL via a simple trick
      const url = typeof location !== 'undefined' ? location.href : '';
      await scanHistoryStore.addScan({ url, module: 'angular', findings });
    }
  }
</script>

<div class="space-y-3">
  <!-- 检测 Angular -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">Angular 检测</div>
      <div class="flex gap-1">
        <button
          class="btn btn-sm btn-primary"
          disabled={detectLoading}
          onclick={detectAngular}
        >
          {detectLoading ? '检测中...' : '检测 Angular'}
        </button>
        <ExportMenu items={exportItems} module="angular" serializers={{ json: angularJson, text: angularText }} copySerialize={angularText} disabled={!lastDetectResult && !storeResult} />
      </div>
    </div>
    {#if detectStatus}
      <div class="text-xs text-gray-500">{detectStatus}</div>
    {/if}
  </div>

  <!-- 检测结果 -->
  {#if detectResult}
    <div class="card p-3 space-y-2">
      <!-- 标题行 -->
      <div class="flex items-center gap-2 flex-wrap">
        <span class="badge {detectResult.detected ? 'badge-success' : 'badge-gray'}">
          {detectResult.detected ? '已检测到' : '未检测到'}
        </span>
        <span class="text-sm font-medium">
          {detectResult.variant || 'Angular'}{detectResult.version ? ' ' + detectResult.version : ''}
        </span>
      </div>

      <!-- 框架变体 -->
      {#if detectResult.variant}
        <div class="flex items-center gap-2 text-xs">
          <span class="text-gray-500 w-16 shrink-0">变体</span>
          <span class="badge badge-info">{detectResult.variant}</span>
        </div>
      {/if}

      <!-- 版本 -->
      {#if detectResult.version}
        <div class="flex items-center gap-2 text-xs">
          <span class="text-gray-500 w-16 shrink-0">版本</span>
          <span class="font-mono">{detectResult.version}</span>
        </div>
      {/if}

      <!-- 运行模式 -->
      {#if detectResult.mode}
        <div class="flex items-center gap-2 text-xs">
          <span class="text-gray-500 w-16 shrink-0">模式</span>
          <span class="badge {modeBadgeColor(detectResult.mode)}">{detectResult.mode}</span>
        </div>
      {/if}

      <!-- 模块/组件 -->
      {#if detectResult.modules?.length > 0}
        <div class="text-xs">
          <span class="text-gray-500">{detectResult.variant === 'Angular' ? '组件/模块' : '模块'} ({detectResult.modules.length})</span>
          <div class="flex flex-wrap gap-1 mt-1">
            {#each detectResult.modules as m}
              <span class="badge badge-outline text-xs">{m}</span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- 路由 -->
      {#if detectResult.routes?.length > 0}
        <div class="text-xs">
          <span class="text-gray-500">路由 ({detectResult.routes.length})</span>
          <div class="space-y-0.5 mt-1">
            {#each detectResult.routes as r}
              <div class="font-mono text-xs">{r}</div>
            {/each}
          </div>
        </div>
      {/if}

      <!-- 检测信号 -->
      {#if detectResult.signals?.length > 0}
        <div class="text-xs">
          <span class="text-gray-500">检测信号</span>
          <div class="space-y-0.5 mt-1">
            {#each detectResult.signals as s}
              <div class="text-xs">{s}</div>
            {/each}
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- Store 探索 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">Store / State 探索</div>
      <button
        class="btn btn-sm btn-primary"
        disabled={storeLoading}
        onclick={exploreStore}
      >
        {storeLoading ? '探索中...' : '探索 State'}
      </button>
    </div>
    {#if storeStatus}
      <div class="text-xs text-gray-500">{storeStatus}</div>
    {/if}
    {#if storeResult && Object.keys(storeResult.stores || {}).length > 0}
      <input class="input text-xs" placeholder="搜索 Store..." bind:value={storeSearch} />
    {/if}
  </div>

  <!-- Store 探索结果 -->
  {#if storeResult}
    <!-- 子标签页切换 -->
    <div class="flex gap-1">
      <button
        class="btn btn-sm {activeSubTab === 'store' ? 'btn-primary' : ''}"
        onclick={() => (activeSubTab = 'store')}
      >
        Store
      </button>
      <button
        class="btn btn-sm {activeSubTab === 'routes' ? 'btn-primary' : ''}"
        onclick={() => (activeSubTab = 'routes')}
      >
        路由 {storeResult.routes?.length ? `(${storeResult.routes.length})` : ''}
      </button>
      <button
        class="btn btn-sm {activeSubTab === 'api' ? 'btn-primary' : ''}"
        onclick={() => (activeSubTab = 'api')}
      >
        API {storeResult.apiEndpoints?.length ? `(${storeResult.apiEndpoints.length})` : ''}
      </button>
    </div>

    <!-- Store 标签页 -->
    {#if activeSubTab === 'store'}
      {#if filteredStoreKeys.length === 0 && (!storeResult.signals || storeResult.signals.length === 0)}
        <div class="card p-3 text-center text-xs text-gray-500">未发现 NgRx Store / Signal</div>
      {:else}
        <!-- Store 列表 -->
        {#each filteredStoreKeys as storeId}
          {@const storeData = storeResult.stores[storeId] || { state: {}, type: 'unknown' }}
          {@const state = storeData.state || {}}
          {@const rows = flattenStoreTree(state)}
          <div class="card p-3 space-y-1">
            <div class="flex items-center gap-2">
              <span class="text-xs font-medium font-mono">{storeId}</span>
              <span class="badge badge-outline text-xs">{storeData.type || 'unknown'}</span>
            </div>
            {#if rows.length > 0}
              <div class="space-y-0.5 overflow-x-auto">
                {#each rows as row}
                  <div class="flex items-baseline gap-1 text-xs" style="padding-left: {row.depth * 16}px">
                    <span class="font-mono text-gray-600 dark:text-gray-500 w-32 shrink-0 truncate">{row.key}</span>
                    <span class="text-gray-500 w-12 shrink-0">{row.type}</span>
                    <span class="font-mono break-all flex-1 {row.sensitive ? 'text-red-500 dark:text-red-400' : 'text-gray-700 dark:text-gray-300'}">{row.valuePreview}</span>
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        {/each}

        <!-- Signals 列表 -->
        {#if storeResult.signals?.length > 0}
          <div class="card p-3 space-y-1">
            <div class="text-xs font-medium">Signals</div>
            {#each storeResult.signals as s}
              <div class="flex items-center gap-2 text-xs">
                <span class="font-mono">{s.name || 'unknown'}</span>
                <span class="badge badge-outline text-xs">{s.component || 'global'}</span>
              </div>
            {/each}
          </div>
        {/if}

        <!-- 复制按钮 -->
        <div class="flex gap-1">
          <button class="btn btn-sm flex-1" onclick={copyStoreJson}>复制 Store JSON</button>
        </div>
      {/if}
    {/if}

    <!-- 路由标签页 -->
    {#if activeSubTab === 'routes'}
      {#if !storeResult.routes || storeResult.routes.length === 0}
        <div class="card p-3 text-center text-xs text-gray-500">未发现路由</div>
      {:else}
        <div class="space-y-1">
          {#each storeResult.routes as r}
            <div class="card p-2 flex items-center gap-2 flex-wrap text-xs">
              <code class="font-mono">{r.path || '/'}</code>
              {#if r.component}
                <span class="badge badge-info text-xs">{r.component}</span>
              {/if}
              {#if r.lazy}
                <span class="badge badge-outline text-xs">懒加载</span>
              {/if}
              {#if r.guards && r.guards.length > 0}
                {#each r.guards as g}
                  <span class="badge badge-outline text-xs">{g}</span>
                {/each}
              {/if}
              {#if r.source}
                <span class="text-gray-500 text-xs">{r.source}</span>
              {/if}
            </div>
          {/each}
        </div>
        <div class="flex gap-1">
          <button class="btn btn-sm flex-1" onclick={copyRoutesText}>复制路由</button>
        </div>
      {/if}
    {/if}

    <!-- API 端点标签页 -->
    {#if activeSubTab === 'api'}
      {#if !storeResult.apiEndpoints || storeResult.apiEndpoints.length === 0}
        <div class="card p-3 text-center text-xs text-gray-500">未发现 API 端点</div>
      {:else}
        <div class="space-y-0.5">
          {#each storeResult.apiEndpoints as ep}
            <div class="card p-2 flex items-center gap-2 text-xs">
              <code class="font-mono break-all flex-1">
                {ep.length > 100 ? ep.substring(0, 97) + '...' : ep}
              </code>
              <button class="btn btn-sm btn-ghost text-xs shrink-0" onclick={() => copyEndpoint(ep)}>复制</button>
            </div>
          {/each}
        </div>
      {/if}
    {/if}

    <!-- 错误信息 -->
    {#if storeResult.errors?.length > 0}
      <div class="card p-2 text-xs text-yellow-600 dark:text-yellow-500 space-y-0.5">
        <div class="font-medium">警告</div>
        {#each storeResult.errors as err}
          <div>{err}</div>
        {/each}
      </div>
    {/if}
  {/if}
</div>
