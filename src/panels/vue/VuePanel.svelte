<script lang="ts">
  // Vue 分析面板 — 灵眸 v6.0
  // 检测 Vue 框架、分析路由/守卫、探索 Vuex/Pinia Store
  import { sendToContent } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import {
    type VueDetectResult,
    type VueRouteNode,
    type StoreExploreResult,
    type StoreTreeRow,
    countRouteStats,
    scorePermissionExposure,
    flattenStoreTree,
    isSensitiveEntry,
  } from '@/lib/analyzers/vue-analyzer';

  // ===== 状态 =====
  let detecting = $state(false);
  let exploring = $state(false);
  let detectResult = $state<VueDetectResult | null>(null);
  let storeResult = $state<StoreExploreResult | null>(null);
  let routeFilter = $state('');
  let storeFilter = $state('');
  let expandedStores = $state<Set<string>>(new Set());
  let currentUrl = $state('');

  // 自动填充当前 URL
  $effect(() => {
    getActiveTabUrl().then(u => { if (u) currentUrl = u; });
  });

  // ===== 检测 Vue =====
  async function detectVue() {
    detecting = true;
    detectResult = null;
    storeResult = null;

    const data = await sendToContent({ type: 'VK_VUE_DETECT' });

    if (!data || !(data as VueDetectResult).detected) {
      detectResult = null;
      detecting = false;
      toastStore.show(
        data ? '未检测到 Vue 框架' : '无法连接内容脚本（请刷新页面后重试）',
        data ? 'warning' : 'error',
      );
      return;
    }

    detectResult = data as VueDetectResult;
    detecting = false;
    toastStore.show(`检测到 Vue ${(data as VueDetectResult).version}`, 'success');
  }

  // ===== 探索 Store =====
  async function exploreStore() {
    exploring = true;
    storeResult = null;

    const data = await sendToContent({ type: 'VK_VUE_STORE_EXPLORE' });

    if (!data || !(data as StoreExploreResult).store) {
      storeResult = null;
      exploring = false;
      toastStore.show(
        data ? '未检测到 Vuex/Pinia Store' : '无法连接内容脚本',
        data ? 'warning' : 'error',
      );
      return;
    }

    storeResult = data as StoreExploreResult;
    exploring = false;
    const frameworks = (data as StoreExploreResult).store.frameworks || [];
    const storeCount = Object.keys((data as StoreExploreResult).store.stores || {}).length;
    toastStore.show(`${frameworks.join(', ')} | ${storeCount} 个 Store`, 'success');
  }

  // ===== 路由过滤 =====
  let filteredRoutes = $derived<VueRouteNode[]>(
    !detectResult?.routes || !routeFilter
      ? detectResult?.routes || []
      : filterNodes(detectResult.routes, routeFilter.toLowerCase()),
  );

  function filterNodes(routes: VueRouteNode[], keyword: string): VueRouteNode[] {
    return routes.filter(r => {
      const pathMatch = r.path.toLowerCase().includes(keyword);
      const nameMatch = r.name?.toLowerCase().includes(keyword) || false;
      if (pathMatch || nameMatch) return true;
      if (r.children?.length) return filterNodes(r.children, keyword).length > 0;
      return false;
    }).map(r => ({
      ...r,
      children: r.children?.length ? filterNodes(r.children, keyword) : [],
    }));
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
      store: storeResult ? storeResult.store : undefined,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vue-analysis-${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('报告已导出', 'success');
  }

  // ===== 辅助 =====
  function severityColor(sensitive: boolean): string {
    return sensitive ? 'text-red-500 dark:text-red-400' : '';
  }
</script>

<div class="space-y-3">
  <!-- 当前 URL -->
  <div class="card p-2 text-xs text-gray-500">
    <b>目标:</b> <span class="font-mono break-all">{currentUrl || '未获取'}</span>
  </div>

  <!-- 检测区域 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">Vue 检测</div>
      <button
        class="btn btn-sm btn-primary"
        disabled={detecting}
        onclick={detectVue}
      >
        {detecting ? '检测中...' : '检测 Vue'}
      </button>
    </div>

    {#if detectResult}
      <!-- 基本信息 -->
      <div class="space-y-1 text-xs">
        <div class="flex items-center gap-2">
          <span class="text-gray-500 w-20 shrink-0">版本</span>
          <span class="badge badge-ok">Vue {detectResult.version}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-gray-500 w-20 shrink-0">Router</span>
          {#if detectResult.router}
            <span class="badge badge-ok">
              已检测 ({detectResult.routerInfo?.mode || '?'} 模式)
            </span>
          {:else}
            <span class="text-gray-400">未检测到</span>
          {/if}
        </div>
        {#if detectResult.routerInfo}
          <div class="flex items-center gap-2">
            <span class="text-gray-500 w-20 shrink-0">Base Path</span>
            <span class="font-mono">{detectResult.routerInfo.base || '/'}</span>
          </div>
        {/if}
        <div class="flex items-center gap-2">
          <span class="text-gray-500 w-20 shrink-0">Store</span>
          {#if detectResult.store}
            <span class="badge badge-warn">已检测</span>
          {:else}
            <span class="text-gray-400">未检测到</span>
          {/if}
        </div>
      </div>

      <!-- 路由统计 -->
      {#if detectResult.router && detectResult.routes.length > 0}
        {@const stats = countRouteStats(detectResult.routes)}
        {@const exposure = scorePermissionExposure(stats)}
        <div class="space-y-1 text-xs mt-2">
          <div class="flex items-center gap-2 flex-wrap">
            <span>总计 {stats.total} 条路由</span>
            {#if stats.authCount > 0}
              <span class="badge badge-auth">需认证 {stats.authCount}</span>
            {/if}
            {#if stats.sensitiveCount > 0}
              <span class="badge badge-sensitive">敏感路径 {stats.sensitiveCount}</span>
            {/if}
            {#if stats.beforeEnterCount > 0}
              <span class="badge badge-enter">beforeEnter {stats.beforeEnterCount}</span>
            {/if}
          </div>
          {#if exposure > 0}
            <div class="text-yellow-600 dark:text-yellow-500">
              权限暴露评分: {exposure}/100
            </div>
          {/if}
        </div>

        <!-- 全局守卫 -->
        {#if detectResult.guards && Object.keys(detectResult.guards).length > 0}
          <div class="space-y-0.5 text-xs mt-1">
            <span class="text-gray-500">全局守卫:</span>
            {#each Object.entries(detectResult.guards) as [guardName, count]}
              <span class="badge">{guardName}({count})</span>
            {/each}
          </div>
        {/if}

        <!-- 路由过滤 + 树 -->
        <div class="mt-2">
          <div class="flex items-center gap-1 mb-1">
            <input
              class="input text-xs flex-1"
              placeholder="过滤路由..."
              bind:value={routeFilter}
            />
            <span class="text-xs text-gray-400 whitespace-nowrap">
              {detectResult.routes.length} 条
            </span>
          </div>
          <div class="space-y-0.5 max-h-80 overflow-y-auto">
            {#each filteredRoutes as route (route.path)}
              {@render routeNode(route, 0)}
            {/each}
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="flex gap-1 mt-2">
          <button class="btn btn-sm flex-1" onclick={copyDetectJson}>复制 JSON</button>
          <button class="btn btn-sm flex-1" onclick={exportReport}>导出报告</button>
        </div>
      {/if}
    {/if}
  </div>

  <!-- Store 探索 -->
  {#if detectResult?.store}
    <div class="card p-3 space-y-2">
      <div class="flex items-center justify-between">
        <div class="text-sm font-medium">Store 探索</div>
        <button
          class="btn btn-sm btn-primary"
          disabled={exploring}
          onclick={exploreStore}
        >
          {exploring ? '探索中...' : '探索 Store'}
        </button>
      </div>

      {#if storeResult}
        <!-- Store 框架标签 -->
        <div class="flex gap-1 flex-wrap text-xs">
          {#each (storeResult.store.frameworks || []) as fw}
            <span class="badge badge-ok">{fw}</span>
          {/each}
          {#if storeResult.store.errors?.length > 0}
            <span class="badge badge-sensitive">
              错误: {storeResult.store.errors.join('; ')}
            </span>
          {/if}
        </div>

        <!-- Store 列表 -->
        {#each Object.entries(storeResult.store.stores || {}) as [storeId, storeData]}
          {@const isExpanded = expandedStores.has(storeId)}
          <div class="card p-2 space-y-1 text-xs">
            <div class="flex items-center gap-2 cursor-pointer" onclick={() => toggleStore(storeId)}>
              <span class="text-gray-500">{isExpanded ? '▼' : '▶'}</span>
              <span class="font-semibold">{storeId}</span>
              <span class="badge">{storeData.type || 'unknown'}</span>
            </div>

            {#if isExpanded}
              <!-- Vuex extra info -->
              {#if storeData.type === 'vuex' && 'getters' in storeData}
                {@const vuex = storeData as any}
                {#if vuex.getters?.length > 0}
                  <div class="flex gap-1 flex-wrap">
                    {#each vuex.getters as g}
                      <span class="badge text-blue-600 dark:text-blue-400">{g}</span>
                    {/each}
                  </div>
                {/if}
                {#if vuex.mutations?.length > 0}
                  <div class="flex gap-1 flex-wrap">
                    {#each vuex.mutations as m}
                      <span class="badge text-yellow-600 dark:text-yellow-500">{m}</span>
                    {/each}
                  </div>
                {/if}
                {#if vuex.actions?.length > 0}
                  <div class="flex gap-1 flex-wrap">
                    {#each vuex.actions as a}
                      <span class="badge text-purple-600 dark:text-purple-400">{a}</span>
                    {/each}
                  </div>
                {/if}
              {/if}

              <!-- Store State 树 -->
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

        <!-- API 端点 -->
        {#if storeResult.actions?.apiEndpoints?.length > 0}
          <div class="space-y-1 text-xs">
            <div class="text-xs font-medium">API 端点 ({storeResult.actions.apiEndpoints.length})</div>
            <div class="space-y-0.5">
              {#each storeResult.actions.apiEndpoints as ep}
                <div class="flex items-center gap-1">
                  <code class="font-mono text-xs break-all flex-1">{ep}</code>
                  <button
                    class="btn btn-sm text-[10px] shrink-0"
                    onclick={() => {
                      navigator.clipboard.writeText(ep);
                      toastStore.show('已复制: ' + ep, 'success');
                    }}
                  >
                    复制
                  </button>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- 自定义指令 -->
        {#if storeResult.directives?.length > 0}
          <div class="space-y-1 text-xs">
            <div class="text-xs font-medium">自定义指令 ({storeResult.directives.length})</div>
            {#each storeResult.directives as dir}
              <div class="flex items-center gap-2">
                <span class="font-mono">{dir.name}</span>
                <span class="text-gray-400">{dir.count} 次</span>
                {#if dir.examples?.length > 0}
                  <span class="text-gray-500 truncate">{dir.examples[0]}</span>
                {/if}
              </div>
            {/each}
          </div>
        {/if}

        <!-- Store 操作 -->
        <div class="flex gap-1">
          <button class="btn btn-sm flex-1" onclick={copyStoreJson}>复制 Store JSON</button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<!-- 递归渲染路由节点 -->
{#snippet routeNode(route: VueRouteNode, depth: number)}
  <div
    class="flex items-center gap-1 flex-wrap text-xs py-0.5 border-b border-gray-100 dark:border-gray-800"
    style="padding-left: {depth * 16}px"
  >
    <span class="font-mono {severityColor(route.sensitive)}">{route.path}</span>
    {#if route.name}
      <span class="text-gray-500">{route.name}</span>
    {/if}
    {#if route.hasAuth}
      <span class="badge badge-auth">auth</span>
    {/if}
    {#if route.sensitive}
      <span class="badge badge-sensitive">sensitive</span>
    {/if}
    {#if route.hasBeforeEnter}
      <span class="badge badge-enter">beforeEnter</span>
    {/if}
    {#if route.childCount > 0}
      <span class="badge">{route.childCount} sub</span>
    {/if}
  </div>
  {#if route.children?.length > 0}
    {#each route.children as child (child.path)}
      {@render routeNode(child, depth + 1)}
    {/each}
  {/if}
{/snippet}
