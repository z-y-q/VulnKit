<script lang="ts">
  // RuoYi 路由分析面板 — 灵眸 v6.0
  // 流程：注册 Hook → 监听 VK_RUOYI_HOOK_EVENT → 实时显示捕获的路由/请求
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import {
    type HookEvent,
    type CapturedRequest,
    type ClassifiedRoute,
    type RuoYiCveEntry,
    matchCvesByVersion,
    getAllCves,
    classifyRoute,
    getSensitiveRoutes,
    aggregateHookEvents,
    classifyRequest,
    classifyStatus,
    statusColor,
    cveSeverityLabel,
    cveSeverityColor,
    routeCategoryLabel,
    extractPathsFromRouterData,
  } from '@/lib/analyzers/ruoyi-analyzer';

  // —— 状态 ——
  let hookActive = $state(false);
  let registering = $state(false);
  let events = $state<HookEvent[]>([]);
  let capturedRequests = $state<CapturedRequest[]>([]);
  let detectedVersion = $state('');
  let detectedVariant = $state('');
  let matchedCves = $state<RuoYiCveEntry[]>([]);
  let sensitiveRoutes = $state<ClassifiedRoute[]>([]);
  let statusText = $state('');
  let showCvePanel = $state(false);
  let activeSubTab = $state<'routes' | 'api' | 'cve'>('routes');

  // —— 派生数据 ——
  let routerEvents = $derived(
    events.filter((e) => e.event === 'routers_captured'),
  );
  let userInfoEvents = $derived(
    events.filter((e) => e.event === 'userinfo_captured'),
  );
  let totalEvents = $derived(events.length);
  let totalRequests = $derived(capturedRequests.length);

  let aggregated = $derived(aggregateHookEvents(events));

  // —— 监听器注册/清理 ——
  $effect(() => {
    if (!hookActive) return;

    const listener = (
      msg: { type: string; event?: string; augmented?: unknown; injected?: unknown },
      _sender: unknown,
    ) => {
      if (msg.type === 'VK_RUOYI_HOOK_EVENT' && msg.event) {
        const hookEvent: HookEvent = {
          event: msg.event,
          augmented: msg.augmented,
          injected: msg.injected,
          timestamp: Date.now(),
        };
        events = [...events, hookEvent];

        // 如果是 API 请求类型的日志，分类后追加
        if (msg.event === 'api_request' && msg.augmented) {
          const aug = msg.augmented as { url?: string; method?: string; status?: number; time?: string };
          if (aug.url) {
            const req: CapturedRequest = {
              url: aug.url,
              method: aug.method || 'GET',
              status: aug.status || 0,
              time: aug.time || '',
              category: classifyRequest(aug.url),
            };
            capturedRequests = [...capturedRequests, req];
            // 自动分类新路由
            const classified = classifyRoute(aug.url);
            if (classified.category !== 'normal' && classified.category !== 'auth') {
              if (!sensitiveRoutes.some((r) => r.path === classified.path)) {
                sensitiveRoutes = [...sensitiveRoutes, classified];
              }
            }
          }
        }
      }
    };

    browser.runtime.onMessage.addListener(listener);
    return () => {
      browser.runtime.onMessage.removeListener(listener);
    };
  });

  // —— Hook 注册/注销 ——
  async function registerHook() {
    registering = true;
    statusText = '正在注册 Hook...';
    events = [];
    capturedRequests = [];
    detectedVersion = '';
    detectedVariant = '';
    matchedCves = [];
    sensitiveRoutes = [];

    try {
      const tabUrl = await getActiveTabUrl();
      if (!tabUrl) {
        toastStore.show('无法获取当前标签页 URL', 'error');
        statusText = '';
        registering = false;
        return;
      }

      const origin = new URL(tabUrl).origin;
      const r = await sendMessage({ type: 'REGISTER_RUOYI_HOOK', origin });
      if (r.success) {
        hookActive = true;
        statusText = 'Hook 已注册，正在监听...';
        toastStore.show('Hook 已注册，刷新页面或浏览以捕获路由', 'success');
      } else {
        statusText = '';
        toastStore.show(`注册失败: ${r.error || '未知错误'}`, 'error');
      }
    } catch (e: any) {
      statusText = '';
      toastStore.show(`注册失败: ${e.message || '未知错误'}`, 'error');
    } finally {
      registering = false;
    }
  }

  async function unregisterHook() {
    try {
      await sendMessage({ type: 'UNREGISTER_RUOYI_HOOK' });
      hookActive = false;
      statusText = 'Hook 已停止';
      toastStore.show('Hook 已注销', 'info');
    } catch (e: any) {
      toastStore.show(`注销失败: ${e.message}`, 'error');
    }
  }

  // —— CVE 查询 ——
  function lookupCves() {
    if (detectedVersion) {
      matchedCves = matchCvesByVersion(detectedVersion);
    } else {
      matchedCves = getAllCves();
    }
    showCvePanel = true;
  }

  // —— 复制/导出 ——
  function copyRoutes() {
    const paths = sensitiveRoutes.map((r) => r.path);
    if (paths.length === 0) {
      toastStore.show('没有可复制的路由', 'warning');
      return;
    }
    navigator.clipboard.writeText(paths.join('\n')).then(() => {
      toastStore.show(`已复制 ${paths.length} 条路由`, 'success');
    });
  }

  function exportJson() {
    const data = {
      timestamp: new Date().toISOString(),
      version: detectedVersion,
      variant: detectedVariant,
      events: events.length,
      capturedRequests: capturedRequests.length,
      sensitiveRoutes: sensitiveRoutes.map((r) => ({
        path: r.path,
        category: r.category,
        title: r.title,
      })),
      matchedCves: matchedCves.map((c) => ({
        id: c.id,
        title: c.title,
        severity: c.severity,
        affected: c.affected,
      })),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ruoyi-report-${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('报告已导出', 'success');
  }

  // —— 辅助 ——
  function severityBadge(severity: string): string {
    if (severity === 'critical') return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
    if (severity === 'high') return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
    if (severity === 'medium') return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
    return 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400';
  }
</script>

<div class="space-y-3">
  <!-- Hook 控制 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm font-medium">RuoYi 路由 Hook</div>
        <div class="text-xs text-gray-500">
          {hookActive
            ? `Hook 运行中 — 已捕获 ${totalEvents} 个事件`
            : '注册 Hook 以监听 RuoYi 路由/API 流量'}
        </div>
      </div>
      <div class="flex gap-1">
        {#if hookActive}
          <button class="btn btn-sm" onclick={unregisterHook}>停止</button>
        {:else}
          <button
            class="btn btn-sm btn-primary"
            disabled={registering}
            onclick={registerHook}
          >
            {registering ? '注册中...' : '注册 Hook'}
          </button>
        {/if}
      </div>
    </div>

    {#if statusText}
      <div class="text-xs text-gray-500">{statusText}</div>
    {/if}

    <!-- 状态摘要 -->
    {#if hookActive && aggregated.routerCaptured}
      <div class="flex gap-2 flex-wrap text-xs">
        {#if aggregated.routerCaptured}
          <span class="badge bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
            路由已捕获
          </span>
        {/if}
        {#if aggregated.userinfoCaptured}
          <span class="badge bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
            UserInfo 已捕获
          </span>
        {/if}
        {#if aggregated.hookRestored}
          <span class="badge bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400">
            Hook 已恢复
          </span>
        {/if}
        {#if aggregated.augmentCount > 0}
          <span class="badge bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400">
            增强注入: {aggregated.augmentCount}
          </span>
        {/if}
        {#if totalRequests > 0}
          <span class="badge bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300">
            API 请求: {totalRequests}
          </span>
        {/if}
      </div>
    {/if}
  </div>

  <!-- 子标签切换 -->
  {#if hookActive && (totalEvents > 0 || totalRequests > 0)}
    <div class="flex gap-1">
      <button
        class="btn btn-sm {activeSubTab === 'routes' ? 'btn-primary' : ''}"
        onclick={() => (activeSubTab = 'routes')}
      >
        路由 ({sensitiveRoutes.length})
      </button>
      <button
        class="btn btn-sm {activeSubTab === 'api' ? 'btn-primary' : ''}"
        onclick={() => (activeSubTab = 'api')}
      >
        API ({totalRequests})
      </button>
      <button
        class="btn btn-sm {activeSubTab === 'cve' ? 'btn-primary' : ''}"
        onclick={() => { activeSubTab = 'cve'; lookupCves(); }}
      >
        CVE ({matchedCves.length})
      </button>
    </div>
  {/if}

  <!-- 路由面板 -->
  {#if activeSubTab === 'routes'}
    {#if sensitiveRoutes.length > 0}
      <div class="space-y-1">
        {#each sensitiveRoutes as route}
          <div class="card p-2 flex items-center gap-2">
            <span class="badge {severityBadge(route.category === 'admin' ? 'high' : route.category === 'cloud' ? 'medium' : 'low')}">
              {routeCategoryLabel(route.category)}
            </span>
            <span class="text-xs font-mono flex-1 break-all">{route.path}</span>
            {#if route.title}
              <span class="text-xs text-gray-400">{route.title}</span>
            {/if}
          </div>
        {/each}
      </div>

      <div class="flex gap-1">
        <button class="btn btn-sm flex-1" onclick={copyRoutes}>复制路由</button>
        <button class="btn btn-sm flex-1" onclick={exportJson}>导出报告</button>
      </div>
    {:else if hookActive}
      <div class="card p-3 text-center">
        <div class="text-xs text-gray-400">
          刷新目标页面或浏览功能以捕获路由
        </div>
      </div>
    {/if}
  {/if}

  <!-- API 流量面板 -->
  {#if activeSubTab === 'api' && totalRequests > 0}
    <div class="space-y-1">
      {#each capturedRequests.slice(-50).reverse() as req}
        <div class="card p-2 flex items-center gap-2 text-xs">
          <span class="font-mono font-bold w-16 shrink-0 {statusColor(classifyStatus(req.status))}">
            {req.method}
          </span>
          <span class="font-mono w-8 shrink-0 {statusColor(classifyStatus(req.status))}">
            {req.status || '-'}
          </span>
          <span class="font-mono flex-1 break-all truncate">{req.url}</span>
          <span class="text-gray-400 shrink-0">{req.time}</span>
        </div>
      {/each}
    </div>
  {:else if activeSubTab === 'api' && hookActive}
    <div class="card p-3 text-center">
      <div class="text-xs text-gray-400">
        等待 API 请求捕获...
      </div>
    </div>
  {/if}

  <!-- CVE 面板 -->
  {#if activeSubTab === 'cve'}
    <div class="space-y-1">
      {#if detectedVersion}
        <div class="card p-2 text-xs">
          <span class="text-gray-500">检测版本:</span>
          <span class="font-mono font-bold ml-1">{detectedVersion}</span>
          {#if detectedVariant}
            <span class="badge bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 ml-2">
              {detectedVariant}
            </span>
          {/if}
        </div>
      {/if}

      {#if matchedCves.length > 0}
        {#each matchedCves as cve}
          <div class="card p-3 space-y-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="badge {severityBadge(cve.severity)}">
                {cveSeverityLabel(cve.severity).toUpperCase()}
              </span>
              <span class="text-xs font-bold {cveSeverityColor(cve.severity)}">{cve.id}</span>
            </div>
            <div class="text-xs font-medium">{cve.title}</div>
            <div class="text-xs text-gray-500">{cve.description}</div>
            <div class="text-xs text-gray-400">
              影响版本: {cve.affected.join(', ')}
            </div>
            {#if cve.refs && cve.refs.length > 0}
              <div class="flex gap-1">
                {#each cve.refs as ref}
                  <a
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-xs text-blue-500 hover:text-blue-400 underline"
                  >
                    NVD
                  </a>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      {:else}
        <div class="card p-3 text-center">
          <div class="text-sm">未找到已知 CVE</div>
          <div class="text-xs text-gray-400 mt-1">
            未检测到版本信息或该版本暂无已知漏洞
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- 未激活时的提示 -->
  {#if !hookActive && totalEvents === 0}
    <div class="card p-3 text-center space-y-1">
      <div class="text-sm">RuoYi 路由分析</div>
      <div class="text-xs text-gray-400">
        注册 Hook 后将自动捕获 RuoYi 框架的动态路由、API 请求等流量数据，
        并匹配已知 CVE 漏洞库进行安全评估。
      </div>
    </div>
  {/if}
</div>
