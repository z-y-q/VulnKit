<script lang="ts">
  // 资产测绘面板 — 灵眸 v6.0
  // ZoomEye API 集成：搜索主机/服务，结果分页，导出 CSV/JSON，复制 IP 列表
  import { sendMessage } from '@/lib/core/messaging';
  import { toastStore } from '@/stores/ui';
  import {
    buildZoomEyeUrl,
    normalizeResults,
    buildCsv,
    type ZoomEyeResult,
    type ZoomEyeMode,
  } from '@/lib/scanners/asset-engine';

  // ===== 常量 =====
  const STORAGE_KEY_API = 'lingmou_zoomeye_key';

  // ===== 状态 =====
  let apiKey = $state('');
  let query = $state('');
  let mode = $state<ZoomEyeMode>('host');
  let searching = $state(false);
  let statusText = $state('');
  let results = $state<ZoomEyeResult[]>([]);
  let currentPage = $state(1);
  let totalPages = $state(1);
  let searchFilter = $state('');

  // ===== 挂载时读取持久化 API Key =====
  $effect(() => {
    browser.storage.local.get(STORAGE_KEY_API).then((stored) => {
      if (stored?.[STORAGE_KEY_API]) {
        apiKey = stored[STORAGE_KEY_API] as string;
      }
    });
  });

  // ===== 持久化 API Key =====
  function saveApiKey() {
    browser.storage.local.set({ [STORAGE_KEY_API]: apiKey.trim() }).then(() => {
      toastStore.show('API Key 已保存', 'success');
    });
  }

  // ===== 派生 =====
  let filtered = $derived(() => {
    if (!searchFilter) return results;
    const q = searchFilter.toLowerCase();
    return results.filter(
      (r) =>
        r.ip.toLowerCase().includes(q) ||
        r.hostname.toLowerCase().includes(q) ||
        r.service.toLowerCase().includes(q) ||
        r.country.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q),
    );
  });

  // ===== 核心搜索 =====
  async function search(page = 1) {
    if (!apiKey.trim()) {
      toastStore.show('请先输入 ZoomEye API Key', 'warning');
      return;
    }
    if (!query.trim()) {
      toastStore.show('请输入搜索语句', 'warning');
      return;
    }

    searching = true;
    statusText = '正在查询 ZoomEye...';
    results = [];

    const url = buildZoomEyeUrl(query.trim(), page, mode);

    try {
      const resp = await sendMessage({
        type: 'FETCH_URL_AUTH',
        url,
        provider: 'zoomeye',
        key: apiKey.trim(),
      });

      // 响应格式：{ success: true, data: string } | { success: false, error: string }
      if (!resp || !(resp as any).success) {
        const errMsg = (resp as any)?.error || '请求失败';
        handleApiError(errMsg);
        return;
      }

      // 解析 JSON
      let json: any;
      try {
        json = JSON.parse((resp as any).data);
      } catch {
        toastStore.show('响应解析失败', 'error');
        statusText = '查询失败：响应格式异常';
        return;
      }

      if (json.error) {
        toastStore.show(`API 错误: ${json.message || json.error}`, 'error');
        statusText = `API 错误: ${json.message || json.error}`;
        return;
      }

      const list = json.matches || json.data || [];
      const total = json.total ?? list.length;

      results = normalizeResults(json, mode);
      currentPage = page;
      totalPages = Math.max(1, Math.ceil(total / (list.length || 10)));

      statusText = `ZoomEye: 查询完成 (第 ${page} 页，共 ${total} 条${list.length > 0 ? '，本页 ' + list.length + ' 条' : ''})`;
    } catch (e: any) {
      toastStore.show(`查询失败: ${e.message}`, 'error');
      statusText = `查询失败: ${e.message}`;
    } finally {
      searching = false;
    }
  }

  /** 根据错误信息给出更友好的提示 */
  function handleApiError(errMsg: string) {
    if (errMsg.includes('401') || errMsg.includes('login failed')) {
      toastStore.show('API Key 无效，请检查后重试', 'error');
      statusText = 'API Key 无效';
    } else if (errMsg.includes('429') || errMsg.includes('rate')) {
      toastStore.show('请求频率超限，请稍后再试', 'warning');
      statusText = '请求频率超限';
    } else if (errMsg.includes('403') || errMsg.includes('quota')) {
      toastStore.show('API 配额不足', 'warning');
      statusText = 'API 配额不足';
    } else {
      toastStore.show(`请求失败: ${errMsg}`, 'error');
      statusText = `请求失败: ${errMsg}`;
    }
  }

  // ===== 分页 =====
  function goToPage(page: number) {
    if (page < 1 || page > totalPages || page === currentPage) return;
    search(page);
  }

  // ===== 导出 =====
  function exportCsv() {
    const data = searchFilter
      ? results.filter(
          (r) =>
            r.ip.toLowerCase().includes(searchFilter.toLowerCase()) ||
            r.hostname.toLowerCase().includes(searchFilter.toLowerCase()) ||
            r.service.toLowerCase().includes(searchFilter.toLowerCase()),
        )
      : results;
    if (data.length === 0) {
      toastStore.show('没有可导出的结果', 'warning');
      return;
    }
    const csv = buildCsv(data);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    downloadBlob(blob, `lingmou-asset-zoomeye-${Date.now()}.csv`);
    toastStore.show('CSV 已导出', 'success');
  }

  function exportJson() {
    if (results.length === 0) {
      toastStore.show('没有可导出的结果', 'warning');
      return;
    }
    const json = JSON.stringify(results, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    downloadBlob(blob, `lingmou-asset-zoomeye-${Date.now()}.json`);
    toastStore.show('JSON 已导出', 'success');
  }

  function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function copyIpList() {
    const ips = [...new Set(results.map((r) => r.ip).filter((ip) => ip && ip !== '-'))];
    if (ips.length === 0) {
      toastStore.show('没有 IP 可复制', 'warning');
      return;
    }
    navigator.clipboard.writeText(ips.join('\n')).then(() => {
      toastStore.show(`已复制 ${ips.length} 个 IP`, 'success');
    });
  }
</script>

<div class="space-y-3">
  <!-- API Key 配置 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-2">
      <input
        class="input flex-1 text-xs font-mono"
        type="password"
        placeholder="ZoomEye API Key"
        bind:value={apiKey}
      />
      <button class="btn btn-sm btn-primary" onclick={saveApiKey}>保存</button>
    </div>
  </div>

  <!-- 搜索栏 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <!-- 模式切换 -->
      <div class="flex gap-0.5">
        <button
          class="btn btn-sm {mode === 'host' ? 'bg-primary text-white' : 'btn-ghost'}"
          onclick={() => { mode = 'host'; }}
        >
          Host
        </button>
        <button
          class="btn btn-sm {mode === 'web' ? 'bg-primary text-white' : 'btn-ghost'}"
          onclick={() => { mode = 'web'; }}
        >
          Web
        </button>
      </div>
      <input
        class="input flex-1 text-xs font-mono"
        placeholder='查询语句，如 country:"CN" +service:"http"'
        bind:value={query}
      />
      <button class="btn btn-sm btn-primary" disabled={searching || !query.trim() || !apiKey.trim()} onclick={() => search(1)}>
        {searching ? '查询中...' : '搜索'}
      </button>
    </div>
  </div>

  <!-- 状态 -->
  {#if statusText}
    <div class="text-xs text-gray-500">{statusText}</div>
  {/if}

  <!-- 结果工具栏 -->
  {#if results.length > 0}
    <div class="flex items-center gap-2 text-xs flex-wrap">
      <input
        class="input text-xs flex-1 min-w-24"
        placeholder="过滤结果..."
        bind:value={searchFilter}
      />
      <span class="text-gray-400 shrink-0">{filtered().length} 条</span>
      <button class="btn btn-sm shrink-0" onclick={copyIpList}>复制 IP</button>
      <button class="btn btn-sm shrink-0" onclick={exportCsv}>导出 CSV</button>
      <button class="btn btn-sm shrink-0" onclick={exportJson}>导出 JSON</button>
    </div>
  {/if}

  <!-- 结果表格 -->
  {#if filtered().length > 0}
    <div class="card overflow-hidden">
      <div class="overflow-x-auto max-h-72 overflow-y-auto">
        <table class="w-full text-xs">
          <thead class="sticky top-0 bg-white dark:bg-gray-800">
            <tr class="border-b border-gray-200 dark:border-gray-700">
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">IP</th>
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">端口</th>
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">服务</th>
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">主机名</th>
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">国家</th>
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">地区</th>
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">标题</th>
            </tr>
          </thead>
          <tbody>
            {#each filtered() as r}
              <tr class="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                <td class="px-3 py-1.5 font-mono">{r.ip}</td>
                <td class="px-3 py-1.5 font-mono">{r.port || '-'}</td>
                <td class="px-3 py-1.5">
                  <span class="badge badge-sm bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">{r.service}</span>
                </td>
                <td class="px-3 py-1.5 font-mono truncate max-w-32" title={r.hostname}>{r.hostname}</td>
                <td class="px-3 py-1.5">{r.country}</td>
                <td class="px-3 py-1.5">{r.region}</td>
                <td class="px-3 py-1.5 truncate max-w-32" title={r.title}>{r.title}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {:else if !searching && results.length === 0 && statusText}
    <div class="text-center text-gray-400 text-sm py-8">
      未找到匹配结果
    </div>
  {:else if !searching}
    <div class="text-center text-gray-400 text-sm py-8">
      输入 ZoomEye API Key 和查询语句开始资产测绘
    </div>
  {/if}

  <!-- 分页 -->
  {#if totalPages > 1}
    <div class="flex items-center justify-center gap-1 text-xs">
      <button class="btn btn-sm" disabled={currentPage <= 1} onclick={() => goToPage(currentPage - 1)}>
        上一页
      </button>
      <span class="px-2 text-gray-500">
        {currentPage} / {totalPages}
      </span>
      <button class="btn btn-sm" disabled={currentPage >= totalPages} onclick={() => goToPage(currentPage + 1)}>
        下一页
      </button>
    </div>
  {/if}
</div>
