<script lang="ts">
  // 资产测绘面板
  // ZoomEye API 集成：搜索主机/服务，结果分页，导出 CSV/JSON，复制 IP 列表
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import ResponsiveTable, { type Col } from '@/components/results/ResponsiveTable.svelte';

  // ResponsiveTable 列配置：宽屏全显，按 hideUnder 逐级隐藏，<480px 切卡片（IP 做标题）
  const ASSET_COLS: Col[] = [
    { key: 'ip', header: 'IP', primary: true },
    { key: 'port', header: '端口', hideUnder: 480 },
    { key: 'service', header: '服务', hideUnder: 560 },
    { key: 'hostname', header: '主机名', hideUnder: 720 },
    { key: 'country', header: '国家', hideUnder: 480 },
    { key: 'region', header: '地区', hideUnder: 600 },
    { key: 'title', header: '标题', hideUnder: 720 },
  ];
  import {
    buildZoomEyeUrl,
    normalizeResults,
    normalizeFofaResults,
    normalizeShodanResults,
    buildFofaApiUrl,
    buildShodanApiUrl,
    buildCsv,
    ASSET_ENGINES,
    type ZoomEyeResult,
    type ZoomEyeMode,
  } from '@/lib/scanners/asset-engine';

  // ===== 常量 =====
  const STORAGE_KEY_API = 'lingmou_zoomeye_key';
  const STORAGE_KEY_FOFA = 'lingmou_fofa'; // {email, key}
  const STORAGE_KEY_SHODAN = 'lingmou_shodan_key';

  type Engine = 'zoomeye' | 'fofa' | 'shodan';

  // ===== 状态 =====
  let engine = $state<Engine>('zoomeye');
  let apiKey = $state('');
  let fofaEmail = $state('');
  let fofaKey = $state('');
  let shodanKey = $state('');
  let query = $state('');
  let mode = $state<ZoomEyeMode>('host');
  let searching = $state(false);
  let statusText = $state('');
  let results = $state<ZoomEyeResult[]>([]);
  let currentPage = $state(1);

  // 自动填充当前域名到查询（如 site:example.com）
  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u && !query) {
        try { const h = new URL(u).hostname; query = `site:"${h}"`; } catch { /* */ }
      }
    });
  });

  let totalPages = $state(1);
  let searchFilter = $state('');

  // ===== 挂载时读取持久化 API Key =====
  $effect(() => {
    browser.storage.local.get([STORAGE_KEY_API, STORAGE_KEY_FOFA, STORAGE_KEY_SHODAN]).then((stored) => {
      if (stored?.[STORAGE_KEY_API]) apiKey = stored[STORAGE_KEY_API] as string;
      const fofa = stored?.[STORAGE_KEY_FOFA] as { email?: string; key?: string } | undefined;
      if (fofa && typeof fofa === 'object') { fofaEmail = fofa.email || ''; fofaKey = fofa.key || ''; }
      if (stored?.[STORAGE_KEY_SHODAN]) shodanKey = stored[STORAGE_KEY_SHODAN] as string;
    });
  });

  // ===== 持久化 API Key =====
  function saveApiKey() {
    if (engine === 'zoomeye') {
      browser.storage.local.set({ [STORAGE_KEY_API]: apiKey.trim() }).then(() => toastStore.show('ZoomEye Key 已保存', 'success'));
    } else if (engine === 'fofa') {
      browser.storage.local.set({ [STORAGE_KEY_FOFA]: { email: fofaEmail.trim(), key: fofaKey.trim() } }).then(() => toastStore.show('FOFA 凭证已保存', 'success'));
    } else {
      browser.storage.local.set({ [STORAGE_KEY_SHODAN]: shodanKey.trim() }).then(() => toastStore.show('Shodan Key 已保存', 'success'));
    }
  }

  // ===== 派生 =====
  let filtered = $derived.by(() => {
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

  // ===== 凭证校验 =====
  function ensureCredentials(): boolean {
    if (engine === 'zoomeye') {
      if (!apiKey.trim()) { toastStore.show('请先输入 ZoomEye API Key', 'warning'); return false; }
    } else if (engine === 'fofa') {
      if (!fofaEmail.trim() || !fofaKey.trim()) { toastStore.show('请先输入 FOFA Email + Key', 'warning'); return false; }
    } else {
      if (!shodanKey.trim()) { toastStore.show('请先输入 Shodan API Key', 'warning'); return false; }
    }
    return true;
  }

  const ENGINE_LABEL: Record<Engine, string> = { zoomeye: 'ZoomEye', fofa: 'FOFA', shodan: 'Shodan' };

  /** 解析 background 响应 → JSON 对象；失败抛错 */
  async function parseResponse(resp: any, label: string): Promise<any> {
    if (!resp || !resp.success) throw new Error(resp?.error || '请求失败');
    try { return JSON.parse(resp.data); }
    catch { throw new Error(`${label} 响应解析失败（格式异常）`); }
  }

  // ===== 核心搜索（按引擎分发）=====
  async function search(page = 1) {
    if (!ensureCredentials()) return;
    if (!query.trim()) { toastStore.show('请输入搜索语句', 'warning'); return; }

    searching = true;
    results = [];
    const label = ENGINE_LABEL[engine];
    statusText = `正在查询 ${label}...`;

    try {
      let rawJson: any;
      let total = 0;
      let pageSize = 10;

      if (engine === 'zoomeye') {
        const url = buildZoomEyeUrl(query.trim(), page, mode);
        const resp = await sendMessage({
          type: 'FETCH_URL_AUTH', url, provider: 'zoomeye', key: apiKey.trim(),
        });
        rawJson = await parseResponse(resp, label);
        if (rawJson.error) throw new Error(rawJson.message || rawJson.error);
        const list = rawJson.matches || rawJson.data || [];
        total = rawJson.total ?? list.length;
        pageSize = list.length || 10;
        results = normalizeResults(rawJson, mode);
      } else if (engine === 'fofa') {
        const url = buildFofaApiUrl(query.trim(), fofaEmail.trim(), fofaKey.trim());
        const resp = await sendMessage({ type: 'FETCH_URL', url });
        rawJson = await parseResponse(resp, label);
        results = normalizeFofaResults(rawJson);
        total = Number(rawJson.size) || results.length;
        pageSize = results.length || 100;
      } else {
        const url = buildShodanApiUrl(query.trim(), shodanKey.trim(), page);
        const resp = await sendMessage({ type: 'FETCH_URL', url });
        rawJson = await parseResponse(resp, label);
        results = normalizeShodanResults(rawJson);
        total = Number(rawJson.total) || results.length;
        pageSize = 100;
      }

      currentPage = page;
      totalPages = Math.max(1, Math.ceil(total / pageSize));
      statusText = `${label}: 查询完成 (第 ${page} 页，共 ${total} 条${results.length > 0 ? '，本页 ' + results.length + ' 条' : ''})`;
    } catch (e: any) {
      handleApiError(e.message || String(e));
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
    if (filtered.length === 0) {
      toastStore.show('没有可导出的结果', 'warning');
      return;
    }
    const csv = buildCsv(filtered);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    downloadBlob(blob, `lingmou-asset-zoomeye-${Date.now()}.csv`);
    toastStore.show('CSV 已导出', 'success');
  }

  function exportJson() {
    if (filtered.length === 0) {
      toastStore.show('没有可导出的结果', 'warning');
      return;
    }
    const json = JSON.stringify(filtered, null, 2);
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
  <!-- 引擎选择 + API Key 配置 -->
  <div class="card p-3 space-y-2">
    <!-- 引擎切换 -->
    <div class="flex gap-0.5">
      {#each (['zoomeye', 'fofa', 'shodan'] as Engine[]) as eng}
        <button
          class="btn btn-sm flex-1 {engine === eng ? 'bg-primary text-white' : 'btn-ghost'}"
          onclick={() => { engine = eng; results = []; statusText = ''; }}
        >
          {ENGINE_LABEL[eng]}
        </button>
      {/each}
    </div>

    <!-- ZoomEye：单 Key -->
    {#if engine === 'zoomeye'}
      <div class="flex gap-2">
        <input
          class="input flex-1 text-xs font-mono"
          type="password"
          placeholder="ZoomEye API Key"
          bind:value={apiKey}
        />
        <button class="btn btn-sm btn-primary" onclick={saveApiKey}>保存</button>
      </div>
    {:else if engine === 'fofa'}
      <!-- FOFA：Email + Key -->
      <div class="flex gap-2">
        <input
          class="input flex-1 text-xs font-mono"
          placeholder="FOFA Email"
          bind:value={fofaEmail}
        />
        <input
          class="input flex-1 text-xs font-mono"
          type="password"
          placeholder="FOFA API Key"
          bind:value={fofaKey}
        />
        <button class="btn btn-sm btn-primary" onclick={saveApiKey}>保存</button>
      </div>
    {:else}
      <!-- Shodan：单 Key -->
      <div class="flex gap-2">
        <input
          class="input flex-1 text-xs font-mono"
          type="password"
          placeholder="Shodan API Key"
          bind:value={shodanKey}
        />
        <button class="btn btn-sm btn-primary" onclick={saveApiKey}>保存</button>
      </div>
    {/if}
  </div>

  <!-- 搜索栏 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <!-- 模式切换（仅 ZoomEye） -->
      {#if engine === 'zoomeye'}
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
      {/if}
      <input
        class="input flex-1 text-xs font-mono"
        placeholder={engine === 'fofa'
          ? 'FOFA 语法，如 title="后台" && country="CN"'
          : engine === 'shodan'
            ? 'Shodan 语法，如 apache country:CN'
            : '查询语句，如 country:"CN" +service:"http"'}
        bind:value={query}
      />
      <button class="btn btn-sm btn-primary" disabled={searching || !query.trim()} onclick={() => search(1)}>
        {searching ? '查询中...' : '搜索'}
      </button>
    </div>
    <!-- 多平台测绘入口（无需 API Key，浏览器直开；ZoomEye 语法可能需调整） -->
    <div class="flex items-center gap-1 text-xs flex-wrap">
      <span class="text-gray-400">其他平台:</span>
      {#each ASSET_ENGINES as eng}
        <a
          href={eng.build(query)}
          target="_blank"
          class="btn btn-xs {query.trim() ? '' : 'pointer-events-none opacity-50'}"
          onclick={() => !query.trim() && toastStore.show('请先输入查询语句', 'warning')}
        >
          {eng.label}
        </a>
      {/each}
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
      <span class="text-gray-400 shrink-0">{filtered.length} 条</span>
      <button class="btn btn-sm shrink-0" onclick={copyIpList}>复制 IP</button>
      <button class="btn btn-sm shrink-0" onclick={exportCsv}>导出 CSV</button>
      <button class="btn btn-sm shrink-0" onclick={exportJson}>导出 JSON</button>
    </div>
  {/if}

  <!-- 结果表格 -->
  {#if filtered.length > 0}
    <div class="card overflow-hidden">
      <ResponsiveTable cols={ASSET_COLS} rows={filtered} cardLabel={(r) => r.ip}>
        {#snippet cell(col, r)}
          {#if col.key === 'ip'}
            <span class="font-mono">{r.ip}</span>
          {:else if col.key === 'port'}
            <span class="font-mono">{r.port || '-'}</span>
          {:else if col.key === 'service'}
            <span class="badge badge-sm bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">{r.service}</span>
          {:else if col.key === 'hostname'}
            <span class="font-mono block truncate max-w-32" title={r.hostname}>{r.hostname}</span>
          {:else if col.key === 'country'}
            {r.country}
          {:else if col.key === 'region'}
            {r.region}
          {:else if col.key === 'title'}
            <span class="block truncate max-w-32" title={r.title}>{r.title}</span>
          {/if}
        {/snippet}
      </ResponsiveTable>
    </div>
  {:else if !searching && results.length === 0 && statusText}
    <EmptyState message="未找到匹配结果" />
  {:else if !searching}
    <EmptyState message="输入 ZoomEye API Key 和查询语句开始资产测绘" />
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
