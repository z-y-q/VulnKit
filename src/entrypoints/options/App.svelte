<script lang="ts">
  // 设置页 — 灵眸 v6.0
  // 1. API 密钥管理（ZoomEye）
  // 2. 扫描历史管理（查看/清空）
  // 3. 存储用量概览与清理
  // 4. 主题切换 / 关于
  import { themeStore, toastStore } from '@/stores/ui';
  import { scanHistoryStore, MODULE_LABELS, type ScanHistoryEntry } from '@/stores/scan-history';

  const ZOEYEYE_KEY = 'lingmou_zoomeye_key';

  let isDark = $derived($themeStore);

  let apiKey = $state('');
  let history = $state<ScanHistoryEntry[]>([]);
  let storageItems = $state<{ key: string; label: string; bytes: number }[]>([]);
  let storageTotal = $state(0);

  const KNOWN_STORAGE_KEYS: { key: string; label: string }[] = [
    { key: 'pentest_scan_history', label: '扫描历史' },
    { key: ZOEYEYE_KEY, label: 'ZoomEye 密钥' },
    { key: 'lingmou-theme', label: '主题设置' },
    { key: 'pendingPanel', label: '待跳转面板' },
    { key: 'pentest_spoof', label: '伪装状态' },
  ];

  $effect(() => {
    browser.storage.local.get(ZOEYEYE_KEY).then(r => {
      apiKey = (r[ZOEYEYE_KEY] as string) || '';
    });
    refreshHistory();
    refreshStorage();
  });

  async function refreshHistory() {
    await scanHistoryStore.refresh();
  }

  async function refreshStorage() {
    const keys = KNOWN_STORAGE_KEYS.map(k => k.key);
    const data = await browser.storage.local.get(keys);
    const items: { key: string; label: string; bytes: number }[] = [];
    let total = 0;
    for (const k of KNOWN_STORAGE_KEYS) {
      const val = data[k.key];
      if (val === undefined) continue;
      const bytes = new Blob([JSON.stringify(val)]).size;
      items.push({ key: k.key, label: k.label, bytes });
      total += bytes;
    }
    storageItems = items.sort((a, b) => b.bytes - a.bytes);
    storageTotal = total;
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  async function saveApiKey() {
    await browser.storage.local.set({ [ZOEYEYE_KEY]: apiKey.trim() });
    toastStore.show('ZoomEye API 密钥已保存', 'success');
  }

  async function clearApiKey() {
    if (!confirm('确定清除 ZoomEye API 密钥？')) return;
    await browser.storage.local.remove(ZOEYEYE_KEY);
    apiKey = '';
    toastStore.show('已清除 API 密钥', 'success');
  }

  async function clearHistory() {
    if (!confirm('确定清空全部扫描历史？此操作不可恢复。')) return;
    await scanHistoryStore.clear();
    await refreshHistory();
    toastStore.show('扫描历史已清空', 'success');
  }

  async function clearStorageKey(key: string, label: string) {
    if (!confirm(`确定清除「${label}」？`)) return;
    await browser.storage.local.remove(key);
    await refreshStorage();
    toastStore.show(`${label} 已清除`, 'success');
  }

  function toggleTheme() {
    themeStore.toggle();
  }

  let historyByModule = $derived.by(() => {
    const map = new Map<string, number>();
    for (const e of history) map.set(e.moduleName || e.module, (map.get(e.moduleName || e.module) || 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  });
</script>

<div class="max-w-2xl mx-auto p-6 space-y-6">
  <!-- Header -->
  <header class="flex items-center justify-between">
    <div>
      <h1 class="text-2xl font-bold text-primary">灵眸 v6.0</h1>
      <p class="text-sm text-gray-400">渗透测试浏览器扩展 · 设置</p>
    </div>
    <button
      class="p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-500"
      onclick={toggleTheme}
      title="切换主题"
    >
      {#if isDark}🌙{:else}☀️{/if}
    </button>
  </header>

  <!-- API 密钥 -->
  <section class="card p-4 space-y-3">
    <h2 class="text-sm font-semibold">🔑 API 密钥</h2>
    <div>
      <label class="text-xs text-gray-500" for="zy-key">ZoomEye API Key</label>
      <div class="flex gap-1 mt-1">
        <input id="zy-key" class="input flex-1 text-sm font-mono" type="password" placeholder="ZoomEye API KEY" bind:value={apiKey} />
        <button class="btn btn-sm btn-primary" onclick={saveApiKey}>保存</button>
        <button class="btn btn-sm" onclick={clearApiKey} disabled={!apiKey}>清除</button>
      </div>
      <p class="text-xs text-gray-400 mt-1">用于「资产测绘」面板。密钥仅本地存储，不上传任何服务器。</p>
    </div>
  </section>

  <!-- 扫描历史 -->
  <section class="card p-4 space-y-3">
    <div class="flex items-center justify-between">
      <h2 class="text-sm font-semibold">📜 扫描历史</h2>
      <button class="btn btn-sm" onclick={clearHistory} disabled={history.length === 0}>清空全部</button>
    </div>
    <div class="text-xs text-gray-500">共 {history.length} 条记录（7 天 TTL，每域名最多 50 条）</div>
    {#if historyByModule.length > 0}
      <div class="flex flex-wrap gap-1.5">
        {#each historyByModule as [name, count]}
          <span class="badge text-xs bg-gray-100 dark:bg-gray-700">{name}: {count}</span>
        {/each}
      </div>
    {:else}
      <p class="text-xs text-gray-400">暂无扫描记录。扫描结果将自动汇总到「历史档案」与「统一报告」。</p>
    {/if}
  </section>

  <!-- 存储用量 -->
  <section class="card p-4 space-y-3">
    <div class="flex items-center justify-between">
      <h2 class="text-sm font-semibold">💾 存储用量</h2>
      <span class="text-xs text-gray-400">总计 {formatBytes(storageTotal)}</span>
    </div>
    {#if storageItems.length > 0}
      <div class="space-y-1.5">
        {#each storageItems as item (item.key)}
          <div class="flex items-center gap-2 text-sm">
            <span class="flex-1">{item.label}</span>
            <span class="text-xs text-gray-400 font-mono w-20 text-right">{formatBytes(item.bytes)}</span>
            <button class="btn btn-sm text-xs" onclick={() => clearStorageKey(item.key, item.label)}>清除</button>
          </div>
        {/each}
      </div>
    {:else}
      <p class="text-xs text-gray-400">暂无已存储数据。</p>
    {/if}
  </section>

  <!-- 关于 -->
  <section class="card p-4 space-y-2 text-xs text-gray-500">
    <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300">ℹ️ 关于</h2>
    <p>灵眸 (VulnKit) v6.0 — 基于 WXT + Svelte 5 + TypeScript 的 Manifest V3 渗透测试扩展。</p>
    <p class="text-yellow-600 dark:text-yellow-500">⚠️ 仅用于授权的安全测试。测试前请确认目标在 SRC 授权范围内，验证即止，不得越界、破坏数据或获取个人信息。</p>
  </section>
</div>
