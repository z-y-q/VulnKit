<script lang="ts">
  // 存储检查面板
  // 检查 localStorage / sessionStorage / Cookies / IndexedDB / window 全局变量
  import { getActiveTab, getActiveTabUrl, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { toCsv } from '@/lib/actions/serializers';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import {
    classifyStorageValue,
    truncate,
    escapeHtml,
    type StorageItem,
    type IndexedDBInfo,
  } from '@/lib/scanners/storage-engine';

  // ---------- 类型 ----------

  interface ScanResult {
    localItems: StorageItem[];
    sessionItems: StorageItem[];
    cookies: StorageItem[];
    windowVars: StorageItem[];
    idbInfo: IndexedDBInfo | null;
  }

  // ---------- 状态 ----------

  let scanning = $state(false);
  let localItems = $state<StorageItem[]>([]);
  let sessionItems = $state<StorageItem[]>([]);
  let cookies = $state<StorageItem[]>([]);
  let windowVars = $state<StorageItem[]>([]);
  let idbInfo = $state<IndexedDBInfo | null>(null);
  let activeTab = $state<'local' | 'session' | 'cookie' | 'window' | 'idb'>('local');
  let searchQuery = $state('');
  let filter = $state<'all' | 'sensitive'>('all');
  let sortBy = $state<'default' | 'key' | 'size'>('default');
  let expandedKeys = $state<Set<string>>(new Set());

  // ---------- 导出计算 ----------

  let localFiltered = $derived(applyFilterSort(localItems));
  let sessionFiltered = $derived(applyFilterSort(sessionItems));
  let cookieFiltered = $derived(applyFilterSort(cookies));
  let windowFiltered = $derived(applyFilterSort(windowVars));

  let localSensitive = $derived(localItems.filter(i => i.isSensitive).length);
  let sessionSensitive = $derived(sessionItems.filter(i => i.isSensitive).length);
  let cookieSensitive = $derived(cookies.filter(i => i.isSensitive).length);
  let windowSensitive = $derived(windowVars.filter(i => i.isSensitive).length);

  // ---------- 工具函数 ----------

  function applyFilterSort(items: StorageItem[]): StorageItem[] {
    let filtered = items;
    if (filter === 'sensitive') {
      filtered = items.filter(i => i.isSensitive);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(i =>
        (i.key + ' ' + i.value).toLowerCase().includes(q),
      );
    }
    if (sortBy === 'key') {
      filtered = [...filtered].sort((a, b) => a.key.localeCompare(b.key));
    } else if (sortBy === 'size') {
      filtered = [...filtered].sort((a, b) => b.value.length - a.value.length);
    }
    return filtered;
  }

  function toggleExpand(key: string) {
    if (expandedKeys.has(key)) {
      expandedKeys.delete(key);
    } else {
      expandedKeys.add(key);
    }
  }

  function severityColor(sev: 'high' | 'medium' | 'low'): string {
    switch (sev) {
      case 'high': return 'text-red-600 dark:text-red-400';
      case 'medium': return 'text-yellow-600 dark:text-yellow-400';
      default: return 'text-blue-600 dark:text-blue-400';
    }
  }

  function severityBg(sev: 'high' | 'medium' | 'low'): string {
    switch (sev) {
      case 'high': return 'bg-red-50 dark:bg-red-900/20 border-l-4 border-red-400';
      case 'medium': return 'bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-400';
      default: return '';
    }
  }

  // ---------- 扫描历史映射 ----------

  function mapStorageToFindings(items: StorageItem[]): ScanFinding[] {
    return items
      .filter(i => i.isSensitive)
      .map(i => ({
        title: i.key,
        severity: i.severity as ScanFinding['severity'],
        detail: i.value.length > 80 ? i.value.substring(0, 80) + '...' : i.value,
        evidence: i.storageType,
      }));
  }

  // ---------- 扫描逻辑 ----------

  // —— TaskController 接管扫描状态机 ——
  const controller = createTaskController<void, void>({
    run: async (_input, ctx) => {
      ctx.reportProgress({ phase: '读取页面存储' });
      localItems = [];
      sessionItems = [];
      cookies = [];
      windowVars = [];
      idbInfo = null;

      const tab = await getActiveTab();
      if (!tab?.id) throw new Error('无法获取当前标签页');

      const [localResult, sessionResult, cookieResult, windowResult, idbResult] = await Promise.all([
        readWebStorage(tab.id, 'local'),
        readWebStorage(tab.id, 'session'),
        readCookies(tab.id),
        readWindowVars(tab.id),
        readIndexedDB(tab.id),
      ]);

      if (ctx.signal.aborted) return;

      localItems = localResult;
      sessionItems = sessionResult;
      cookies = cookieResult;
      windowVars = windowResult;
      idbInfo = idbResult;

      try {
        const pageUrl = await getActiveTabUrl();
        if (pageUrl) {
          const allItems = [...localItems, ...sessionItems, ...cookies, ...windowVars];
          await scanHistoryStore.addScan({
            url: pageUrl,
            module: 'storage-check',
            findings: mapStorageToFindings(allItems),
          });
        }
      } catch { /* store failure must not break scan */ }
    },
  }, { centerPanel: 'storage-check', centerLabel: '存储检查' });

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  // scanning 复用控制器运行态；scanned = 有任何终态结果
  $effect(() => { scanning = cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating'; });
  let scanned = $derived(
    cs.status === 'succeeded' || cs.status === 'cancelled' ||
    localItems.length > 0 || sessionItems.length > 0 || cookies.length > 0 || windowVars.length > 0,
  );

  async function startScan() {
    const r = await controller.start();
    if (r.status === 'succeeded') {
      const totalSensitive = localSensitive + sessionSensitive + cookieSensitive + windowSensitive;
      const total = localItems.length + sessionItems.length + cookies.length + windowVars.length;
      if (totalSensitive > 0) {
        toastStore.show(`扫描完成：${total} 条存储中发现 ${totalSensitive} 条敏感数据`, 'warning');
      } else {
        toastStore.show(`扫描完成：${total} 条存储，无敏感数据`, 'success');
      }
    } else if (r.status === 'cancelled') {
      toastStore.show('扫描已取消', 'info');
    }
  }

  function readWebStorage(tabId: number, type: 'local' | 'session'): Promise<StorageItem[]> {
    return execInTab<{ key: string; value: string }[]>(
      tabId,
      function (stype: string) {
        const storage = stype === 'local' ? localStorage : sessionStorage;
        const result: { key: string; value: string }[] = [];
        const len = Math.min(storage.length, 500);
        for (let i = 0; i < len; i++) {
          const key = storage.key(i);
          if (key === null) continue;
          result.push({ key, value: storage.getItem(key) || '' });
        }
        return result;
      },
      { world: 'MAIN', args: [type] },
    ).then(raw => {
      if (!raw) return [];
      return raw.map(item => {
        const sens = classifyStorageValue(item.key, item.value);
        return {
          key: item.key,
          value: item.value,
          isSensitive: sens.isSensitive,
          matchedPatterns: sens.patterns,
          severity: sens.severity,
          storageType: type,
        };
      });
    });
  }

  function readCookies(tabId: number): Promise<StorageItem[]> {
    return execInTab<{ key: string; value: string }[]>(
      tabId,
      function () {
        const raw = document.cookie || '';
        if (!raw) return [];
        return raw.split(';').map(pair => {
          const eq = pair.indexOf('=');
          if (eq === -1) return { key: pair.trim(), value: '' };
          return { key: pair.substring(0, eq).trim(), value: pair.substring(eq + 1).trim() };
        });
      },
      { world: 'MAIN' },
    ).then(raw => {
      if (!raw) return [];
      return raw.map(item => {
        const sens = classifyStorageValue(item.key, item.value);
        return {
          key: item.key,
          value: item.value,
          isSensitive: sens.isSensitive,
          matchedPatterns: sens.patterns,
          severity: sens.severity,
          storageType: 'cookie' as const,
        };
      });
    });
  }

  function readWindowVars(tabId: number): Promise<StorageItem[]> {
    return execInTab<{ key: string; value: string }[]>(
      tabId,
      function () {
        const targets = [
          '__INITIAL_STATE__', '__NUXT__', '__APP_STATE__', '__NEXT_DATA__',
          '__APP_CONFIG__', 'window.__config', 'APP_CONFIG',
          '__VUE_APP_CONFIG__', 'VUE_APP_BASE_URL',
        ];
        const results: { key: string; value: string }[] = [];
        for (let i = 0; i < targets.length; i++) {
          try {
            const val = (function (k: string) { return (window as any)[k]; })(targets[i]);
            if (val !== undefined && val !== null) {
              results.push({ key: targets[i], value: JSON.stringify(val).substring(0, 2000) });
            }
          } catch { /* skip */ }
        }
        return results;
      },
      { world: 'MAIN' },
    ).then(raw => {
      if (!raw) return [];
      return raw.map(item => {
        const sens = classifyStorageValue(item.key, item.value);
        return {
          key: item.key,
          value: item.value,
          isSensitive: sens.isSensitive,
          matchedPatterns: sens.patterns,
          severity: sens.severity,
          storageType: 'window' as const,
        };
      });
    });
  }

  function readIndexedDB(tabId: number): Promise<IndexedDBInfo | null> {
    return execInTab<any>(
      tabId,
      async function () {
        try {
          const dbs = await indexedDB.databases();
          if (!dbs || dbs.length === 0) return { databases: [] };

          const result: any[] = [];
          for (let i = 0; i < dbs.length; i++) {
            const dbInfo = dbs[i];
            try {
              const db = await new Promise<IDBDatabase>((resolve, reject) => {
                const req = indexedDB.open(dbInfo.name!, dbInfo.version!);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
              });
              const stores: any[] = [];
              for (let s = 0; s < db.objectStoreNames.length; s++) {
                const storeName = db.objectStoreNames[s];
                try {
                  const tx = db.transaction(storeName, 'readonly');
                  const store = tx.objectStore(storeName);
                  const count = await new Promise<number>((res, rej) => {
                    const r = store.count();
                    r.onsuccess = () => res(r.result);
                    r.onerror = () => rej(r.error);
                  });
                  const records: string[] = [];
                  if (count > 0 && count <= 100) {
                    const allRecords = await new Promise<any[]>((res, rej) => {
                      const r = store.getAll();
                      r.onsuccess = () => res(r.result);
                      r.onerror = () => rej(r.error);
                    });
                    for (let ri = 0; ri < allRecords.length; ri++) {
                      let str = JSON.stringify(allRecords[ri]);
                      if (str.length > 500) str = str.substring(0, 500) + '...';
                      records.push(str);
                    }
                  }
                  stores.push({ name: storeName, count, records });
                } catch {
                  stores.push({ name: storeName, count: -1, records: [] });
                }
              }
              db.close();
              result.push({ name: dbInfo.name, version: dbInfo.version, stores });
            } catch {
              result.push({ name: dbInfo.name, version: dbInfo.version || 0, stores: [] });
            }
          }
          return { databases: result };
        } catch (e: any) {
          return { databases: [], error: e.message };
        }
      },
      { world: 'MAIN' },
    );
  }

  // ---------- 操作 ----------

  function deleteStorageItem(storageType: string, key: string) {
    getActiveTab().then(t => {
      if (!t?.id) return;
      if (storageType === 'local' || storageType === 'session') {
        execInTab(t.id, function (params: { type: string; key: string }) {
          const storage = params.type === 'local' ? localStorage : sessionStorage;
          storage.removeItem(params.key);
        }, { world: 'MAIN', args: [{ type: storageType, key }] });
      } else if (storageType === 'cookie') {
        // Cookie 需通过设置过期时间删除，逐 path/domain 尝试
        execInTab(t.id, function (params: { key: string }) {
          const paths = ['/', location.pathname.replace(/\/[^/]*$/, '') || '/'];
          const host = location.hostname;
          const domains = host ? [host, '.' + host.split('.').slice(-2).join('.')] : [''];
          for (const p of [...new Set(paths)]) {
            for (const d of [...new Set(domains)]) {
              document.cookie = `${params.key}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${p}; domain=${d}`;
              document.cookie = `${params.key}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${p}`;
            }
          }
        }, { world: 'MAIN', args: [{ key }] });
      } else {
        // window 变量
        execInTab(t.id, function (params: { key: string }) {
          try { (window as any)[params.key] = undefined; } catch { /* ignore */ }
        }, { world: 'MAIN', args: [{ key }] });
      }

      // 更新本地状态
      if (storageType === 'local') localItems = localItems.filter(i => i.key !== key);
      else if (storageType === 'session') sessionItems = sessionItems.filter(i => i.key !== key);
      else if (storageType === 'cookie') cookies = cookies.filter(i => i.key !== key);
      else windowVars = windowVars.filter(i => i.key !== key);

      toastStore.show('已删除', 'success');
    }).catch(() => {
      toastStore.show('删除失败：无法访问当前标签页', 'error');
    });
  }

  function activeTabItems(): StorageItem[] {
    if (activeTab === 'local') return localItems;
    if (activeTab === 'session') return sessionItems;
    if (activeTab === 'cookie') return cookies;
    if (activeTab === 'window') return windowVars;
    return [];
  }

  function copyAllData() {
    const items = activeTabItems();
    if (items.length === 0) { toastStore.show('无数据可复制', 'warning'); return; }
    const obj: Record<string, string> = {};
    for (const item of items) obj[item.key] = item.value;
    copyText(JSON.stringify(obj, null, 2), '已复制全部数据');
  }

  function copyIdbData() {
    if (!idbInfo?.databases?.length) { toastStore.show('无 IndexedDB 数据', 'warning'); return; }
    copyText(JSON.stringify(idbInfo, null, 2), '已复制 IndexedDB 数据');
  }

  function copyValue(value: string) {
    copyText(value, '已复制值');
  }

  // —— 导出序列化器（作用于当前 activeTab 的 items）——
  function storageJson(items: StorageItem[]): string {
    const obj: Record<string, string> = {};
    for (const item of items) obj[item.key] = item.value;
    return JSON.stringify({ category: activeTab, data: obj }, null, 2);
  }
  function storageCsv(items: StorageItem[]): string {
    return toCsv([
      ['key', 'value', 'sensitive', 'severity', 'storageType'],
      ...items.map(i => [i.key, i.value, String(i.isSensitive), i.severity, i.storageType]),
    ]);
  }
  function storageText(items: StorageItem[]): string {
    return items.map(i => `[${i.storageType}${i.isSensitive ? '/敏感' : ''}] ${i.key} = ${i.value}`).join('\n');
  }

  function clearAllStorage() {
    let count = 0;
    if (activeTab === 'local') count = localFiltered.length;
    else if (activeTab === 'session') count = sessionFiltered.length;
    else if (activeTab === 'cookie') count = cookieFiltered.length;
    else if (activeTab === 'window') count = windowFiltered.length;
    if (count === 0) {
      toastStore.show('当前分类无数据', 'warning');
      return;
    }
    const label = activeTab === 'local' ? 'localStorage' : activeTab === 'session' ? 'sessionStorage' : activeTab === 'cookie' ? 'Cookie' : 'Window 全局变量';
    if (!confirm(`确定清空当前页面的全部 ${label}（${count} 条）？此操作不可撤销。`)) return;

    getActiveTab().then(t => {
      if (!t?.id) return;
      if (activeTab === 'local' || activeTab === 'session') {
        execInTab(t.id, function (params: { type: string }) {
          const storage = params.type === 'local' ? localStorage : sessionStorage;
          storage.clear();
        }, { world: 'MAIN', args: [activeTab] });
      } else if (activeTab === 'cookie') {
        execInTab(t.id, function () {
          const raw = document.cookie || '';
          const names: string[] = [];
          raw.split(';').forEach(pair => {
            const eq = pair.indexOf('=');
            names.push(eq === -1 ? pair.trim() : pair.substring(0, eq).trim());
          });
          const paths = ['/', location.pathname.replace(/\/[^/]*$/, '') || '/'];
          const host = location.hostname;
          const domains = host ? [host, '.' + host.split('.').slice(-2).join('.')] : [''];
          for (const name of names) {
            for (const p of [...new Set(paths)]) {
              for (const d of [...new Set(domains)]) {
                document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${p}; domain=${d}`;
                document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${p}`;
              }
            }
          }
        }, { world: 'MAIN' });
      } else {
        // window 变量
        const keys = windowFiltered.map(i => i.key);
        execInTab(t.id, function (params: { keys: string[] }) {
          for (const k of params.keys) {
            try { (window as any)[k] = undefined; } catch { /* ignore */ }
          }
        }, { world: 'MAIN', args: [{ keys }] });
      }

      if (activeTab === 'local') localItems = [];
      else if (activeTab === 'session') sessionItems = [];
      else if (activeTab === 'cookie') cookies = [];
      else if (activeTab === 'window') windowVars = [];

      toastStore.show(`已清空 ${label}`, 'success');
    }).catch(() => {
      toastStore.show('清空失败：无法访问当前标签页', 'error');
    });
  }
</script>

<div class="space-y-3">
  <!-- 操作栏 -->
  <div class="card p-3">
    <div class="flex items-center gap-2">
      {#if scanning}
        <button class="btn btn-sm btn-danger" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
      {:else}
        <button class="btn btn-sm btn-primary" onclick={startScan}>检查存储</button>
      {/if}
      {#if scanned}
        <button class="btn btn-sm" onclick={copyAllData}>复制全部</button>
        {#if activeTab !== 'idb'}
          <ExportMenu items={activeTabItems()} module="storage-check" serializers={{ json: storageJson, csv: storageCsv, text: storageText }} />
          <button class="btn btn-sm text-red-500" onclick={clearAllStorage}>清空全部</button>
        {/if}
      {/if}
    </div>
  </div>

  {#if cs.status === 'failed'}
    <ErrorState error={cs.error!} onRetry={startScan} />
  {/if}

  <!-- 未扫描提示 -->
  {#if !scanned && !scanning}
    <div class="card p-3">
      <div class="text-sm text-gray-400">点击「检查存储」扫描当前页面的 localStorage、sessionStorage、Cookie、IndexedDB 及全局变量</div>
    </div>
  {/if}

  <!-- 存储类型 Tab -->
  {#if scanned}
    <div class="flex gap-1 flex-wrap">
      <button class="btn btn-sm" class:btn-primary={activeTab === 'local'} onclick={() => activeTab = 'local'}>
        localStorage ({localItems.length}){localSensitive > 0 ? ` 🔴${localSensitive}` : ''}
      </button>
      <button class="btn btn-sm" class:btn-primary={activeTab === 'session'} onclick={() => activeTab = 'session'}>
        sessionStorage ({sessionItems.length}){sessionSensitive > 0 ? ` 🔴${sessionSensitive}` : ''}
      </button>
      <button class="btn btn-sm" class:btn-primary={activeTab === 'cookie'} onclick={() => activeTab = 'cookie'}>
        Cookie ({cookies.length}){cookieSensitive > 0 ? ` 🔴${cookieSensitive}` : ''}
      </button>
      <button class="btn btn-sm" class:btn-primary={activeTab === 'window'} onclick={() => activeTab = 'window'}>
        Window ({windowVars.length}){windowSensitive > 0 ? ` 🔴${windowSensitive}` : ''}
      </button>
      <button class="btn btn-sm" class:btn-primary={activeTab === 'idb'} onclick={() => activeTab = 'idb'}>
        IndexedDB {idbInfo?.databases?.length ? `(${idbInfo.databases.length})` : ''}
      </button>
    </div>

    <!-- 搜索 / 过滤 -->
    {#if activeTab !== 'idb'}
      <div class="flex gap-2 items-center">
        <input
          type="text"
          class="input flex-1 text-xs"
          placeholder="搜索键名或值..."
          bind:value={searchQuery}
        />
        <button
          class="btn btn-xs"
          class:btn-primary={filter === 'all'}
          onclick={() => filter = 'all'}
        >全部</button>
        <button
          class="btn btn-xs"
          class:btn-primary={filter === 'sensitive'}
          onclick={() => filter = 'sensitive'}
        >敏感</button>
        <select class="input text-xs w-16 ml-auto" bind:value={sortBy}>
          <option value="default">默认</option>
          <option value="key">按键名</option>
          <option value="size">按大小</option>
        </select>
      </div>
    {/if}

    <!-- localStorage -->
    {#if activeTab === 'local'}
      {@render storageList(localFiltered, 'local')}
    {/if}

    <!-- sessionStorage -->
    {#if activeTab === 'session'}
      {@render storageList(sessionFiltered, 'session')}
    {/if}

    <!-- Cookie -->
    {#if activeTab === 'cookie'}
      {@render storageList(cookieFiltered, 'cookie')}
    {/if}

    <!-- Window -->
    {#if activeTab === 'window'}
      {@render storageList(windowFiltered, 'window')}
    {/if}

    <!-- IndexedDB -->
    {#if activeTab === 'idb'}
      <div class="card p-3 space-y-3">
        {#if idbInfo?.databases && idbInfo.databases.length > 0}
          <div class="flex justify-end">
            <button class="btn btn-xs" onclick={copyIdbData}>复制全部</button>
          </div>
          {#each idbInfo.databases as db (db.name)}
            <div class="space-y-1">
              <div class="text-sm font-medium">{db.name} <span class="badge text-xs">v{db.version}</span></div>
              {#if db.stores?.length > 0}
                {#each db.stores as store (`${db.name}:${store.name}`)}
                  <div class="ml-3 space-y-1">
                    <div class="text-xs text-gray-500">
                      {store.name} <span class="badge text-xs">{store.count} 条</span>
                    </div>
                    {#if store.records?.length > 0}
                      <div class="space-y-0.5 ml-3">
                        {#each store.records as record, i (i)}
                          <div class="text-xs font-mono bg-gray-50 dark:bg-gray-800 rounded p-1 break-all">{truncate(record, 200)}</div>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/each}
              {:else}
                <div class="ml-3 text-xs text-gray-400">无 object store</div>
              {/if}
            </div>
          {/each}
        {:else}
          <div class="text-sm text-gray-400">{idbInfo?.error ? `错误: ${idbInfo.error}` : '未发现 IndexedDB 数据库'}</div>
        {/if}
      </div>
    {/if}
  {/if}
</div>

{#snippet storageList(items: StorageItem[], storageType: string)}
  <div class="space-y-1">
    {#if items.length === 0}
      <div class="card p-3">
        <div class="text-sm text-gray-400">{filter === 'sensitive' ? '无匹配的敏感数据' : '存储为空'}</div>
      </div>
    {:else}
      {#each items as item (`${storageType}:${item.key}`)}
        <div class="card p-2 text-xs {item.isSensitive ? severityBg(item.severity) : ''}">
          <div class="flex items-start gap-2">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-1">
                <span class="font-mono font-medium truncate">{escapeHtml(item.key)}</span>
                {#if item.isSensitive}
                  {#each item.matchedPatterns as pat (pat)}
                    <span class="badge {severityColor(item.severity)}">{escapeHtml(pat)}</span>
                  {/each}
                {/if}
              </div>
              <div
                class="text-gray-500 mt-0.5 break-all cursor-pointer select-all"
                class:line-clamp-2={!expandedKeys.has(item.key)}
                role="button"
                tabindex="0"
                onclick={() => toggleExpand(item.key)}
                onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleExpand(item.key); } }}
                title="点击展开/收起"
              >
                {expandedKeys.has(item.key) ? escapeHtml(item.value) : escapeHtml(truncate(item.value, 120))}
              </div>
            </div>
            <div class="flex gap-1 shrink-0">
              <button class="btn btn-xs" onclick={() => copyValue(item.value)} title="复制值">复制</button>
              <button class="btn btn-xs text-red-500" onclick={() => deleteStorageItem(storageType, item.key)} title="删除">删除</button>
            </div>
          </div>
        </div>
      {/each}
    {/if}
  </div>
{/snippet}
