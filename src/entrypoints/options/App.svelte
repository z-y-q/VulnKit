<script lang="ts">
  // 设置页 — 灵眸 v6.0
  // 1. API 密钥管理（ZoomEye）
  // 2. 扫描历史管理（查看/清空）
  // 3. 存储用量概览与清理
  // 4. 主题切换 / 关于
  import { themeStore, toastStore } from '@/stores/ui';
  import { scanHistoryStore, MODULE_LABELS, type ScanHistoryEntry } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { SCAN_SETTINGS_BOUNDS } from '@/lib/core/settings';
  import {
    loadPrefs,
    savePrefs,
    resetPrefs,
    fetchRemotePayloads,
    type GeneralPrefs,
    type DefaultEncoding,
    type DefaultHash,
  } from '@/lib/core/general-prefs';

  const ZOEYEYE_KEY = 'lingmou_zoomeye_key';
  const PREFS_KEY = 'lingmouPrefs';

  let isDark = $derived($themeStore);

  let apiKey = $state('');
  let history = $state<ScanHistoryEntry[]>([]);
  let storageItems = $state<{ key: string; label: string; bytes: number }[]>([]);
  let storageTotal = $state(0);

  // 通用偏好
  let prefs = $state<GeneralPrefs | null>(null);
  let excludeText = $state('');
  let remoteFetching = $state(false);

  // 扫描参数（从 store 拉到本地编辑态，保存时写回）
  let scanSettings = $derived($scanSettingsStore);
  let editTimeout = $state(0);
  let editConcurrency = $state(0);
  let editMaxPerHost = $state(0);
  let editMinInterval = $state(0);
  let settingsLoaded = $state(false);

  $effect(() => {
    // store 首次加载后同步到编辑态
    if (!settingsLoaded && scanSettings.requestTimeoutMs) {
      editTimeout = scanSettings.requestTimeoutMs / 1000;
      editConcurrency = scanSettings.concurrency;
      editMaxPerHost = scanSettings.maxConcurrentPerHost;
      editMinInterval = scanSettings.minIntervalPerHostMs;
      settingsLoaded = true;
    }
  });

  const KNOWN_STORAGE_KEYS: { key: string; label: string }[] = [
    { key: 'pentest_scan_history', label: '扫描历史' },
    { key: ZOEYEYE_KEY, label: 'ZoomEye 密钥' },
    { key: 'lingmou-theme', label: '主题设置' },
    { key: 'pendingPanel', label: '待跳转面板' },
    { key: 'pentest_spoof', label: '伪装状态' },
    { key: 'pentestSettings', label: '扫描参数/右键菜单' },
    { key: PREFS_KEY, label: '通用偏好/远程载荷' },
  ];

  $effect(() => {
    browser.storage.local.get(ZOEYEYE_KEY).then(r => {
      apiKey = (r[ZOEYEYE_KEY] as string) || '';
    });
    loadPrefs().then(p => {
      prefs = p;
      excludeText = p.gatherExcludeDomains.join('\n');
    });
    refreshHistory();
    refreshStorage();
  });

  // ===== 通用偏好 =====
  async function saveEncodingDefault(v: DefaultEncoding) {
    if (!prefs) return;
    prefs = await savePrefs({ defaultEncoding: v });
    toastStore.show('默认编码已保存', 'success');
  }
  async function saveHashDefault(v: DefaultHash) {
    if (!prefs) return;
    prefs = await savePrefs({ defaultHash: v });
    toastStore.show('默认哈希算法已保存', 'success');
  }
  async function saveExcludeList() {
    const list = excludeText
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    prefs = await savePrefs({ gatherExcludeDomains: list });
    toastStore.show(`已保存 ${list.length} 条排除域名`, 'success');
  }
  async function saveRemoteUrl() {
    if (!prefs) return;
    const url = prefs.payloadRemoteUrl.trim();
    if (url) {
      try {
        new URL(url);
      } catch {
        toastStore.show('URL 格式无效', 'error');
        return;
      }
    }
    prefs = await savePrefs({ payloadRemoteUrl: url });
    toastStore.show(url ? '远程 Payload URL 已保存' : '已清空远程 Payload URL', 'success');
  }
  async function fetchRemote() {
    if (!prefs?.payloadRemoteUrl) {
      toastStore.show('请先填写远程 Payload URL', 'warning');
      return;
    }
    remoteFetching = true;
    try {
      const cache = await fetchRemotePayloads(prefs.payloadRemoteUrl);
      prefs = await savePrefs({ remotePayloads: cache });
      toastStore.show(
        `拉取成功${cache.version ? `（v${cache.version}）` : ''}，已缓存 ${
          Object.keys(cache.payloads || {}).length
        } 类`,
        'success',
      );
    } catch (e) {
      toastStore.show('拉取失败：' + (e as Error).message, 'error');
    } finally {
      remoteFetching = false;
    }
  }
  async function clearRemote() {
    if (!prefs) return;
    prefs = await savePrefs({ remotePayloads: null });
    toastStore.show('已清除远程 Payload 缓存', 'success');
  }
  async function resetAllPrefs() {
    if (!confirm('确定恢复全部通用偏好为默认？')) return;
    prefs = await resetPrefs();
    excludeText = '';
    toastStore.show('通用偏好已恢复默认', 'success');
  }

  // ===== 完整数据备份 =====
  async function exportAllData() {
    const all = await browser.storage.local.get(null);
    const blob = new Blob([JSON.stringify({ __app: 'lingmou-v6', __exportedAt: Date.now(), data: all }, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lingmou-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('已导出全部数据', 'success');
  }

  let importInput: HTMLInputElement;

  async function importAllData(file: File) {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const data = parsed?.data && typeof parsed.data === 'object' ? parsed.data : parsed;
      if (!data || typeof data !== 'object') throw new Error('文件格式无效');
      if (!confirm(`将合并导入 ${Object.keys(data).length} 个键到本地存储，覆盖同名键。继续？`)) return;
      await browser.storage.local.set(data);
      toastStore.show('数据导入完成，刷新页面生效', 'success');
      setTimeout(() => location.reload(), 800);
    } catch (e) {
      toastStore.show('导入失败：' + (e as Error).message, 'error');
    }
  }

  async function clearAllData() {
    if (!confirm('⚠️ 将清除本扩展所有本地数据（密钥/历史/设置/规则），不可恢复。继续？')) return;
    if (!confirm('再次确认：这会清空一切，需要重新配置。真的继续？')) return;
    await browser.storage.local.clear();
    toastStore.show('已清空全部数据，即将刷新', 'success');
    setTimeout(() => location.reload(), 800);
  }

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

  async function saveScanSettings() {
    await scanSettingsStore.update({
      requestTimeoutMs: Math.round(editTimeout * 1000),
      concurrency: editConcurrency,
      maxConcurrentPerHost: editMaxPerHost,
      minIntervalPerHostMs: editMinInterval,
    });
    toastStore.show('扫描参数已保存', 'success');
  }

  function resetScanSettings() {
    editTimeout = 10;
    editConcurrency = 6;
    editMaxPerHost = 6;
    editMinInterval = 0;
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

  // ===== 面板排序 / 显示隐藏 =====
  import { panelMeta } from '@/panels/registry';
  import { panelLayoutStore } from '@/stores/panel-layout';
  let layout = $derived($panelLayoutStore);
  // 当前编辑顺序（基于 layout.order 重排 panelMeta）
  let orderedPanels = $derived.by(() => {
    const idx = new Map(layout.order.map((id, i) => [id, i]));
    return [...panelMeta].sort((a, b) => {
      const ia = idx.has(a.id) ? idx.get(a.id)! : 1e9;
      const ib = idx.has(b.id) ? idx.get(b.id)! : 1e9;
      if (ia !== ib) return ia - ib;
      return panelMeta.indexOf(a) - panelMeta.indexOf(b);
    });
  });
  async function movePanel(index: number, delta: number) {
    const newList = orderedPanels.map(p => p.id);
    const j = index + delta;
    if (j < 0 || j >= newList.length) return;
    [newList[index], newList[j]] = [newList[j], newList[index]];
    await panelLayoutStore.setOrder(newList);
  }
  async function togglePanelVisible(id: string) {
    await panelLayoutStore.toggleHidden(id);
  }
  async function resetLayout() {
    if (!confirm('恢复面板默认顺序并显示全部？')) return;
    await panelLayoutStore.reset();
    toastStore.show('已恢复默认布局', 'success');
  }

  // ===== HaE 规则 YAML 管理 =====
  import {
    loadCustomRulesYaml, saveCustomRulesYaml, clearCustomRules,
    parseRulesYaml, defaultRulesToYaml,
  } from '@/lib/scanners/hae-store';
  let haeText = $state('');
  let haeDirty = $state(false);
  let haeLoaded = $state(false);

  $effect(() => {
    loadCustomRulesYaml().then(t => { haeText = t; haeLoaded = true; });
  });

  async function saveHae() {
    try {
      parseRulesYaml(haeText); // 先校验，非法则抛错
      await saveCustomRulesYaml(haeText);
      haeDirty = false;
      toastStore.show('HaE 规则已保存并生效', 'success');
    } catch (e: any) {
      toastStore.show('保存失败：' + (e.message || 'YAML 解析错误'), 'error');
    }
  }
  function loadDefaultHae() {
    if (!confirm('用默认规则覆盖当前编辑区？（自定义规则需重新保存才会生效）')) return;
    haeText = defaultRulesToYaml();
    haeDirty = true;
    toastStore.show('已载入默认规则到编辑区（需点击保存）', 'info');
  }
  async function clearHae() {
    if (!confirm('确定清空所有自定义 HaE 规则？将仅保留内置默认规则。')) return;
    await clearCustomRules();
    haeText = '';
    haeDirty = false;
    toastStore.show('已清空自定义规则', 'success');
  }
  function exportHae() {
    const blob = new Blob([haeText || defaultRulesToYaml()], { type: 'text/yaml;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `hae-rules-${new Date().toISOString().slice(0, 10)}.yaml`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  function importHae(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      haeText = String(reader.result || '');
      haeDirty = true;
      toastStore.show('已导入 YAML，请校验后点击保存', 'info');
    };
    reader.readAsText(file);
    input.value = '';
  }
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

  <!-- HaE 规则管理 -->
  <section class="card p-4 space-y-3">
    <div class="flex items-center justify-between">
      <h2 class="text-sm font-semibold">📜 HaE 规则管理</h2>
      <div class="flex gap-1">
        <button class="btn btn-xs" onclick={loadDefaultHae} title="载入默认规则到编辑区">载入默认</button>
        <label class="btn btn-xs cursor-pointer" title="从 YAML 文件导入">
          导入
          <input type="file" accept=".yaml,.yml,.txt" class="hidden" onchange={importHae} />
        </label>
        <button class="btn btn-xs" onclick={exportHae}>导出</button>
        <button class="btn btn-xs text-red-500" onclick={clearHae}>清空自定义</button>
      </div>
    </div>
    <p class="text-xs text-gray-400">YAML 格式，自定义规则追加到内置默认规则之后，供「信息收集」面板使用。字段：group / rules[]{name, f_regex, s_regex, format, color, sensitive}。保存时自动校验正则合法性。</p>
    <textarea
      class="input font-mono text-xs w-full"
      rows="12"
      placeholder="# 示例：&#10;- group: 自定义规则&#10;  rules:&#10;    - name: 内网IP&#10;      f_regex: '(?:10\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.|192\\.168\\.)\\d{1,3}'&#10;      format: '{0}'&#10;      color: orange&#10;      sensitive: false"
      bind:value={haeText}
      oninput={() => (haeDirty = true)}
    ></textarea>
    <div class="flex items-center gap-2">
      <button class="btn btn-sm btn-primary" onclick={saveHae} disabled={!haeLoaded}>保存并生效</button>
      {#if haeDirty}<span class="text-xs text-amber-500">未保存的修改</span>{/if}
    </div>
  </section>

  <!-- 面板排序 / 显示隐藏 -->
  <section class="card p-4 space-y-3">
    <div class="flex items-center justify-between">
      <h2 class="text-sm font-semibold">🧭 面板排序与显示</h2>
      <button class="btn btn-xs" onclick={resetLayout}>恢复默认</button>
    </div>
    <p class="text-xs text-gray-400">调整侧栏/弹窗中面板的显示顺序与可见性。隐藏的面板不会出现在工具栏（仍可通过快捷方式访问）。</p>
    <div class="space-y-0.5 max-h-72 overflow-y-auto">
      {#each orderedPanels as p, i (p.id)}
        <div class="flex items-center gap-2 text-xs py-1 px-1 rounded hover:bg-gray-50 dark:hover:bg-gray-800">
          <input
            type="checkbox"
            checked={!layout.hidden.includes(p.id)}
            onchange={() => togglePanelVisible(p.id)}
            class="accent-blue-500 shrink-0"
          />
          <span class="text-base w-5 text-center">{p.icon}</span>
          <span class="flex-1 truncate">{p.label}</span>
          <span class="text-gray-400 text-[10px]">{p.category}</span>
          <button class="btn btn-xs px-1.5" disabled={i === 0} onclick={() => movePanel(i, -1)} title="上移">↑</button>
          <button class="btn btn-xs px-1.5" disabled={i === orderedPanels.length - 1} onclick={() => movePanel(i, 1)} title="下移">↓</button>
        </div>
      {/each}
    </div>
  </section>

  <!-- 扫描参数 -->
  <section class="card p-4 space-y-3">
    <div class="flex items-center justify-between">
      <h2 class="text-sm font-semibold">⚡ 扫描参数</h2>
      <span class="text-xs text-gray-400">实时生效 · background 侧</span>
    </div>
    <p class="text-xs text-gray-400 -mt-1">控制测试强度，避免对目标造成压力（SRC 合规要求）。限流按目标主机全局生效，跨面板共享。</p>
    <div class="grid grid-cols-2 gap-3">
      <label class="space-y-1">
        <span class="text-xs text-gray-500">请求超时（秒）</span>
        <input
          class="input text-sm"
          type="number"
          min={SCAN_SETTINGS_BOUNDS.requestTimeoutMs.min / 1000}
          max={SCAN_SETTINGS_BOUNDS.requestTimeoutMs.max / 1000}
          step="1"
          bind:value={editTimeout}
        />
        <span class="text-[10px] text-gray-400">单个 HTTP 请求的最大等待</span>
      </label>
      <label class="space-y-1">
        <span class="text-xs text-gray-500">面板并发数</span>
        <input
          class="input text-sm"
          type="number"
          min={SCAN_SETTINGS_BOUNDS.concurrency.min}
          max={SCAN_SETTINGS_BOUNDS.concurrency.max}
          step="1"
          bind:value={editConcurrency}
        />
        <span class="text-[10px] text-gray-400">单个扫描面板的并发 worker</span>
      </label>
      <label class="space-y-1">
        <span class="text-xs text-gray-500">每主机最大并发</span>
        <input
          class="input text-sm"
          type="number"
          min={SCAN_SETTINGS_BOUNDS.maxConcurrentPerHost.min}
          max={SCAN_SETTINGS_BOUNDS.maxConcurrentPerHost.max}
          step="1"
          bind:value={editMaxPerHost}
        />
        <span class="text-[10px] text-gray-400">同一目标主机同时在飞的请求上限</span>
      </label>
      <label class="space-y-1">
        <span class="text-xs text-gray-500">每主机最小间隔（毫秒）</span>
        <input
          class="input text-sm"
          type="number"
          min={SCAN_SETTINGS_BOUNDS.minIntervalPerHostMs.min}
          max={SCAN_SETTINGS_BOUNDS.minIntervalPerHostMs.max}
          step="50"
          bind:value={editMinInterval}
        />
        <span class="text-[10px] text-gray-400">同主机相邻请求间隔，0=不限速</span>
      </label>
    </div>
    <div class="flex gap-1 pt-1">
      <button class="btn btn-sm btn-primary" onclick={saveScanSettings}>保存</button>
      <button class="btn btn-sm" onclick={resetScanSettings}>恢复默认</button>
    </div>
  </section>

  <!-- 工具默认值 -->
  {#if prefs}
    <section class="card p-4 space-y-3">
      <h2 class="text-sm font-semibold">🛠️ 工具默认值</h2>
      <div class="grid grid-cols-2 gap-3">
        <label class="space-y-1">
          <span class="text-xs text-gray-500">默认编码类型</span>
          <select
            class="input text-sm"
            value={prefs.defaultEncoding}
            onchange={(e) => saveEncodingDefault((e.currentTarget as HTMLSelectElement).value as DefaultEncoding)}
          >
            <option value="base64">Base64</option>
            <option value="url">URL 编码</option>
            <option value="html">HTML 实体</option>
            <option value="hex">十六进制</option>
          </select>
          <span class="text-[10px] text-gray-400">编码工具面板打开时的默认子标签</span>
        </label>
        <label class="space-y-1">
          <span class="text-xs text-gray-500">默认哈希算法</span>
          <select
            class="input text-sm"
            value={prefs.defaultHash}
            onchange={(e) => saveHashDefault((e.currentTarget as HTMLSelectElement).value as DefaultHash)}
          >
            <option value="SHA-256">SHA-256</option>
            <option value="SHA-1">SHA-1</option>
            <option value="MD5">MD5</option>
          </select>
          <span class="text-[10px] text-gray-400">右键选区哈希 / Hash 工具默认算法</span>
        </label>
      </div>
    </section>

    <!-- 采集过滤 -->
    <section class="card p-4 space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold">🚫 采集过滤</h2>
        <span class="text-xs text-gray-400">信息收集 / 子域名排除</span>
      </div>
      <p class="text-xs text-gray-400 -mt-1">每行一个域名，匹配的域名在采集时自动过滤。支持 <code class="text-[10px]">.example.com</code> 后缀（含子域）。</p>
      <textarea
        class="input w-full text-xs font-mono"
        rows="4"
        placeholder={"例如：\n.google.com\n.cnzz.com\ndoubleclick.net"}
        bind:value={excludeText}
      ></textarea>
      <div class="flex gap-1">
        <button class="btn btn-sm btn-primary" onclick={saveExcludeList}>保存排除列表</button>
      </div>
    </section>

    <!-- 远程 Payload -->
    <section class="card p-4 space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold">☁️ 远程 Payload</h2>
        {#if prefs.remotePayloads}
          <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">
            已缓存{prefs.remotePayloads.version ? ` v${prefs.remotePayloads.version}` : ''}
          </span>
        {/if}
      </div>
      <p class="text-xs text-gray-400 -mt-1">配置远程 JSON（需含 <code class="text-[10px]">version</code> + <code class="text-[10px]">payloads</code> 字段），拉取后缓存，XSS/Payload 面板优先使用。</p>
      <div class="flex gap-1">
        <input
          class="input flex-1 text-xs font-mono"
          type="url"
          placeholder="https://example.com/lingmou-payloads.json"
          bind:value={prefs.payloadRemoteUrl}
        />
        <button class="btn btn-sm" onclick={saveRemoteUrl}>保存 URL</button>
      </div>
      <div class="flex gap-1 flex-wrap">
        <button class="btn btn-sm btn-primary" onclick={fetchRemote} disabled={remoteFetching || !prefs.payloadRemoteUrl}>
          {remoteFetching ? '拉取中...' : '⬇ 拉取并缓存'}
        </button>
        <button class="btn btn-sm" onclick={clearRemote} disabled={!prefs.remotePayloads}>清除缓存</button>
      </div>
      {#if prefs.remotePayloads?.fetchedAt}
        <div class="text-[10px] text-gray-400">
          上次拉取: {new Date(prefs.remotePayloads.fetchedAt).toLocaleString('zh-CN')} ·
          {Object.keys(prefs.remotePayloads.payloads || {}).length} 类载荷
        </div>
      {/if}
    </section>

    <!-- 数据备份 -->
    <section class="card p-4 space-y-3">
      <h2 class="text-sm font-semibold">📦 数据备份</h2>
      <p class="text-xs text-gray-400 -mt-1">导出全部本地数据（密钥/历史/设置/规则/伪装状态）为 JSON，可在另一台机器导入恢复。</p>
      <div class="flex gap-1 flex-wrap">
        <button class="btn btn-sm btn-primary" onclick={exportAllData}>⬇ 导出全部</button>
        <button class="btn btn-sm" onclick={() => importInput?.click()}>⬆ 导入数据</button>
        <input
          bind:this={importInput}
          type="file"
          accept="application/json"
          class="hidden"
          onchange={(e) => {
            const f = (e.currentTarget as HTMLInputElement).files?.[0];
            if (f) importAllData(f);
            (e.currentTarget as HTMLInputElement).value = '';
          }}
        />
        <button class="btn btn-sm btn-danger ml-auto" onclick={clearAllData}>⚠ 清空全部数据</button>
      </div>
      <div class="flex gap-1 pt-1 border-t border-gray-100 dark:border-gray-700">
        <button class="btn btn-sm" onclick={resetAllPrefs}>恢复通用偏好默认</button>
      </div>
    </section>
  {/if}

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
