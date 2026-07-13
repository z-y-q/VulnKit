<script lang="ts">
  // 设置页 — 灵眸 v6.0（阶段2重构：分区导航 + hash 路由 + 统一保存状态 + ConfirmDialog，对齐 §4.3）
  // 业务逻辑不变；布局改为左侧目录 + 右侧分区；10 处原生 confirm 改 confirmStore.ask。
  import { themeStore, toastStore } from '@/stores/ui';
  import { scanHistoryStore, MODULE_LABELS, type ScanHistoryEntry } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { SCAN_SETTINGS_BOUNDS } from '@/lib/core/settings';
  import { getAppVersion } from '@/lib/core/app-version';
  import { confirmStore } from '@/stores/confirm';
  import ConfirmDialog from '@/components/feedback/ConfirmDialog.svelte';
  import {
    buildBackup,
    applyBundle,
    parseBackup,
    summarizeBundle,
    type BackupBundle,
    type BundleSummary,
  } from '@/lib/core/backup';

  let version = $derived(getAppVersion());
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
  let history = $derived($scanHistoryStore);
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
    if (!settingsLoaded && scanSettings.requestTimeoutMs) {
      editTimeout = scanSettings.requestTimeoutMs / 1000;
      editConcurrency = scanSettings.concurrency;
      editMaxPerHost = scanSettings.maxConcurrentPerHost;
      editMinInterval = scanSettings.minIntervalPerHostMs;
      settingsLoaded = true;
    }
  });

  // 扫描参数未保存检测（驱动顶部状态条）
  let scanDirty = $derived(
    settingsLoaded &&
      (Math.round(editTimeout * 1000) !== scanSettings.requestTimeoutMs ||
        editConcurrency !== scanSettings.concurrency ||
        editMaxPerHost !== scanSettings.maxConcurrentPerHost ||
        editMinInterval !== scanSettings.minIntervalPerHostMs),
  );

  const KNOWN_STORAGE_KEYS: { key: string; label: string }[] = [
    { key: 'pentest_scan_history', label: '扫描历史' },
    { key: ZOEYEYE_KEY, label: 'ZoomEye 密钥' },
    { key: 'lingmou-theme', label: '主题设置' },
    { key: 'pendingAction', label: '待跳转任务' },
    { key: 'pentest_spoof', label: '伪装状态' },
    { key: 'pentestSettings', label: '扫描参数/右键菜单' },
    { key: PREFS_KEY, label: '通用偏好/远程载荷' },
    { key: 'haeCustomRules', label: 'HaE 自定义规则' },
    { key: 'panelLayout', label: '面板布局' },
  ];

  $effect(() => {
    browser.storage.local.get(ZOEYEYE_KEY).then((r) => {
      apiKey = (r[ZOEYEYE_KEY] as string) || '';
    });
    loadPrefs().then((p) => {
      prefs = p;
      excludeText = p.gatherExcludeDomains.join('\n');
    });
    refreshHistory();
    refreshStorage();
  });

  // ===== 分区导航（§4.3） =====
  const SECTIONS = [
    { id: 'general', label: '常规', icon: '⚙️', hint: '即时保存' },
    { id: 'scan', label: '扫描与限流', icon: '⚡', hint: '修改后保存' },
    { id: 'api', label: 'API 与远程数据', icon: '🔑', hint: '手动保存' },
    { id: 'hae', label: 'HaE 规则', icon: '📜', hint: '修改后保存' },
    { id: 'nav', label: '工具与导航', icon: '🧭', hint: '实时生效' },
    { id: 'data', label: '历史与存储', icon: '💾', hint: '只读 / 清理' },
    { id: 'backup', label: '备份与恢复', icon: '📦', hint: '手动操作' },
    { id: 'about', label: '关于', icon: 'ℹ️', hint: '' },
  ] as const;

  let activeSection = $state<string>('general');

  $effect(() => {
    const apply = () => {
      const h = location.hash.replace('#', '');
      if (h && SECTIONS.some((s) => s.id === h)) activeSection = h;
    };
    apply();
    window.addEventListener('hashchange', apply);
    return () => window.removeEventListener('hashchange', apply);
  });

  function go(id: string) {
    location.hash = id;
    activeSection = id;
    // 锚点跳转：浏览器原生会滚动到 section；额外 smooth 兜底
    requestAnimationFrame(() => {
      document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

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
      .map((s) => s.trim())
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
    const ok = await confirmStore.ask({
      title: '恢复通用偏好默认',
      message: '确定恢复全部通用偏好（编码/哈希/排除列表/远程 Payload）为默认？',
      variant: 'default',
      confirmLabel: '恢复',
    });
    if (!ok) return;
    prefs = await resetPrefs();
    excludeText = '';
    toastStore.show('通用偏好已恢复默认', 'success');
  }

  // ===== 备份与恢复（字段白名单 §7.7） =====
  let includeSecrets = $state(false);
  let exportPreview = $state<{ keys: number; bytes: number } | null>(null);

  let importInput: HTMLInputElement | undefined = $state();
  let pendingImport = $state<{
    bundle: BackupBundle;
    legacy: boolean;
    unknownKeys: string[];
    summary: BundleSummary;
  } | null>(null);
  let importIncludeSecrets = $state(false);
  let importMode = $state<'merge' | 'overwrite'>('merge');

  async function refreshExportPreview() {
    const bundle = await buildBackup({ includeSecrets, includeHistory: true });
    const s = summarizeBundle(bundle);
    exportPreview = { keys: s.totalKeys, bytes: s.totalBytes };
  }

  $effect(() => {
    // includeSecrets 变化时刷新导出预览
    void includeSecrets;
    refreshExportPreview();
  });

  async function exportAllData() {
    if (includeSecrets) {
      const ok = await confirmStore.ask({
        title: '包含敏感配置',
        message: '备份文件将以明文包含 API Key 与伪装状态。请妥善保管，避免随项目/聊天传输。确认？',
        variant: 'danger',
        confirmLabel: '确认明文导出',
      });
      if (!ok) return;
    }
    const bundle = await buildBackup({ includeSecrets, includeHistory: true });
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lingmou-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show(`已导出 ${Object.keys(bundle.data).length} 项${includeSecrets ? '（含敏感配置）' : ''}`, 'success');
  }

  async function pickImport(file: File) {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const { bundle, legacy, unknownKeys } = parseBackup(parsed);
      if (!bundle || Object.keys(bundle.data).length === 0) {
        toastStore.show('文件无可导入数据（或格式无效）', 'error');
        return;
      }
      pendingImport = { bundle, legacy, unknownKeys, summary: summarizeBundle(bundle) };
      importIncludeSecrets = false;
      importMode = 'merge';
    } catch (e) {
      toastStore.show('解析失败：' + (e as Error).message, 'error');
    }
  }

  async function confirmImport() {
    if (!pendingImport) return;
    if (importIncludeSecrets) {
      const ok = await confirmStore.ask({
        title: '导入敏感配置',
        message: '将以备份中的 API Key / 伪装状态覆盖本机现有值。确认？',
        variant: 'danger',
        confirmLabel: '确认覆盖',
      });
      if (!ok) return;
    }
    const result = await applyBundle(pendingImport.bundle, {
      includeSecrets: importIncludeSecrets,
      includeHistory: true,
      mode: importMode,
    });
    pendingImport = null;
    toastStore.show(`导入 ${result.applied.length} 项，跳过 ${result.skipped.length} 项，即将刷新`, 'success');
    setTimeout(() => location.reload(), 1000);
  }

  function cancelImport() {
    pendingImport = null;
  }

  async function clearAllData() {
    const ok1 = await confirmStore.ask({
      title: '清空全部数据',
      message: '⚠️ 将清除本扩展所有本地数据（密钥/历史/设置/规则），不可恢复。继续？',
      variant: 'danger',
      confirmLabel: '继续',
    });
    if (!ok1) return;
    const ok2 = await confirmStore.ask({
      title: '再次确认',
      message: '这会清空一切，需要重新配置。真的继续？',
      variant: 'danger',
      confirmLabel: '确认清空',
    });
    if (!ok2) return;
    await browser.storage.local.clear();
    toastStore.show('已清空全部数据，即将刷新', 'success');
    setTimeout(() => location.reload(), 800);
  }

  async function refreshHistory() {
    await scanHistoryStore.refresh();
  }

  async function refreshStorage() {
    const keys = KNOWN_STORAGE_KEYS.map((k) => k.key);
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
    const ok = await confirmStore.ask({
      title: '清除 API 密钥',
      message: '确定清除 ZoomEye API 密钥？',
      variant: 'default',
      confirmLabel: '清除',
    });
    if (!ok) return;
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
    const ok = await confirmStore.ask({
      title: '清空扫描历史',
      message: '确定清空全部扫描历史？此操作不可恢复。',
      variant: 'danger',
      confirmLabel: '清空',
    });
    if (!ok) return;
    await scanHistoryStore.clear();
    await refreshHistory();
    toastStore.show('扫描历史已清空', 'success');
  }

  async function clearStorageKey(key: string, label: string) {
    const ok = await confirmStore.ask({
      title: `清除「${label}」`,
      message: `确定清除存储项「${label}」？`,
      variant: 'default',
      confirmLabel: '清除',
    });
    if (!ok) return;
    await browser.storage.local.remove(key);
    await refreshStorage();
    toastStore.show(`${label} 已清除`, 'success');
  }

  function toggleTheme() {
    themeStore.toggle();
  }

  let historyByModule = $derived.by(() => {
    const map = new Map<string, number>();
    for (const e of history)
      map.set(e.moduleName || e.module, (map.get(e.moduleName || e.module) || 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  });

  // ===== 面板排序 / 显示隐藏 =====
  import { panelMeta } from '@/panels/registry';
  import { panelLayoutStore, sortByLayout } from '@/stores/panel-layout';
  let layout = $derived($panelLayoutStore);
  let orderedPanels = $derived(sortByLayout(panelMeta, layout));
  async function movePanel(index: number, delta: number) {
    const newList = orderedPanels.map((p) => p.id);
    const j = index + delta;
    if (j < 0 || j >= newList.length) return;
    [newList[index], newList[j]] = [newList[j], newList[index]];
    await panelLayoutStore.setOrder(newList);
  }
  async function togglePanelVisible(id: string) {
    await panelLayoutStore.toggleHidden(id);
  }
  async function resetLayout() {
    const ok = await confirmStore.ask({
      title: '恢复面板默认布局',
      message: '恢复面板默认顺序并显示全部？',
      variant: 'default',
      confirmLabel: '恢复',
    });
    if (!ok) return;
    await panelLayoutStore.reset();
    toastStore.show('已恢复默认布局', 'success');
  }

  // ===== HaE 规则 YAML 管理 =====
  import {
    loadCustomRulesYaml,
    saveCustomRulesYaml,
    clearCustomRules,
    parseRulesYaml,
    defaultRulesToYaml,
  } from '@/lib/scanners/hae-store';
  let haeText = $state('');
  let haeDirty = $state(false);
  let haeLoaded = $state(false);

  $effect(() => {
    loadCustomRulesYaml().then((t) => {
      haeText = t;
      haeLoaded = true;
    });
  });

  async function saveHae() {
    try {
      parseRulesYaml(haeText);
      await saveCustomRulesYaml(haeText);
      haeDirty = false;
      toastStore.show('HaE 规则已保存并生效', 'success');
    } catch (e: any) {
      toastStore.show('保存失败：' + (e.message || 'YAML 解析错误'), 'error');
    }
  }
  async function loadDefaultHae() {
    const ok = await confirmStore.ask({
      title: '载入默认规则',
      message: '用默认规则覆盖当前编辑区？（自定义规则需重新保存才会生效）',
      variant: 'default',
      confirmLabel: '载入',
    });
    if (!ok) return;
    haeText = defaultRulesToYaml();
    haeDirty = true;
    toastStore.show('已载入默认规则到编辑区（需点击保存）', 'info');
  }
  async function clearHae() {
    const ok = await confirmStore.ask({
      title: '清空自定义 HaE 规则',
      message: '确定清空所有自定义 HaE 规则？将仅保留内置默认规则。',
      variant: 'danger',
      confirmLabel: '清空',
    });
    if (!ok) return;
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

<div class="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
  <!-- Header -->
  <header class="sticky top-0 z-20 bg-white/90 dark:bg-gray-800/90 backdrop-blur border-b border-gray-200 dark:border-gray-700">
    <div class="max-w-5xl mx-auto px-5 py-3 flex items-center justify-between">
      <div>
        <h1 class="text-lg font-bold text-primary">灵眸 v{version}</h1>
        <p class="text-xs text-gray-400">渗透测试浏览器扩展 · 设置</p>
      </div>
      <div class="flex items-center gap-3">
        {#if haeDirty || scanDirty}
          <span class="text-xs text-amber-600 dark:text-amber-400" title="有未保存的修改">
            {#if scanDirty}⚡ 扫描参数未保存{/if}
            {#if scanDirty && haeDirty} · {/if}
            {#if haeDirty}📜 HaE 未保存{/if}
          </span>
        {/if}
        <button
          type="button"
          class="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500"
          onclick={toggleTheme}
          title="切换主题"
          aria-label="切换主题"
        >
          {#if isDark}🌙{:else}☀️{/if}
        </button>
      </div>
    </div>
  </header>

  <div class="max-w-5xl mx-auto px-5 py-6 lg:flex lg:gap-6">
    <!-- 左侧目录（窄宽变顶部横向 chips） -->
    <nav class="lg:w-48 lg:shrink-0 mb-4 lg:mb-0" aria-label="设置分区">
      <div class="flex lg:flex-col gap-1 overflow-x-auto lg:overflow-visible lg:sticky lg:top-20">
        {#each SECTIONS as s (s.id)}
          <button
            type="button"
            class="shrink-0 lg:shrink flex items-center gap-2 px-3 py-2 rounded-lg text-sm whitespace-nowrap transition-colors {activeSection === s.id
              ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 font-semibold'
              : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'}"
            aria-current={activeSection === s.id ? 'true' : undefined}
            onclick={() => go(s.id)}
          >
            <span aria-hidden="true">{s.icon}</span>
            <span>{s.label}</span>
          </button>
        {/each}
      </div>
    </nav>

    <!-- 右侧分区内容 -->
    <main class="flex-1 min-w-0 space-y-6">
      <!-- 常规 -->
      <section id="general" class="card p-4 space-y-3 scroll-mt-20">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-semibold">⚙️ 常规</h2>
          <span class="text-xs text-gray-400">即时保存</span>
        </div>
        {#if prefs}
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
        {/if}
      </section>

      <!-- 扫描与限流 -->
      <section id="scan" class="card p-4 space-y-3 scroll-mt-20">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-semibold">⚡ 扫描与限流</h2>
          <span class="text-xs text-gray-400">修改后点保存 · background 侧实时生效</span>
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
          <button type="button" class="btn btn-sm btn-primary" onclick={saveScanSettings} disabled={!scanDirty}>保存</button>
          <button type="button" class="btn btn-sm" onclick={resetScanSettings}>恢复默认</button>
          {#if scanDirty}<span class="text-xs text-amber-500 self-center">未保存的修改</span>{/if}
        </div>
      </section>

      <!-- API 与远程数据 -->
      <section id="api" class="space-y-3 scroll-mt-20">
        <div class="card p-4 space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="text-sm font-semibold">🔑 API 密钥</h2>
            <span class="text-xs text-gray-400">手动保存</span>
          </div>
          <div>
            <label class="text-xs text-gray-500" for="zy-key">ZoomEye API Key</label>
            <div class="flex gap-1 mt-1">
              <input id="zy-key" class="input flex-1 text-sm font-mono" type="password" placeholder="ZoomEye API KEY" bind:value={apiKey} />
              <button type="button" class="btn btn-sm btn-primary" onclick={saveApiKey}>保存</button>
              <button type="button" class="btn btn-sm" onclick={clearApiKey} disabled={!apiKey}>清除</button>
            </div>
            <p class="text-xs text-gray-400 mt-1">用于「资产测绘」面板。密钥仅本地存储，不上传任何服务器。</p>
          </div>
        </div>

        {#if prefs}
          <div class="card p-4 space-y-3">
            <div class="flex items-center justify-between">
              <h2 class="text-sm font-semibold">☁️ 远程 Payload</h2>
              {#if prefs.remotePayloads}
                <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">
                  已缓存{prefs.remotePayloads.version ? ` v${prefs.remotePayloads.version}` : ''}
                </span>
              {:else}
                <span class="text-xs text-gray-400">手动保存</span>
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
              <button type="button" class="btn btn-sm" onclick={saveRemoteUrl}>保存 URL</button>
            </div>
            <div class="flex gap-1 flex-wrap">
              <button type="button" class="btn btn-sm btn-primary" onclick={fetchRemote} disabled={remoteFetching || !prefs.payloadRemoteUrl}>
                {remoteFetching ? '拉取中...' : '⬇ 拉取并缓存'}
              </button>
              <button type="button" class="btn btn-sm" onclick={clearRemote} disabled={!prefs.remotePayloads}>清除缓存</button>
            </div>
            {#if prefs.remotePayloads?.fetchedAt}
              <div class="text-[10px] text-gray-400">
                上次拉取: {new Date(prefs.remotePayloads.fetchedAt).toLocaleString('zh-CN')} ·
                {Object.keys(prefs.remotePayloads.payloads || {}).length} 类载荷
              </div>
            {/if}
          </div>
        {/if}
      </section>

      <!-- HaE 规则 -->
      <section id="hae" class="card p-4 space-y-3 scroll-mt-20">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-semibold">📜 HaE 规则管理</h2>
          <span class="text-xs text-gray-400">修改后保存并生效</span>
        </div>
        <div class="flex items-center gap-1 flex-wrap">
          <button type="button" class="btn btn-xs" onclick={loadDefaultHae} title="载入默认规则到编辑区">载入默认</button>
          <label class="btn btn-xs cursor-pointer" title="从 YAML 文件导入">
            导入
            <input type="file" accept=".yaml,.yml,.txt" class="hidden" onchange={importHae} />
          </label>
          <button type="button" class="btn btn-xs" onclick={exportHae}>导出</button>
          <button type="button" class="btn btn-xs text-red-500" onclick={clearHae}>清空自定义</button>
        </div>
        <p class="text-xs text-gray-400">YAML 格式，自定义规则追加到内置默认规则之后，供「信息收集」面板使用。字段：group / rules[]（每条含 name, f_regex, s_regex, format, color, sensitive）。保存时自动校验正则合法性。</p>
        <textarea
          class="input font-mono text-xs w-full"
          rows="10"
          placeholder="# 示例：&#10;- group: 自定义规则&#10;  rules:&#10;    - name: 内网IP&#10;      f_regex: '(?:10\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.|192\\.168\\.)\\d&#123;1,3&#125;'&#10;      format: '&#123;0&#125;'&#10;      color: orange&#10;      sensitive: false"
          bind:value={haeText}
          oninput={() => (haeDirty = true)}
        ></textarea>
        <div class="flex items-center gap-2">
          <button type="button" class="btn btn-sm btn-primary" onclick={saveHae} disabled={!haeLoaded}>保存并生效</button>
          {#if haeDirty}<span class="text-xs text-amber-500">未保存的修改</span>{/if}
        </div>
      </section>

      <!-- 工具与导航 -->
      <section id="nav" class="space-y-3 scroll-mt-20">
        <div class="card p-4 space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="text-sm font-semibold">🧭 面板排序与显示</h2>
            <span class="text-xs text-gray-400">实时生效</span>
          </div>
          <p class="text-xs text-gray-400 -mt-1">调整侧栏/弹窗中面板的显示顺序与可见性。隐藏的面板不出现在工具栏与搜索结果。</p>
          <div class="space-y-0.5 max-h-72 overflow-y-auto">
            {#each orderedPanels as p, i (p.id)}
              <div class="flex items-center gap-2 text-xs py-1 px-1 rounded hover:bg-gray-50 dark:hover:bg-gray-800">
                <input
                  type="checkbox"
                  checked={!layout.hidden.includes(p.id)}
                  onchange={() => togglePanelVisible(p.id)}
                  class="accent-blue-500 shrink-0"
                  aria-label="显示 {p.label}"
                />
                <span class="text-base w-5 text-center">{p.icon}</span>
                <span class="flex-1 truncate">{p.label}</span>
                <span class="text-gray-400 text-[10px]">{p.category}</span>
                <button type="button" class="btn btn-xs px-1.5" disabled={i === 0} onclick={() => movePanel(i, -1)} title="上移" aria-label="上移 {p.label}">↑</button>
                <button type="button" class="btn btn-xs px-1.5" disabled={i === orderedPanels.length - 1} onclick={() => movePanel(i, 1)} title="下移" aria-label="下移 {p.label}">↓</button>
              </div>
            {/each}
          </div>
          <button type="button" class="btn btn-xs" onclick={resetLayout}>恢复默认</button>
        </div>

        {#if prefs}
          <div class="card p-4 space-y-3">
            <div class="flex items-center justify-between">
              <h2 class="text-sm font-semibold">🚫 采集过滤</h2>
              <span class="text-xs text-gray-400">保存后生效</span>
            </div>
            <p class="text-xs text-gray-400 -mt-1">每行一个域名，匹配的域名在采集时自动过滤。支持 <code class="text-[10px]">.example.com</code> 后缀（含子域）。</p>
            <textarea
              class="input w-full text-xs font-mono"
              rows="4"
              placeholder={"例如：\n.google.com\n.cnzz.com\ndoubleclick.net"}
              bind:value={excludeText}
            ></textarea>
            <div class="flex gap-1">
              <button type="button" class="btn btn-sm btn-primary" onclick={saveExcludeList}>保存排除列表</button>
            </div>
          </div>
        {/if}
      </section>

      <!-- 历史与存储 -->
      <section id="data" class="space-y-3 scroll-mt-20">
        <div class="card p-4 space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="text-sm font-semibold">📜 扫描历史</h2>
            <button type="button" class="btn btn-sm" onclick={clearHistory} disabled={history.length === 0}>清空全部</button>
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
        </div>

        <div class="card p-4 space-y-3">
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
                  <button type="button" class="btn btn-sm text-xs" onclick={() => clearStorageKey(item.key, item.label)}>清除</button>
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-xs text-gray-400">暂无已存储数据。</p>
          {/if}
        </div>
      </section>

      <!-- 备份与恢复 -->
      <section id="backup" class="card p-4 space-y-3 scroll-mt-20">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-semibold">📦 备份与恢复</h2>
          <span class="text-xs text-gray-400">字段白名单 · 手动操作</span>
        </div>
        <p class="text-xs text-gray-400 -mt-1">默认排除 API Key、伪装状态等敏感配置与临时状态；按字段白名单导出/导入，schemaVersion=<span class="font-mono">1</span>。</p>

        <!-- 导出 -->
        <div class="space-y-2 p-3 rounded-lg bg-gray-50 dark:bg-gray-800/40 border border-gray-200/60 dark:border-gray-700/40">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-gray-600 dark:text-gray-300">导出</span>
            {#if exportPreview}
              <span class="text-[10px] text-gray-400">{exportPreview.keys} 项 · {formatBytes(exportPreview.bytes)}</span>
            {/if}
          </div>
          <label class="flex items-start gap-2 text-xs cursor-pointer">
            <input type="checkbox" bind:checked={includeSecrets} class="accent-blue-500 mt-0.5" />
            <span>
              包含敏感配置（API Key / 伪装状态）
              {#if includeSecrets}<span class="text-red-500 block">⚠️ 明文存储，请妥善保管</span>{/if}
            </span>
          </label>
          <button type="button" class="btn btn-sm btn-primary" onclick={exportAllData}>⬇ 导出备份</button>
        </div>

        <!-- 导入 -->
        <div class="space-y-2 p-3 rounded-lg bg-gray-50 dark:bg-gray-800/40 border border-gray-200/60 dark:border-gray-700/40">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-gray-600 dark:text-gray-300">导入</span>
            <button type="button" class="btn btn-xs" onclick={() => importInput?.click()}>选择备份文件…</button>
            <input
              bind:this={importInput}
              type="file"
              accept="application/json"
              class="hidden"
              onchange={(e) => {
                const f = (e.currentTarget as HTMLInputElement).files?.[0];
                if (f) pickImport(f);
                (e.currentTarget as HTMLInputElement).value = '';
              }}
            />
          </div>

          {#if pendingImport}
            <div class="space-y-2 text-xs">
              {#if pendingImport.legacy}
                <p class="text-amber-500">旧格式备份，已按白名单过滤后解析。</p>
              {/if}
              <div class="text-gray-500 dark:text-gray-400">
                将导入类别：
                {#each pendingImport.summary.categories as c}
                  <span class="inline-block mr-2">{c.name}({c.count})</span>
                {/each}
                · 共 {pendingImport.summary.totalKeys} 项 · {formatBytes(pendingImport.summary.totalBytes)}
              </div>
              {#if pendingImport.summary.hasSecrets}
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" bind:checked={importIncludeSecrets} class="accent-blue-500" />
                  导入敏感配置（覆盖本机 API Key / 伪装状态）
                </label>
              {/if}
              <label class="flex items-center gap-2 cursor-pointer">
                <span>冲突策略：</span>
                <select bind:value={importMode} class="input py-0.5 text-xs w-auto">
                  <option value="merge">合并（保留本机其他项）</option>
                  <option value="overwrite">覆盖（先清偏好/规则/历史再写入）</option>
                </select>
              </label>
              {#if pendingImport.unknownKeys.length}
                <p class="text-gray-400">未知键（拒绝导入）：{pendingImport.unknownKeys.join(', ')}</p>
              {/if}
              <div class="flex gap-1 pt-1">
                <button type="button" class="btn btn-sm btn-primary" onclick={confirmImport}>确认导入</button>
                <button type="button" class="btn btn-sm" onclick={cancelImport}>取消</button>
              </div>
            </div>
          {/if}
        </div>

        <div class="flex flex-wrap gap-1 pt-1 border-t border-gray-100 dark:border-gray-700">
          <button type="button" class="btn btn-sm" onclick={resetAllPrefs}>恢复通用偏好默认</button>
          <button type="button" class="btn btn-sm btn-danger ml-auto" onclick={clearAllData}>⚠ 清空全部数据</button>
        </div>
      </section>

      <!-- 关于 -->
      <section id="about" class="card p-4 space-y-2 text-xs text-gray-500 scroll-mt-20">
        <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300">ℹ️ 关于</h2>
        <p>灵眸 (VulnKit) v{version} — 基于 WXT + Svelte 5 + TypeScript 的 Manifest V3 渗透测试扩展。</p>
        <p class="text-yellow-600 dark:text-yellow-500">⚠️ 仅用于授权的安全测试。测试前请确认目标在 SRC 授权范围内，验证即止，不得越界、破坏数据或获取个人信息。</p>
      </section>
    </main>
  </div>
</div>

<ConfirmDialog />
