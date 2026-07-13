<script lang="ts">
  import { themeStore, activePanelStore, autoRunStore } from '@/stores/ui';
  import Sidebar from '@/components/layout/Sidebar.svelte';
  import PanelHeader from '@/components/layout/PanelHeader.svelte';
  import StatusBar from '@/components/layout/StatusBar.svelte';
  import Toast from '@/components/ui/Toast.svelte';
  import PanelLoadState from '@/components/feedback/PanelLoadState.svelte';
  import PanelErrorState from '@/components/feedback/PanelErrorState.svelte';
  import { panels } from '@/panels';
  import { panelLayoutStore, applyLayout } from '@/stores/panel-layout';
  import { getActiveTab } from '@/lib/core/tabs';
  import {
    claimPendingAction,
    migrateLegacyPending,
    PENDING_ACTION_STORAGE_KEY,
  } from '@/lib/navigation/pending-actions';
  import { getAppVersion } from '@/lib/core/app-version';
  import { recentPanelsStore } from '@/stores/recent-panels';

  // 当前活跃面板（$store 自动订阅/取消）
  let activePanel = $derived($activePanelStore);

  // 版本号统一来源（对齐 §7.6）
  let version = $derived(getAppVersion());

  // 可见面板（应用排序 + 隐藏过滤）— Sidebar / 快捷键 / pending 共用同一导航数据源（§3.2）
  let visiblePanels = $derived(applyLayout(panels, $panelLayoutStore));
  let visibleIds = $derived(visiblePanels.map(p => p.id));

  // 统一切换入口：记录上一面板（供加载失败时返回），并经 store 落地
  let prevPanel = $state<string | null>(null);
  function setActivePanel(id: string) {
    if (id === activePanel) return;
    prevPanel = activePanel;
    activePanelStore.set(id);
    recentPanelsStore.record(id); // 记录最近使用（§4.1）
  }

  // 当前面板必须来自可见列表（§3.2）：无效时回退到第一个可见面板。
  // 覆盖「初始面板被隐藏 / 隐藏当前面板 / pending 指向隐藏面板」三种场景。
  $effect(() => {
    if (visibleIds.length === 0) return;
    if (!visibleIds.includes(activePanel)) {
      activePanelStore.set(visibleIds[0]);
    }
  });

  let currentPanel = $derived(visiblePanels.find(p => p.id === activePanel));

  let isDark = $derived($themeStore);

  // —— pending action 消费（§3.1）——
  // 仅认领属于当前 active tab 的 pending；不匹配则保留，避免多 tab 串台与误消费。
  async function consumePending() {
    const tab = await getActiveTab();
    if (!tab?.id) return;
    const action = await claimPendingAction(tab.id);
    if (!action) return;
    // 切到目标面板（若指向隐藏面板，上方 effect 会纠正到第一个可见面板）
    setActivePanel(action.panel);
    if (action.mode === 'autorun') {
      autoRunStore.fire({ panel: action.panel, url: action.url, nonce: action.nonce });
    }
  }

  $effect(() => {
    migrateLegacyPending(); // 清理旧版无 tabId 的全局 pending，避免幽灵消费
    consumePending();
    const listener = (changes: Record<string, any>, area: string) => {
      if (area !== 'local') return;
      if (changes[PENDING_ACTION_STORAGE_KEY]) consumePending();
    };
    browser.storage.onChanged.addListener(listener);
    return () => browser.storage.onChanged.removeListener(listener);
  });

  function handlePanelSelect(id: string) {
    setActivePanel(id);
  }

  function toggleTheme() {
    themeStore.toggle();
  }

  function openOptions() {
    browser.runtime.openOptionsPage();
  }

  // —— 动态加载重试（§3.3）——
  // loadNonce 变化触发 {#key} 重新求值 {#await}，重新调用 loader。
  let loadNonce = $state(0);
  function retryLoad() {
    loadNonce++;
  }

  // —— 响应式折叠（§4.1.5）：窄宽自动图标栏，用户可手动覆盖 ——
  let narrow = $state(false);
  let manualIconMode = $state<boolean | null>(null); // null=跟随宽度
  let iconMode = $derived(manualIconMode ?? narrow);
  let rootEl: HTMLElement | undefined = $state();
  function toggleIconMode() {
    manualIconMode = !iconMode;
  }
  $effect(() => {
    if (!rootEl) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width ?? 0;
      narrow = w < 520;
    });
    ro.observe(rootEl);
    return () => ro.disconnect();
  });

  // 键盘快捷键：Alt+1~8 切换到前 8 个可见面板
  $effect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const n = parseInt(e.key, 10);
      if (!n || n < 1 || n > 8) return;
      const target = visiblePanels[n - 1];
      if (target) {
        e.preventDefault();
        setActivePanel(target.id);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  });
</script>

<div bind:this={rootEl} class="flex flex-col h-full bg-gray-50 dark:bg-slate-900">
  <!-- Header -->
  <header class="flex items-center justify-between px-4 py-2.5 bg-white/80 dark:bg-gray-800/60 border-b border-gray-200/50 dark:border-gray-700/30 shrink-0 vk-glass shadow-sm">
    <div class="flex items-center gap-2.5">
      <div class="w-7 h-7 rounded-lg vk-brand-bg flex items-center justify-center text-white text-xs font-bold shadow-md shadow-blue-500/30">灵</div>
      <span class="text-base font-bold vk-brand-gradient tracking-tight">灵眸</span>
      <span class="text-[10px] text-gray-400 font-mono px-1.5 py-0.5 rounded-md bg-gray-100/80 dark:bg-gray-700/50 font-medium">v{version}</span>
    </div>
    <div class="flex items-center gap-1">
      <button type="button" onclick={toggleTheme} class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700/50 text-gray-500 dark:text-gray-400 transition-all duration-200 hover:text-gray-700 dark:hover:text-gray-200" title="切换主题" aria-label="切换主题">
        {#if isDark}
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
        {:else}
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
        {/if}
      </button>
      <button type="button" onclick={openOptions} class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700/50 text-gray-500 dark:text-gray-400 transition-all duration-200 hover:text-gray-700 dark:hover:text-gray-200" title="设置" aria-label="打开设置">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
      </button>
    </div>
  </header>

  <!-- Main Content -->
  <div class="flex flex-1 overflow-hidden">
    <!-- Sidebar -->
    <Sidebar activePanel={activePanel} onselect={handlePanelSelect} {iconMode} onToggleIconMode={toggleIconMode} />

    <!-- Panel Area -->
    <main class="flex-1 flex flex-col overflow-hidden">
      {#if currentPanel}
        <PanelHeader
          title={currentPanel.label}
          icon={currentPanel.icon}
          category={currentPanel.category}
          categoryLabel={currentPanel.categoryLabel}
          catColor={currentPanel.catColor}
        />
        <div class="flex-1 overflow-y-auto p-3.5">
          {#key `${activePanel}-${loadNonce}`}
            <div class="vk-fade-in">
              {#await currentPanel.load()}
                <PanelLoadState label={currentPanel.label} icon={currentPanel.icon} />
              {:then module}
                {@const Panel = module.default}
                <Panel />
              {:catch err}
                <PanelErrorState
                  label={currentPanel.label}
                  error={err}
                  onRetry={retryLoad}
                  onBack={prevPanel ? () => setActivePanel(prevPanel!) : undefined}
                />
              {/await}
            </div>
          {/key}
        </div>
      {:else if visibleIds.length === 0}
        <div class="flex-1 flex items-center justify-center text-gray-400 px-6 text-center">
          <div class="vk-fade-in">
            <div class="text-5xl mb-3">🛠️</div>
            <div class="text-sm">所有工具已被隐藏</div>
            <div class="text-xs mt-1 text-gray-400 dark:text-gray-500">前往「设置 → 工具与导航」恢复显示</div>
          </div>
        </div>
      {:else}
        <div class="flex-1 flex items-center justify-center text-gray-400">
          <div class="text-center vk-fade-in">
            <div class="text-5xl mb-3">🛡️</div>
            <div class="text-sm">选择一个工具开始</div>
          </div>
        </div>
      {/if}
    </main>
  </div>

  <!-- Status Bar -->
  <StatusBar />
</div>

<!-- Toast Container -->
<Toast />
