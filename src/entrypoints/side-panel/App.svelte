<script lang="ts">
  import { themeStore, activePanelStore } from '@/stores/ui';
  import Sidebar from '@/components/layout/Sidebar.svelte';
  import PanelHeader from '@/components/layout/PanelHeader.svelte';
  import StatusBar from '@/components/layout/StatusBar.svelte';
  import Toast from '@/components/ui/Toast.svelte';
  import { panels } from '@/panels';

  // 当前活跃面板（订阅 store）
  let activePanel = $state('encoding');
  activePanelStore.subscribe(v => { activePanel = v; });

  // 查找当前面板配置
  let currentPanel = $derived(panels.find(p => p.id === activePanel));

  let isDark = $state(false);
  themeStore.subscribe(v => { isDark = v; });

  // Popup 快捷入口跳转：popup 写入 pendingPanel，此处消费并切到对应面板
  $effect(() => {
    browser.storage.local.get('pendingPanel').then((res) => {
      const target = res?.pendingPanel as string | undefined;
      if (target && panels.some((p) => p.id === target)) {
        activePanelStore.set(target);
      }
      if (target) {
        browser.storage.local.remove('pendingPanel');
      }
    });
  });

  function handlePanelSelect(id: string) {
    activePanelStore.set(id);
  }

  function toggleTheme() {
    themeStore.toggle();
  }

  function openOptions() {
    browser.runtime.openOptionsPage();
  }
</script>

<div class="flex flex-col h-full">
  <!-- Header -->
  <header class="flex items-center justify-between px-3 py-2 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shrink-0">
    <div class="flex items-center gap-2">
      <span class="text-base font-bold text-primary">灵眸</span>
      <span class="text-xs text-gray-400">v6.0</span>
    </div>
    <div class="flex items-center gap-1">
      <button onclick={toggleTheme} class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400" title="切换主题">
        {#if isDark}
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
        {:else}
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
        {/if}
      </button>
      <button onclick={openOptions} class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400" title="设置">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
      </button>
    </div>
  </header>

  <!-- Main Content -->
  <div class="flex flex-1 overflow-hidden">
    <!-- Sidebar -->
    <Sidebar activePanel={activePanel} onselect={handlePanelSelect} />

    <!-- Panel Area -->
    <main class="flex-1 flex flex-col overflow-hidden">
      {#if currentPanel}
        <PanelHeader title={currentPanel.label} icon={currentPanel.icon} category={currentPanel.category} />
        <div class="flex-1 overflow-y-auto p-3">
          {#if currentPanel.component}
            {@const Panel = currentPanel.component}
            <Panel />
          {/if}
        </div>
      {:else}
        <div class="flex-1 flex items-center justify-center text-gray-400">
          <div class="text-center">
            <div class="text-4xl mb-2">🛡️</div>
            <div>选择一个工具开始</div>
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
