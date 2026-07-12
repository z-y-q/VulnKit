<script lang="ts">
  import { themeStore, activePanelStore } from '@/stores/ui';
  import Sidebar from '@/components/layout/Sidebar.svelte';
  import PanelHeader from '@/components/layout/PanelHeader.svelte';
  import StatusBar from '@/components/layout/StatusBar.svelte';
  import Toast from '@/components/ui/Toast.svelte';
  import { panels } from '@/panels';

  // 当前活跃面板（$store 自动订阅/取消）
  let activePanel = $derived($activePanelStore);

  // 查找当前面板配置
  let currentPanel = $derived(panels.find(p => p.id === activePanel));

  let isDark = $derived($themeStore);

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

  // 键盘快捷键：Alt+1~8 切换到前 8 个面板（按侧栏顺序）
  $effect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      // 仅处理 Alt+1..8
      const n = parseInt(e.key, 10);
      if (!n || n < 1 || n > 8) return;
      const target = panels[n - 1];
      if (target) {
        e.preventDefault();
        activePanelStore.set(target.id);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  });
</script>

<div class="flex flex-col h-full bg-gray-50 dark:bg-slate-900">
  <!-- Header -->
  <header class="flex items-center justify-between px-4 py-2.5 bg-white/80 dark:bg-gray-800/60 border-b border-gray-200/50 dark:border-gray-700/30 shrink-0 vk-glass shadow-sm">
    <div class="flex items-center gap-2.5">
      <div class="w-7 h-7 rounded-lg vk-brand-bg flex items-center justify-center text-white text-xs font-bold shadow-md shadow-blue-500/30">灵</div>
      <span class="text-base font-bold vk-brand-gradient tracking-tight">灵眸</span>
      <span class="text-[10px] text-gray-400 font-mono px-1.5 py-0.5 rounded-md bg-gray-100/80 dark:bg-gray-700/50 font-medium">v6.0</span>
    </div>
    <div class="flex items-center gap-1">
      <button onclick={toggleTheme} class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700/50 text-gray-500 dark:text-gray-400 transition-all duration-200 hover:text-gray-700 dark:hover:text-gray-200" title="切换主题">
        {#if isDark}
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
        {:else}
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
        {/if}
      </button>
      <button onclick={openOptions} class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700/50 text-gray-500 dark:text-gray-400 transition-all duration-200 hover:text-gray-700 dark:hover:text-gray-200" title="设置">
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
        <PanelHeader
          title={currentPanel.label}
          icon={currentPanel.icon}
          category={currentPanel.category}
          categoryLabel={currentPanel.categoryLabel}
          catColor={currentPanel.catColor}
        />
        <div class="flex-1 overflow-y-auto p-3.5">
          {#key activePanel}
            <div class="vk-fade-in">
              {#if currentPanel.component}
                {@const Panel = currentPanel.component}
                <Panel />
              {/if}
            </div>
          {/key}
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
