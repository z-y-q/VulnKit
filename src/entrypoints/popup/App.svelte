<script lang="ts">
  // Popup 精简版 — 快捷入口，显示 6 个最常用功能
  const quickActions = [
    { id: 'encoding', label: '编码工具', icon: '🔤', color: '#e67e22' },
    { id: 'xssscan', label: 'XSS扫描', icon: '⚡', color: '#e74c3c' },
    { id: 'cors', label: 'CORS检测', icon: '🔗', color: '#e74c3c' },
    { id: 'headers', label: '安全头', icon: '🛡️', color: '#e74c3c' },
    { id: 'sniff', label: '网站嗅探', icon: '👃', color: '#e74c3c' },
    { id: 'report', label: '统一报告', icon: '📊', color: '#999' },
  ];

  async function openSidePanel() {
    await (browser.sidePanel as any).open();
    window.close();
  }

  async function openSidePanelToPanel(panelId: string) {
    await (browser.sidePanel as any).open();
    // Store the target panel to navigate to after side panel loads
    await browser.storage.local.set({ pendingPanel: panelId });
    window.close();
  }
</script>

<div class="w-64 p-3 bg-white dark:bg-gray-900">
  <!-- Header -->
  <div class="flex items-center justify-between mb-3">
    <div class="flex items-center gap-2">
      <span class="text-lg font-bold text-primary">灵眸</span>
      <span class="text-xs text-gray-400">v6.0</span>
    </div>
  </div>

  <!-- Open Full Panel Button -->
  <button
    class="w-full btn btn-primary mb-3 py-2 text-center"
    onclick={openSidePanel}
  >
    打开完整面板 →
  </button>

  <!-- Quick Actions -->
  <div class="space-y-1">
    {#each quickActions as action}
      <button
        class="w-full flex items-center gap-2 px-2 py-1.5 rounded text-sm hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
        onclick={() => openSidePanelToPanel(action.id)}
      >
        <span class="text-base">{action.icon}</span>
        <span>{action.label}</span>
      </button>
    {/each}
  </div>
</div>
