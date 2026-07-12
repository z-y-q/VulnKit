<script lang="ts">
  // Popup — 灵眸 v6.0
  // 纯 scoped CSS，不依赖 UnoCSS，确保 Chrome 扩展 popup 渲染正确
  import { panelMeta } from '@/panels/registry';
  import { panelLayoutStore, applyLayout } from '@/stores/panel-layout';

  let layout = $derived($panelLayoutStore);

  const categories = [
    { id: 'all', label: '全部', color: '#4A90E2' },
    { id: 'recon', label: '侦察', color: '#4A90E2' },
    { id: 'scan', label: '扫描', color: '#e74c3c' },
    { id: 'exploit', label: '利用', color: '#e67e22' },
    { id: 'framework', label: '框架', color: '#27ae60' },
    { id: 'tools', label: '工具', color: '#9b59b6' },
    { id: 'report', label: '报告', color: '#999' },
  ] as const;

  type CatId = (typeof categories)[number]['id'];
  let activeCat = $state<CatId>('all');

  // 当前分类下显示的面板（应用布局：排序 + 过滤隐藏）
  let filteredPanels = $derived(
    applyLayout(
      activeCat === 'all'
        ? panelMeta
        : panelMeta.filter((p) => p.category === activeCat),
      layout,
    )
  );

  // 标签页分页（每页 16 个）
  const PAGE_SIZE = 16;
  let page = $state(0);
  let totalPages = $derived(Math.max(1, Math.ceil(filteredPanels.length / PAGE_SIZE)));

  // 分页后当前页的面板
  let pagedPanels = $derived(
    filteredPanels.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  );

  // 切换分类时重置分页
  $effect(() => {
    filteredPanels;
    page = 0;
  });

  async function openSidePanel() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      await browser.sidePanel.open({ tabId: tab.id });
    }
    window.close();
  }

  async function openSidePanelToPanel(panelId: string) {
    await browser.storage.local.set({ pendingPanel: panelId });
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      await browser.sidePanel.open({ tabId: tab.id });
    }
    window.close();
  }

  function setCat(id: CatId) {
    activeCat = id;
  }

  // 面板角标：扫描类=S，编码=^（对齐 v5 Badge）
  function badgeFor(panel: (typeof panelMeta)[number]): string {
    if (panel.id === 'encoding') return '^';
    if (panel.category === 'scan') return 'S';
    return '';
  }

  // Alt+Left/Right 翻页（对齐 v5）
  $effect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key === 'ArrowLeft' && page > 0) { e.preventDefault(); page--; }
      else if (e.key === 'ArrowRight' && page < totalPages - 1) { e.preventDefault(); page++; }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  });
</script>

<div class="popup-root">
  <!-- Header -->
  <header class="popup-header">
    <div class="popup-brand">
      <div class="popup-logo">灵</div>
      <span class="popup-title">灵眸</span>
      <span class="popup-version">v6.0</span>
    </div>

    <!-- Category Chips -->
    <div class="category-row">
      {#each categories as cat}
        <button
          class="category-chip {activeCat === cat.id ? 'active' : ''}"
          style={activeCat === cat.id ? `background:${cat.color};border-color:${cat.color}` : ''}
          onclick={() => setCat(cat.id)}
        >
          <span class="cat-dot" style="background:{activeCat === cat.id ? '#fff' : cat.color}"></span>
          {cat.label}
        </button>
      {/each}
    </div>
  </header>

  <!-- Tool Grid -->
  <div class="popup-grid">
    {#each pagedPanels as panel (panel.id)}
      <button
        class="tool-btn"
        onclick={() => openSidePanelToPanel(panel.id)}
        title={panel.label}
      >
        {#if badgeFor(panel)}<span class="tool-badge">{badgeFor(panel)}</span>{/if}
        <span class="tool-icon">{panel.icon}</span>
        <span class="tool-label">{panel.label}</span>
      </button>
    {/each}
  </div>

  <!-- Pagination -->
  {#if totalPages > 1}
    <div class="pagination">
      <button class="page-btn" disabled={page === 0} onclick={() => page--}>◀</button>
      <span class="page-info">{page + 1}/{totalPages}</span>
      <button class="page-btn" disabled={page >= totalPages - 1} onclick={() => page++}>▶</button>
    </div>
  {/if}

  <!-- Footer -->
  <footer class="popup-footer">
    <span class="footer-count">共 {panelMeta.length} 个工具</span>
    <button class="open-panel-btn" onclick={openSidePanel}>打开面板 →</button>
  </footer>
</div>

<style>
  /* ===== Popup 全局 ===== */
  .popup-root {
    width: 320px;
    display: flex;
    flex-direction: column;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif;
    font-size: 13px;
    color: #333;
    background: #fff;
    max-height: 560px;
    user-select: none;
  }

  /* ===== Header ===== */
  .popup-header {
    padding: 12px 14px 10px;
    flex-shrink: 0;
    border-bottom: 1px solid #f0f0f0;
  }

  .popup-brand {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
  }

  .popup-logo {
    width: 26px;
    height: 26px;
    border-radius: 8px;
    background: linear-gradient(135deg, #4A90E2, #357ABD);
    color: #fff;
    font-size: 12px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 6px rgba(74, 144, 226, 0.35);
  }

  .popup-title {
    font-size: 16px;
    font-weight: 700;
    background: linear-gradient(135deg, #4A90E2, #6dd5ed);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .popup-version {
    font-size: 10px;
    color: #999;
    font-family: 'SF Mono', Monaco, monospace;
    padding: 2px 6px;
    border-radius: 4px;
    background: #f5f5f5;
  }

  /* ===== Category Chips ===== */
  .category-row {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
  }

  .category-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 9px;
    border: 1px solid #e0e0e0;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 500;
    color: #666;
    background: #fff;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .category-chip:hover {
    border-color: #bbb;
    background: #fafafa;
  }

  .category-chip.active {
    color: #fff;
    border-color: transparent;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.12);
  }

  .cat-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    transition: background 0.15s ease;
  }

  /* ===== Tool Grid ===== */
  .popup-grid {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 3px;
    padding: 10px 10px;
    overflow-y: auto;
  }

  .tool-btn {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    padding: 8px 4px 6px;
    border: none;
    border-radius: 8px;
    background: transparent;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .tool-btn:hover {
    background: #eef4fc;
    transform: scale(1.04);
  }

  .tool-btn:active {
    transform: scale(0.96);
  }

  .tool-icon {
    font-size: 18px;
    line-height: 1;
    transition: transform 0.15s ease;
  }

  .tool-btn:hover .tool-icon {
    transform: scale(1.12);
  }

  .tool-label {
    font-size: 10px;
    color: #666;
    line-height: 1.2;
    text-align: center;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tool-btn:hover .tool-label {
    color: #4A90E2;
  }

  .tool-badge {
    position: absolute;
    top: 2px;
    right: 4px;
    font-size: 8px;
    font-weight: 700;
    color: #fff;
    background: #e74c3c;
    width: 11px;
    height: 11px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
  }

  .tool-btn {
    position: relative;
  }

  /* ===== Pagination ===== */
  .pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 6px 0;
    border-top: 1px solid #f5f5f5;
  }

  .page-btn {
    border: none;
    background: none;
    color: #999;
    font-size: 10px;
    cursor: pointer;
    padding: 2px 6px;
    border-radius: 4px;
    transition: all 0.15s;
  }

  .page-btn:hover:not(:disabled) {
    background: #f0f0f0;
    color: #4A90E2;
  }

  .page-btn:disabled {
    opacity: 0.3;
    cursor: default;
  }

  .page-info {
    font-size: 10px;
    color: #999;
    font-family: 'SF Mono', Monaco, monospace;
  }

  /* ===== Footer ===== */
  .popup-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 14px;
    border-top: 1px solid #f0f0f0;
    background: #fafafa;
    flex-shrink: 0;
  }

  .footer-count {
    font-size: 10px;
    color: #999;
  }

  .open-panel-btn {
    padding: 5px 12px;
    border: none;
    border-radius: 6px;
    background: #4A90E2;
    color: #fff;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
    box-shadow: 0 1px 4px rgba(74, 144, 226, 0.3);
  }

  .open-panel-btn:hover {
    background: #357ABD;
    box-shadow: 0 2px 8px rgba(74, 144, 226, 0.4);
  }

  .open-panel-btn:active {
    transform: scale(0.97);
  }

  /* ===== Scrollbar ===== */
  .popup-grid::-webkit-scrollbar {
    width: 4px;
  }
  .popup-grid::-webkit-scrollbar-track {
    background: transparent;
  }
  .popup-grid::-webkit-scrollbar-thumb {
    background: #d0d0d0;
    border-radius: 2px;
  }
</style>
