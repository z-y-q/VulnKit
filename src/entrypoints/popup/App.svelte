<script lang="ts">
  // Popup（阶段2重构：当前页状态 + 搜索 + 最近，对齐 §4.2）
  // 纯 scoped CSS，不依赖 UnoCSS，确保 Chrome 扩展 popup 渲染正确。
  // 暗色 class 钩子已留，批次 2c 接入 shared.css 变量后即跟随主题。
  import { panelMeta, panelMatches } from '@/panels/registry';
  import { panelLayoutStore, applyLayout } from '@/stores/panel-layout';
  import { recentPanelsStore } from '@/stores/recent-panels';
  import { getAppVersion } from '@/lib/core/app-version';
  import { setPendingAction } from '@/lib/navigation/pending-actions';
  import { themeStore } from '@/stores/ui';

  let version = $derived(getAppVersion());

  // 跟随全局主题（与 side-panel/options 共用 themeStore，§7.5）
  $effect(() => {
    document.documentElement.classList.toggle('dark', $themeStore);
  });

  // 失败反馈：URL 不支持 / sidePanel.open 失败时留 Popup 展示原因（§3.1）
  let errorMsg = $state('');

  // —— 当前页状态（§4.2.4）：展示域名与可执行状态 ——
  let pageStatus = $state<{ domain: string; ok: boolean; reason?: string } | null>(null);

  async function resolveTarget(): Promise<{ tabId: number; url: string } | { error: string }> {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== 'number') return { error: '未找到当前标签页' };
    const url = tab.url || '';
    if (!url) return { error: '当前页面不可用，请切换到普通网页' };
    try {
      const u = new URL(url);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { error: `不支持 ${u.protocol} 页面，请切换到普通网页` };
      }
    } catch {
      return { error: '当前页面 URL 无效' };
    }
    return { tabId: tab.id, url };
  }

  // 初始化：解析当前页状态
  $effect(() => {
    resolveTarget().then((r) => {
      if ('error' in r) {
        pageStatus = { domain: '', ok: false, reason: r.error };
      } else {
        try {
          pageStatus = { domain: new URL(r.url).hostname, ok: true };
        } catch {
          pageStatus = { domain: '', ok: false };
        }
      }
    });
  });

  let pageReady = $derived(pageStatus?.ok === true);

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
      activeCat === 'all' ? panelMeta : panelMeta.filter((p) => p.category === activeCat),
      layout,
    ),
  );

  // —— 搜索（§4.2.2：替代分页的主要发现方式） ——
  let query = $state('');
  let q = $derived(query.trim().toLowerCase());
  let searchResults = $derived(
    q ? applyLayout(panelMeta, layout).filter((p) => panelMatches(p, q)) : [],
  );

  // —— 最近使用（§4.2.1） ——
  let recent = $derived($recentPanelsStore);
  let recentVisible = $derived(
    recent
      .filter((id) => !layout.hidden.includes(id))
      .slice(0, 4)
      .map((id) => panelMeta.find((p) => p.id === id))
      .filter((p): p is (typeof panelMeta)[number] => !!p),
  );

  async function openSidePanel() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (typeof tab?.id === 'number') {
      try {
        await browser.sidePanel.open({ tabId: tab.id });
      } catch (e) {
        errorMsg = `无法打开侧栏：${(e as Error).message}`;
        return;
      }
    }
    window.close();
  }

  async function openSidePanelToPanel(panelId: string) {
    const r = await resolveTarget();
    if ('error' in r) {
      errorMsg = r.error;
      return;
    }
    errorMsg = '';
    await setPendingAction({ panel: panelId, tabId: r.tabId, url: r.url, mode: 'open', nonce: Date.now() });
    try {
      await browser.sidePanel.open({ tabId: r.tabId });
      window.close();
    } catch (e) {
      errorMsg = `任务已就绪，但无法自动打开侧栏：${(e as Error).message}。请点击下方「打开面板」。`;
    }
  }

  async function quickAction(panelId: string) {
    const r = await resolveTarget();
    if ('error' in r) {
      errorMsg = r.error;
      return;
    }
    errorMsg = '';
    await setPendingAction({ panel: panelId, tabId: r.tabId, url: r.url, mode: 'autorun', nonce: Date.now() });
    try {
      await browser.sidePanel.open({ tabId: r.tabId });
      window.close();
    } catch (e) {
      errorMsg = `任务已就绪，但无法自动打开侧栏：${(e as Error).message}。请点击下方「打开面板」。`;
    }
  }

  // 一键操作清单（高频，对当前页面即点即跑）
  const QUICK_ACTIONS: { id: string; label: string; icon: string; color: string }[] = [
    { id: 'cors', label: 'CORS', icon: '🔗', color: '#e74c3c' },
    { id: 'headers', label: '安全头', icon: '🛡️', color: '#27ae60' },
    { id: 'subdomain', label: '子域名', icon: '🌐', color: '#4A90E2' },
    { id: 'sniff', label: '嗅探', icon: '👃', color: '#9b59b6' },
    { id: 'waf', label: 'WAF', icon: '🔥', color: '#e67e22' },
    { id: 'links', label: '提取链接', icon: '📥', color: '#16a085' },
  ];

  function setCat(id: CatId) {
    activeCat = id;
  }

  // 搜索框 Enter：打开首个匹配
  function onSearchKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && searchResults.length) {
      e.preventDefault();
      openSidePanelToPanel(searchResults[0].id);
    }
  }

  // 面板角标：扫描类=S，编码=^（对齐 v5 Badge）
  function badgeFor(panel: (typeof panelMeta)[number]): string {
    if (panel.id === 'encoding') return '^';
    if (panel.category === 'scan') return 'S';
    return '';
  }
</script>

<div class="popup-root">
  <!-- Header -->
  <header class="popup-header">
    <div class="popup-brand">
      <div class="popup-logo">灵</div>
      <span class="popup-title">灵眸</span>
      <span class="popup-version">v{version}</span>
    </div>

    <!-- 当前页状态（§4.2.4） -->
    <div class="page-status {pageReady ? 'ok' : 'bad'}" title={pageStatus?.reason || ''}>
      <span class="status-dot"></span>
      {#if pageStatus?.ok}
        <span class="status-domain" title={pageStatus.domain}>{pageStatus.domain || '当前页面'}</span>
      {:else}
        <span class="status-domain">{pageStatus?.reason || '当前页面不可用'}</span>
      {/if}
    </div>

    <!-- Category Chips -->
    <div class="category-row">
      {#each categories as cat (cat.id)}
        <button
          type="button"
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

  {#if errorMsg}
    <div class="popup-error" role="alert">
      <span class="popup-error-icon" aria-hidden="true">⚠️</span>
      <span class="popup-error-text">{errorMsg}</span>
    </div>
  {/if}

  <!-- 搜索框（§4.2.2） -->
  <div class="search-bar">
    <svg class="search-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
    <label for="popup-search" class="sr-only">搜索工具</label>
    <input
      id="popup-search"
      type="search"
      placeholder="搜索工具…"
      autocomplete="off"
      spellcheck="false"
      bind:value={query}
      onkeydown={onSearchKeydown}
    />
  </div>

  <!-- 一键操作（对当前页面即点即跑） -->
  <div class="quick-bar">
    <div class="quick-title">⚡ 一键操作 · 当前页</div>
    <div class="quick-grid">
      {#each QUICK_ACTIONS as qa (qa.id)}
        <button
          type="button"
          class="quick-btn"
          disabled={!pageReady}
          onclick={() => quickAction(qa.id)}
          title={pageReady ? `对当前页面运行 ${qa.label}` : '请先切换到普通网页'}
        >
          <span class="quick-icon" style="color:{qa.color}">{qa.icon}</span>
          <span class="quick-label">{qa.label}</span>
        </button>
      {/each}
    </div>
  </div>

  <!-- 最近使用（非搜索态） -->
  {#if !q && recentVisible.length}
    <div class="recent-bar">
      <div class="quick-title">🕐 最近使用</div>
      <div class="recent-grid">
        {#each recentVisible as panel (panel.id)}
          <button type="button" class="recent-btn" onclick={() => openSidePanelToPanel(panel.id)} title={panel.label}>
            <span class="recent-icon">{panel.icon}</span>
            <span class="recent-label">{panel.label}</span>
          </button>
        {/each}
      </div>
    </div>
  {/if}

  <!-- 工具区：搜索结果 / 分类网格 -->
  <div class="popup-grid">
    {#if q}
      {#if searchResults.length}
        {#each searchResults as panel (panel.id)}
          <button
            type="button"
            class="tool-btn"
            onclick={() => openSidePanelToPanel(panel.id)}
            title={panel.label}
          >
            {#if badgeFor(panel)}<span class="tool-badge">{badgeFor(panel)}</span>{/if}
            <span class="tool-icon">{panel.icon}</span>
            <span class="tool-label">{panel.label}</span>
          </button>
        {/each}
      {:else}
        <div class="search-empty">
          <div class="search-empty-icon" aria-hidden="true">🔍</div>
          未找到匹配「{query}」的工具
        </div>
      {/if}
    {:else}
      {#each filteredPanels as panel (panel.id)}
        <button
          type="button"
          class="tool-btn"
          onclick={() => openSidePanelToPanel(panel.id)}
          title={panel.label}
        >
          {#if badgeFor(panel)}<span class="tool-badge">{badgeFor(panel)}</span>{/if}
          <span class="tool-icon">{panel.icon}</span>
          <span class="tool-label">{panel.label}</span>
        </button>
      {/each}
    {/if}
  </div>

  <!-- Footer -->
  <footer class="popup-footer">
    <span class="footer-count">共 {panelMeta.length} 个工具</span>
    <button type="button" class="open-panel-btn" onclick={openSidePanel}>打开面板 →</button>
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
    margin-bottom: 8px;
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
    margin-left: auto;
  }

  /* ===== 当前页状态 ===== */
  .page-status {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    margin-bottom: 8px;
    border-radius: 8px;
    font-size: 11px;
    background: #f5f7fa;
  }
  .page-status .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .page-status.ok { background: #f0f9f0; color: #2e7d32; }
  .page-status.ok .status-dot { background: #4CAF50; box-shadow: 0 0 6px #4CAF5080; }
  .page-status.bad { background: #fef2f2; color: #b91c1c; }
  .page-status.bad .status-dot { background: #ef4444; }
  .status-domain {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* ===== 错误提示条 ===== */
  .popup-error {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    margin: 8px 12px 0;
    padding: 8px 10px;
    background: #fef2f2;
    border: 1px solid #fecaca;
    border-radius: 8px;
    font-size: 11px;
    color: #b91c1c;
    line-height: 1.4;
    flex-shrink: 0;
  }
  .popup-error-icon { flex-shrink: 0; }
  .popup-error-text { flex: 1; }

  /* ===== 搜索框 ===== */
  .search-bar {
    position: relative;
    padding: 8px 12px 6px;
    flex-shrink: 0;
  }
  .search-icon {
    position: absolute;
    left: 20px;
    top: 50%;
    transform: translateY(-50%);
    width: 14px;
    height: 14px;
    color: #999;
    pointer-events: none;
  }
  .search-bar input {
    width: 100%;
    padding: 6px 10px 6px 30px;
    font-size: 12px;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    background: #f9f9f9;
    color: #333;
    outline: none;
    transition: all 0.15s ease;
  }
  .search-bar input:focus {
    border-color: #4A90E2;
    background: #fff;
    box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.15);
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
  .category-chip:hover { border-color: #bbb; background: #fafafa; }
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
  }

  /* ===== Quick Action Bar ===== */
  .quick-bar {
    padding: 6px 12px 6px;
    border-bottom: 1px solid #f0f0f0;
    flex-shrink: 0;
    background: linear-gradient(180deg, #f8fbff 0%, #fff 100%);
  }
  .quick-title {
    font-size: 10px;
    font-weight: 700;
    color: #888;
    letter-spacing: 0.3px;
    margin-bottom: 6px;
  }
  .quick-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 5px;
  }
  .quick-btn {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 7px 8px;
    border: 1px solid #e4ecf5;
    border-radius: 8px;
    background: #fff;
    cursor: pointer;
    transition: all 0.15s ease;
    text-align: left;
  }
  .quick-btn:hover:not(:disabled) {
    border-color: #4A90E2;
    background: #eef4fc;
    transform: translateY(-1px);
    box-shadow: 0 2px 6px rgba(74, 144, 226, 0.18);
  }
  .quick-btn:active:not(:disabled) { transform: translateY(0) scale(0.98); }
  .quick-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .quick-icon { font-size: 14px; line-height: 1; flex-shrink: 0; }
  .quick-label { font-size: 11px; font-weight: 600; color: #444; }

  /* ===== 最近使用 ===== */
  .recent-bar {
    padding: 6px 12px;
    border-bottom: 1px solid #f0f0f0;
    flex-shrink: 0;
  }
  .recent-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 5px;
  }
  .recent-btn {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 5px 8px;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
    background: #fafafa;
    cursor: pointer;
    transition: all 0.15s ease;
    text-align: left;
    overflow: hidden;
  }
  .recent-btn:hover { border-color: #4A90E2; background: #eef4fc; }
  .recent-icon { font-size: 13px; flex-shrink: 0; }
  .recent-label {
    font-size: 11px;
    color: #555;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* ===== Tool Grid ===== */
  .popup-grid {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 3px;
    padding: 8px 10px;
    overflow-y: auto;
    align-content: start;
  }
  .tool-btn {
    position: relative;
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
  .tool-btn:hover { background: #eef4fc; transform: scale(1.04); }
  .tool-btn:active { transform: scale(0.96); }
  .tool-icon { font-size: 18px; line-height: 1; transition: transform 0.15s ease; }
  .tool-btn:hover .tool-icon { transform: scale(1.12); }
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
  .tool-btn:hover .tool-label { color: #4A90E2; }
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

  .search-empty {
    grid-column: 1 / -1;
    text-align: center;
    font-size: 11px;
    color: #999;
    padding: 24px 12px;
  }
  .search-empty-icon { font-size: 22px; margin-bottom: 6px; }

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
  .footer-count { font-size: 10px; color: #999; }
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
  .open-panel-btn:hover { background: #357ABD; box-shadow: 0 2px 8px rgba(74, 144, 226, 0.4); }
  .open-panel-btn:active { transform: scale(0.97); }

  /* ===== 无障碍辅助 ===== */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  /* ===== Scrollbar ===== */
  .popup-grid::-webkit-scrollbar { width: 4px; }
  .popup-grid::-webkit-scrollbar-track { background: transparent; }
  .popup-grid::-webkit-scrollbar-thumb { background: #d0d0d0; border-radius: 2px; }

  /* ===== 暗色主题（最小覆盖，§7.5；完整 token 迁移留阶段 5） ===== */
  :global(.dark) .popup-root { background: var(--vk-bg); color: var(--vk-text); }
  :global(.dark) .popup-header { border-color: var(--vk-border); }
  :global(.dark) .popup-version { background: var(--vk-bg-sunken); color: var(--vk-text-muted); }
  :global(.dark) .page-status { background: var(--vk-bg-sunken); }
  :global(.dark) .page-status.ok { background: rgba(16, 185, 129, 0.12); color: #6ee7b7; }
  :global(.dark) .page-status.bad { background: rgba(239, 68, 68, 0.12); color: #fca5a5; }
  :global(.dark) .popup-error { background: rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.3); color: #fca5a5; }
  :global(.dark) .search-bar input { background: var(--vk-bg-soft); color: var(--vk-text); border-color: var(--vk-border); }
  :global(.dark) .search-icon { color: var(--vk-text-muted); }
  :global(.dark) .category-chip { background: var(--vk-bg); color: var(--vk-text-muted); border-color: var(--vk-border); }
  :global(.dark) .category-chip:hover { background: var(--vk-bg-sunken); }
  :global(.dark) .quick-bar { background: var(--vk-bg); border-color: var(--vk-border); }
  :global(.dark) .quick-title { color: var(--vk-text-muted); }
  :global(.dark) .quick-btn { background: var(--vk-bg); border-color: var(--vk-border); }
  :global(.dark) .quick-btn:hover:not(:disabled) { background: var(--vk-bg-sunken); }
  :global(.dark) .quick-label { color: var(--vk-text); }
  :global(.dark) .recent-bar { border-color: var(--vk-border); }
  :global(.dark) .recent-btn { background: var(--vk-bg-soft); border-color: var(--vk-border); }
  :global(.dark) .recent-btn:hover { background: var(--vk-bg-sunken); }
  :global(.dark) .recent-label { color: var(--vk-text); }
  :global(.dark) .tool-label { color: var(--vk-text-muted); }
  :global(.dark) .tool-btn:hover { background: var(--vk-bg-sunken); }
  :global(.dark) .popup-footer { background: var(--vk-bg-soft); border-color: var(--vk-border); }
  :global(.dark) .footer-count { color: var(--vk-text-muted); }
  :global(.dark) .popup-grid::-webkit-scrollbar-thumb { background: #475569; }
</style>
