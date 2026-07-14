<script lang="ts">
  // Cookie 安全审计面板
  import { getActiveTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';

  // ---------- 类型 ----------

  type SevLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

  interface AuditIssue {
    severity: SevLevel;
    text: string;
    fix?: string;
  }

  interface AuditedCookie {
    name: string;
    value: string;
    domain: string;
    path: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string;
    expirationDate?: number;
    session: boolean;
    hostOnly?: boolean;
  }

  interface AuditResult {
    cookie: AuditedCookie;
    issues: AuditIssue[];
    maxSev: SevLevel;
    sevScore: number;
  }

  // ---------- 常量 ----------

  const SEV_ORDER: Record<SevLevel, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  const SEV_LABELS: Record<SevLevel, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  };

  const SENSITIVE_NAMES = [
    'session', 'token', 'auth', 'key', 'secret', 'admin',
    'user', 'pass', 'jwt', 'sid', 'uid', 'csrf', 'xsrf',
    'oauth', 'refresh', 'access', 'id_token', 'connect',
  ];

  const FIX_RECOMMENDATIONS: Record<string, string> = {
    '缺少 Secure 标志': '添加 Secure; 属性 — 仅通过 HTTPS 传输',
    '缺少 HttpOnly 标志': '添加 HttpOnly; 属性 — 防止 JavaScript 访问',
    'SameSite=None 但缺少 Secure': 'SameSite=None 必须搭配 Secure; 属性',
    'SameSite=None': '考虑改为 SameSite=Lax 或 SameSite=Strict 减少跨站风险',
    'SameSite 未设置': '显式设置 SameSite=Lax 或 SameSite=Strict',
    '敏感 Cookie': '敏感 Cookie 应同时设置 Secure + HttpOnly',
    '过期时间超过 1 年': '缩短有效期，敏感 Cookie 使用会话模式',
    '通配符域名': '限制 domain 到具体子域名而非通配符',
    '__Host- 前缀缺少 Secure': '__Host- 前缀要求 Secure 属性',
    '__Host- 前缀 Path 非 /': '__Host- 前缀要求 Path=/',
    '__Host- 前缀设置了 Domain': '__Host- 前缀禁止设置 Domain 属性',
    '__Secure- 前缀缺少 Secure': '__Secure- 前缀要求 Secure 属性',
  };

  // ---------- 审计纯函数 ----------

  function auditCookie(c: AuditedCookie, isHttpsSite: boolean): AuditResult {
    const issues: AuditIssue[] = [];
    const isHttps = c.secure || isHttpsSite;
    const nameLower = c.name.toLowerCase();

    // 规则 1: 未设 Secure 标志（HTTPS 域名下）
    if (!c.secure && isHttps) {
      issues.push({ severity: 'high', text: '缺少 Secure 标志 (HTTPS 域名下应启用)' });
    }

    // 规则 2: 未设 HttpOnly
    if (!c.httpOnly) {
      issues.push({ severity: 'medium', text: '缺少 HttpOnly 标志 (可通过 JS 访问)' });
    }

    // 规则 3: SameSite=None 但缺少 Secure
    if (c.sameSite === 'no_restriction' || c.sameSite === 'none') {
      if (!c.secure) {
        issues.push({ severity: 'critical', text: 'SameSite=None 但缺少 Secure (浏览器可能拒绝)' });
      } else {
        issues.push({ severity: 'medium', text: 'SameSite=None — 跨站请求携带 Cookie' });
      }
      // 规则 4: SameSite 未设置
    } else if (!c.sameSite || c.sameSite === 'unspecified') {
      issues.push({ severity: 'low', text: 'SameSite 未设置 (浏览器可能默认 Lax)' });
    }

    // 规则 5: 敏感 cookie 名匹配
    const isSensitive = SENSITIVE_NAMES.some(kw => nameLower.includes(kw));
    if (isSensitive) {
      if (!c.secure) {
        issues.push({ severity: 'critical', text: `敏感 Cookie (${c.name}) 未设置 Secure` });
      }
      if (!c.httpOnly) {
        issues.push({ severity: 'high', text: `敏感 Cookie (${c.name}) 未设置 HttpOnly` });
      }
    }

    // 规则 6: 过期时间超过 1 年
    if (c.expirationDate) {
      const now = Date.now() / 1000;
      const oneYear = 365 * 24 * 60 * 60;
      if (c.expirationDate - now > oneYear) {
        issues.push({
          severity: 'low',
          text: `过期时间超过 1 年 (${new Date(c.expirationDate * 1000).toLocaleDateString()})`,
        });
      }
      // 规则 7: 会话 Cookie
    } else if (c.session) {
      issues.push({ severity: 'info', text: '会话 Cookie (关闭浏览器后失效)' });
    }

    // 规则 8: Path 为 /
    if (c.path === '/') {
      issues.push({ severity: 'info', text: 'Path 为 / (全站可访问)' });
    }

    // 规则 9: 通配符域名
    if (c.domain && c.domain.startsWith('.')) {
      issues.push({ severity: 'low', text: `通配符域名 ${c.domain} (子域名共享)` });
    }

    // 规则 10: __Host- 前缀约束
    if (c.name.indexOf('__Host-') === 0) {
      if (!c.secure) {
        issues.push({ severity: 'high', text: '__Host- 前缀缺少 Secure' });
      }
      if (c.path !== '/') {
        issues.push({ severity: 'high', text: `__Host- 前缀 Path 非 / (当前: ${c.path || '/'})` });
      }
      if (c.domain) {
        issues.push({ severity: 'high', text: '__Host- 前缀设置了 Domain (应省略)' });
      }
      // 规则 11: __Secure- 前缀约束
    } else if (c.name.indexOf('__Secure-') === 0) {
      if (!c.secure) {
        issues.push({ severity: 'high', text: '__Secure- 前缀缺少 Secure' });
      }
    }

    // 为每条 issue 附加修复建议
    for (const issue of issues) {
      for (const [key, rec] of Object.entries(FIX_RECOMMENDATIONS)) {
        if (issue.text.includes(key)) {
          issue.fix = rec;
          break;
        }
      }
    }

    // 计算最高严重级别
    const sevScore = issues.reduce((max, i) => Math.max(max, SEV_ORDER[i.severity] || 0), 0);
    const maxSev = (Object.keys(SEV_ORDER).find(k => SEV_ORDER[k as SevLevel] === sevScore) || 'info') as SevLevel;

    return { cookie: c, issues, maxSev, sevScore };
  }

  // ---------- 状态 ----------

  let loading = $state(true);
  let results = $state<AuditResult[]>([]);
  let statusText = $state('');
  let filter = $state<'all' | SevLevel>('all');
  let searchText = $state('');

  // 派生：过滤 + 排序后的结果
  let displayResults = $derived(() => {
    let list = results;
    if (filter !== 'all') {
      list = list.filter(r => r.maxSev === filter);
    }
    if (searchText) {
      const q = searchText.toLowerCase();
      list = list.filter(r =>
        r.cookie.name.toLowerCase().includes(q) ||
        r.cookie.domain.toLowerCase().includes(q),
      );
    }
    // 按风险高→低排序
    return [...list].sort((a, b) => b.sevScore - a.sevScore);
  });

  // 派生：统计
  let stats = $derived(() => {
    const counts: Record<SevLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of results) {
      counts[r.maxSev]++;
    }
    return counts;
  });

  // ---------- 扫描历史映射 ----------

  function mapCookieAuditToFindings(audited: AuditResult[], pageUrl: string): ScanFinding[] {
    const findings: ScanFinding[] = [];
    for (const r of audited) {
      for (const issue of r.issues) {
        findings.push({
          title: `${r.cookie.name}: ${issue.text}`,
          severity: issue.severity,
          detail: issue.fix || issue.text,
          url: pageUrl,
        });
      }
    }
    return findings;
  }

  // ---------- 加载 ----------

  $effect(() => {
    loadCookies();
  });

  async function loadCookies() {
    loading = true;
    statusText = '正在审计 Cookie...';

    try {
      const tab = await getActiveTab();
      if (!tab?.url) {
        statusText = '无法获取当前页面';
        loading = false;
        return;
      }

      const url = new URL(tab.url);
      const hostname = url.hostname;
      const isHttpsSite = url.protocol === 'https:';
      const domain = hostname;

      // 获取 cookie
      const cookies = await browser.cookies.getAll({ domain });

      let targetCookies = cookies;

      // 如果精确域名无 cookie，尝试父域名
      if (!targetCookies || targetCookies.length === 0) {
        const parts = domain.split('.');
        if (parts.length > 2) {
          const baseDomain = parts.slice(-2).join('.');
          const parentCookies = await browser.cookies.getAll({ domain: baseDomain });
          if (parentCookies && parentCookies.length > 0) {
            targetCookies = parentCookies;
          }
        }
      }

      if (!targetCookies || targetCookies.length === 0) {
        statusText = '当前域名没有 Cookie';
        loading = false;
        return;
      }

      // 审计
      const audited: AuditResult[] = targetCookies.map(c => auditCookie(c, isHttpsSite));
      audited.sort((a, b) => b.sevScore - a.sevScore);

      results = audited;
      statusText = `审计完成: ${audited.length} 个 Cookie`;

      // 发布到扫描历史
      try {
        await scanHistoryStore.addScan({
          url: tab.url,
          module: 'cookie-audit',
          findings: mapCookieAuditToFindings(audited, tab.url),
        });
      } catch { /* store failure must not break scan */ }
    } catch (e: any) {
      statusText = `查询失败: ${e.message || e}`;
    } finally {
      loading = false;
    }
  }

  // ---------- 操作 ----------

  function copyValue(value: string) {
    navigator.clipboard.writeText(value).then(() => {
      toastStore.show('已复制 Cookie 值', 'success');
    });
  }

  async function deleteCookie(c: AuditedCookie) {
    try {
      await browser.cookies.remove({
        url: `${c.secure ? 'https' : 'http'}://${c.domain.replace(/^\./, '')}${c.path || '/'}`,
        name: c.name,
      });
      results = results.filter(r => r.cookie.name !== c.name || r.cookie.domain !== c.domain);
      toastStore.show(`已删除 ${c.name}`, 'success');
    } catch (e: any) {
      toastStore.show(`删除失败: ${e.message || e}`, 'error');
    }
  }

  // ===== Cookie 编辑/新增/批量导入（v5 spoof 能力）=====

  let editorOpen = $state(false);
  let editing = $state<AuditedCookie | null>(null);
  let form = $state({ name: '', value: '', domain: '', path: '/', secure: false, httpOnly: false, sameSite: 'unspecified' });
  let importText = $state('');
  let importOpen = $state(false);

  /** 获取当前活动标签页 URL（Cookie 操作上下文） */
  async function currentPageUrl(): Promise<string> {
    const tab = await getActiveTab();
    return tab?.url || '';
  }

  async function openAdd() {
    editing = null;
    const pageUrl = await currentPageUrl();
    let domain = '';
    try { domain = new URL(pageUrl).hostname; } catch { /* ignore */ }
    form = { name: '', value: '', domain, path: '/', secure: pageUrl.startsWith('https'), httpOnly: false, sameSite: 'lax' };
    editorOpen = true;
  }

  function openEdit(c: AuditedCookie) {
    editing = c;
    form = {
      name: c.name,
      value: c.value,
      domain: c.domain.replace(/^\./, ''),
      path: c.path || '/',
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite || 'lax',
    };
    editorOpen = true;
  }

  async function saveCookie() {
    if (!form.name || !form.domain) {
      toastStore.show('Cookie 名称和域名必填', 'warning');
      return;
    }
    try {
      const url = `${form.secure ? 'https' : 'http'}://${form.domain}${form.path || '/'}`;
      await browser.cookies.set({
        url,
        name: form.name,
        value: form.value,
        domain: form.domain.startsWith('.') ? form.domain : '.' + form.domain,
        path: form.path || '/',
        secure: form.secure,
        httpOnly: form.httpOnly,
        sameSite: form.sameSite as any,
      });
      toastStore.show(`${editing ? '已修改' : '已新增'} ${form.name}`, 'success');
      editorOpen = false;
      await loadCookies();
    } catch (e: any) {
      toastStore.show(`保存失败: ${e.message || e}`, 'error');
    }
  }

  /** 批量导入：解析 "name=value; name2=value2" 或每行一个 */
  async function importCookies() {
    const raw = importText.trim();
    if (!raw) {
      toastStore.show('请输入 Cookie 字符串', 'warning');
      return;
    }
    let domain = '';
    const pageUrl = await currentPageUrl();
    try { domain = new URL(pageUrl).hostname; } catch { /* ignore */ }
    const isHttps = pageUrl.startsWith('https');
    // 兼容分号分隔和换行分隔
    const pairs = raw.split(/[;\n]/).map(s => s.trim()).filter(Boolean);
    let ok = 0;
    for (const pair of pairs) {
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      try {
        await browser.cookies.set({
          url: `${isHttps ? 'https' : 'http'}://${domain}/`,
          name,
          value,
          domain: '.' + domain,
          path: '/',
          secure: isHttps,
          httpOnly: false,
          sameSite: 'lax' as any,
        });
        ok++;
      } catch { /* ignore single failure */ }
    }
    toastStore.show(`已导入 ${ok}/${pairs.length} 个 Cookie`, ok > 0 ? 'success' : 'error');
    importOpen = false;
    importText = '';
    if (ok > 0) await loadCookies();
  }

  /** 批量清除当前域名所有 Cookie */
  async function clearAll() {
    const pageUrl = await currentPageUrl();
    if (!confirm(`确认删除 ${pageUrl} 域名下所有 Cookie？此操作不可撤销。`)) return;
    try {
      let domain = '';
      try { domain = new URL(pageUrl).hostname; } catch { /* ignore */ }
      const all = await browser.cookies.getAll({ domain });
      let n = 0;
      for (const c of all) {
        try {
          await browser.cookies.remove({ url: `${c.secure ? 'https' : 'http'}://${domain}${c.path}`, name: c.name });
          n++;
        } catch { /* ignore */ }
      }
      toastStore.show(`已清除 ${n} 个 Cookie`, 'success');
      await loadCookies();
    } catch (e: any) {
      toastStore.show(`清除失败: ${e.message || e}`, 'error');
    }
  }

  function copyAuditReport() {
    if (results.length === 0) {
      toastStore.show('没有审计结果', 'warning');
      return;
    }
    const lines = results.map(r => {
      const c = r.cookie;
      let line = `${c.name}=[已隐藏]`;
      line += ` | Secure:${c.secure ? 'Y' : 'N'}`;
      line += ` HttpOnly:${c.httpOnly ? 'Y' : 'N'}`;
      line += ` SameSite:${c.sameSite || 'none'}`;
      if (r.issues.length > 0) {
        line += ` | Issues: ${r.issues.map(i => `[${i.severity.toUpperCase()}] ${i.text}`).join('; ')}`;
      }
      return line;
    });
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      toastStore.show(`已复制 ${results.length} 条审计结果`, 'success');
    });
  }

  function copyMarkdownReport() {
    if (results.length === 0) {
      toastStore.show('没有审计结果', 'warning');
      return;
    }
    const headers = ['Cookie', 'Secure', 'HttpOnly', 'SameSite', 'Issues'];
    const rows = results.map(r => {
      const c = r.cookie;
      const issuesText = r.issues.length > 0
        ? r.issues.map(i => `[${i.severity.toUpperCase()}] ${i.text}`).join('; ')
        : '-';
      return [c.name, c.secure ? 'Yes' : 'No', c.httpOnly ? 'Yes' : 'No', c.sameSite || 'none', issuesText];
    });
    const colWidths = headers.map((h, i) =>
      Math.max(h.length, ...rows.map(r => r[i].length)),
    );
    const pad = (s: string, w: number) => s.padEnd(w);
    const sep = colWidths.map(w => '-'.repeat(w)).join(' | ');
    const headerLine = headers.map((h, i) => pad(h, colWidths[i])).join(' | ');
    const dataLines = rows.map(r => r.map((cell, i) => pad(cell, colWidths[i])).join(' | '));
    const md = `${headerLine}\n${sep}\n${dataLines.join('\n')}`;
    navigator.clipboard.writeText(md).then(() => {
      toastStore.show('已复制 Markdown 表格', 'success');
    });
  }

  function exportJson() {
    if (results.length === 0) {
      toastStore.show('没有可导出的结果', 'warning');
      return;
    }
    const report = {
      timestamp: new Date().toISOString(),
      cookies: results.map(r => ({
        name: r.cookie.name,
        domain: r.cookie.domain,
        path: r.cookie.path,
        secure: r.cookie.secure,
        httpOnly: r.cookie.httpOnly,
        sameSite: r.cookie.sameSite,
        issues: r.issues,
      })),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cookie-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toastStore.show('已导出 JSON', 'success');
  }

  // ---------- 工具 ----------

  function sevBadgeClass(sev: SevLevel): string {
    const map: Record<SevLevel, string> = {
      critical: 'bg-red-600 text-white',
      high: 'bg-orange-500 text-white',
      medium: 'bg-yellow-400 text-gray-900',
      low: 'bg-blue-400 text-gray-900',
      info: 'bg-gray-300 text-gray-700 dark:bg-gray-600 dark:text-gray-200',
    };
    return map[sev] || map.info;
  }

  function sevDotClass(sev: SevLevel): string {
    const map: Record<SevLevel, string> = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-400',
      low: 'bg-blue-400',
      info: 'bg-gray-400',
    };
    return map[sev] || map.info;
  }

  function flagClass(ok: boolean): string {
    return ok
      ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
      : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
  }

  function truncate(s: string, max: number = 40): string {
    return s.length > max ? s.slice(0, max) + '...' : s;
  }

  const FILTER_OPTIONS: { id: 'all' | SevLevel; label: string }[] = [
    { id: 'all', label: '全部' },
    { id: 'critical', label: '严重' },
    { id: 'high', label: '高危' },
    { id: 'medium', label: '中危' },
    { id: 'low', label: '低危' },
    { id: 'info', label: '信息' },
  ];
</script>

<div class="space-y-3">
  <!-- 状态栏 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">Cookie 安全审计</div>
      <button class="btn btn-xs btn-ghost" onclick={loadCookies} disabled={loading}>
        {loading ? '扫描中...' : '刷新'}
      </button>
    </div>
    <div class="text-xs text-gray-500">{statusText || '就绪'}</div>

    {#if !loading && results.length > 0}
      <!-- 统计徽章 -->
      <div class="flex gap-2 flex-wrap">
        <span class="text-xs px-2 py-0.5 rounded-full bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-200">
          总数 {results.length}
        </span>
        {#each Object.entries(stats()) as [sev, count]}
          {#if count > 0}
            <span class="text-xs px-2 py-0.5 rounded-full {sevBadgeClass(sev as SevLevel)}">
              {SEV_LABELS[sev as SevLevel]} {count}
            </span>
          {/if}
        {/each}
      </div>

      <!-- 过滤 + 搜索 + 操作 -->
      <div class="flex gap-1 flex-wrap">
        {#each FILTER_OPTIONS as f}
          <button
            class="btn btn-xs {filter === f.id ? 'bg-primary text-white' : 'btn-ghost'}"
            onclick={() => (filter = f.id)}
          >
            {f.label}
          </button>
        {/each}
      </div>

      <div class="flex gap-1">
        <input
          class="input text-xs flex-1"
          placeholder="搜索 Cookie 名称 / 域名..."
          bind:value={searchText}
        />
      </div>

      <div class="flex gap-1 flex-wrap">
        <button class="btn btn-xs btn-soft" onclick={openAdd}>+ 新增</button>
        <button class="btn btn-xs btn-soft" onclick={() => (importOpen = true)}>批量导入</button>
        <button class="btn btn-xs text-red-500" onclick={clearAll}>清除全部</button>
        <button class="btn btn-xs" onclick={copyAuditReport}>复制报告</button>
        <button class="btn btn-xs" onclick={copyMarkdownReport}>复制 MD</button>
        <button class="btn btn-xs btn-primary" onclick={exportJson}>导出 JSON</button>
      </div>
    {/if}
  </div>

  <!-- 结果列表 -->
  {#if loading}
    <div class="text-xs text-gray-400 text-center py-4">正在审计...</div>
  {:else if results.length === 0}
    <div class="text-xs text-gray-400 text-center py-4">{statusText || '点击刷新开始审计'}</div>
  {:else}
    <div class="space-y-2">
      {#each displayResults() as r (r.cookie.name + r.cookie.domain)}
        <div class="card p-3 space-y-1">
          <!-- Cookie 头部：名称 + 域名 + 操作 -->
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-2 min-w-0">
              <span class="w-2 h-2 rounded-full shrink-0 {sevDotClass(r.maxSev)}"></span>
              <span class="text-sm font-medium truncate">{r.cookie.name}</span>
              <span class="text-xs text-gray-400 truncate">{r.cookie.domain}</span>
            </div>
            <div class="flex gap-1 shrink-0">
              <button class="btn btn-xs" title="复制值" onclick={() => copyValue(r.cookie.value)}>复制</button>
              <button class="btn btn-xs text-blue-500" title="编辑" onclick={() => openEdit(r.cookie)}>编辑</button>
              <button class="btn btn-xs text-red-500" title="删除" onclick={() => deleteCookie(r.cookie)}>删除</button>
            </div>
          </div>

          <!-- 值截断 -->
          <div class="text-xs font-mono text-gray-400 truncate">{truncate(r.cookie.value, 60)}</div>

          <!-- 标志徽章 -->
          <div class="flex gap-1 flex-wrap">
            <span class="text-xs px-1.5 py-0.5 rounded {flagClass(r.cookie.secure)}">
              Secure {r.cookie.secure ? '✓' : '✗'}
            </span>
            <span class="text-xs px-1.5 py-0.5 rounded {flagClass(r.cookie.httpOnly)}">
              HttpOnly {r.cookie.httpOnly ? '✓' : '✗'}
            </span>
            <span class="text-xs px-1.5 py-0.5 rounded {flagClass(!!(r.cookie.sameSite && r.cookie.sameSite !== 'unspecified'))}">
              SameSite: {r.cookie.sameSite || '未设置'}
            </span>
            <span class="text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400">
              Path: {r.cookie.path || '/'}
            </span>
          </div>

          <!-- 问题列表 -->
          {#if r.issues.length > 0}
            <div class="space-y-0.5 mt-1">
              {#each r.issues as issue}
                <div class="flex items-start gap-1.5 text-xs">
                  <span class="w-1.5 h-1.5 rounded-full mt-1 shrink-0 {sevDotClass(issue.severity)}"></span>
                  <div class="min-w-0">
                    <span class="{issue.severity === 'critical' || issue.severity === 'high' ? 'text-red-600 dark:text-red-400 font-medium' : 'text-gray-600 dark:text-gray-300'}">
                      {issue.text}
                    </span>
                    {#if issue.fix}
                      <div class="text-gray-400 dark:text-gray-500">{issue.fix}</div>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}

      {#if displayResults().length === 0 && results.length > 0}
        <div class="text-xs text-gray-400 text-center py-2">无匹配结果</div>
      {/if}
    </div>
  {/if}
</div>

<!-- Cookie 编辑/新增弹窗 -->
{#if editorOpen}
  <div class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true">
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-md p-4 space-y-3">
      <div class="flex items-center justify-between">
        <span class="text-sm font-bold">{editing ? '编辑 Cookie' : '新增 Cookie'}</span>
        <button class="text-gray-400 hover:text-gray-600" onclick={() => (editorOpen = false)}>✕</button>
      </div>
      <div class="space-y-2">
        <div>
          <label for="cookie-edit-name" class="text-xs text-gray-500">名称</label>
          <input id="cookie-edit-name" class="input text-xs" bind:value={form.name} placeholder="session_id" />
        </div>
        <div>
          <label for="cookie-edit-value" class="text-xs text-gray-500">值</label>
          <input id="cookie-edit-value" class="input text-xs font-mono" bind:value={form.value} placeholder="value" />
        </div>
        <div class="flex gap-2">
          <div class="flex-1">
            <label for="cookie-edit-domain" class="text-xs text-gray-500">域名</label>
            <input id="cookie-edit-domain" class="input text-xs" bind:value={form.domain} placeholder="example.com" />
          </div>
          <div class="flex-1">
            <label for="cookie-edit-path" class="text-xs text-gray-500">路径</label>
            <input id="cookie-edit-path" class="input text-xs" bind:value={form.path} placeholder="/" />
          </div>
        </div>
        <div class="flex gap-2 flex-wrap text-xs">
          <label class="flex items-center gap-1"><input type="checkbox" bind:checked={form.secure} class="accent-blue-500" /> Secure</label>
          <label class="flex items-center gap-1"><input type="checkbox" bind:checked={form.httpOnly} class="accent-blue-500" /> HttpOnly</label>
          <label class="flex items-center gap-1">SameSite:
            <select class="input text-xs w-24" bind:value={form.sameSite}>
              <option value="unspecified">默认</option>
              <option value="lax">Lax</option>
              <option value="strict">Strict</option>
              <option value="no_restriction">None</option>
            </select>
          </label>
        </div>
      </div>
      <div class="flex justify-end gap-2 pt-1">
        <button class="btn btn-sm btn-ghost" onclick={() => (editorOpen = false)}>取消</button>
        <button class="btn btn-sm btn-primary" onclick={saveCookie}>保存</button>
      </div>
    </div>
  </div>
{/if}

<!-- 批量导入弹窗 -->
{#if importOpen}
  <div class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true">
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-md p-4 space-y-3">
      <div class="flex items-center justify-between">
        <span class="text-sm font-bold">批量导入 Cookie</span>
        <button class="text-gray-400 hover:text-gray-600" onclick={() => (importOpen = false)}>✕</button>
      </div>
      <p class="text-xs text-gray-400">支持 <code class="font-mono">name=value; name2=value2</code> 格式，或每行一个。导入到当前域名。</p>
      <textarea class="input text-xs font-mono" rows="6" placeholder="session_id=abc123; token=eyJhbGc..." bind:value={importText}></textarea>
      <div class="flex justify-end gap-2">
        <button class="btn btn-sm btn-ghost" onclick={() => (importOpen = false)}>取消</button>
        <button class="btn btn-sm btn-primary" onclick={importCookies}>导入</button>
      </div>
    </div>
  </div>
{/if}
