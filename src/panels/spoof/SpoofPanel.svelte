<script lang="ts">
  // 请求伪造面板
  // UA 伪造 + 请求头伪造（X-Forwarded-For / Referer / Client-IP / 自定义）+ Cookie 管理
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import uaPresets from '@/lib/data/spoof-ua-presets.json';

  type Tab = 'ua' | 'headers' | 'cookies';
  let tab = $state<Tab>('ua');

  // —— UA ——
  type UaCategory = 'mobile' | 'desktop' | 'brand' | 'custom';
  let uaCategory = $state<UaCategory>('mobile');
  let customUa = $state('');
  let uaActive = $state(false);

  const presets = uaPresets as Record<string, { label: string; value: string }[]>;

  function selectUa(value: string) {
    customUa = value;
  }

  async function applyUa() {
    if (!customUa.trim()) {
      toastStore.show('请选择或输入 User-Agent', 'warning');
      return;
    }
    const url = await getActiveTabUrl();
    if (!url) {
      toastStore.show('无法获取当前页面（需 http/https）', 'error');
      return;
    }
    const r = await sendMessage({ type: 'SPOOF_UA', url, userAgent: customUa.trim() });
    if (r.success) {
      uaActive = true;
      toastStore.show('UA 已应用，刷新页面生效', 'success');
    } else {
      toastStore.show(`应用失败: ${r.error}`, 'error');
    }
  }

  async function resetUa() {
    const r = await sendMessage({ type: 'RESET_SPOOF_UA' });
    if (r.success) {
      uaActive = false;
      toastStore.show('UA 已恢复', 'success');
    } else {
      toastStore.show(`恢复失败: ${r.error}`, 'error');
    }
  }

  // —— Headers ——
  let xff = $state('');
  let referer = $state('');
  let clientIp = $state('');
  let customHeaders = $state<{ name: string; value: string }[]>([]);
  let newHdrName = $state('');
  let newHdrValue = $state('');
  let headersActive = $state(false);

  function addCustomHeader() {
    if (!newHdrName.trim() || !newHdrValue.trim()) return;
    customHeaders = [...customHeaders, { name: newHdrName.trim(), value: newHdrValue.trim() }];
    newHdrName = '';
    newHdrValue = '';
  }

  function removeCustomHeader(i: number) {
    customHeaders = customHeaders.filter((_, idx) => idx !== i);
  }

  async function applyHeaders() {
    if (!xff && !referer && !clientIp && customHeaders.length === 0) {
      toastStore.show('请至少填写一项', 'warning');
      return;
    }
    const url = await getActiveTabUrl();
    if (!url) {
      toastStore.show('无法获取当前页面（需 http/https）', 'error');
      return;
    }
    const r = await sendMessage({
      type: 'SPOOF_HEADERS',
      url,
      headers: { xff, referer, clientIp, custom: customHeaders },
    });
    if (r.success) {
      headersActive = true;
      toastStore.show('请求头已应用，刷新页面生效', 'success');
    } else {
      toastStore.show(`应用失败: ${r.error}`, 'error');
    }
  }

  async function resetHeaders() {
    const r = await sendMessage({ type: 'RESET_SPOOF_HEADERS' });
    if (r.success) {
      headersActive = false;
      toastStore.show('请求头已恢复', 'success');
    } else {
      toastStore.show(`恢复失败: ${r.error}`, 'error');
    }
  }

  // —— Cookie 管理（v5 spoof cookie 能力）——
  type CookieRow = { name: string; value: string; domain: string; path: string; secure: boolean; httpOnly: boolean; sameSite: string };
  let cookieList = $state<CookieRow[]>([]);
  let cookieFilter = $state('');
  let cookieEditorOpen = $state(false);
  let editingCookieName = $state<string | null>(null);
  let cookieForm = $state<CookieRow>({ name: '', value: '', domain: '', path: '/', secure: false, httpOnly: false, sameSite: 'lax' });
  let cookieImportText = $state('');
  let cookieImportOpen = $state(false);

  async function currentDomain(): Promise<string> {
    const url = await getActiveTabUrl();
    try { return url ? new URL(url).hostname : ''; } catch { return ''; }
  }

  async function loadCookies() {
    const domain = await currentDomain();
    if (!domain) { toastStore.show('无法获取当前域名', 'error'); return; }
    try {
      const all = await browser.cookies.getAll({ domain });
      cookieList = all.map(c => ({
        name: c.name, value: c.value, domain: c.domain, path: c.path,
        secure: c.secure, httpOnly: c.httpOnly,
        sameSite: (c.sameSite || 'unspecified').toLowerCase(),
      }));
    } catch (e: any) {
      toastStore.show('读取 Cookie 失败: ' + (e.message || ''), 'error');
    }
  }

  let filteredCookies = $derived(
    cookieFilter ? cookieList.filter(c => c.name.toLowerCase().includes(cookieFilter.toLowerCase()) || c.value.toLowerCase().includes(cookieFilter.toLowerCase())) : cookieList,
  );

  function openAddCookie() {
    editingCookieName = null;
    cookieForm = { name: '', value: '', domain: '', path: '/', secure: false, httpOnly: false, sameSite: 'lax' };
    currentDomain().then(d => { cookieForm = { ...cookieForm, domain: d }; });
    cookieEditorOpen = true;
  }

  function openEditCookie(c: CookieRow) {
    editingCookieName = c.name;
    cookieForm = { ...c, domain: c.domain.replace(/^\./, '') };
    cookieEditorOpen = true;
  }

  async function saveCookieForm() {
    if (!cookieForm.name || !cookieForm.domain) { toastStore.show('名称和域名必填', 'warning'); return; }
    try {
      const url = `${cookieForm.secure ? 'https' : 'http'}://${cookieForm.domain}${cookieForm.path || '/'}`;
      await browser.cookies.set({
        url,
        name: cookieForm.name,
        value: cookieForm.value,
        domain: cookieForm.domain.startsWith('.') ? cookieForm.domain : '.' + cookieForm.domain,
        path: cookieForm.path || '/',
        secure: cookieForm.secure,
        httpOnly: cookieForm.httpOnly,
        sameSite: cookieForm.sameSite as any,
      });
      toastStore.show(`${editingCookieName ? '已修改' : '已新增'} ${cookieForm.name}`, 'success');
      cookieEditorOpen = false;
      await loadCookies();
    } catch (e: any) {
      toastStore.show('保存失败: ' + (e.message || ''), 'error');
    }
  }

  async function deleteCookie(c: CookieRow) {
    const url = `${c.secure ? 'https' : 'http'}://${c.domain.replace(/^\./, '')}${c.path}`;
    try {
      await browser.cookies.remove({ url, name: c.name, storeId: undefined as any });
      toastStore.show(`已删除 ${c.name}`, 'success');
      await loadCookies();
    } catch (e: any) {
      toastStore.show('删除失败: ' + (e.message || ''), 'error');
    }
  }

  async function importCookies() {
    const raw = cookieImportText.trim();
    if (!raw) { toastStore.show('请输入 Cookie 字符串', 'warning'); return; }
    const domain = await currentDomain();
    if (!domain) { toastStore.show('无法获取当前域名', 'error'); return; }
    const isHttps = (await getActiveTabUrl())?.startsWith('https');
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
          name, value, domain: '.' + domain, path: '/',
          secure: !!isHttps, httpOnly: false, sameSite: 'lax' as any,
        });
        ok++;
      } catch { /* ignore single */ }
    }
    toastStore.show(`已导入 ${ok}/${pairs.length} 个 Cookie`, ok > 0 ? 'success' : 'error');
    cookieImportOpen = false;
    cookieImportText = '';
    if (ok > 0) await loadCookies();
  }

  function exportCookies() {
    if (cookieList.length === 0) { toastStore.show('没有可导出的 Cookie', 'warning'); return; }
    const text = cookieList.map(c => `${c.name}=${c.value}`).join('; ');
    navigator.clipboard.writeText(text).then(() => toastStore.show(`已复制 ${cookieList.length} 个 Cookie`, 'success'));
  }

  async function clearAllCookies() {
    const domain = await currentDomain();
    if (!domain) return;
    if (!confirm(`确认删除 ${domain} 域名下所有 Cookie？此操作不可撤销。`)) return;
    try {
      const all = await browser.cookies.getAll({ domain });
      for (const c of all) {
        const url = `${c.secure ? 'https' : 'http'}://${c.domain.replace(/^\./, '')}${c.path}`;
        try { await browser.cookies.remove({ url, name: c.name }); } catch { /* ignore */ }
      }
      toastStore.show(`已清除 ${all.length} 个 Cookie`, 'success');
      await loadCookies();
    } catch (e: any) {
      toastStore.show('清除失败: ' + (e.message || ''), 'error');
    }
  }

  // 切到 cookies tab 时自动加载
  $effect(() => { if (tab === 'cookies' && cookieList.length === 0) loadCookies(); });
</script>

<div class="space-y-3">
  <div class="seg">
    {#each [{ id: 'ua', label: 'UA 伪造' }, { id: 'headers', label: '请求头伪造' }, { id: 'cookies', label: 'Cookie 管理' }] as t}
      <button class={tab === t.id ? 'seg-btn-active' : 'seg-btn-inactive'} onclick={() => (tab = t.id as Tab)}>{t.label}</button>
    {/each}
  </div>

  {#if tab === 'ua'}
    {#if uaActive}
      <div class="text-xs text-green-500">✅ UA 伪造已启用</div>
    {/if}

    <div class="seg">
      {#each [{ id: 'mobile', label: '手机' }, { id: 'desktop', label: '桌面' }, { id: 'brand', label: '爬虫' }, { id: 'custom', label: '自定义' }] as c}
        <button class={uaCategory === c.id ? 'seg-btn-active' : 'seg-btn-inactive'} onclick={() => (uaCategory = c.id as UaCategory)}>{c.label}</button>
      {/each}
    </div>

    {#if uaCategory !== 'custom'}
      <div class="space-y-1 max-h-48 overflow-y-auto">
        {#each presets[uaCategory] as p}
          <button
            class="w-full text-left card p-2 hover:border-primary {customUa === p.value ? 'border-primary bg-blue-50 dark:bg-blue-900/20' : ''}"
            onclick={() => selectUa(p.value)}
          >
            <div class="text-xs font-medium">{p.label}</div>
            <div class="text-xs text-gray-500 font-mono truncate">{p.value}</div>
          </button>
        {/each}
      </div>
    {/if}

    <div>
      <label for="spoof-ua" class="block text-xs text-gray-500 mb-1">User-Agent</label>
      <textarea id="spoof-ua" class="input font-mono text-xs" rows="2" placeholder="选择预设或输入自定义 UA" bind:value={customUa}></textarea>
    </div>

    <div class="flex gap-1">
      <button class="btn btn-sm btn-primary flex-1" onclick={applyUa}>应用</button>
      <button class="btn btn-sm flex-1" onclick={resetUa} disabled={!uaActive}>恢复</button>
    </div>

  {:else if tab === 'headers'}
    {#if headersActive}
      <div class="text-xs text-green-500">✅ 请求头伪造已启用</div>
    {/if}

    <div class="card p-2 space-y-2">
      <div>
        <label for="spoof-xff" class="block text-xs text-gray-500 mb-1">X-Forwarded-For</label>
        <input id="spoof-xff" class="input text-xs font-mono" placeholder="1.2.3.4" bind:value={xff} />
      </div>
      <div>
        <label for="spoof-referer" class="block text-xs text-gray-500 mb-1">Referer</label>
        <input id="spoof-referer" class="input text-xs font-mono" placeholder="https://internal.target.local/" bind:value={referer} />
      </div>
      <div>
        <label for="spoof-clientip" class="block text-xs text-gray-500 mb-1">Client-IP / X-Real-IP</label>
        <input id="spoof-clientip" class="input text-xs font-mono" placeholder="10.0.0.1" bind:value={clientIp} />
      </div>
    </div>

    <!-- 自定义头 -->
    <div>
      <div class="text-xs text-gray-500 mb-1">自定义请求头</div>
      {#each customHeaders as h, i}
        <div class="flex gap-1 mb-1">
          <input class="input text-xs font-mono flex-1" value={h.name} readonly />
          <input class="input text-xs font-mono flex-1" value={h.value} readonly />
          <button class="btn btn-xs" onclick={() => removeCustomHeader(i)}>✕</button>
        </div>
      {/each}
      <div class="flex gap-1">
        <input class="input text-xs font-mono flex-1" placeholder="Header-Name" bind:value={newHdrName} />
        <input class="input text-xs font-mono flex-1" placeholder="value" bind:value={newHdrValue} />
        <button class="btn btn-xs btn-primary" onclick={addCustomHeader}>+</button>
      </div>
    </div>

    <div class="flex gap-1">
      <button class="btn btn-sm btn-primary flex-1" onclick={applyHeaders}>应用</button>
      <button class="btn btn-sm flex-1" onclick={resetHeaders} disabled={!headersActive}>恢复</button>
    </div>
  {:else if tab === 'cookies'}
    <!-- Cookie 列表 -->
    <div class="flex items-center gap-1 text-xs">
      <input class="input text-xs flex-1" placeholder="过滤 Cookie..." bind:value={cookieFilter} />
      <button class="btn btn-xs" onclick={loadCookies}>刷新</button>
      <button class="btn btn-xs btn-primary" onclick={openAddCookie}>新增</button>
      <button class="btn btn-xs" onclick={() => (cookieImportOpen = true)}>导入</button>
      <button class="btn btn-xs" onclick={exportCookies}>导出</button>
      <button class="btn btn-xs btn-danger" onclick={clearAllCookies}>全清</button>
    </div>

    {#if cookieEditorOpen}
      <div class="card p-2 space-y-2">
        <div class="text-xs font-medium">{editingCookieName ? '编辑 Cookie' : '新增 Cookie'}</div>
        <div class="grid grid-cols-2 gap-2 text-xs">
          <input class="input text-xs font-mono col-span-2" placeholder="名称" bind:value={cookieForm.name} />
          <input class="input text-xs font-mono col-span-2" placeholder="值" bind:value={cookieForm.value} />
          <input class="input text-xs font-mono" placeholder="域名" bind:value={cookieForm.domain} />
          <input class="input text-xs font-mono" placeholder="路径" bind:value={cookieForm.path} />
        </div>
        <div class="flex items-center gap-3 text-xs flex-wrap">
          <label class="flex items-center gap-1"><input type="checkbox" bind:checked={cookieForm.secure} class="accent-blue-500" />Secure</label>
          <label class="flex items-center gap-1"><input type="checkbox" bind:checked={cookieForm.httpOnly} class="accent-blue-500" />HttpOnly</label>
          <select class="input text-xs w-28" bind:value={cookieForm.sameSite}>
            <option value="lax">SameSite=Lax</option>
            <option value="strict">SameSite=Strict</option>
            <option value="none">SameSite=None</option>
            <option value="unspecified">未指定</option>
          </select>
        </div>
        <div class="flex gap-1">
          <button class="btn btn-xs btn-primary flex-1" onclick={saveCookieForm}>保存</button>
          <button class="btn btn-xs flex-1" onclick={() => (cookieEditorOpen = false)}>取消</button>
        </div>
      </div>
    {/if}

    {#if cookieImportOpen}
      <div class="card p-2 space-y-2">
        <div class="text-xs font-medium">批量导入（name=value; name2=value2，写入当前域名）</div>
        <textarea class="input font-mono text-xs" rows="3" placeholder="token=eyJxxx; role=admin" bind:value={cookieImportText}></textarea>
        <div class="flex gap-1">
          <button class="btn btn-xs btn-primary flex-1" onclick={importCookies}>导入</button>
          <button class="btn btn-xs flex-1" onclick={() => (cookieImportOpen = false)}>取消</button>
        </div>
      </div>
    {/if}

    <div class="text-xs text-gray-500">当前域名 {cookieList.length} 个 Cookie</div>
    <div class="space-y-1 max-h-80 overflow-y-auto">
      {#each filteredCookies as c (c.name + c.domain + c.path)}
        <div class="card p-2 text-xs">
          <div class="flex items-center gap-2">
            <span class="font-mono font-medium flex-1 truncate" title={c.value}>{c.name}</span>
            {#if c.secure}<span class="badge text-xs bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300">S</span>{/if}
            {#if c.httpOnly}<span class="badge text-xs bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300">H</span>{/if}
            <button class="text-xs text-gray-500 hover:text-primary" onclick={() => openEditCookie(c)}>编辑</button>
            <button class="text-xs text-red-400 hover:text-red-600" onclick={() => deleteCookie(c)}>删除</button>
          </div>
          <div class="font-mono text-gray-500 truncate">{c.value}</div>
          <div class="text-gray-500">{c.domain}{c.path}</div>
        </div>
      {/each}
    </div>
  {/if}
</div>
