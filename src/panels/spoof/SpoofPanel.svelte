<script lang="ts">
  // 请求伪造面板 — 灵眸 v6.0
  // UA 伪造 + 请求头伪造（X-Forwarded-For / Referer / Client-IP / 自定义）
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import uaPresets from '@/lib/data/spoof-ua-presets.json';

  type Tab = 'ua' | 'headers';
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
</script>

<div class="space-y-3">
  <div class="flex gap-1">
    {#each [{ id: 'ua', label: 'UA 伪造' }, { id: 'headers', label: '请求头伪造' }] as t}
      <button class="btn btn-sm {tab === t.id ? 'bg-primary text-white' : 'btn-ghost'}" onclick={() => (tab = t.id as Tab)}>{t.label}</button>
    {/each}
  </div>

  {#if tab === 'ua'}
    {#if uaActive}
      <div class="text-xs text-green-500">✅ UA 伪造已启用</div>
    {/if}

    <div class="flex gap-1 flex-wrap">
      {#each [{ id: 'mobile', label: '📱 手机' }, { id: 'desktop', label: '🖥️ 桌面' }, { id: 'brand', label: '🤖 爬虫' }, { id: 'custom', label: '✏️ 自定义' }] as c}
        <button class="btn btn-xs {uaCategory === c.id ? 'bg-primary text-white' : 'btn-ghost'}" onclick={() => (uaCategory = c.id as UaCategory)}>{c.label}</button>
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
            <div class="text-xs text-gray-400 font-mono truncate">{p.value}</div>
          </button>
        {/each}
      </div>
    {/if}

    <div>
      <label class="block text-xs text-gray-500 mb-1">User-Agent</label>
      <textarea class="input font-mono text-xs" rows="2" placeholder="选择预设或输入自定义 UA" bind:value={customUa}></textarea>
    </div>

    <div class="flex gap-1">
      <button class="btn btn-sm btn-primary flex-1" onclick={applyUa}>应用</button>
      <button class="btn btn-sm flex-1" onclick={resetUa} disabled={!uaActive}>恢复</button>
    </div>

  {:else}
    {#if headersActive}
      <div class="text-xs text-green-500">✅ 请求头伪造已启用</div>
    {/if}

    <div class="card p-2 space-y-2">
      <div>
        <label class="block text-xs text-gray-500 mb-1">X-Forwarded-For</label>
        <input class="input text-xs font-mono" placeholder="1.2.3.4" bind:value={xff} />
      </div>
      <div>
        <label class="block text-xs text-gray-500 mb-1">Referer</label>
        <input class="input text-xs font-mono" placeholder="https://internal.target.local/" bind:value={referer} />
      </div>
      <div>
        <label class="block text-xs text-gray-500 mb-1">Client-IP / X-Real-IP</label>
        <input class="input text-xs font-mono" placeholder="10.0.0.1" bind:value={clientIp} />
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
  {/if}
</div>
