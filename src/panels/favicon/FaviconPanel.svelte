<script lang="ts">
  // 图标识别面板 -- 灵眸 v6.0
  // Fetch favicon, compute mmh3 hash (Shodan/FOFA format), show queries + product match.

  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import {
    computeFaviconHash,
    buildShodanQuery,
    buildFofaQuery,
    KNOWN_FAVICONS,
  } from '@/lib/scanners/favicon-engine';

  // ===== State =====

  let targetUrl = $state('');
  let extracting = $state(false);
  let statusText = $state('');
  let faviconDataUri = $state('');
  let faviconUrl = $state('');
  let hashValue = $state<number | null>(null);
  let matchedProduct = $state<string | null>(null);
  let shodanQuery = $state('');
  let fofaQuery = $state('');
  let imgError = $state(false);

  // ===== Actions =====

  async function autoFill() {
    const url = await getActiveTabUrl();
    if (url) targetUrl = url;
  }

  async function startExtract() {
    const url = targetUrl.trim();
    if (!url) {
      toastStore.show('请输入 URL', 'warning');
      return;
    }

    const validated = validateProbeUrl(url);
    if ('error' in validated) {
      toastStore.show(`无效 URL: ${validated.error}`, 'warning');
      return;
    }

    extracting = true;
    statusText = '提取中...';
    faviconDataUri = '';
    faviconUrl = '';
    hashValue = null;
    matchedProduct = null;
    shodanQuery = '';
    fofaQuery = '';
    imgError = false;

    try {
      const origin = validated.parsed.origin;

      // Try fetching /favicon.ico first
      const resolvedUrl = `${origin}/favicon.ico`;
      faviconUrl = resolvedUrl;

      const response = await sendMessage({ type: 'FETCH_IMAGE', url: resolvedUrl });

      if (!response.success || !response.data) {
        const errMsg = !response.success ? (response as { error: string }).error : '网络错误';
        statusText = '获取失败';
        toastStore.show(`图标获取失败: ${errMsg}`, 'error');
        return;
      }

      const base64Data = response.data;

      // Build displayable data URI if not already
      if (base64Data.startsWith('data:')) {
        faviconDataUri = base64Data;
      } else {
        faviconDataUri = `data:image/x-icon;base64,${base64Data}`;
      }

      // Compute mmh3 hash
      const hash = computeFaviconHash(base64Data);
      hashValue = hash;

      // Build query strings
      shodanQuery = buildShodanQuery(hash);
      fofaQuery = buildFofaQuery(hash);

      // Look up known product
      matchedProduct = KNOWN_FAVICONS[hash] ?? null;

      // SVG warning
      if (base64Data.startsWith('data:image/svg+xml')) {
        toastStore.show('SVG 图标哈希可能与平台结果不匹配', 'warning');
      }

      statusText = matchedProduct
        ? `识别到: ${matchedProduct}`
        : '提取成功，未匹配已知产品';

      toastStore.show(
        matchedProduct ? `识别到: ${matchedProduct}` : '图标提取成功',
        matchedProduct ? 'success' : 'info',
      );
    } catch (err: any) {
      statusText = `提取失败: ${err.message || '未知错误'}`;
      toastStore.show(`提取失败: ${err.message || '未知错误'}`, 'error');
    } finally {
      extracting = false;
    }
  }

  function copyShodanQuery() {
    if (!shodanQuery) {
      toastStore.show('请先提取图标', 'warning');
      return;
    }
    navigator.clipboard.writeText(shodanQuery).then(() => {
      toastStore.show('已复制 Shodan 查询语句', 'success');
    });
  }

  function copyFofaQuery() {
    if (!fofaQuery) {
      toastStore.show('请先提取图标', 'warning');
      return;
    }
    navigator.clipboard.writeText(fofaQuery).then(() => {
      toastStore.show('已复制 FOFA 查询语句', 'success');
    });
  }

  function copyHash() {
    if (hashValue === null) {
      toastStore.show('请先提取图标', 'warning');
      return;
    }
    navigator.clipboard.writeText(String(hashValue)).then(() => {
      toastStore.show('已复制 MMH3 Hash', 'success');
    });
  }

  function openShodan() {
    if (!shodanQuery) return;
    window.open(`https://www.shodan.io/search?query=${encodeURIComponent(shodanQuery)}`, '_blank');
  }

  function openFofa() {
    if (!fofaQuery) return;
    window.open(`https://fofa.info/result?qbase64=${btoa(fofaQuery)}`, '_blank');
  }
</script>

<div class="space-y-3">
  <!-- URL 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <input
        class="input text-xs font-mono flex-1"
        placeholder="https://target.example.com"
        bind:value={targetUrl}
      />
      <button class="btn btn-sm btn-ghost text-xs" onclick={autoFill}>自动填充</button>
    </div>

    <div class="flex gap-1">
      <button
        class="btn btn-sm btn-primary flex-1"
        disabled={extracting || !targetUrl.trim()}
        onclick={startExtract}
      >
        {extracting ? '提取中...' : '提取图标指纹'}
      </button>
    </div>

    {#if statusText}
      <div class="text-xs text-gray-500">{statusText}</div>
    {/if}
  </div>

  <!-- 提取中 -->
  {#if extracting}
    <div class="card p-3 text-center">
      <div class="text-xs text-gray-500">正在获取站点 favicon...</div>
    </div>
  {/if}

  <!-- 结果区域 -->
  {#if !extracting && hashValue !== null}
    <!-- Favicon 预览 -->
    <div class="card p-3 space-y-2">
      <div class="text-xs font-medium">Favicon 预览</div>
      <div class="flex items-center gap-3">
        {#if faviconDataUri && !imgError}
          <img
            src={faviconDataUri}
            alt="favicon"
            class="w-12 h-12 rounded border border-gray-200 dark:border-gray-700 object-contain"
            onerror={() => (imgError = true)}
          />
        {:else}
          <div class="w-12 h-12 rounded border border-gray-200 dark:border-gray-700 flex items-center justify-center text-gray-400 text-lg">
            ?
          </div>
        {/if}
        <div class="text-xs font-mono text-gray-500 break-all">{faviconUrl}</div>
      </div>
    </div>

    <!-- Hash 结果 -->
    <div class="card p-3 space-y-2">
      <div class="text-xs font-medium">MMH3 Hash</div>
      <div class="flex items-center gap-2">
        <code class="text-sm font-mono flex-1 break-all">{hashValue}</code>
        <button class="btn btn-sm text-xs" onclick={copyHash}>复制</button>
      </div>
    </div>

    <!-- 产品匹配 -->
    {#if matchedProduct}
      <div class="card p-3 space-y-1">
        <div class="text-xs font-medium">识别结果</div>
        <div class="flex items-center gap-2">
          <span class="badge bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">
            {matchedProduct}
          </span>
        </div>
      </div>
    {/if}

    <!-- 搜索引擎查询 -->
    <div class="card p-3 space-y-2">
      <div class="text-xs font-medium">搜索引擎查询</div>

      <!-- Shodan -->
      <div class="space-y-1">
        <div class="text-xs text-gray-400">Shodan</div>
        <div class="flex items-center gap-2">
          <code class="text-xs font-mono flex-1 break-all">{shodanQuery}</code>
          <button class="btn btn-sm text-xs" onclick={copyShodanQuery}>复制</button>
          <button class="btn btn-sm btn-ghost text-xs" onclick={openShodan}>打开</button>
        </div>
      </div>

      <!-- FOFA -->
      <div class="space-y-1">
        <div class="text-xs text-gray-400">FOFA</div>
        <div class="flex items-center gap-2">
          <code class="text-xs font-mono flex-1 break-all">{fofaQuery}</code>
          <button class="btn btn-sm text-xs" onclick={copyFofaQuery}>复制</button>
          <button class="btn btn-sm btn-ghost text-xs" onclick={openFofa}>打开</button>
        </div>
      </div>
    </div>
  {/if}

  <!-- 无结果 -->
  {#if !extracting && hashValue === null && statusText && statusText.includes('失败')}
    <div class="card p-3 text-center space-y-1">
      <div class="text-sm">图标获取失败</div>
      <div class="text-xs text-gray-400">
        目标站点可能没有 favicon，或网络请求被阻止
      </div>
    </div>
  {/if}
</div>
