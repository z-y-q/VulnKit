<script lang="ts">
  // 图标识别面板
  // Fetch favicon, compute mmh3 hash (Shodan/FOFA format), show queries + product match.

  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import {
    computeFaviconHash,
    computeMd5Hex,
    computeSha256Hex,
    discoverFaviconUrl,
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
  let md5Hex = $state('');
  let sha256Hex = $state('');
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
    md5Hex = '';
    sha256Hex = '';
    matchedProduct = null;
    shodanQuery = '';
    fofaQuery = '';
    imgError = false;

    try {
      const origin = validated.parsed.origin;
      const baseUrl = validated.parsed.href;

      // 优先从页面 HTML 的 <link rel="icon"> 发现 favicon URL，回退 /favicon.ico
      let resolvedUrl = `${origin}/favicon.ico`;
      try {
        const htmlRes = await sendMessage({ type: 'FETCH_URL', url: baseUrl }) as { success: boolean; data?: string };
        if (htmlRes.success && htmlRes.data) {
          const discovered = discoverFaviconUrl(htmlRes.data, baseUrl);
          if (discovered) resolvedUrl = discovered;
        }
      } catch { /* ignore，用默认 /favicon.ico */ }
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

      // Compute hashes: mmh3（Shodan/FOFA）+ MD5 + SHA256
      const hash = computeFaviconHash(base64Data);
      hashValue = hash;
      md5Hex = computeMd5Hex(base64Data);
      sha256Hex = await computeSha256Hex(base64Data);

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

  function copyFaviconUrl() {
    if (!faviconUrl) {
      toastStore.show('请先提取图标', 'warning');
      return;
    }
    navigator.clipboard.writeText(faviconUrl).then(() => {
      toastStore.show('已复制 Favicon URL', 'success');
    });
  }

  function openZoomEye() {
    if (!md5Hex) return;
    window.open(`https://www.zoomeye.org/searchResult?q=icon_hash:${md5Hex}`, '_blank');
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
          <div class="w-12 h-12 rounded border border-gray-200 dark:border-gray-700 flex items-center justify-center text-gray-500 text-lg">
            ?
          </div>
        {/if}
        <div class="text-xs font-mono text-gray-500 break-all">{faviconUrl}</div>
        <button class="btn btn-xs shrink-0" onclick={copyFaviconUrl} title="复制 URL">复制 URL</button>
      </div>
    </div>

    <!-- Hash 结果 -->
    <div class="card p-3 space-y-2">
      <div class="text-xs font-medium">MMH3 Hash <span class="text-gray-500 font-normal">(Shodan/FOFA)</span></div>
      <div class="flex items-center gap-2">
        <code class="text-sm font-mono flex-1 break-all">{hashValue}</code>
        <button class="btn btn-sm text-xs" onclick={copyHash}>复制</button>
      </div>
      {#if md5Hex}
        <div class="text-xs font-medium mt-2">MD5</div>
        <div class="flex items-center gap-2">
          <code class="text-xs font-mono flex-1 break-all text-gray-600 dark:text-gray-300">{md5Hex}</code>
          <button class="btn btn-sm text-xs" onclick={() => { navigator.clipboard.writeText(md5Hex); toastStore.show('已复制 MD5', 'success'); }}>复制</button>
        </div>
      {/if}
      {#if sha256Hex}
        <div class="text-xs font-medium mt-2">SHA-256</div>
        <div class="flex items-center gap-2">
          <code class="text-xs font-mono flex-1 break-all text-gray-600 dark:text-gray-300">{sha256Hex}</code>
          <button class="btn btn-sm text-xs" onclick={() => { navigator.clipboard.writeText(sha256Hex); toastStore.show('已复制 SHA-256', 'success'); }}>复制</button>
        </div>
      {/if}
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
        <div class="text-xs text-gray-500">Shodan</div>
        <div class="flex items-center gap-2">
          <code class="text-xs font-mono flex-1 break-all">{shodanQuery}</code>
          <button class="btn btn-sm text-xs" onclick={copyShodanQuery}>复制</button>
          <button class="btn btn-sm btn-ghost text-xs" onclick={openShodan}>打开</button>
        </div>
      </div>

      <!-- FOFA -->
      <div class="space-y-1">
        <div class="text-xs text-gray-500">FOFA</div>
        <div class="flex items-center gap-2">
          <code class="text-xs font-mono flex-1 break-all">{fofaQuery}</code>
          <button class="btn btn-sm text-xs" onclick={copyFofaQuery}>复制</button>
          <button class="btn btn-sm btn-ghost text-xs" onclick={openFofa}>打开</button>
        </div>
      </div>

      <!-- ZoomEye -->
      {#if md5Hex}
        <div class="space-y-1">
          <div class="text-xs text-gray-500">ZoomEye</div>
          <div class="flex items-center gap-2">
            <code class="text-xs font-mono flex-1 break-all">icon_hash:{md5Hex}</code>
            <button class="btn btn-sm text-xs" onclick={() => { navigator.clipboard.writeText(`icon_hash:${md5Hex}`); toastStore.show('已复制 ZoomEye 查询', 'success'); }}>复制</button>
            <button class="btn btn-sm btn-ghost text-xs" onclick={openZoomEye}>打开</button>
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- 无结果 -->
  {#if !extracting && hashValue === null && statusText && statusText.includes('失败')}
    <div class="card p-3 text-center space-y-1">
      <div class="text-sm">图标获取失败</div>
      <div class="text-xs text-gray-500">
        目标站点可能没有 favicon，或网络请求被阻止
      </div>
    </div>
  {/if}
</div>
