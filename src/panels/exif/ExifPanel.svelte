<script lang="ts">
  // EXIF 查看面板
  // 支持本地文件 / URL / 页面图片三种模式
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTab, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import {
    parseExif,
    groupExifSections,
    hasGpsPrivacyRisk,
    formatGpsDms,
    buildMapUrl,
    type ExifData,
    type ExifSection,
  } from '@/lib/exif/exif-utils';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { toMarkdownTable } from '@/lib/actions/serializers';

  // ---------- 状态 ----------

  let mode = $state<'local' | 'url' | 'page'>('local');
  let url = $state('');
  let loading = $state(false);
  let statusMsg = $state('');
  let exifData = $state<ExifData | null>(null);
  let sections = $state<ExifSection[]>([]);
  let previewUrl = $state('');
  let fileName = $state('');
  let fileSize = $state('');
  let privacyWarning = $state(false);
  let pageImages = $state<{ src: string; alt: string; w: number; h: number }[]>([]);
  let scanningPage = $state(false);

  // ---------- 核心逻辑 ----------

  async function handleFile(file: File) {
    loading = true;
    statusMsg = '正在解析...';
    exifData = null;
    sections = [];
    privacyWarning = false;

    // 显示预览
    previewUrl = URL.createObjectURL(file);
    fileName = file.name;
    fileSize = `${(file.size / 1024).toFixed(1)} KB`;

    try {
      const buffer = await file.arrayBuffer();
      const data = parseExif(buffer);

      if (!data || Object.keys(data).length === 0) {
        statusMsg = '未检测到 EXIF 信息';
        loading = false;
        return;
      }

      exifData = data;
      sections = groupExifSections(data);
      privacyWarning = hasGpsPrivacyRisk(data);
      statusMsg = '';
      toastStore.show('EXIF 解析完成', 'success');
    } catch (e: any) {
      statusMsg = `解析失败: ${e.message}`;
    } finally {
      loading = false;
    }
  }

  async function fetchFromUrl() {
    if (!url.trim()) {
      toastStore.show('请输入图片 URL', 'warning');
      return;
    }
    loading = true;
    statusMsg = '正在获取图片...';
    exifData = null;
    sections = [];
    privacyWarning = false;
    previewUrl = url.trim();
    fileName = url.split('/').pop() || url;
    fileSize = '';

    try {
      const result = await sendMessage({ type: 'FETCH_IMAGE', url: url.trim() });
      if (!result.success) {
        statusMsg = `获取失败: ${result.error || '未知错误'}`;
        loading = false;
        return;
      }

      const b64 = (result as any).data.replace(/^data:[^;]+;base64,/, '');
      const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      const mimeMatch = url.match(/\.(jpe?g|png|webp|tiff?|heic)/i);
      const mime = mimeMatch
        ? `image/${mimeMatch[1].toLowerCase().replace('jpg', 'jpeg')}`
        : 'image/jpeg';
      const blob = new Blob([bytes], { type: mime });
      const file = new File([blob], fileName, { type: mime });
      fileSize = `${(file.size / 1024).toFixed(1)} KB`;

      // 使用文件解析
      const buffer = await file.arrayBuffer();
      const data = parseExif(buffer);

      if (!data || Object.keys(data).length === 0) {
        statusMsg = '未检测到 EXIF 信息';
        loading = false;
        return;
      }

      exifData = data;
      sections = groupExifSections(data);
      privacyWarning = hasGpsPrivacyRisk(data);
      statusMsg = '';
      toastStore.show('EXIF 解析完成', 'success');
    } catch (e: any) {
      statusMsg = `获取失败: ${e.message}`;
    } finally {
      loading = false;
    }
  }

  async function scanPageImages() {
    scanningPage = true;
    pageImages = [];
    const tab = await getActiveTab();
    if (!tab?.id) {
      scanningPage = false;
      toastStore.show('无法获取当前标签页', 'error');
      return;
    }

    const images = await execInTab<{ src: string; alt: string; w: number; h: number }[]>(
      tab.id,
      function () {
        const imgs: { src: string; alt: string; w: number; h: number }[] = [];
        document.querySelectorAll('img[src]').forEach(function (img: any) {
          if (img.src && img.naturalWidth > 50 && img.naturalHeight > 50) {
            if (/^(blob:|data:|javascript:)/i.test(img.src)) return;
            imgs.push({ src: img.src, alt: img.alt || '', w: img.naturalWidth, h: img.naturalHeight });
          }
        });
        document.querySelectorAll('[style*="background"]').forEach(function (el: Element) {
          const m = (el as HTMLElement).style.backgroundImage.match(/url\(["']?(.*?)["']?\)/);
          if (m && m[1] && !/^(blob:|data:|javascript:)/i.test(m[1])) {
            imgs.push({ src: m[1], alt: '', w: 0, h: 0 });
          }
        });
        const unique = new Map<string, { src: string; alt: string; w: number; h: number }>();
        imgs.forEach(function (i) { if (!unique.has(i.src)) unique.set(i.src, i); });
        return Array.from(unique.values()).slice(0, 50);
      },
      { world: 'ISOLATED' },
    );

    pageImages = images || [];
    scanningPage = false;
    if (pageImages.length === 0) {
      toastStore.show('未找到图片', 'warning');
    } else {
      toastStore.show(`找到 ${pageImages.length} 张图片`, 'success');
    }
  }

  function selectPageImage(src: string) {
    url = src;
    mode = 'url';
    fetchFromUrl();
  }

  function copyExifData() {
    if (!exifData) {
      toastStore.show('请先解析 EXIF 数据', 'warning');
      return;
    }
    copyText(JSON.stringify(exifData, null, 2), '已复制 EXIF JSON');
  }

  // —— 导出序列化器（作用于 sections 扁平字段）——
  type ExifFlatField = { section: string; label: string; value: string };
  let flatFields = $derived(
    sections.flatMap(s => s.fields.map(f => ({ section: s.title, label: f.label, value: f.value }))),
  );
  function exifJson(items: ExifFlatField[]): string {
    return JSON.stringify(exifData, null, 2);
  }
  function exifMd(items: ExifFlatField[]): string {
    return toMarkdownTable(['分组', '字段', '值'], items.map(f => [f.section, f.label, f.value]));
  }
  function exifText(items: ExifFlatField[]): string {
    return items.map(f => `[${f.section}] ${f.label}: ${f.value}`).join('\n');
  }

  function clearExif() {
    exifData = null;
    sections = [];
    statusMsg = '';
    previewUrl = '';
    fileName = '';
    fileSize = '';
    privacyWarning = false;
    pageImages = [];
  }

  function onFileInput(e: Event) {
    const input = e.target as HTMLInputElement;
    if (input.files?.[0]) handleFile(input.files[0]);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    const file = e.dataTransfer?.files[0];
    if (file) handleFile(file);
  }

  function onDragOver(e: DragEvent) {
    e.preventDefault();
  }
</script>

<div class="space-y-3">
  <!-- 模式切换 -->
  <div class="flex gap-1">
    <button class="btn btn-sm" class:btn-primary={mode === 'local'} onclick={() => mode = 'local'}>本地文件</button>
    <button class="btn btn-sm" class:btn-primary={mode === 'url'} onclick={() => mode = 'url'}>URL</button>
    <button class="btn btn-sm" class:btn-primary={mode === 'page'} onclick={() => mode = 'page'}>页面图片</button>
    <div class="flex-1"></div>
    {#if exifData}
      <button class="btn btn-sm" onclick={copyExifData}>复制 JSON</button>
      <ExportMenu items={flatFields} module="exif" serializers={{ json: exifJson, markdown: exifMd, text: exifText }} />
      <button class="btn btn-sm" onclick={clearExif}>清空</button>
    {/if}
  </div>

  <!-- 本地文件模式 -->
  {#if mode === 'local'}
    <div class="card p-3 space-y-2">
      <div
        class="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center cursor-pointer hover:border-blue-400 transition-colors"
        onclick={() => document.getElementById('exif-file-input')?.click()}
        onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); document.getElementById('exif-file-input')?.click(); } }}
        ondrop={onDrop}
        ondragover={onDragOver}
        role="button"
        tabindex="0"
      >
        <div class="text-2xl mb-1">📷</div>
        <div class="text-sm text-gray-500">拖拽图片到此处或点击选择文件</div>
        <input
          id="exif-file-input"
          type="file"
          accept="image/*"
          class="hidden"
          onchange={onFileInput}
        />
      </div>
    </div>
  {/if}

  <!-- URL 模式 -->
  {#if mode === 'url'}
    <div class="card p-3 space-y-2">
      <div class="flex gap-2">
        <input
          type="text"
          class="input flex-1"
          placeholder="https://example.com/photo.jpg"
          bind:value={url}
        />
        <button class="btn btn-sm btn-primary" disabled={loading || !url.trim()} onclick={fetchFromUrl}>
          {loading ? '获取中...' : '获取'}
        </button>
      </div>
    </div>
  {/if}

  <!-- 页面图片模式 -->
  {#if mode === 'page'}
    <div class="card p-3 space-y-2">
      <div class="flex items-center justify-between">
        <div class="text-sm font-medium">扫描页面图片</div>
        <button class="btn btn-sm btn-primary" disabled={scanningPage} onclick={scanPageImages}>
          {scanningPage ? '扫描中...' : '扫描'}
        </button>
      </div>
      {#if pageImages.length > 0}
        <div class="text-xs text-gray-500">找到 {pageImages.length} 张图片（点击查看 EXIF）</div>
        <div class="space-y-1 max-h-60 overflow-y-auto">
          {#each pageImages as img}
            <button
              class="flex items-center gap-2 w-full text-left p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              onclick={() => selectPageImage(img.src)}
            >
              <img src={img.src} alt="" class="w-8 h-8 object-cover rounded" />
              <div class="flex-1 min-w-0">
                <div class="text-xs truncate">{img.alt || img.src.split('/').pop()}</div>
                {#if img.w}
                  <div class="text-xs text-gray-500">{img.w} x {img.h}</div>
                {/if}
              </div>
              <div class="text-xs text-gray-500 truncate max-w-48">{img.src}</div>
            </button>
          {/each}
        </div>
      {:else if !scanningPage}
        <div class="text-xs text-gray-500">点击「扫描」查找页面中的图片</div>
      {/if}
    </div>
  {/if}

  <!-- 加载状态 -->
  {#if loading}
    <div class="card p-3">
      <div class="text-sm text-gray-500">{statusMsg || '处理中...'}</div>
    </div>
  {/if}

  <!-- 错误/空状态 -->
  {#if statusMsg && !loading}
    <div class="card p-3">
      <div class="text-sm text-gray-500">{statusMsg}</div>
    </div>
  {/if}

  <!-- 隐私警告 -->
  {#if privacyWarning}
    <div class="card p-3 border-l-4 border-yellow-400 bg-yellow-50 dark:bg-yellow-900/20">
      <div class="text-sm font-medium text-yellow-700 dark:text-yellow-400">⚠️ 隐私风险：图片包含 GPS 定位信息</div>
      <div class="text-xs text-yellow-600 dark:text-yellow-500 mt-1">上传此图片可能泄露您的地理位置</div>
      {#if exifData && typeof exifData['latitude'] === 'number' && typeof exifData['longitude'] === 'number'}
        <a
          href={buildMapUrl(exifData['latitude'] as number, exifData['longitude'] as number)}
          target="_blank"
          rel="noopener noreferrer"
          class="inline-block mt-1 text-xs text-blue-600 dark:text-blue-400 underline hover:no-underline"
        >
          在 Google Maps 中查看位置
        </a>
      {/if}
    </div>
  {/if}

  <!-- 预览 -->
  {#if previewUrl && (exifData || statusMsg === '')}
    <div class="card p-3">
      <div class="flex gap-3">
        <img src={previewUrl} alt="preview" class="w-20 h-20 object-cover rounded" />
        <div class="text-xs text-gray-500 space-y-1">
          {#if fileName}
            <div class="truncate max-w-60" title={fileName}>{fileName}</div>
          {/if}
          {#if fileSize}
            <div>{fileSize}</div>
          {/if}
        </div>
      </div>
    </div>
  {/if}

  <!-- EXIF 分组展示 -->
  {#if sections.length > 0}
    {#each sections as section}
      <div class="card p-3 space-y-1">
        <div class="text-sm font-medium">{section.icon} {section.title}</div>
        <div class="space-y-1">
          {#each section.fields as field}
            <div class="flex justify-between text-xs">
              <span class="text-gray-500 shrink-0">{field.label}</span>
              <span class="text-right break-all ml-2" title={String(field.raw)}>{field.value}</span>
            </div>
          {/each}
        </div>
      </div>
    {/each}
  {/if}
</div>
