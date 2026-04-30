// VulnKit - EXIF Viewer
window.VulnKitExif = (function () {
  'use strict';

  let lastExifData = null;

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  var utils = {};
  ['get', 'escapeHtml', 'copyText', 'showToast'].forEach(function (method) {
    utils[method] = function () {
      var u = getUtils();
      if (!u || typeof u[method] !== 'function') return undefined;
      return u[method].apply(u, arguments);
    };
  });

  const EXIF_SECTIONS = [
    {
      title: '拍摄信息',
      fields: [
        { key: 'DateTimeOriginal', label: '拍摄时间', format: 'date' },
        { key: 'ISO', label: 'ISO 感光度' },
        { key: 'FNumber', label: '光圈', format: 'fnumber' },
        { key: 'ExposureTime', label: '快门速度', format: 'exposure' },
        { key: 'ExposureCompensation', label: '曝光补偿', format: 'ev' },
        { key: 'FocalLength', label: '焦距', format: 'focal' },
        { key: 'FocalLengthIn35mmFormat', label: '等效焦距', format: 'focal' },
        { key: 'MeteringMode', label: '测光模式' },
        { key: 'WhiteBalance', label: '白平衡' },
        { key: 'Flash', label: '闪光灯' },
        { key: 'ExposureProgram', label: '曝光程序' },
      ],
    },
    {
      title: '相机信息',
      fields: [
        { key: 'Make', label: '品牌' },
        { key: 'Model', label: '型号' },
        { key: 'LensModel', label: '镜头' },
        { key: 'LensMake', label: '镜头品牌' },
        { key: 'Software', label: '软件' },
        { key: 'ImageWidth', label: '图像宽度', format: 'pixel' },
        { key: 'ImageHeight', label: '图像高度', format: 'pixel' },
        { key: 'ColorSpace', label: '色彩空间' },
      ],
    },
    {
      title: 'GPS 信息',
      fields: [
        { key: 'latitude', label: '纬度', format: 'gps' },
        { key: 'longitude', label: '经度', format: 'gps' },
        { key: 'GPSAltitude', label: '海拔', format: 'altitude' },
      ],
    },
  ];

  function formatExifValue(value, format) {
    if (value === undefined || value === null) return null;
    switch (format) {
      case 'date':
        if (value instanceof Date) return value.toLocaleString('zh-CN');
        return String(value);
      case 'fnumber':
        return 'f/' + value;
      case 'exposure':
        if (value < 1) {
          const denom = Math.round(1 / value);
          return '1/' + denom + 's';
        }
        return value + 's';
      case 'ev':
        return (value >= 0 ? '+' : '') + value + ' EV';
      case 'focal':
        return value + 'mm';
      case 'pixel':
        return value + ' px';
      case 'altitude':
        return value + ' m';
      case 'gps':
        return value;
      default:
        return String(value);
    }
  }

  function formatGpsDms(value) {
    const abs = Math.abs(value);
    const d = Math.floor(abs);
    const m = Math.floor((abs - d) * 60);
    const s = ((abs - d) * 60 - m) * 60;
    const dir = value > 0 ? 'N' : 'S';
    return d + '\u00B0' + m + "'" + s.toFixed(2) + '"' + dir;
  }

  async function handleExifFile(file) {
    var resultEl = utils.get('exif-result');
    var emptyEl = utils.get('exif-empty');
    var sectionsEl = utils.get('exif-sections');
    var previewImg = utils.get('exif-preview-img');
    var fileNameEl = utils.get('exif-file-name');
    var fileSizeEl = utils.get('exif-file-size');

    if (!resultEl || !emptyEl || !sectionsEl) return;
    resultEl.classList.add('hidden');
    emptyEl.classList.add('hidden');
    sectionsEl.innerHTML = '<div class="empty-state">正在解析...</div>';

    const objectUrl = URL.createObjectURL(file);
    if (previewImg) {
      previewImg.onload = function () {
        URL.revokeObjectURL(objectUrl);
      };
      previewImg.src = objectUrl;
    }
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileSizeEl) fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';

    try {
      const exif = await exifr.parse(file, {
        tiff: true,
        exif: true,
        gps: true,
        ifd1: true,
        interop: false,
        translateValues: true,
        translateKeys: true,
        reviveValues: true,
      });

      if (!exif || Object.keys(exif).length === 0) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        sectionsEl.innerHTML = '';
        lastExifData = null;
        return;
      }

      lastExifData = exif;
      resultEl.classList.remove('hidden');

      let html = '';
      EXIF_SECTIONS.forEach(section => {
        const hasData = section.fields.some(f => exif[f.key] !== undefined && exif[f.key] !== null);
        if (!hasData) return;

        html += '<div class="exif-section">';
        html += '<div class="exif-section-title">' + section.title + '</div>';

        section.fields.forEach(field => {
          if (exif[field.key] === undefined || exif[field.key] === null) return;

          if (field.format === 'gps' && (field.key === 'latitude' || field.key === 'longitude')) {
            const lat = exif.latitude;
            const lon = exif.longitude;
            const latStr = formatGpsDms(lat) + ' (' + lat.toFixed(6) + ')';
            const lonStr =
              formatGpsDms(lon).replace('N', 'E').replace('S', 'W') + ' (' + lon.toFixed(6) + ')';
            if (field.key === 'latitude') {
              html +=
                '<div class="exif-row"><span class="exif-label">纬度</span><span class="exif-value" title="' +
                utils.escapeHtml(String(lat)) +
                '">' +
                utils.escapeHtml(latStr) +
                '</span></div>';
            } else {
              html +=
                '<div class="exif-row"><span class="exif-label">经度</span><span class="exif-value" title="' +
                utils.escapeHtml(String(lon)) +
                '">' +
                utils.escapeHtml(lonStr) +
                '</span></div>';
            }
            return;
          }

          const formatted = formatExifValue(exif[field.key], field.format);
          if (!formatted) return;

          html += '<div class="exif-row">';
          html += '<span class="exif-label">' + field.label + '</span>';
          html +=
            '<span class="exif-value" title="' +
            utils.escapeHtml(String(exif[field.key])) +
            '">' +
            utils.escapeHtml(formatted) +
            '</span>';
          html += '</div>';
        });

        if (
          exif.latitude !== undefined &&
          exif.longitude !== undefined &&
          section.title === 'GPS 信息'
        ) {
          const mapUrl = 'https://www.google.com/maps?q=' + exif.latitude + ',' + exif.longitude;
          html +=
            '<div class="exif-gps-row"><a class="exif-gps-link" href="' +
            mapUrl +
            '" target="_blank">在地图中查看</a></div>';
        }

        html += '</div>';
      });

      sectionsEl.innerHTML = html || '';
      utils.showToast('EXIF 解析完成', 'success');
    } catch (e) {
      resultEl.classList.remove('hidden');
      emptyEl.classList.remove('hidden');
      emptyEl.textContent = '解析失败: ' + e.message;
      sectionsEl.innerHTML = '';
      lastExifData = null;
    }
  }

  function initExifDragDrop() {
    const area = utils.get('exif-upload-area');
    const fileInput = utils.get('exif-file-input');
    if (!area || !fileInput) return;

    area.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', e => {
      if (e.target.files[0]) handleExifFile(e.target.files[0]);
    });
    area.addEventListener('dragover', e => {
      e.preventDefault();
      area.classList.add('dragover');
    });
    area.addEventListener('dragleave', () => area.classList.remove('dragover'));
    area.addEventListener('drop', e => {
      e.preventDefault();
      area.classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file) handleExifFile(file);
    });
  }

  function switchExifMode(mode) {
    document
      .querySelectorAll('.exif-mode-btn')
      .forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
    var localEl = utils.get('exif-mode-local');
    var urlEl = utils.get('exif-mode-url');
    var pageEl = utils.get('exif-mode-page');
    if (localEl) localEl.classList.toggle('hidden', mode !== 'local');
    if (urlEl) urlEl.classList.toggle('hidden', mode !== 'url');
    if (pageEl) pageEl.classList.toggle('hidden', mode !== 'page');
  }

  async function fetchExifFromUrl(url) {
    const resultEl = utils.get('exif-result');
    const emptyEl = utils.get('exif-empty');
    const sectionsEl = utils.get('exif-sections');
    const previewImg = utils.get('exif-preview-img');
    const fileNameEl = utils.get('exif-file-name');
    const fileSizeEl = utils.get('exif-file-size');

    if (!resultEl || !emptyEl || !sectionsEl) return;
    resultEl.classList.add('hidden');
    emptyEl.classList.add('hidden');
    sectionsEl.innerHTML = '<div class="empty-state">正在获取图片...</div>';

    if (previewImg) previewImg.src = url;
    if (fileNameEl) fileNameEl.textContent = url.split('/').pop() || url;
    if (fileSizeEl) fileSizeEl.textContent = '';

    chrome.runtime.sendMessage({ type: 'FETCH_IMAGE', url }, response => {
      if (!response || response.error) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        emptyEl.textContent = '获取失败: ' + (response?.error || '无响应，请检查网络');
        sectionsEl.innerHTML = '';
        return;
      }
      if (!response.data) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        emptyEl.textContent = '获取失败: 图片数据为空';
        sectionsEl.innerHTML = '';
        return;
      }
      const b64 = response.data.replace(/^data:[^;]+;base64,/, '');
      const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      const mimeMatch = url.match(/\.(jpe?g|png|webp|tiff?|heic)/i);
      const mime = mimeMatch
        ? 'image/' + mimeMatch[1].toLowerCase().replace('jpg', 'jpeg')
        : 'image/jpeg';
      const blob = new Blob([bytes], { type: mime });
      const file = new File([blob], fileNameEl.textContent, { type: mime });
      fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';
      handleExifFile(file);
    });
  }

  async function scanPageImages() {
    const container = utils.get('exif-page-images');
    container.innerHTML = '<div class="empty-state">正在扫描...</div>';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        container.innerHTML = '<div class="empty-state">无法获取当前页面</div>';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const imgs = [];
          document.querySelectorAll('img[src]').forEach(img => {
            if (img.src && img.naturalWidth > 50 && img.naturalHeight > 50) {
              if (/^(blob:|data:)/i.test(img.src)) return;
              imgs.push({
                src: img.src,
                alt: img.alt || '',
                w: img.naturalWidth,
                h: img.naturalHeight,
              });
            }
          });
          document.querySelectorAll('[style*="background"]').forEach(el => {
            const m = el.style.backgroundImage.match(/url\(["']?(.*?)["']?\)/);
            if (m && m[1] && !/^(blob:|data:)/i.test(m[1])) {
              imgs.push({ src: m[1], alt: '', w: 0, h: 0 });
            }
          });
          const unique = [...new Map(imgs.map(i => [i.src, i])).values()];
          return unique.slice(0, 50);
        },
      });

      const images = results?.[0]?.result || [];
      if (images.length === 0) {
        container.innerHTML = '<div class="empty-state">未找到图片</div>';
        return;
      }

      let html =
        '<div class="exif-page-count">找到 ' + images.length + ' 张图片（点击查看 EXIF）</div>';
      images.forEach(img => {
        html += '<div class="exif-page-item" data-url="' + utils.escapeHtml(img.src) + '">';
        html += '<img class="exif-page-thumb" src="' + utils.escapeHtml(img.src) + '" alt="">';
        html += '<div class="exif-page-info">';
        if (img.w) html += '<span>' + img.w + ' x ' + img.h + '</span>';
        html +=
          '<span class="exif-page-src">' +
          utils.escapeHtml(img.alt || img.src.split('/').pop()) +
          '</span>';
        html += '</div></div>';
      });
      container.innerHTML = html;

      container.querySelectorAll('.exif-page-item').forEach(item => {
        item.addEventListener('click', () => {
          fetchExifFromUrl(item.dataset.url);
        });
      });
    } catch (e) {
      container.innerHTML =
        '<div class="empty-state">扫描失败: ' + utils.escapeHtml(e.message) + '</div>';
    }
  }

  function checkExifPending() {
    chrome.storage.local.get(['exif_pending_url'], result => {
      const url = result.exif_pending_url;
      if (!url) return;
      chrome.storage.local.remove(['exif_pending_url']);
      switchExifMode('url');
      utils.get('exif-url-input').value = url;
      fetchExifFromUrl(url);
    });
  }

  function copyExifData() {
    if (!lastExifData) {
      utils.showToast('请先解析 EXIF 数据', 'warning');
      return;
    }
    utils.copyText(JSON.stringify(lastExifData, null, 2));
    utils.showToast('已复制 EXIF JSON', 'success');
  }

  function clearExif() {
    var resultEl = utils.get('exif-result');
    var emptyEl = utils.get('exif-empty');
    var sectionsEl = utils.get('exif-sections');
    var previewImg = utils.get('exif-preview-img');
    if (resultEl) resultEl.classList.add('hidden');
    if (emptyEl) emptyEl.classList.add('hidden');
    if (sectionsEl) sectionsEl.innerHTML = '';
    if (previewImg) previewImg.src = '';
    lastExifData = null;
  }

  return {
    initExifDragDrop,
    switchExifMode,
    fetchExifFromUrl,
    scanPageImages,
    checkExifPending,
    copyExifData,
    clearExif,
    get lastExifData() {
      return lastExifData;
    },
    set lastExifData(v) {
      lastExifData = v;
    },
  };
})();
