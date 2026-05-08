// 灵眸 - EXIF Viewer
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastExifData = null;

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
      return `f/${value}`;
    case 'exposure':
      if (value < 1) {
        const denom = Math.round(1 / value);
        return `1/${denom}s`;
      }
      return `${value}s`;
    case 'ev':
      return `${value >= 0 ? '+' : ''}${value} EV`;
    case 'focal':
      return `${value}mm`;
    case 'pixel':
      return `${value} px`;
    case 'altitude':
      return `${value} m`;
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
  return `${d}°${m}'${s.toFixed(2)}"${dir}`;
}

function getExifEls() {
  return {
    result: utils.get('exif-result'),
    empty: utils.get('exif-empty'),
    sections: utils.get('exif-sections'),
    preview: utils.get('exif-preview-img'),
    fileName: utils.get('exif-file-name'),
    fileSize: utils.get('exif-file-size'),
  };
}

function resetExifPanel(msg) {
  let els = getExifEls();
  if (!els.result || !els.empty || !els.sections) return null;
  els.result.classList.add('hidden');
  els.empty.classList.add('hidden');
  utils.setEmpty('exif-sections', msg);
  return els;
}

function showExifError(els, msg) {
  if (!els || !els.result || !els.empty) return;
  els.result.classList.remove('hidden');
  els.empty.classList.remove('hidden');
  if (msg !== undefined) els.empty.textContent = msg;
  if (els.sections) els.sections.innerHTML = '';
}

function exifRowHtml(label, value, raw) {
  return `<div class="exif-row"><span class="exif-label">${label}</span><span class="exif-value" title="${utils.escapeHtml(String(raw != null ? raw : value))}">${utils.escapeHtml(String(value))}</span></div>`;
}

async function handleExifFile(file) {
  let els = resetExifPanel('正在解析...');
  if (!els) return;

  const objectUrl = URL.createObjectURL(file);
  if (els.preview) {
    els.preview.onload = function () {
      URL.revokeObjectURL(objectUrl);
    };
    els.preview.src = objectUrl;
  }
  if (els.fileName) els.fileName.textContent = file.name;
  if (els.fileSize) els.fileSize.textContent = `${(file.size / 1024).toFixed(1)} KB`;

  try {
    if (typeof window.exifr === 'undefined') {
      showExifError(els, 'EXIF 库加载中，请稍候...');
      return;
    }
    const exif = await window.exifr.parse(file, {
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
      showExifError(els);
      lastExifData = null;
      return;
    }

    lastExifData = exif;
    els.result.classList.remove('hidden');

    let html = '';
    EXIF_SECTIONS.forEach(function (section) {
      const hasData = section.fields.some(function (f) {
        return exif[f.key] !== undefined && exif[f.key] !== null;
      });
      if (!hasData) return;

      html += '<div class="exif-section">';
      html += `<div class="exif-section-title">${section.title}</div>`;

      section.fields.forEach(function (field) {
        if (exif[field.key] === undefined || exif[field.key] === null) return;

        if (field.format === 'gps') {
          const coord = exif[field.key];
          let coordStr = `${formatGpsDms(coord)} (${coord.toFixed(6)})`;
          if (field.key === 'longitude') coordStr = coordStr.replace('N', 'E').replace('S', 'W');
          html += exifRowHtml(field.label, coordStr, coord);
          return;
        }

        const formatted = formatExifValue(exif[field.key], field.format);
        if (!formatted) return;
        html += exifRowHtml(field.label, formatted, exif[field.key]);
      });

      if (
        exif.latitude !== undefined &&
        exif.longitude !== undefined &&
        section.title === 'GPS 信息'
      ) {
        html += `<div class="exif-gps-row"><a class="exif-gps-link" href="https://www.google.com/maps?q=${exif.latitude},${exif.longitude}" target="_blank">在地图中查看</a></div>`;
      }

      html += '</div>';
    });

    els.sections.innerHTML = html || '';
    utils.showToast('EXIF 解析完成', 'success');
  } catch (e) {
    showExifError(els, `解析失败: ${e.message}`);
    lastExifData = null;
  }
}

function initExifDragDrop() {
  const area = utils.get('exif-upload-area');
  const fileInput = utils.get('exif-file-input');
  if (!area || !fileInput) return;

  area.addEventListener('click', function () {
    return fileInput.click();
  });
  fileInput.addEventListener('change', function (e) {
    if (e.target.files[0]) handleExifFile(e.target.files[0]);
  });
  area.addEventListener('dragover', function (e) {
    e.preventDefault();
    area.classList.add('dragover');
  });
  area.addEventListener('dragleave', function () {
    return area.classList.remove('dragover');
  });
  area.addEventListener('drop', function (e) {
    e.preventDefault();
    area.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) handleExifFile(file);
  });
}

function switchExifMode(mode) {
  document.querySelectorAll('.exif-mode-btn').forEach(function (b) {
    return b.classList.toggle('active', b.dataset.mode === mode);
  });
  const localEl = utils.get('exif-mode-local');
  const urlEl = utils.get('exif-mode-url');
  const pageEl = utils.get('exif-mode-page');
  if (localEl) localEl.classList.toggle('hidden', mode !== 'local');
  if (urlEl) urlEl.classList.toggle('hidden', mode !== 'url');
  if (pageEl) pageEl.classList.toggle('hidden', mode !== 'page');
}

async function fetchExifFromUrl(url) {
  let els = resetExifPanel('正在获取图片...');
  if (!els) return;
  if (els.preview) els.preview.src = url;
  if (els.fileName) els.fileName.textContent = url.split('/').pop() || url;
  if (els.fileSize) els.fileSize.textContent = '';

  chrome.runtime.sendMessage({ type: 'FETCH_IMAGE', url: url }, function (response) {
    if (chrome.runtime.lastError) {
      showExifError(els, `获取失败: ${chrome.runtime.lastError.message}`);
      return;
    }
    if (!response || response.error) {
      showExifError(
        els,
        `获取失败: ${response && response.error ? response.error : '无响应，请检查网络'}`
      );
      return;
    }
    if (!response.data) {
      showExifError(els, '获取失败: 图片数据为空');
      return;
    }
    const b64 = response.data.replace(/^data:[^;]+;base64,/, '');
    const bytes = Uint8Array.from(atob(b64), function (c) {
      return c.charCodeAt(0);
    });
    const mimeMatch = url.match(/\.(jpe?g|png|webp|tiff?|heic)/i);
    const mime = mimeMatch
      ? `image/${mimeMatch[1].toLowerCase().replace('jpg', 'jpeg')}`
      : 'image/jpeg';
    const blob = new Blob([bytes], { type: mime });
    const fname = els.fileName ? els.fileName.textContent : '';
    const file = new File([blob], fname, { type: mime });
    if (els.fileSize) els.fileSize.textContent = `${(file.size / 1024).toFixed(1)} KB`;
    handleExifFile(file);
  });
}

async function scanPageImages() {
  const container = utils.get('exif-page-images');
  if (!container) return;
  utils.setEmpty('exif-page-images', '正在扫描...');

  try {
    const tab = await utils.getActiveTab();
    if (!tab || !tab.url) {
      utils.setEmpty('exif-page-images', '无法获取当前页面');
      return;
    }

    const images =
      (await utils.execInTabData(
        tab.id,
        function () {
          const imgs = [];
          document.querySelectorAll('img[src]').forEach(function (img) {
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
          document.querySelectorAll('[style*="background"]').forEach(function (el) {
            const m = el.style.backgroundImage.match(/url\(["']?(.*?)["']?\)/);
            if (m && m[1] && !/^(blob:|data:)/i.test(m[1])) {
              imgs.push({ src: m[1], alt: '', w: 0, h: 0 });
            }
          });
          const unique = new Map();
          imgs.forEach(function (i) {
            if (!unique.has(i.src)) unique.set(i.src, i);
          });
          return Array.from(unique.values()).slice(0, 50);
        },
        { world: 'ISOLATED' }
      )) || [];
    if (images.length === 0) {
      utils.setEmpty('exif-page-images', '未找到图片');
      return;
    }

    let html = `<div class="exif-page-count">找到 ${images.length} 张图片（点击查看 EXIF）</div>`;
    images.forEach(function (img) {
      html += `<div class="exif-page-item" data-url="${utils.escapeHtml(img.src)}">
        <img class="exif-page-thumb" src="${utils.escapeHtml(img.src)}" alt="">
        <div class="exif-page-info">
          ${img.w ? `<span>${img.w} x ${img.h}</span>` : ''}
          <span class="exif-page-src">${utils.escapeHtml(img.alt || img.src.split('/').pop())}</span>
        </div></div>`;
    });
    container.innerHTML = html;

    container.querySelectorAll('.exif-page-item').forEach(function (item) {
      item.addEventListener('click', function () {
        fetchExifFromUrl(item.dataset.url);
      });
    });
  } catch (e) {
    utils.setEmpty('exif-page-images', `扫描失败: ${e.message}`);
  }
}

function checkExifPending() {
  chrome.storage.local.get(['exif_pending_url'], function (result) {
    const url = result.exif_pending_url;
    if (!url) return;
    chrome.storage.local.remove(['exif_pending_url']);
    switchExifMode('url');
    const urlInput = utils.get('exif-url-input');
    if (urlInput) urlInput.value = url;
    fetchExifFromUrl(url);
  });
}

function copyExifData() {
  lastExifData = utils.requireInput(lastExifData, '请先解析 EXIF 数据');
  if (!lastExifData) return;
  utils.copyAndToast(JSON.stringify(lastExifData, null, 2), '已复制 EXIF JSON');
}

function clearExif() {
  const els = getExifEls();
  if (els.result) els.result.classList.add('hidden');
  if (els.empty) els.empty.classList.add('hidden');
  if (els.sections) els.sections.innerHTML = '';
  if (els.preview) els.preview.src = '';
  lastExifData = null;
}

export {
  initExifDragDrop,
  switchExifMode,
  fetchExifFromUrl,
  scanPageImages,
  checkExifPending,
  copyExifData,
  clearExif,
  lastExifData,
};
