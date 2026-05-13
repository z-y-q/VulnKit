// 灵眸 - XSS Scanner (barrel)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { XSS_DATA } from './vk-payload-data.js';
import { getXssScanPayloads } from './vk-xss-data.js';

var _scanPayloads = null;

async function ensureXssPayloads() {
  if (_scanPayloads) return _scanPayloads;
  _scanPayloads = await getXssScanPayloads();
  return _scanPayloads;
}
import { analyzeDomSinks } from './vk-xss-sinks.js';
import { COPY_SVG } from './vk-icons.js';
import { saveScanResult } from './vk-scan-history.js';

import {
  xssPoints,
  xssFilterType,
  xssSearchText,
  xssSortKey,
  lastVerifyResults,
  setXssPointsVal,
  appendXssPoints,
  setXssFilterType as _setXssFilterType,
  setXssSearchText as _setXssSearchText,
  setXssSortKey as _setXssSortKey,
  setLastVerifyResults,
} from './vk-xss-state.js';
import { verifySinglePoint, renderVerifyResults, updateVerifyStatus } from './vk-xss-verify.js';
import {
  startXssIntercept as _startXssIntercept,
  stopXssIntercept as _stopXssIntercept,
  updateXssInterceptStatus,
  harvestXssParamsFromDom,
} from './vk-xss-intercept.js';
import {
  runAutoFuzz,
  stopAutoFuzz,
  renderAutoFuzzResults,
  exportAutoFuzzResults,
  generatePocHtml,
  getAutoFuzzFindings,
  autofuzzState,
} from './vk-xss-autofuzz.js';

var REFLECTION_PROBE = 'vkprobe\'"><xyz';

var XSS_SORT_FNS = {
  source: function (a, b) {
    return (a.source || '').localeCompare(b.source || '');
  },
  url: function (a, b) {
    return (a.url || '').localeCompare(b.url || '');
  },
  param: function (a, b) {
    return (a.param || '').localeCompare(b.param || '');
  },
};

// ====== Filter / Render ======

function getFilteredXssPoints() {
  let list = xssPoints;
  if (xssFilterType !== 'all') {
    list = list.filter(function (p) {
      return p.source === xssFilterType;
    });
  }
  if (xssSearchText) {
    let lower = xssSearchText.toLowerCase();
    list = list.filter(function (p) {
      return (
        (p.url && p.url.toLowerCase().indexOf(lower) !== -1) ||
        (p.param && p.param.toLowerCase().indexOf(lower) !== -1) ||
        (p.source && p.source.toLowerCase().indexOf(lower) !== -1)
      );
    });
  }
  return list;
}

function renderXssPoints() {
  const container = utils.get('xssscan-results');
  const countEl = utils.get('xssscan-count');
  if (!container) return;
  var consoleBtn = utils.get('xss-send-console-btn');
  var copyMdBtn = utils.get('xssscan-copy-md-btn');
  if (consoleBtn) consoleBtn.hidden = xssPoints.length === 0;
  if (copyMdBtn) copyMdBtn.hidden = xssPoints.length === 0;
  const filtered = utils.applySort(getFilteredXssPoints(), xssSortKey, XSS_SORT_FNS);
  if (countEl) {
    let hasFilter = xssFilterType !== 'all' || xssSearchText;
    countEl.innerHTML =
      '<span class="stat-badge stat-total">共 ' +
      xssPoints.length +
      ' 个注入点</span>' +
      (hasFilter ? '<span class="stat-badge stat-found">显示 ' + filtered.length + '</span>' : '');
  }
  if (filtered.length === 0) {
    utils.setEmpty('xssscan-results', '暂无注入点');
    return;
  }
  const sourceLabels = { link: '链接', form: '表单', url: 'URL', ajax: 'AJAX' };
  const sourceColors = { link: '#4A90E2', form: '#e67e22', url: '#27ae60', ajax: '#e74c3c' };

  let html =
    '<div class="xssscan-check-all-row"><label><input type="checkbox" id="xssscan-check-all" checked> 全选</label></div>';
  filtered.forEach(function (p, i) {
    var shortUrl = p.url.length > 40 ? p.url.substring(0, 37) + '...' : p.url;
    html +=
      '<div class="xssscan-card">' +
      '<div class="xssscan-card-top">' +
      '<input type="checkbox" class="xssscan-point-check" data-idx="' +
      i +
      '" checked>' +
      '<span class="xssscan-source-tag" style="background:' +
      (sourceColors[p.source] || '#999') +
      '">' +
      (sourceLabels[p.source] || p.source) +
      '</span>' +
      '<span class="xssscan-method-tag">' +
      utils.escapeHtml(p.method) +
      '</span>' +
      '<button class="xssscan-copy-btn" data-copy="' +
      utils.escapeHtml(p.url) +
      '" title="复制URL">' +
      COPY_SVG +
      '</button>' +
      '</div>' +
      '<div class="xssscan-card-param"><span class="xssscan-param-label">参数:</span> ' +
      utils.escapeHtml(p.param) +
      '</div>' +
      '<div class="xssscan-card-url" title="' +
      utils.escapeHtml(p.url) +
      '">' +
      utils.escapeHtml(shortUrl) +
      '</div>' +
      '</div>';
  });
  container.innerHTML = html;

  const checkAll = container.querySelector('#xssscan-check-all');
  if (checkAll) {
    checkAll.addEventListener('change', function () {
      container.querySelectorAll('.xssscan-point-check').forEach(function (cb) {
        cb.checked = checkAll.checked;
      });
    });
  }

  container.querySelectorAll('.xssscan-copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      var url = btn.getAttribute('data-copy');
      if (url) {
        utils.copyText(url);
        utils.showToast('URL 已复制', 'success');
      }
    });
  });
}

function getSelectedXssPoints() {
  const filtered = getFilteredXssPoints();
  const checks = document.querySelectorAll('.xssscan-point-check');
  return filtered.filter((_, i) => {
    const cb = checks[i];
    return cb && cb.checked;
  });
}

// ====== Payload encoding ======

function encodePayload(payload, encoding) {
  switch (encoding) {
    case 'url':
      return encodeURIComponent(payload);
    case 'html':
      return payload
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    case 'base64':
      return btoa(unescape(encodeURIComponent(payload)));
    default:
      return payload;
  }
}

function buildXssTestUrl(point, payload) {
  try {
    const url = new URL(point.url);
    if (point.method === 'GET') {
      url.searchParams.set(point.param, payload);
      return url.href;
    }
    if (point.method === 'POST') {
      return { url: point.url, method: 'POST', param: point.param, payload: payload };
    }
    return url.href;
  } catch (_) {
    console.debug('URL construction failed', _);
    return null;
  }
}

function getSelectedPayload() {
  const selectEl = utils.get('xssscan-payload-select');
  const customEl = utils.get('xssscan-custom-payload');
  if (customEl && customEl.value.trim()) return customEl.value.trim();
  if (selectEl && selectEl.value) return selectEl.value;
  return _scanPayloads ? _scanPayloads[0].value : '<script>console.log(1)</script>';
}

function getEncodedPayload() {
  let raw = getSelectedPayload();
  let encoding = (utils.get('xssscan-encoding') || {}).value || 'none';
  return encodePayload(raw, encoding);
}

// ====== Intercept wrappers (inject renderXssPoints to avoid circular deps) ======

async function startXssIntercept() {
  return _startXssIntercept(renderXssPoints);
}

async function stopXssIntercept() {
  return _stopXssIntercept(renderXssPoints);
}

// ====== UI handlers ======

async function handleXssHarvest() {
  const statusEl = utils.get('xssscan-status');
  if (statusEl) {
    statusEl.textContent = '正在采集页面参数...';
    statusEl.style.color = '#4A90E2';
  }
  try {
    const domPoints = await harvestXssParamsFromDom();
    const existing = new Set(xssPoints.map(p => `${p.url}|${p.param}|${p.method}`));
    const newPoints = domPoints.filter(p => !existing.has(`${p.url}|${p.param}|${p.method}`));
    appendXssPoints(newPoints);
    renderXssPoints();
    if (statusEl) {
      statusEl.textContent = `采集完成，新增 ${newPoints.length} 个注入点，共 ${xssPoints.length} 个`;
      statusEl.style.color = '#27ae60';
    }
    if (newPoints.length > 0) utils.showToast(`发现 ${newPoints.length} 个注入点`, 'success');
    else utils.showToast('未发现新的注入点', 'info');
    utils.getCurrentDomain().then(function (d) {
      if (d) saveScanResult('xssscan', d, getFindings());
    });
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = `采集失败: ${e.message}`;
      statusEl.style.color = '#e74c3c';
    }
    utils.showToast('采集失败', 'error');
  }
}

async function handleBatchOpenXss() {
  const selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }
  let postCount = selected.filter(p => p.method === 'POST').length;
  let warn =
    postCount > 0
      ? `即将对 ${selected.length} 个注入点进行 XSS 测试（含 ${postCount} 个 POST 表单自动提交），是否继续？`
      : `即将对 ${selected.length} 个注入点打开测试页面，是否继续？`;
  let ok = await utils.confirmDanger(warn);
  if (!ok) return;
  const payload = getEncodedPayload();
  const getPoints = selected.filter(p => p.method !== 'POST');
  const postPoints = selected.filter(p => p.method === 'POST');
  let opened = 0;

  for (const point of getPoints) {
    const result = buildXssTestUrl(point, payload);
    if (!result || typeof result === 'object') continue;
    chrome.tabs.create({ url: result, active: false });
    opened++;
  }

  if (postPoints.length > 0) {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }
    for (const point of postPoints) {
      const targetUrl = point.url;
      try {
        await utils.execInTab(
          tab.id,
          (url, param, pl) => {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = url;
            form.target = '_blank';
            form.style.display = 'none';
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = param;
            input.value = pl;
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
            form.remove();
          },
          { world: 'ISOLATED', args: [targetUrl, point.param, payload] }
        );
        opened++;
      } catch (_) {
        try {
          const escAttr = s =>
            s
              .replace(/&/g, '&amp;')
              .replace(/"/g, '&quot;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;');
          const formHtml = `<form method="POST" action="${escAttr(targetUrl)}"><input type="hidden" name="${escAttr(point.param)}" value="${escAttr(payload)}"></form><script>document.forms[0].submit()<\/script>`;
          const blobUrl = URL.createObjectURL(new Blob([formHtml], { type: 'text/html' }));
          chrome.tabs.create({ url: blobUrl, active: false });
          opened++;
        } catch (_) {
          console.debug('blob URL fallback also failed', _);
        }
      }
    }
  }

  const methodInfo = postPoints.length > 0 ? '（POST 通过页面内表单提交）' : '';
  utils.showToast(`已打开 ${opened} 个测试页面${methodInfo}`, 'success');
}

async function handleVerifyReflection() {
  let selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }

  let probe = REFLECTION_PROBE;
  let statusEl = utils.get('xssscan-status');
  let verifyPanel = utils.get('xssscan-verify-results');
  let verifyList = utils.get('xssscan-verify-list');

  if (statusEl) {
    statusEl.textContent = '正在检查反射...';
    statusEl.style.color = '#4A90E2';
  }
  if (verifyPanel) verifyPanel.style.display = '';

  let results = [];
  for (let i = 0; i < selected.length; i++) {
    if (statusEl) statusEl.textContent = `检查反射中... (${i + 1}/${selected.length})`;
    results.push(await verifySinglePoint(selected[i], probe, probe));
  }

  renderVerifyResults(results, verifyList);
  updateVerifyStatus(results, statusEl);
  setLastVerifyResults(results);
}

function handleOpenReflected() {
  var reflected = lastVerifyResults.filter(function (r) {
    return r.status === 'reflected';
  });
  if (reflected.length === 0) {
    utils.showToast('没有已验证的反射点', 'warning');
    return;
  }
  var payload = getEncodedPayload();
  var opened = 0;
  reflected.forEach(function (r) {
    var point = r.point;
    if (point.method === 'POST') {
      var targetUrl = buildXssTestUrl(point, payload);
      if (targetUrl && typeof targetUrl === 'object') {
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = targetUrl.url;
        form.target = '_blank';
        form.style.display = 'none';
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = targetUrl.param;
        input.value = targetUrl.payload;
        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
        form.remove();
        opened++;
      }
      return;
    }
    var url = buildXssTestUrl(point, payload);
    if (url && typeof url === 'string') {
      chrome.tabs.create({ url: url, active: false });
      opened++;
    }
  });
  utils.showToast('已打开 ' + opened + ' 个反射点测试页面', 'success');
}

function handleCopyXssUrls() {
  const selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }
  const payload = getEncodedPayload();
  const lines = selected
    .map(p => {
      const result = buildXssTestUrl(p, payload);
      if (!result) return null;
      if (typeof result === 'object') {
        return `[POST] ${result.url}\n  参数: ${result.param}=${result.payload}`;
      }
      return result;
    })
    .filter(Boolean);
  if (lines.length === 0) {
    utils.showToast('无法生成测试URL', 'warning');
    return;
  }
  utils.copyText(lines.join('\n'));
  utils.showToast(`已复制 ${lines.length} 个URL`, 'success');
}

function copyMarkdown() {
  var selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }
  var rows = selected.map(function (p) {
    return [p.url || '', p.param || '', p.source || '', p.method || ''];
  });
  var md = '# XSS Injection Points\n\n';
  md += '**Total:** ' + selected.length + '\n\n';
  md += utils.buildMarkdownTable(['URL', 'Parameter', 'Source', 'Payload'], rows);
  utils.copyAndToast(md, '已复制 Markdown 表格');
}

// ====== Init / Clear / Export ======

async function initXssScanPayloadSelect() {
  const payloads = await ensureXssPayloads();
  const select = utils.get('xssscan-payload-select');
  if (!select) return;
  payloads.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.value;
    opt.textContent = p.name;
    select.appendChild(opt);
  });
  if (XSS_DATA) {
    Object.keys(XSS_DATA).forEach(cat => {
      const group = document.createElement('optgroup');
      group.label = cat;
      XSS_DATA[cat].forEach(payload => {
        const opt = document.createElement('option');
        opt.value = payload;
        opt.textContent = payload.length > 50 ? `${payload.substring(0, 47)}...` : payload;
        group.appendChild(opt);
      });
      select.appendChild(group);
    });
  }
}

function clearResults() {
  setXssPointsVal([]);
  renderXssPoints();
  updateXssInterceptStatus();
}

function exportData() {
  if (xssPoints.length === 0) {
    utils.showToast('没有可导出的注入点', 'warning');
    return;
  }
  let rows = xssPoints.map(function (p) {
    return [p.source, p.url, p.param, p.method];
  });
  utils.buildCsv(['Source', 'URL', 'Param', 'Method'], rows, `lingmou-xss-${Date.now()}.csv`);
}

// ====== Filter / Search setters ======

function setXssFilterType(v) {
  _setXssFilterType(v);
}

function setXssSearchText(v) {
  _setXssSearchText(v);
  renderXssPoints();
}

var setFilter = function (v) {
  setXssFilterType(v);
  renderXssPoints();
};
var setSearch = setXssSearchText;

// ====== Auto Fuzz handlers ======

async function handleAutoFuzz() {
  var selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }
  var ok = await utils.confirmDanger('即将对 ' + selected.length + ' 个注入点进行自动 Fuzz 测试');
  if (!ok) return;
  var statusEl = utils.get('xssscan-autofuzz-status');
  var panel = utils.get('xssscan-autofuzz-results');
  var container = utils.get('xssscan-autofuzz-list');
  if (panel) panel.style.display = '';
  var results = await runAutoFuzz(selected, 5, function (progress) {
    if (statusEl) statusEl.textContent = progress.text;
  });
  renderAutoFuzzResults(container, results);
}

function handleStopAutoFuzz() {
  stopAutoFuzz();
  var statusEl = utils.get('xssscan-autofuzz-status');
  if (statusEl) statusEl.textContent = '正在停止...';
}

function handleAutoFuzzExport() {
  exportAutoFuzzResults('csv');
}

function handleGeneratePoc() {
  generatePocHtml();
}

// ====== getFindings for unified report ======

function getFindings() {
  var pointFindings = xssPoints.map(function (p) {
    return {
      severity: 'high',
      title: 'XSS 注入点',
      detail: p.source + ' | ' + p.param + ' (' + p.method + ')',
      module: 'xss',
      url: p.url,
    };
  });
  var fuzzFindings = getAutoFuzzFindings();
  return pointFindings.concat(fuzzFindings);
}

// ====== Export ======

function sortResults(key) {
  _setXssSortKey(key);
  renderXssPoints();
}

export {
  startXssIntercept,
  stopXssIntercept,
  updateXssInterceptStatus,
  renderXssPoints,
  handleXssHarvest,
  handleBatchOpenXss,
  handleVerifyReflection,
  handleOpenReflected,
  handleCopyXssUrls,
  copyMarkdown,
  initXssScanPayloadSelect,
  clearResults,
  exportData,
  analyzeDomSinks,
  xssPoints,
  xssFilterType,
  xssSearchText,
  setXssFilterType,
  setXssSearchText,
  setFilter,
  setSearch,
  getFindings,
  sendToConsole,
  handleAutoFuzz,
  handleStopAutoFuzz,
  handleAutoFuzzExport,
  handleGeneratePoc,
  sortResults,
};

function sendToConsole() {
  if (xssPoints.length === 0) {
    utils.showToast('没有 XSS 注入点', 'warning');
    return;
  }
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (!tabs || !tabs[0] || !tabs[0].id) return;
    var data = xssPoints.map(function (p) {
      return { source: p.source, param: p.param, method: p.method, url: p.url };
    });
    chrome.scripting.executeScript(
      {
        target: { tabId: tabs[0].id },
        world: 'MAIN',
        func: function (points) {
          console.group('%c[灵眸] XSS 注入点', 'color: #ff4444; font-weight: bold');
          console.table(points);
          console.groupEnd();
          console.warn('%c[灵眸] 共发现 ' + points.length + ' 个 XSS 注入点', 'color: #ff4444');
        },
        args: [data],
      },
      function () {
        if (!chrome.runtime.lastError) {
          utils.showToast('已输出 ' + xssPoints.length + ' 个注入点到 Console', 'success');
        }
      }
    );
  });
}
