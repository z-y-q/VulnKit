// 灵眸 - History Archive (Wayback Machine)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastHistoryResults = [];
let allHistoryResults = [];

function showHistoryQuickLinks(domain) {
  if (!domain) return;

  const quickLinks = utils.get('history-quick-links');
  if (!quickLinks) return;
  quickLinks.innerHTML =
    `<button class="quick-link-btn" data-url="https://web.archive.org/web/*/${encodeURIComponent(domain)}/*">Wayback Machine 日历</button>` +
    '<button id="history-latest-btn" class="quick-link-btn quick-latest hidden" data-url="">查看最新快照</button>';

  if (!showHistoryQuickLinks._bound) {
    const panel = utils.get('panel-history');
    if (panel) {
      panel.addEventListener('click', e => {
        const btn = e.target.closest('[data-url]');
        if (btn && btn.dataset.url) {
          chrome.tabs.create({ url: btn.dataset.url });
          e.preventDefault();
        }
      });
      showHistoryQuickLinks._bound = true;
    }
  }
}

function buildCdxUrl(domain) {
  const ALLOWED_MATCH = ['domain', 'host', 'exact', 'prefix', 'suffix'];
  const matchType = (utils.get('history-match-type') || {}).value || 'domain';
  const outputType = (utils.get('history-output-type') || {}).value || 'json';
  const safeMatch = ALLOWED_MATCH.indexOf(matchType) !== -1 ? matchType : 'domain';
  const safeOutput = outputType === 'json' || outputType === 'text' ? outputType : 'json';
  const fields =
    (utils.get('history-fields') || {}).value || 'timestamp,original,statuscode,mimetype';
  const from = (utils.get('history-from') || {}).value || '';
  const to = (utils.get('history-to') || {}).value || '';
  const typeFilter = ((utils.get('history-type-filter') || {}).value || '').trim();

  let url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&collapse=urlkey&matchType=${encodeURIComponent(safeMatch)}&output=${encodeURIComponent(safeOutput)}&fl=${encodeURIComponent(fields)}`;
  if (from) url += `&from=${from}`;
  if (to) url += `&to=${to}`;
  if (typeFilter) {
    const types = typeFilter
      .toLowerCase()
      .split(/[,，\s]+/)
      .filter(Boolean);
    types.forEach(t => {
      url += `&filter=original:.*\\.${encodeURIComponent(t)}($|\\?.*)`;
    });
  }
  url += '&limit=10000';
  return url;
}

function getFileType(url) {
  try {
    const pathname = new URL(url).pathname;
    const ext = pathname.split('.').pop().toLowerCase().split('?')[0].split('#')[0];
    if (ext && ext.length < 10) return ext;
    return '';
  } catch {
    return '';
  }
}

function filterByType(items, typeFilter) {
  if (!typeFilter) return items;
  const types = typeFilter
    .toLowerCase()
    .split(/[,，\s]+/)
    .filter(Boolean);
  if (types.length === 0) return items;
  return items.filter(item => {
    const fileType = getFileType(item.url || '');
    return types.some(t => fileType === t || (item.mimetype || '').includes(t));
  });
}

function parseCdxText(text) {
  return text
    .split('\n')
    .filter(line => line.trim())
    .map(line => {
      const parts = line.split(' ');
      return { raw: line, url: parts[parts.length - 1] || line };
    });
}

function parseCdxJson(data) {
  if (!Array.isArray(data) || data.length < 2) return [];
  const fieldCount = data[0].length;
  return data.slice(1).map(row => {
    const obj = { raw: row.join(' ') };
    row.forEach((val, i) => {
      obj[data[0][i]] = val;
    });
    obj.url = row[fieldCount - 1] || '';
    return obj;
  });
}

function renderHistoryResults(items, isFilter) {
  lastHistoryResults = items;
  if (!isFilter) allHistoryResults = items;
  const container = utils.get('history-timeline');
  const fieldsEl = utils.get('history-fields');
  const fields = fieldsEl ? fieldsEl.value : '';
  const hasTs = fields.includes('timestamp');

  if (items.length === 0) {
    utils.setEmpty('history-timeline', '未找到历史档案');
    utils.setStatus('history-status', '无结果');
    return;
  }

  utils.setStatus('history-status', `共 ${items.length} 条记录`);
  const totalEl = utils.get('history-total');
  if (totalEl) totalEl.textContent = items.length;

  if (hasTs) {
    const timestamps = items
      .map(i => i.timestamp || '')
      .filter(Boolean)
      .sort();
    if (timestamps.length > 0) {
      const fmt = ts => `${ts.substring(0, 4)}-${ts.substring(4, 6)}-${ts.substring(6, 8)}`;
      const firstEl = utils.get('history-first');
      const lastEl = utils.get('history-last');
      const summaryEl = utils.get('history-summary');
      if (firstEl) firstEl.textContent = fmt(timestamps[0]);
      if (lastEl) lastEl.textContent = fmt(timestamps[timestamps.length - 1]);
      if (summaryEl) summaryEl.classList.remove('hidden');
    }
  }

  let html = '';
  items.slice(0, 200).forEach(item => {
    const url = item.url || item.raw;
    const ts = item.timestamp || '';
    const status = item.statuscode || '';
    const mime = item.mimetype || '';
    const dateStr = ts
      ? `${ts.substring(0, 4)}-${ts.substring(4, 6)}-${ts.substring(6, 8)} ${ts.substring(8, 10)}:${ts.substring(10, 12)}`
      : '';
    const waybackUrl = ts
      ? `https://web.archive.org/web/${ts}/${url}`
      : `https://web.archive.org/web/*/${encodeURIComponent(url)}`;

    let statusClass = 'status-other';
    if (status === '200') statusClass = 'status-200';
    else if (status === '301' || status === '302') statusClass = 'status-301';
    else if (status === '404') statusClass = 'status-404';

    html +=
      `<div class="timeline-item">` +
      (hasTs ? `<span class="timeline-date">${utils.escapeHtml(dateStr)}</span>` : '') +
      (status
        ? `<span class="timeline-status ${utils.escapeHtml(statusClass)}">${utils.escapeHtml(status)}</span>`
        : '') +
      (mime ? `<span class="timeline-status status-other">${utils.escapeHtml(mime)}</span>` : '') +
      `<span class="timeline-url" data-wayback="${utils.escapeHtml(waybackUrl)}" title="${utils.escapeHtml(url)}">${utils.escapeHtml(url)}</span>` +
      `<button class="timeline-open" data-url="${utils.escapeHtml(waybackUrl)}">查看</button>` +
      `</div>`;
  });
  if (items.length > 200) html += utils.emptyHtml('仅显示前 200 条');
  container.innerHTML = html;
}

function extractDomain(input) {
  try {
    const url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
    return url.hostname;
  } catch {
    return input.trim();
  }
}

async function queryHistory() {
  let domainEl = utils.get('history-domain');
  let raw = domainEl ? domainEl.value.trim() : '';
  if (!raw) {
    const tab = await utils.getActiveTab();
    if (!tab?.url) {
      utils.showToast('请输入域名或打开一个网页', 'warning');
      return;
    }
    raw = tab.url;
  }
  const domain = extractDomain(raw);
  const domainInput = utils.get('history-domain');
  if (domainInput) domainInput.value = domain;

  showHistoryQuickLinks(domain);
  utils.setStatus('history-status', '正在查询...');
  const timeline = utils.get('history-timeline');
  if (timeline) timeline.innerHTML = '';
  const summary = utils.get('history-summary');
  if (summary) summary.classList.add('hidden');

  const cdxUrl = buildCdxUrl(domain);
  const outputTypeEl = utils.get('history-output-type');
  let outputType = outputTypeEl ? outputTypeEl.value : 'text';
  const isJson = outputType === 'json';
  const result = isJson
    ? await utils.fetchUrlJson({ url: cdxUrl })
    : await utils.fetchUrl({ url: cdxUrl });
  if (!result || !result.success) {
    utils.setStatus('history-status', `查询失败: ${result ? result.error : '超时'}`);
    return;
  }
  try {
    const items = isJson ? parseCdxJson(result.data) : parseCdxText(result.data);
    renderHistoryResults(items);
    utils.showToast('查询完成', 'success');

    const latest = items[items.length - 1];
    if (latest && latest.timestamp) {
      const latestBtn = utils.get('history-latest-btn');
      if (latestBtn) {
        latestBtn.dataset.url = `https://web.archive.org/web/${latest.timestamp}/${latest.url}`;
        latestBtn.classList.remove('hidden');
      }
    }
  } catch {
    utils.setStatus('history-status', '解析结果失败');
  }
}

function exportData() {
  if (!lastHistoryResults || lastHistoryResults.length === 0) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }
  const rows = lastHistoryResults.map(function (item) {
    return [item.timestamp, item.url, item.statuscode, item.mimetype];
  });
  utils.buildCsv(
    ['时间戳', 'URL', '状态码', 'MIME类型'],
    rows,
    `lingmou-history-${Date.now()}.csv`
  );
}

export {
  showHistoryQuickLinks,
  buildCdxUrl,
  filterByType,
  extractDomain,
  queryHistory,
  renderHistoryResults,
  exportData,
  lastHistoryResults,
  allHistoryResults,
};
