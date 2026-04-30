// VulnKit - History Archive (Wayback Machine)
window.VulnKitHistory = (function () {
  'use strict';

  let lastHistoryResults = [];
  let allHistoryResults = [];

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  function showHistoryQuickLinks(domain) {
    if (!domain) return;
    const utils = getUtils();
    const quickLinks = utils.get('history-quick-links');
    quickLinks.innerHTML =
      '<button class="quick-link-btn" data-url="https://web.archive.org/web/*/' +
      encodeURIComponent(domain) +
      '/*">Wayback Machine 日历</button>' +
      '<button id="history-latest-btn" class="quick-link-btn quick-latest hidden" data-url="">查看最新快照</button>';

    if (!showHistoryQuickLinks._bound) {
      const panel = document.getElementById('panel-history');
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
    const utils = getUtils();
    const matchType = (utils.get('history-match-type') || {}).value || 'domain';
    const outputType = (utils.get('history-output-type') || {}).value || 'json';
    const fields =
      (utils.get('history-fields') || {}).value || 'timestamp,original,statuscode,mimetype';
    const from = (utils.get('history-from') || {}).value || '';
    const to = (utils.get('history-to') || {}).value || '';
    const typeFilter = ((utils.get('history-type-filter') || {}).value || '').trim();

    let url = 'https://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(domain);
    url += '&collapse=urlkey';
    url += '&matchType=' + matchType;
    url += '&output=' + outputType;
    url += '&fl=' + encodeURIComponent(fields);
    if (from) url += '&from=' + from;
    if (to) url += '&to=' + to;
    if (typeFilter) {
      const types = typeFilter
        .toLowerCase()
        .split(/[,，\s]+/)
        .filter(Boolean);
      types.forEach(t => {
        url += '&filter=original:.*\\.' + encodeURIComponent(t) + '($|\\?.*)';
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
    const utils = getUtils();
    lastHistoryResults = items;
    if (!isFilter) allHistoryResults = items;
    const container = utils.get('history-timeline');
    const statusEl = utils.get('history-status');
    const fields = utils.get('history-fields').value;
    const hasTs = fields.includes('timestamp');

    if (items.length === 0) {
      container.innerHTML = '<div class="empty-state">未找到历史档案</div>';
      statusEl.textContent = '无结果';
      return;
    }

    statusEl.textContent = '共 ' + items.length + ' 条记录';
    utils.get('history-total').textContent = items.length;

    if (hasTs) {
      const timestamps = items
        .map(i => i.timestamp || '')
        .filter(Boolean)
        .sort();
      if (timestamps.length > 0) {
        const fmt = ts => ts.substring(0, 4) + '-' + ts.substring(4, 6) + '-' + ts.substring(6, 8);
        utils.get('history-first').textContent = fmt(timestamps[0]);
        utils.get('history-last').textContent = fmt(timestamps[timestamps.length - 1]);
        utils.get('history-summary').classList.remove('hidden');
      }
    }

    let html = '';
    items.slice(0, 200).forEach(item => {
      const url = item.url || item.raw;
      const ts = item.timestamp || '';
      const status = item.statuscode || '';
      const mime = item.mimetype || '';
      const dateStr = ts
        ? ts.substring(0, 4) +
          '-' +
          ts.substring(4, 6) +
          '-' +
          ts.substring(6, 8) +
          ' ' +
          ts.substring(8, 10) +
          ':' +
          ts.substring(10, 12)
        : '';
      const waybackUrl = ts
        ? 'https://web.archive.org/web/' + ts + '/' + url
        : 'https://web.archive.org/web/*/' + encodeURIComponent(url);

      let statusClass = 'status-other';
      if (status === '200') statusClass = 'status-200';
      else if (status === '301' || status === '302') statusClass = 'status-301';
      else if (status === '404') statusClass = 'status-404';

      html += '<div class="timeline-item">';
      if (hasTs) html += '<span class="timeline-date">' + utils.escapeHtml(dateStr) + '</span>';
      if (status)
        html +=
          '<span class="timeline-status ' +
          utils.escapeHtml(statusClass) +
          '">' +
          utils.escapeHtml(status) +
          '</span>';
      if (mime)
        html += '<span class="timeline-status status-other">' + utils.escapeHtml(mime) + '</span>';
      html +=
        '<span class="timeline-url" data-wayback="' +
        utils.escapeHtml(waybackUrl) +
        '" title="' +
        utils.escapeHtml(url) +
        '">' +
        utils.escapeHtml(url) +
        '</span>';
      html +=
        '<button class="timeline-open" data-url="' +
        utils.escapeHtml(waybackUrl) +
        '">查看</button>';
      html += '</div>';
    });
    if (items.length > 200) html += '<div class="empty-state">仅显示前 200 条</div>';
    container.innerHTML = html;
  }

  function extractDomain(input) {
    try {
      const url = new URL(/^https?:\/\//i.test(input) ? input : 'https://' + input);
      return url.hostname;
    } catch {
      return input.trim();
    }
  }

  async function queryHistory() {
    const utils = getUtils();
    let raw = utils.get('history-domain').value.trim();
    if (!raw) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('请输入域名或打开一个网页', 'warning');
        return;
      }
      raw = tab.url;
    }
    const domain = extractDomain(raw);
    utils.get('history-domain').value = domain;

    showHistoryQuickLinks(domain);
    utils.get('history-status').textContent = '正在查询...';
    utils.get('history-timeline').innerHTML = '';
    utils.get('history-summary').classList.add('hidden');

    const cdxUrl = buildCdxUrl(domain);
    chrome.runtime.sendMessage({ type: 'FETCH_URL', url: cdxUrl }, response => {
      if (response?.error) {
        utils.get('history-status').textContent = '查询失败: ' + response.error;
        return;
      }
      try {
        const outputType = utils.get('history-output-type').value;
        const items =
          outputType === 'json'
            ? parseCdxJson(JSON.parse(response.data))
            : parseCdxText(response.data);
        renderHistoryResults(items);
        utils.showToast('查询完成', 'success');

        const latest = items[items.length - 1];
        if (latest && latest.timestamp) {
          const latestBtn = document.getElementById('history-latest-btn');
          if (latestBtn) {
            latestBtn.dataset.url =
              'https://web.archive.org/web/' + latest.timestamp + '/' + latest.url;
            latestBtn.classList.remove('hidden');
          }
        }
      } catch {
        utils.get('history-status').textContent = '解析结果失败';
      }
    });
  }

  return {
    showHistoryQuickLinks,
    buildCdxUrl,
    filterByType,
    extractDomain,
    queryHistory,
    renderHistoryResults,
    get lastHistoryResults() {
      return lastHistoryResults;
    },
    set lastHistoryResults(v) {
      lastHistoryResults = v;
    },
    get allHistoryResults() {
      return allHistoryResults;
    },
    set allHistoryResults(v) {
      allHistoryResults = v;
    },
  };
})();
