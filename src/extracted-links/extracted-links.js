(function () {
  'use strict';

  const TAG_LABELS = {
    a: '链接',
    img: '图片',
    script: '脚本',
    link: '资源',
    iframe: '框架',
    form: '表单',
  };
  let allLinks = [];
  let sourceUrl = '';
  let loadAttempts = 0;

  function tryLoadData() {
    chrome.storage.local.get(['contextExtractedLinks', 'contextExtractedUrl'], function (data) {
      if (Array.isArray(data.contextExtractedLinks) && data.contextExtractedLinks.length > 0) {
        allLinks = data.contextExtractedLinks;
        sourceUrl = data.contextExtractedUrl || '';
        chrome.storage.local.remove(['contextExtractedLinks', 'contextExtractedUrl']);
        render();
        return;
      }
      loadAttempts++;
      if (loadAttempts < 10) {
        setTimeout(tryLoadData, 300);
      } else {
        render();
      }
    });
  }

  tryLoadData();

  const searchEl = document.getElementById('search');
  const filterEl = document.getElementById('filter-tag');
  const tbody = document.getElementById('tbody');
  const statsEl = document.getElementById('stats');
  const sourceEl = document.getElementById('source-url');

  searchEl.addEventListener('input', render);
  filterEl.addEventListener('change', render);
  document.getElementById('copy-all').addEventListener('click', copyAll);
  document.getElementById('export-json').addEventListener('click', exportJson);

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function render() {
    const q = (searchEl.value || '').toLowerCase();
    const tag = filterEl.value;
    const filtered = allLinks.filter(function (l) {
      if (tag !== 'all' && l.tag !== tag) return false;
      if (
        q &&
        l.href.toLowerCase().indexOf(q) === -1 &&
        (l.text || '').toLowerCase().indexOf(q) === -1
      )
        return false;
      return true;
    });

    if (sourceEl) sourceEl.textContent = sourceUrl ? '来源: ' + sourceUrl : '';

    const counts = {};
    allLinks.forEach(function (l) {
      counts[l.tag] = (counts[l.tag] || 0) + 1;
    });
    const parts = Object.keys(counts).map(function (k) {
      return (TAG_LABELS[k] || k) + ': ' + counts[k];
    });
    if (statsEl)
      statsEl.textContent =
        '共 ' + allLinks.length + ' 个链接' + (parts.length ? ' (' + parts.join(', ') + ')' : '');

    if (filtered.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty">' +
        (allLinks.length ? '没有匹配的链接' : '未提取到链接') +
        '</td></tr>';
      return;
    }

    let html = '';
    filtered.forEach(function (l, i) {
      html += '<tr>';
      html += '<td>' + (i + 1) + '</td>';
      html +=
        '<td class="url" title="' +
        esc(l.href) +
        '"><a href="' +
        esc(l.href) +
        '" target="_blank" rel="noopener">' +
        esc(l.href) +
        '</a></td>';
      html += '<td class="text">' + esc(l.text || '-') + '</td>';
      html +=
        '<td><span class="tag tag-' +
        esc(l.tag || '') +
        '">' +
        (TAG_LABELS[l.tag] || l.tag || '-') +
        '</span></td>';
      html += '<td>' + esc(l.domain || '-') + '</td>';
      html += '</tr>';
    });
    tbody.innerHTML = html;
  }

  function copyAll() {
    const urls = allLinks
      .map(function (l) {
        return l.href;
      })
      .join('\n');
    navigator.clipboard.writeText(urls).then(function () {
      document.getElementById('copy-all').textContent = '已复制!';
      setTimeout(function () {
        document.getElementById('copy-all').textContent = '复制全部 URL';
      }, 1500);
    });
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(allLinks, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    chrome.downloads.download({ url: url, filename: 'extracted-links.json', saveAs: true });
  }
})();
