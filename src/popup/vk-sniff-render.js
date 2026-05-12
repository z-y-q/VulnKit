// vk-sniff-render.js -- 灵眸 Chrome Extension
// Category grid + tech tags + confidence badges + evidence expansion

import { utilsProxy as utils } from './vk-namespace.js';
import { sniffState } from './vk-sniff-scanner.js';

var PANEL_MAP = {
  'Vue.js': 'vue',
  React: 'react',
  Angular: 'angular',
  Svelte: 'svelte',
  'Next.js': 'react',
  '若依框架': 'ruoyi',
};

var SOURCE_LABELS = {
  headers: 'HTTP 响应头',
  globals: 'JS 全局变量',
  meta: 'Meta 标签',
  body: '页面内容',
  cookies: 'Cookies',
  classNames: 'CSS 类名',
  ids: '元素 ID',
  scriptSrc: '脚本来源',
};

function groupByCategory(results) {
  var groups = {};
  for (var i = 0; i < results.length; i++) {
    var item = results[i];
    if (!groups[item.category]) {
      groups[item.category] = [];
    }
    groups[item.category].push(item);
  }
  return groups;
}

function renderSummary(results) {
  var el = utils.get('sniff-summary');
  if (!el) return;

  if (!results || results.length === 0) {
    el.innerHTML = '';
    el.style.display = 'none';
    return;
  }

  var categories = {};
  for (var i = 0; i < results.length; i++) {
    categories[results[i].category] = true;
  }
  var catCount = Object.keys(categories).length;

  el.style.display = 'block';
  el.innerHTML =
    '<span class="sniff-summary-item">识别 <strong>' +
    results.length +
    '</strong> 项技术</span>' +
    '<span class="sniff-summary-sep">|</span>' +
    '<span class="sniff-summary-item">涵盖 <strong>' +
    catCount +
    '</strong> 个分类</span>';
}

function renderCategoryFilter(results) {
  var container = utils.get('sniff-category-filter');
  if (!container) return;

  if (!results || results.length === 0) {
    container.innerHTML = '';
    container.style.display = 'none';
    return;
  }

  var groups = groupByCategory(results);
  var catNames = Object.keys(groups).sort();

  var html = '<button class="sniff-cat-btn active" data-scat="all">全部</button>';
  for (var i = 0; i < catNames.length; i++) {
    html +=
      '<button class="sniff-cat-btn" data-scat="' +
      utils.escapeHtml(catNames[i]) +
      '">' +
      utils.escapeHtml(catNames[i]) +
      ' <span class="sniff-cat-count">' +
      groups[catNames[i]].length +
      '</span></button>';
  }
  container.innerHTML = html;
  container.style.display = 'flex';

  container.querySelectorAll('.sniff-cat-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      container.querySelectorAll('.sniff-cat-btn').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      renderResults(results, btn.dataset.scat);
    });
  });
}

function renderTechTag(item) {
  var conf = item.confidence;
  var confLabel = conf ? conf.label : '?';
  var confColor = conf ? conf.color : '#9ca3af';
  var versionStr = item.version ? ' v' + utils.escapeHtml(item.version) : '';
  var expandId = 'sniff-evidence-' + item.name.replace(/[^a-zA-Z0-9]/g, '_');
  var gotoPanel = PANEL_MAP[item.name];
  var gotoBtn = gotoPanel
    ? '<button class="sniff-goto-btn" data-goto="' +
      gotoPanel +
      '" title="跳转到分析面板">&rarr;</button>'
    : '';

  return (
    '<div class="sniff-tech-tag" data-expand="' +
    expandId +
    '">' +
    '<span class="sniff-tech-name">' +
    utils.escapeHtml(item.name) +
    versionStr +
    '</span>' +
    gotoBtn +
    '<span class="sniff-conf-badge" style="background:' +
    confColor +
    '">' +
    confLabel +
    '</span>' +
    '<div class="sniff-tech-evidence" id="' +
    expandId +
    '" style="display:none">' +
    renderEvidence(item.evidences) +
    '</div>' +
    '</div>'
  );
}

function renderEvidence(evidences) {
  if (!evidences || evidences.length === 0) return '';

  var html = '<div class="sniff-evidence-list">';
  for (var i = 0; i < evidences.length; i++) {
    var ev = evidences[i];
    var sourceLabel = SOURCE_LABELS[ev.source] || ev.source;
    var evidenceText = typeof ev.evidence === 'string' ? ev.evidence : '';
    if (evidenceText.length > 120) {
      evidenceText = evidenceText.substring(0, 120) + '...';
    }
    html +=
      '<div class="sniff-evidence-row">' +
      '<span class="sniff-evidence-source">' +
      utils.escapeHtml(sourceLabel) +
      '</span>' +
      '<span class="sniff-evidence-text">' +
      utils.escapeHtml(evidenceText) +
      '</span>' +
      '</div>';
  }
  html += '</div>';
  return html;
}

function renderResults(results, categoryFilter) {
  var container = utils.get('sniff-results');
  if (!container) return;

  if (!results || results.length === 0) {
    container.innerHTML = '<div class="empty-state">未检测到任何技术特征</div>';
    return;
  }

  var filtered = results;
  if (categoryFilter && categoryFilter !== 'all') {
    filtered = results.filter(function (r) {
      return r.category === categoryFilter;
    });
  }

  var groups = groupByCategory(filtered);
  var catNames = Object.keys(groups).sort();

  var html = '';
  for (var c = 0; c < catNames.length; c++) {
    var cat = catNames[c];
    var items = groups[cat];
    html += '<div class="sniff-category">';
    html +=
      '<div class="sniff-category-title">' +
      utils.escapeHtml(cat) +
      ' <span class="sniff-cat-badge">' +
      items.length +
      '</span></div>';
    html += '<div class="sniff-category-tags">';
    for (var i = 0; i < items.length; i++) {
      html += renderTechTag(items[i]);
    }
    html += '</div></div>';
  }
  container.innerHTML = html;

  container.querySelectorAll('.sniff-tech-tag').forEach(function (tag) {
    tag.addEventListener('click', function () {
      var expandId = this.dataset.expand;
      var evidenceEl = utils.get(expandId);
      if (evidenceEl) {
        var isHidden = evidenceEl.style.display === 'none';
        evidenceEl.style.display = isHidden ? 'block' : 'none';
        this.classList.toggle('sniff-tech-expanded', isHidden);
      }
    });
  });

  if (!renderResults._gotoBound) {
    container.addEventListener('click', function (e) {
      var btn = e.target.closest('.sniff-goto-btn');
      if (!btn) return;
      e.stopPropagation();
      var target = btn.dataset.goto;
      var tab = document.querySelector('[data-panel="' + target + '"]');
      if (tab) tab.click();
    });
    renderResults._gotoBound = true;
  }
}

function updateFrameworkBadges(results) {
  document.querySelectorAll('.tab-btn .detect-badge').forEach(function (b) {
    b.remove();
  });
  document.querySelectorAll('.tab-btn.has-detect-badge').forEach(function (b) {
    b.classList.remove('has-detect-badge');
  });
  if (!results || results.length === 0) return;

  var badgeMap = {};
  results.forEach(function (r) {
    var panelId = PANEL_MAP[r.name];
    if (!panelId) return;
    if (!badgeMap[panelId] && r.version) {
      badgeMap[panelId] = r.version;
    }
  });

  Object.keys(badgeMap).forEach(function (panelId) {
    var btn = document.querySelector('.tab-btn[data-panel="' + panelId + '"]');
    if (!btn) return;
    btn.classList.add('has-detect-badge');
    var badge = document.createElement('span');
    badge.className = 'detect-badge';
    badge.textContent = badgeMap[panelId];
    btn.appendChild(badge);
  });

  // 持久化角标到 chrome.storage.session
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (!tabs || !tabs[0] || !tabs[0].id) return;
    try {
      chrome.storage.session.set({ 'sniff_badges_' + tabs[0].id: badgeMap });
    } catch (e) {
      /* session storage unavailable */
    }
  });
}

function renderAll(results) {
  renderSummary(results);
  renderCategoryFilter(results);
  renderResults(results, 'all');
  updateFrameworkBadges(results);
}

function restoreFrameworkBadges(badgeMap) {
  document.querySelectorAll('.tab-btn .detect-badge').forEach(function (b) { b.remove(); });
  document.querySelectorAll('.tab-btn.has-detect-badge').forEach(function (b) { b.classList.remove('has-detect-badge'); });
  if (!badgeMap) return;
  Object.keys(badgeMap).forEach(function (panelId) {
    var btn = document.querySelector('.tab-btn[data-panel="' + panelId + '"]');
    if (!btn) return;
    btn.classList.add('has-detect-badge');
    var badge = document.createElement('span');
    badge.className = 'detect-badge';
    badge.textContent = badgeMap[panelId];
    btn.appendChild(badge);
  });
}

function copyResults() {
  if (!sniffState.lastResults || sniffState.lastResults.length === 0) {
    utils.showToast('没有可复制的结果', 'warning');
    return;
  }

  var lines = sniffState.lastResults.map(function (item) {
    var conf = item.confidence ? item.confidence.label : '?';
    var version = item.version ? ' v' + item.version : '';
    return item.name + version + ' [' + item.category + '] (' + conf + ')';
  });
  utils.copyAndToast(lines.join('\n'), '已复制 ' + lines.length + ' 项技术指纹');
}

function exportResults() {
  if (!sniffState.lastResults || sniffState.lastResults.length === 0) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }

  var exportData = sniffState.lastResults.map(function (item) {
    return {
      name: item.name,
      category: item.category,
      confidence: item.confidence ? item.confidence.label : null,
      score: item.confidence ? item.confidence.score : null,
      version: item.version || null,
      matchCount: item.matchedCount,
      evidences: item.evidences.map(function (ev) {
        return {
          source: ev.source,
          evidence: typeof ev.evidence === 'string' ? ev.evidence.substring(0, 200) : null,
        };
      }),
    };
  });

  var blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'sniff-results-' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  URL.revokeObjectURL(url);
  utils.showToast('已导出 JSON', 'success');
}

export { renderAll, copyResults, exportResults, updateFrameworkBadges, restoreFrameworkBadges };
