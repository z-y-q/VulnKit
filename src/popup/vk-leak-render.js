// vk-leak-render.js -- 灵眸 Chrome Extension
// Leak scan results renderer for the sniff panel sub-tab

import { utilsProxy as utils } from './vk-namespace.js';
import {
  SEVERITY_LABELS,
  CONFIDENCE_LABELS,
  CATEGORY_LABELS,
  SEVERITY_COLOR,
  SEVERITY_ORDER,
} from './vk-leak-rules.js';

var leakState = {
  lastResults: null,
  scanning: false,
};

function groupByCategory(results) {
  var groups = {};
  for (var i = 0; i < results.length; i++) {
    var item = results[i];
    var cat = item.category || 'unknown';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(item);
  }
  return groups;
}

function renderSummary(results) {
  var el = utils.get('leak-summary');
  if (!el) return;

  if (!results || results.length === 0) {
    el.innerHTML = '';
    el.style.display = 'none';
    return;
  }

  var sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  var confCounts = { confirmed: 0, likely: 0, suspected: 0 };
  var catSet = {};
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    sevCounts[r.severity] = (sevCounts[r.severity] || 0) + 1;
    confCounts[r.confidence] = (confCounts[r.confidence] || 0) + 1;
    catSet[r.category] = true;
  }

  var parts = [];
  parts.push('发现 <strong>' + results.length + '</strong> 项');
  if (sevCounts.critical > 0) parts.push('<span style="color:red">严重 ' + sevCounts.critical + '</span>');
  if (sevCounts.high > 0) parts.push('<span style="color:orange">高危 ' + sevCounts.high + '</span>');
  if (sevCounts.medium > 0) parts.push('<span style="color:#e6a700">中危 ' + sevCounts.medium + '</span>');
  if (sevCounts.low > 0) parts.push('<span style="color:#36b5c0">低危 ' + sevCounts.low + '</span>');
  if (sevCounts.info > 0) parts.push('<span style="color:#999">信息 ' + sevCounts.info + '</span>');

  el.style.display = 'block';
  el.innerHTML = parts.join('<span class="sniff-summary-sep">|</span>');
}

function renderCategoryFilter(results) {
  var container = utils.get('leak-category-filter');
  if (!container) return;

  if (!results || results.length === 0) {
    container.innerHTML = '';
    container.style.display = 'none';
    return;
  }

  var groups = groupByCategory(results);
  var catNames = Object.keys(groups).sort();

  var html = '<button class="sniff-cat-btn active" data-lcat="all">全部</button>';
  for (var i = 0; i < catNames.length; i++) {
    var label = CATEGORY_LABELS[catNames[i]] || catNames[i];
    html +=
      '<button class="sniff-cat-btn" data-lcat="' + catNames[i] + '">' +
      utils.escapeHtml(label) +
      ' <span class="sniff-cat-count">' + groups[catNames[i]].length + '</span></button>';
  }
  container.innerHTML = html;
  container.style.display = 'flex';

  container.querySelectorAll('.sniff-cat-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      container.querySelectorAll('.sniff-cat-btn').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      renderResults(results, btn.dataset.lcat);
    });
  });
}

function renderFindingItem(item) {
  var sevLabel = SEVERITY_LABELS[item.severity] || item.severity;
  var sevColor = SEVERITY_COLOR[item.severity] || 'gray';
  var confLabel = CONFIDENCE_LABELS[item.confidence] || item.confidence;
  var confColor = item.confidence === 'confirmed' ? 'red' : item.confidence === 'likely' ? 'orange' : '#9ca3af';
  var catLabel = CATEGORY_LABELS[item.category] || item.category;
  var expandId = 'leak-detail-' + item.ruleId + '-' + Math.random().toString(36).slice(2, 8);

  var maskedValue = item.value;
  if (maskedValue.length > 60) maskedValue = maskedValue.slice(0, 30) + '...' + maskedValue.slice(-27);

  var html =
    '<div class="leak-item" data-expand="' + expandId + '">' +
      '<div class="leak-item-header">' +
        '<span class="leak-sev-badge" style="background:' + sevColor + '">' + utils.escapeHtml(sevLabel) + '</span>' +
        '<span class="leak-conf-badge" style="color:' + confColor + ';border-color:' + confColor + '">' + utils.escapeHtml(confLabel) + '</span>' +
        '<span class="leak-cat-label">' + utils.escapeHtml(catLabel) + '</span>' +
      '</div>' +
      '<div class="leak-item-name">' + utils.escapeHtml(item.name) + '</div>' +
      '<div class="leak-item-value"><code>' + utils.escapeHtml(maskedValue) + '</code></div>' +
      (item.evidence ? '<div class="leak-evidence-tag">' + utils.escapeHtml(item.evidence) + '</div>' : '') +
      '<div class="leak-item-detail" id="' + expandId + '" style="display:none">' +
        '<div class="leak-detail-section">' +
          '<div class="leak-detail-label">描述</div>' +
          '<div class="leak-detail-text">' + utils.escapeHtml(item.description || '') + '</div>' +
        '</div>' +
        (item.exploit ? '<div class="leak-detail-section"><div class="leak-detail-label">利用方式</div><div class="leak-detail-text">' + utils.escapeHtml(item.exploit) + '</div></div>' : '') +
        (item.recommendation ? '<div class="leak-detail-section"><div class="leak-detail-label">修复建议</div><div class="leak-detail-text">' + utils.escapeHtml(item.recommendation) + '</div></div>' : '') +
        '<div class="leak-detail-section"><div class="leak-detail-label">完整匹配值</div><div class="leak-detail-text leak-full-value"><code>' + utils.escapeHtml(item.value) + '</code></div></div>' +
      '</div>' +
    '</div>';

  return html;
}

function renderResults(results, categoryFilter) {
  var container = utils.get('leak-results');
  if (!container) return;

  if (!results || results.length === 0) {
    container.innerHTML = '<div class="empty-state">未发现敏感信息泄漏</div>';
    return;
  }

  var filtered = results;
  if (categoryFilter && categoryFilter !== 'all') {
    filtered = results.filter(function (r) {
      return r.category === categoryFilter;
    });
  }

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state">该分类下无结果</div>';
    return;
  }

  var html = '';
  for (var i = 0; i < filtered.length; i++) {
    html += renderFindingItem(filtered[i]);
  }
  container.innerHTML = html;

  container.querySelectorAll('.leak-item').forEach(function (item) {
    item.addEventListener('click', function () {
      var expandId = this.dataset.expand;
      var detailEl = utils.get(expandId);
      if (detailEl) {
        var isHidden = detailEl.style.display === 'none';
        detailEl.style.display = isHidden ? 'block' : 'none';
        this.classList.toggle('leak-item-expanded', isHidden);
      }
    });
  });
}

function renderAll(results) {
  renderSummary(results);
  renderCategoryFilter(results);
  renderResults(results, 'all');
}

function clearAll() {
  leakState.lastResults = null;
  var summaryEl = utils.get('leak-summary');
  if (summaryEl) { summaryEl.innerHTML = ''; summaryEl.style.display = 'none'; }
  var filterEl = utils.get('leak-category-filter');
  if (filterEl) { filterEl.innerHTML = ''; filterEl.style.display = 'none'; }
  var resultsEl = utils.get('leak-results');
  if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">点击「泄露扫描」分析当前页面敏感信息</div>';
  var copyBtn = utils.get('leak-copy-btn');
  if (copyBtn) copyBtn.style.display = 'none';
  var exportBtn = utils.get('leak-export-btn');
  if (exportBtn) exportBtn.style.display = 'none';
}

function copyResults() {
  if (!leakState.lastResults || leakState.lastResults.length === 0) {
    utils.showToast('没有可复制的结果', 'warning');
    return;
  }

  var lines = leakState.lastResults.map(function (item) {
    var sev = SEVERITY_LABELS[item.severity] || item.severity;
    var conf = CONFIDENCE_LABELS[item.confidence] || item.confidence;
    return '[' + sev + '][' + conf + '] ' + item.name + ' = ' + item.value;
  });
  utils.copyAndToast(lines.join('\n'), '已复制 ' + lines.length + ' 条泄露信息');
}

function exportResults() {
  if (!leakState.lastResults || leakState.lastResults.length === 0) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }

  var exportData = leakState.lastResults.map(function (item) {
    return {
      ruleId: item.ruleId,
      name: item.name,
      value: item.value,
      severity: item.severity,
      confidence: item.confidence,
      category: item.category,
      description: item.description,
      exploit: item.exploit,
      recommendation: item.recommendation,
      evidence: item.evidence || null,
    };
  });

  var blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'leak-scan-' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  URL.revokeObjectURL(url);
  utils.showToast('已导出 JSON', 'success');
}

export { leakState, renderAll, clearAll, copyResults, exportResults };
