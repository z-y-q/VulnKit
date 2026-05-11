// vk-headers-render.js -- 灵眸 Chrome Extension
// Rendering layer for security headers analysis

import { utilsProxy as utils } from './vk-namespace.js';
import { CATEGORY_LABELS, CATEGORY_ICONS, STATUS_ICONS } from './vk-headers-data.js';

function renderHeadersResults(analysis, lastAnalysisResult, currentFilter, currentSearch) {
  var container = utils.get('headers-results');
  var scoreContainer = utils.get('headers-score-container');
  var gradeEl = utils.get('headers-grade');
  var scoreRing = utils.get('headers-score-ring');
  var scoreText = utils.get('headers-score-text');
  var summaryEl = utils.get('headers-summary');
  var exportBtn = utils.get('headers-export-btn');

  if (!container || !analysis) return;

  scoreContainer.hidden = false;

  var gradeClass = 'grade-' + analysis.grade.toLowerCase();
  gradeEl.className = 'headers-grade ' + gradeClass;
  gradeEl.textContent = analysis.grade;

  scoreText.textContent = analysis.score;

  var circumference = 2 * Math.PI * 54;
  var offset = circumference - (analysis.score / 100) * circumference;
  scoreRing.style.strokeDashoffset = String(offset);
  scoreRing.classList.remove('score-high', 'score-medium', 'score-low');
  scoreRing.classList.add(
    analysis.score >= 75 ? 'score-high' : analysis.score >= 50 ? 'score-medium' : 'score-low'
  );

  summaryEl.innerHTML =
    '<span class="stat-badge stat-found">通过 ' +
    analysis.passed +
    '</span> ' +
    '<span class="stat-badge stat-warn">警告 ' +
    analysis.warning +
    '</span> ' +
    '<span class="stat-badge stat-vuln">缺失 ' +
    analysis.missing +
    '</span>';

  var filtered = analysis.results.filter(function (r) {
    return applyHeaderFilter(r, currentFilter, currentSearch);
  });
  var grouped = groupByCategory(filtered);

  var html = '';
  var catOrder = ['security', 'privacy', 'cross-origin', 'caching', 'legacy', 'monitoring'];
  for (var c = 0; c < catOrder.length; c++) {
    var cat = catOrder[c];
    var items = grouped[cat];
    if (!items || items.length === 0) continue;
    html += '<div class="headers-category">';
    html +=
      '<div class="headers-category-title">' +
      (CATEGORY_ICONS[cat] || '') +
      ' ' +
      utils.escapeHtml(CATEGORY_LABELS[cat] || cat) +
      '</div>';
    for (var i = 0; i < items.length; i++) {
      var r = items[i];
      html += '<div class="headers-result-card">';
      html += '<div class="headers-result-row">';
      html +=
        '<span class="headers-status-icon">' +
        (STATUS_ICONS[r.status] || STATUS_ICONS.miss) +
        '</span>';
      html += '<span class="headers-header-name">' + utils.escapeHtml(r.name) + '</span>';
      html += '</div>';
      html +=
        '<div class="headers-header-value" data-truncate="true">' +
        utils.escapeHtml(r.detail || '-') +
        '</div>';
      if (r.recommendation) {
        html += '<div class="headers-header-rec">' + utils.escapeHtml(r.recommendation) + '</div>';
      }
      html += '</div>';
    }
    html += '</div>';
  }

  if (
    lastAnalysisResult &&
    lastAnalysisResult.infoLeaks &&
    lastAnalysisResult.infoLeaks.length > 0
  ) {
    html += '<div class="headers-category">';
    html +=
      '<div class="headers-category-title headers-category-infoleak">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/></svg> 信息泄露</div>';
    for (var li = 0; li < lastAnalysisResult.infoLeaks.length; li++) {
      var leak = lastAnalysisResult.infoLeaks[li];
      html += '<div class="headers-result-card headers-infoleak-card">';
      html += '<div class="headers-result-row">';
      html += '<span class="headers-status-icon">' + STATUS_ICONS.warn + '</span>';
      html += '<span class="headers-header-name">' + utils.escapeHtml(leak.name) + '</span>';
      html += '</div>';
      html += '<div class="headers-header-value">' + utils.escapeHtml(leak.detail) + '</div>';
      html += '<div class="headers-header-rec">' + utils.escapeHtml(leak.info) + '</div>';
      html += '</div>';
    }
    html += '</div>';
  }

  if (
    lastAnalysisResult &&
    lastAnalysisResult.cookieAnalysis &&
    lastAnalysisResult.cookieAnalysis.length > 0
  ) {
    html += '<div class="headers-category">';
    html +=
      '<div class="headers-category-title headers-category-cookie">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Cookie 安全</div>';
    for (var ci = 0; ci < lastAnalysisResult.cookieAnalysis.length; ci++) {
      var cf = lastAnalysisResult.cookieAnalysis[ci];
      html += '<div class="headers-result-card">';
      html += '<div class="headers-cookie-name">' + utils.escapeHtml(cf.name) + '</div>';
      html += '<div class="headers-cookie-flags">';
      for (var fi = 0; fi < cf.issues.length; fi++) {
        html +=
          '<span class="headers-cookie-flag warn">' + utils.escapeHtml(cf.issues[fi]) + '</span>';
      }
      if (cf.flags.secure) html += '<span class="headers-cookie-flag pass">Secure</span>';
      if (cf.flags.httponly) html += '<span class="headers-cookie-flag pass">HttpOnly</span>';
      if (cf.flags.samesite) {
        html +=
          '<span class="headers-cookie-flag pass">SameSite=' +
          utils.escapeHtml(cf.flags.samesite) +
          '</span>';
      }
      html += '</div></div>';
    }
    html += '</div>';
  }

  if (
    lastAnalysisResult &&
    lastAnalysisResult.cspDeep &&
    (lastAnalysisResult.cspDeep.bypasses.length > 0 ||
      lastAnalysisResult.cspDeep.missingCritical.length > 0)
  ) {
    var cspDeep = lastAnalysisResult.cspDeep;
    html += '<div class="headers-category">';
    html +=
      '<div class="headers-category-title headers-category-csp-deep">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> CSP 深度分析</div>';

    if (cspDeep.bypasses.length > 0) {
      for (var bi = 0; bi < cspDeep.bypasses.length; bi++) {
        var bp = cspDeep.bypasses[bi];
        html +=
          '<div class="headers-result-card headers-csp-bypass ' + (bp.severity || 'medium') + '">';
        html += '<div class="headers-result-row">';
        html += '<span class="headers-csp-bypass-type">' + utils.escapeHtml(bp.type) + '</span>';
        html +=
          '<span class="headers-csp-bypass-severity ' +
          (bp.severity || 'medium') +
          '">' +
          utils.escapeHtml(bp.severity || 'medium') +
          '</span>';
        html += '</div>';
        html += '<div class="headers-header-rec">' + utils.escapeHtml(bp.description) + '</div>';
        html += '</div>';
      }
    }

    if (cspDeep.missingCritical.length > 0) {
      for (var mi = 0; mi < cspDeep.missingCritical.length; mi++) {
        var mc = cspDeep.missingCritical[mi];
        html += '<div class="headers-result-card headers-csp-missing">';
        html += '<div class="headers-result-row">';
        html +=
          '<span class="headers-csp-missing-name">' + utils.escapeHtml(mc.directive) + '</span>';
        html += '</div>';
        html += '<div class="headers-header-rec">' + utils.escapeHtml(mc.impact) + '</div>';
        html += '</div>';
      }
    }

    html += '</div>';
  }

  if (!html) {
    html = '<div class="empty-state">无匹配结果</div>';
  }

  container.innerHTML = html;
  if (exportBtn) exportBtn.hidden = false;
}

function groupByCategory(results) {
  var groups = {};
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    var cat = r.category || 'other';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(r);
  }
  return groups;
}

function applyHeaderFilter(result, currentFilter, currentSearch) {
  var f = currentFilter;
  if (f === 'missing' && result.status !== 'miss') return false;
  if (f === 'warn' && result.status !== 'warn') return false;
  if (f === 'pass' && result.status !== 'pass') return false;
  var q = currentSearch;
  if (q) {
    var text = (
      (result.name || '') +
      ' ' +
      (result.detail || '') +
      ' ' +
      (result.recommendation || '')
    ).toLowerCase();
    return text.indexOf(q) !== -1;
  }
  return true;
}

export { renderHeadersResults, groupByCategory, applyHeaderFilter };
