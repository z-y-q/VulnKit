// vk-scan-history.js — Scan history persistence for VulnKit
// Stores scan results in chrome.storage.local with deduplication and TTL.
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

var STORAGE_KEY = 'pentest_scan_history';
var MAX_PER_DOMAIN = 50;
var TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

var MODULE_LABELS = {
  cors: 'CORS',
  waf: 'WAF',
  subdomain: '子域名',
  xssscan: 'XSS',
  headers: '安全头',
  'cookie-audit': 'Cookie',
  redirect: '重定向',
  graphql: 'GraphQL',
  'storage-check': '存储检查',
  fuzz: 'Fuzz',
};

function genId() {
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

function pruneExpired(entries) {
  var cutoff = Date.now() - TTL_MS;
  return entries.filter(function (e) { return e.timestamp > cutoff; });
}

function pruneByDomain(entries, domain) {
  var domainEntries = entries.filter(function (e) { return e.domain === domain; });
  if (domainEntries.length <= MAX_PER_DOMAIN) return entries;
  var keep = new Set(domainEntries.slice(-MAX_PER_DOMAIN).map(function (e) { return e.id; }));
  return entries.filter(function (e) {
    return e.domain !== domain || keep.has(e.id);
  });
}

function buildSummary(findings) {
  var s = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  if (!findings) return s;
  findings.forEach(function (f) {
    s.total++;
    var sev = (f.severity || 'info').toLowerCase();
    if (sev === 'critical') s.critical++;
    else if (sev === 'high') s.high++;
    else if (sev === 'medium') s.medium++;
    else if (sev === 'low') s.low++;
    else s.info++;
  });
  return s;
}

/**
 * Save a scan result to history.
 * @param {string} moduleId - Panel module ID
 * @param {string} domain - Target domain
 * @param {Array} findings - Array of finding objects { severity, title, detail, url }
 * @param {Object} [opts] - Optional extra fields: { url }
 */
function saveScanResult(moduleId, domain, findings, opts) {
  if (!moduleId || !domain) return;
  var trimmed = (findings || []).slice(0, 200); // cap to prevent storage bloat
  var summary = buildSummary(trimmed);
  var entry = {
    id: genId(),
    moduleId: moduleId,
    domain: domain,
    url: (opts && opts.url) || domain,
    timestamp: Date.now(),
    summary: summary,
    findings: trimmed,
  };

  chrome.storage.local.get(STORAGE_KEY, function (data) {
    var entries = Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [];

    // Dedup: replace if same module+domain within 5 minutes
    var dedupWindow = Date.now() - 5 * 60 * 1000;
    entries = entries.filter(function (e) {
      return !(e.moduleId === moduleId && e.domain === domain && e.timestamp > dedupWindow);
    });

    entries.push(entry);
    entries = pruneExpired(entries);
    entries = pruneByDomain(entries, domain);

    // Hard cap overall
    if (entries.length > 500) {
      entries = entries.slice(-500);
    }

    var update = {};
    update[STORAGE_KEY] = entries;
    chrome.storage.local.set(update);
  });
}

/**
 * Query scan history with optional filters.
 * @param {Object} [filters] - { domain, moduleId, since (timestamp) }
 * @param {function} callback - receives entries array (descending by timestamp)
 */
function getScanHistory(filters, callback) {
  chrome.storage.local.get(STORAGE_KEY, function (data) {
    var entries = Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [];
    entries = pruneExpired(entries);

    if (filters) {
      if (filters.domain) {
        entries = entries.filter(function (e) { return e.domain === filters.domain; });
      }
      if (filters.moduleId) {
        entries = entries.filter(function (e) { return e.moduleId === filters.moduleId; });
      }
      if (filters.since) {
        entries = entries.filter(function (e) { return e.timestamp >= filters.since; });
      }
    }

    entries.sort(function (a, b) { return b.timestamp - a.timestamp; });

    // Persist pruned entries
    var update = {};
    update[STORAGE_KEY] = pruneByDomain(entries.reduce(function (acc, e) {
      acc.push(e);
      return acc;
    }, [].concat(
      pruneExpired(Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [])
    )), '');
    // Actually just re-save all pruned
    var allPruned = pruneExpired(Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : []);
    var upd = {};
    upd[STORAGE_KEY] = allPruned.slice(0, 500);
    chrome.storage.local.set(upd);

    if (callback) callback(entries);
  });
}

/**
 * Compare two scans and return diff categories.
 */
function diffScans(oldScan, newScan) {
  if (!oldScan || !newScan) return null;

  var oldMap = {};
  (oldScan.findings || []).forEach(function (f) {
    oldMap[(f.title || '') + '|' + (f.detail || '')] = f;
  });
  var newMap = {};
  (newScan.findings || []).forEach(function (f) {
    newMap[(f.title || '') + '|' + (f.detail || '')] = f;
  });

  var result = { newIssues: [], fixed: [], unchanged: [], escalated: [], improved: [] };

  Object.keys(newMap).forEach(function (key) {
    if (!oldMap[key]) {
      result.newIssues.push(newMap[key]);
    } else {
      var oldSev = severityRank(oldMap[key].severity);
      var newSev = severityRank(newMap[key].severity);
      if (newSev > oldSev) {
        result.escalated.push({ old: oldMap[key], current: newMap[key] });
      } else if (newSev < oldSev) {
        result.improved.push({ old: oldMap[key], current: newMap[key] });
      } else {
        result.unchanged.push(newMap[key]);
      }
    }
  });

  Object.keys(oldMap).forEach(function (key) {
    if (!newMap[key]) {
      result.fixed.push(oldMap[key]);
    }
  });

  return result;
}

function severityRank(sev) {
  var s = (sev || 'info').toLowerCase();
  if (s === 'critical') return 4;
  if (s === 'high') return 3;
  if (s === 'medium') return 2;
  if (s === 'low') return 1;
  return 0;
}

function deleteScanEntry(id, callback) {
  chrome.storage.local.get(STORAGE_KEY, function (data) {
    var entries = Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [];
    entries = entries.filter(function (e) { return e.id !== id; });
    var update = {};
    update[STORAGE_KEY] = entries;
    chrome.storage.local.set(update, callback);
  });
}

function clearAllHistory(callback) {
  var update = {};
  update[STORAGE_KEY] = [];
  chrome.storage.local.set(update, callback);
}

// ====== Render scan history UI in report panel ======

function renderHistoryContainer() {
  var existing = utils.get('scan-history-section');
  if (existing) existing.remove();

  var container = document.createElement('div');
  container.id = 'scan-history-section';
  container.innerHTML =
    '<div class="scan-history-header" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">' +
      '<span class="scan-history-title" style="font-size:12px;font-weight:600;color:var(--text-primary);cursor:pointer;" id="scan-history-toggle">扫描历史 ▾</span>' +
      '<div style="display:flex;gap:4px;">' +
        '<button class="btn btn-sm btn-outline" id="scan-history-diff-btn" style="display:none;">对比</button>' +
        '<button class="btn btn-sm btn-outline" id="scan-history-clear-btn">清空</button>' +
      '</div>' +
    '</div>' +
    '<div id="scan-history-list" class="scan-history-list"></div>' +
    '<div id="scan-history-diff-view" class="scan-history-diff-view" style="display:none;"></div>';

  var reportSummary = utils.get('report-summary');
  if (reportSummary) {
    reportSummary.parentNode.insertBefore(container, reportSummary);
  }

  utils.bindClick('scan-history-toggle', function () {
    var list = utils.get('scan-history-list');
    if (!list) return;
    var isHidden = list.style.display === 'none';
    list.style.display = isHidden ? '' : 'none';
    this.textContent = isHidden ? '扫描历史 ▾' : '扫描历史 ▸';
    if (isHidden && list.children.length === 0) loadAndRenderHistory();
  });

  utils.bindClick('scan-history-clear-btn', function () {
    clearAllHistory(function () {
      var list = utils.get('scan-history-list');
      if (list) list.innerHTML = '<div class="report-findings-empty">暂无历史记录</div>';
      utils.showToast('历史已清空', 'success');
    });
  });

  utils.bindClick('scan-history-diff-btn', handleDiffSelection);
}

var selectedHistoryEntries = [];

function loadAndRenderHistory() {
  var list = utils.get('scan-history-list');
  if (!list) return;
  list.innerHTML = '<div class="report-findings-empty">加载中...</div>';

  utils.getCurrentDomain().then(function (domain) {
    if (!domain) {
      list.innerHTML = '<div class="report-findings-empty">无法获取当前域名</div>';
      return;
    }
    getScanHistory({ domain: domain }, function (entries) {
      renderHistoryEntries(entries);
    });
  });
}

function renderHistoryEntries(entries) {
  var list = utils.get('scan-history-list');
  if (!list) return;

  if (!entries || entries.length === 0) {
    list.innerHTML = '<div class="report-findings-empty">暂无历史记录</div>';
    return;
  }

  selectedHistoryEntries = [];
  var diffBtn = utils.get('scan-history-diff-btn');
  if (diffBtn) diffBtn.style.display = 'none';

  var html = '';
  var seen = new Set();
  entries.forEach(function (entry) {
    var key = entry.moduleId + ':' + new Date(entry.timestamp).toLocaleDateString();
    if (seen.has(key)) return;
    seen.add(key);

    var label = MODULE_LABELS[entry.moduleId] || entry.moduleId;
    var time = new Date(entry.timestamp);
    var timeStr = time.toLocaleDateString() + ' ' +
      String(time.getHours()).padStart(2, '0') + ':' +
      String(time.getMinutes()).padStart(2, '0');

    var sevHtml = '';
    if (entry.summary.critical > 0) sevHtml += '<span style="color:#e74c3c;font-weight:600;">C' + entry.summary.critical + '</span> ';
    if (entry.summary.high > 0) sevHtml += '<span style="color:#e67e22;font-weight:600;">H' + entry.summary.high + '</span> ';
    if (entry.summary.medium > 0) sevHtml += '<span style="color:#f39c12;">M' + entry.summary.medium + '</span> ';
    if (entry.summary.low > 0) sevHtml += '<span style="color:#3498db;">L' + entry.summary.low + '</span> ';
    if (entry.summary.info > 0) sevHtml += '<span style="color:#95a5a6;">I' + entry.summary.info + '</span> ';
    if (!sevHtml) sevHtml = '<span style="color:#27ae60;">无风险</span>';

    html +=
      '<div class="scan-history-entry" data-entry-id="' + entry.id + '">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;">' +
          '<div>' +
            '<span class="report-finding-module">' + label + '</span>' +
            '<span style="font-size:10px;color:var(--text-secondary);margin-left:6px;">' + timeStr + '</span>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:6px;">' +
            '<span class="scan-history-sev">' + sevHtml + '</span>' +
            '<span style="font-size:10px;color:var(--text-secondary);">' + entry.summary.total + ' 条</span>' +
            '<input type="checkbox" class="scan-history-check" data-entry-id="' + entry.id + '" style="cursor:pointer;">' +
            '<button class="btn btn-sm btn-outline scan-history-del-btn" data-entry-id="' + entry.id + '" style="padding:1px 6px;font-size:10px;">✕</button>' +
          '</div>' +
        '</div>' +
      '</div>';
  });

  list.innerHTML = html;

  // Bind delete buttons
  list.querySelectorAll('.scan-history-del-btn').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      var id = this.getAttribute('data-entry-id');
      deleteScanEntry(id, function () {
        loadAndRenderHistory();
      });
    });
  });

  // Bind checkboxes for diff
  list.querySelectorAll('.scan-history-check').forEach(function (cb) {
    cb.addEventListener('change', function () {
      var id = this.getAttribute('data-entry-id');
      if (this.checked) {
        selectedHistoryEntries.push(id);
      } else {
        selectedHistoryEntries = selectedHistoryEntries.filter(function (eid) { return eid !== id; });
      }
      if (diffBtn) diffBtn.style.display = selectedHistoryEntries.length === 2 ? '' : 'none';
    });
  });
}

function handleDiffSelection() {
  if (selectedHistoryEntries.length !== 2) {
    utils.showToast('请选择两条记录进行对比', 'warning');
    return;
  }

  chrome.storage.local.get(STORAGE_KEY, function (data) {
    var entries = Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [];
    var oldEntry = entries.find(function (e) { return e.id === selectedHistoryEntries[0]; });
    var newEntry = entries.find(function (e) { return e.id === selectedHistoryEntries[1]; });
    if (!oldEntry || !newEntry) {
      utils.showToast('记录不存在', 'error');
      return;
    }
    if (oldEntry.timestamp > newEntry.timestamp) {
      var tmp = oldEntry;
      oldEntry = newEntry;
      newEntry = tmp;
    }

    var diff = diffScans(oldEntry, newEntry);
    if (!diff) return;
    renderDiffView(oldEntry, newEntry, diff);
  });
}

function renderDiffView(oldEntry, newEntry, diff) {
  var view = utils.get('scan-history-diff-view');
  if (!view) return;
  view.style.display = '';

  var oldLabel = MODULE_LABELS[oldEntry.moduleId] || oldEntry.moduleId;
  var newLabel = MODULE_LABELS[newEntry.moduleId] || newEntry.moduleId;
  var oldTime = new Date(oldEntry.timestamp).toLocaleString();
  var newTime = new Date(newEntry.timestamp).toLocaleString();

  var html = '<div class="scan-history-diff">';
  html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
  html += '<span style="font-size:12px;font-weight:600;">对比结果</span>';
  html += '<button class="btn btn-sm btn-outline" id="scan-history-diff-close">关闭</button>';
  html += '</div>';
  html += '<div style="font-size:10px;color:var(--text-secondary);margin-bottom:8px;">';
  html += oldLabel + ' (' + oldTime + ') → ' + newLabel + ' (' + newTime + ')';
  html += '</div>';

  if (diff.newIssues.length > 0) {
    html += '<div style="margin-bottom:6px;"><span style="color:#e74c3c;font-weight:600;font-size:11px;">新增 (' + diff.newIssues.length + ')</span></div>';
    diff.newIssues.forEach(function (f) {
      html += diffItem(f, '#e74c3c');
    });
  }
  if (diff.fixed.length > 0) {
    html += '<div style="margin-bottom:6px;"><span style="color:#27ae60;font-weight:600;font-size:11px;">已修复 (' + diff.fixed.length + ')</span></div>';
    diff.fixed.forEach(function (f) {
      html += diffItem(f, '#27ae60');
    });
  }
  if (diff.escalated.length > 0) {
    html += '<div style="margin-bottom:6px;"><span style="color:#e67e22;font-weight:600;font-size:11px;">严重程度升级 (' + diff.escalated.length + ')</span></div>';
    diff.escalated.forEach(function (d) {
      html += diffItem(d.current, '#e67e22', '由 ' + (d.old.severity || 'info') + ' → ' + (d.current.severity || 'info'));
    });
  }
  if (diff.improved.length > 0) {
    html += '<div style="margin-bottom:6px;"><span style="color:#3498db;font-weight:600;font-size:11px;">严重程度改善 (' + diff.improved.length + ')</span></div>';
    diff.improved.forEach(function (d) {
      html += diffItem(d.current, '#3498db', '由 ' + (d.old.severity || 'info') + ' → ' + (d.current.severity || 'info'));
    });
  }
  if (diff.unchanged.length > 0) {
    html += '<div style="margin-bottom:6px;"><span style="color:#95a5a6;font-size:11px;">未变化 (' + diff.unchanged.length + ')</span></div>';
  }
  if (diff.newIssues.length === 0 && diff.fixed.length === 0 && diff.escalated.length === 0 && diff.improved.length === 0) {
    html += '<div class="report-findings-empty">两次扫描结果完全一致</div>';
  }

  html += '</div>';
  view.innerHTML = html;

  var closeBtn = utils.get('scan-history-diff-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', function () {
      view.style.display = 'none';
      view.innerHTML = '';
    });
  }
}

function diffItem(f, color, extra) {
  var html = '<div class="report-finding-item" style="border-left:3px solid ' + color + ';">';
  html += '<div class="report-finding-title">' + escHtml(f.title || '未知') + '</div>';
  if (f.detail) html += '<div class="report-finding-detail">' + escHtml(f.detail) + '</div>';
  if (extra) html += '<div class="report-finding-detail" style="color:' + color + ';">' + escHtml(extra) + '</div>';
  html += '</div>';
  return html;
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export {
  MODULE_LABELS,
  saveScanResult,
  getScanHistory,
  diffScans,
  deleteScanEntry,
  clearAllHistory,
  renderHistoryContainer,
  loadAndRenderHistory,
};
