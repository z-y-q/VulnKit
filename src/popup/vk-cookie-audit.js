// 灵眸 - Cookie Security Audit
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { saveScanResult } from './vk-scan-history.js';

let lastResult = null;
let currentFilter = 'all';
let currentSearch = '';
let currentSort = '';
var CA_SORT_FNS = {
  severity: function (a, b) {
    var o = { critical: 0, high: 1, medium: 2, info: 3 };
    return (o[a._maxSev] || 3) - (o[b._maxSev] || 3);
  },
  name: function (a, b) {
    return (a.cookie.name || '').localeCompare(b.cookie.name || '');
  },
};

const SENSITIVE_NAMES = [
  'session',
  'token',
  'auth',
  'key',
  'secret',
  'admin',
  'user',
  'pass',
  'jwt',
  'sid',
  'uid',
  'csrf',
  'xsrf',
  'oauth',
  'refresh',
  'access',
  'id_token',
  'connect',
];

const FIX_RECOMMENDATIONS = {
  '缺少 Secure 标志': '添加 Secure; 属性 — 仅通过 HTTPS 传输',
  '缺少 HttpOnly 标志': '添加 HttpOnly; 属性 — 防止 JavaScript 访问',
  'SameSite=None 但缺少 Secure': 'SameSite=None 必须搭配 Secure; 属性',
  'SameSite=None': '考虑改为 SameSite=Lax 或 SameSite=Strict 减少跨站风险',
  'SameSite 未设置': '显式设置 SameSite=Lax 或 SameSite=Strict',
  '敏感 Cookie': '敏感 Cookie 应同时设置 Secure + HttpOnly',
  '过期时间超过 1 年': '缩短有效期，敏感 Cookie 使用会话模式',
  通配符域名: '限制 domain 到具体子域名而非通配符',
  '__Host- 前缀缺少 Secure': '__Host- 前缀要求 Secure 属性',
  '__Host- 前缀 Path 非 /': '__Host- 前缀要求 Path=/',
  '__Host- 前缀设置了 Domain': '__Host- 前缀禁止设置 Domain 属性',
  '__Secure- 前缀缺少 Secure': '__Secure- 前缀要求 Secure 属性',
};

function auditCookies() {
  const statusEl = utils.get('cookie-audit-status');
  const resultsEl = utils.get('cookie-audit-results');
  const copyBtn = utils.get('cookie-audit-copy-btn');
  const exportBtn = utils.get('cookie-audit-export-btn');
  const copyMdBtn = utils.get('cookie-audit-copy-md-btn');

  if (statusEl) statusEl.textContent = '正在审计 Cookie...';

  utils.getCurrentDomain().then(function (domain) {
    if (!domain) {
      if (statusEl) statusEl.textContent = '无法获取当前域名';
      return;
    }

    // Get target page protocol from active tab, not popup's chrome-extension: protocol
    utils.requireTabId().then(function (tab) {
      const isHttpsSite = tab && tab.url && tab.url.indexOf('https://') === 0;

      chrome.cookies.getAll({ domain: domain }, function (cookies) {
        if (chrome.runtime.lastError) {
          if (statusEl) statusEl.textContent = `查询失败: ${chrome.runtime.lastError.message}`;
          return;
        }
        if (!cookies || cookies.length === 0) {
          const parts = domain.split('.');
          if (parts.length > 2) {
            const baseDomain = parts.slice(-2).join('.');
            chrome.cookies.getAll({ domain: baseDomain }, function (parentCookies) {
              if (chrome.runtime.lastError) {
                if (statusEl)
                  statusEl.textContent = `查询失败: ${chrome.runtime.lastError.message}`;
                return;
              }
              if (parentCookies && parentCookies.length > 0) {
                processCookies(parentCookies, isHttpsSite, statusEl, resultsEl, copyBtn, exportBtn);
              } else {
                showNoCookies(statusEl, resultsEl, copyBtn, exportBtn);
              }
            });
            return;
          }
          showNoCookies(statusEl, resultsEl, copyBtn, exportBtn);
          return;
        }
        processCookies(cookies, isHttpsSite, statusEl, resultsEl, copyBtn, exportBtn);
      });
    });
  });
}

function showNoCookies(statusEl, resultsEl, copyBtn, exportBtn) {
  if (statusEl) statusEl.textContent = '当前域名没有 Cookie';
  if (resultsEl) resultsEl.innerHTML = '<div class="cookie-no-cookies">当前域名没有 Cookie</div>';
  if (copyBtn) copyBtn.style.display = 'none';
  if (exportBtn) exportBtn.style.display = 'none';
  if (copyMdBtn) copyMdBtn.style.display = 'none';
}

function processCookies(cookies, isHttpsSite, statusEl, resultsEl, copyBtn, exportBtn) {
  const results = cookies.map(function (c) {
    return analyzeCookie(c, isHttpsSite);
  });
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  results.forEach(function (r) {
    let max = r.issues.reduce(function (m, i) {
      return Math.max(m, SEV_ORDER[i.severity] || 0);
    }, 0);
    r._maxSev = max;
    const sevKey = Object.keys(SEV_ORDER).find(function (k) {
      return SEV_ORDER[k] === max;
    });
    if (sevKey && severityCounts.hasOwnProperty(sevKey)) severityCounts[sevKey]++;
  });
  results.sort(function (a, b) {
    return b._maxSev - a._maxSev;
  });

  lastResult = results;
  if (statusEl) statusEl.textContent = `审计完成: ${cookies.length} 个 Cookie`;
  if (copyBtn) copyBtn.style.display = '';
  if (exportBtn) exportBtn.style.display = '';
  if (copyMdBtn) copyMdBtn.style.display = '';

  renderStats(severityCounts);
  renderResults(results);

  utils.getCurrentDomain().then(function (d) {
    if (d) saveScanResult('cookie-audit', d, getFindings());
  });
}

function analyzeCookie(cookie, isHttpsSite) {
  const issues = [];
  const isHttps = cookie.secure || isHttpsSite;

  if (!cookie.secure && isHttps) {
    issues.push({ severity: 'high', text: '缺少 Secure 标志 (HTTPS 域名下应启用)' });
  }
  if (!cookie.httpOnly) {
    issues.push({ severity: 'medium', text: '缺少 HttpOnly 标志 (可通过 JS 访问)' });
  }
  if (cookie.sameSite === 'no_restriction' || cookie.sameSite === 'none') {
    if (!cookie.secure) {
      issues.push({ severity: 'critical', text: 'SameSite=None 但缺少 Secure (浏览器可能拒绝)' });
    } else {
      issues.push({ severity: 'medium', text: 'SameSite=None — 跨站请求携带 Cookie' });
    }
  } else if (!cookie.sameSite || cookie.sameSite === 'unspecified') {
    issues.push({ severity: 'low', text: 'SameSite 未设置 (浏览器可能默认 Lax)' });
  }

  const cookieName = (cookie.name || '').toLowerCase();
  const hasSensitiveKeyword = SENSITIVE_NAMES.some(function (kw) {
    return cookieName.indexOf(kw) !== -1;
  });
  if (hasSensitiveKeyword) {
    if (!cookie.secure) {
      issues.push({
        severity: 'critical',
        text: `敏感 Cookie (${cookie.name}) 未设置 Secure`,
      });
    }
    if (!cookie.httpOnly) {
      issues.push({
        severity: 'high',
        text: `敏感 Cookie (${cookie.name}) 未设置 HttpOnly`,
      });
    }
  }

  if (cookie.expirationDate) {
    const now = Date.now() / 1000;
    const oneYear = 365 * 24 * 60 * 60;
    if (cookie.expirationDate - now > oneYear) {
      issues.push({
        severity: 'low',
        text: `过期时间超过 1 年 (${new Date(cookie.expirationDate * 1000).toLocaleDateString()})`,
      });
    }
  } else if (cookie.session) {
    issues.push({ severity: 'info', text: '会话 Cookie (关闭浏览器后失效)' });
  }

  if (cookie.path === '/') {
    issues.push({ severity: 'info', text: 'Path 为 / (全站可访问)' });
  }

  if (cookie.domain && cookie.domain.startsWith('.')) {
    issues.push({ severity: 'low', text: `通配符域名 ${cookie.domain} (子域名共享)` });
  }

  const rawName = cookie.name || '';
  if (rawName.indexOf('__Host-') === 0) {
    if (!cookie.secure) {
      issues.push({ severity: 'high', text: '__Host- 前缀缺少 Secure' });
    }
    if (cookie.path !== '/') {
      issues.push({
        severity: 'high',
        text: `__Host- 前缀 Path 非 / (当前: ${cookie.path || '/'})`,
      });
    }
    if (cookie.domain) {
      issues.push({ severity: 'high', text: '__Host- 前缀设置了 Domain (应省略)' });
    }
  } else if (rawName.indexOf('__Secure-') === 0) {
    if (!cookie.secure) {
      issues.push({ severity: 'high', text: '__Secure- 前缀缺少 Secure' });
    }
  }

  return { cookie: cookie, issues: issues };
}

function renderStats(counts) {
  const statsEl = utils.get('cookie-audit-stats');
  if (!statsEl) return;
  let html = '';
  const labels = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
  Object.keys(counts).forEach(function (sev) {
    if (counts[sev] > 0) {
      html += `<div class="cookie-audit-stat"><span class="cookie-audit-stat-badge ${sev}">${counts[sev]}</span><span class="cookie-audit-stat-label">${labels[sev]}</span></div>`;
    }
  });
  statsEl.innerHTML = html;
  statsEl.style.display = '';
}

function getFixRecommendation(issueText) {
  const keys = Object.keys(FIX_RECOMMENDATIONS);
  for (let i = 0; i < keys.length; i++) {
    if (issueText.indexOf(keys[i]) !== -1) {
      return FIX_RECOMMENDATIONS[keys[i]];
    }
  }
  return null;
}

function renderResults(results) {
  const resultsEl = utils.get('cookie-audit-results');
  if (!resultsEl) return;

  let html = '';
  results.forEach(function (r) {
    let c = r.cookie;
    html += `<div class="cookie-item"><div class="cookie-item-header"><span class="cookie-name">${utils.escapeHtml(c.name)}</span><span class="cookie-domain">${utils.escapeHtml(c.domain || '')}</span></div><div class="cookie-flags"><span class="cookie-flag ${c.secure ? 'ok' : 'warn'}">Secure</span><span class="cookie-flag ${c.httpOnly ? 'ok' : 'warn'}">HttpOnly</span><span class="cookie-flag ${c.sameSite && c.sameSite !== 'unspecified' ? 'ok' : 'warn'}">SameSite: ${utils.escapeHtml(c.sameSite || '未设置')}</span><span class="cookie-flag ${c.path ? 'ok' : 'warn'}">Path: ${utils.escapeHtml(c.path || '/')}</span></div>`;

    if (r.issues.length > 0) {
      html += '<div class="cookie-issues">';
      r.issues.forEach(function (issue) {
        const fix = getFixRecommendation(issue.text);
        html += `<div class="cookie-issue"><span class="cookie-issue-severity ${issue.severity}"></span><span class="cookie-issue-text">${utils.escapeHtml(issue.text)}</span>${fix ? `<span class="cookie-issue-fix">💡 ${utils.escapeHtml(fix)}</span>` : ''}</div>`;
      });
      html += '</div>';
    }
    html += '</div>';
  });
  resultsEl.innerHTML = html;
}

function copyResults() {
  if (!lastResult || lastResult.length === 0) {
    utils.showToast('没有审计结果', 'warning');
    return;
  }
  const lines = lastResult.map(function (r) {
    const c = r.cookie;
    let line = `${c.name}=[已隐藏]`;
    line += ` | Secure:${c.secure ? 'Y' : 'N'}`;
    line += ` HttpOnly:${c.httpOnly ? 'Y' : 'N'}`;
    line += ` SameSite:${c.sameSite || 'none'}`;
    if (r.issues.length > 0) {
      line += ` | Issues: ${r.issues
        .map(function (i) {
          return `[${i.severity.toUpperCase()}] ${i.text}`;
        })
        .join('; ')}`;
    }
    return line;
  });
  utils.copyAndToast(lines.join('\n'), `已复制 ${lastResult.length} 条审计结果`);
}

function copyMarkdown() {
  if (!lastResult || lastResult.length === 0) {
    utils.showToast('没有审计结果', 'warning');
    return;
  }
  var headers = ['Cookie', 'Secure', 'HttpOnly', 'SameSite', 'Issues'];
  var rows = lastResult.map(function (r) {
    var c = r.cookie;
    var issuesText =
      r.issues.length > 0
        ? r.issues
            .map(function (i) {
              return '[' + i.severity.toUpperCase() + '] ' + i.text;
            })
            .join('; ')
        : '-';
    return [
      c.name,
      c.secure ? 'Yes' : 'No',
      c.httpOnly ? 'Yes' : 'No',
      c.sameSite || 'none',
      issuesText,
    ];
  });
  var md = utils.buildMarkdownTable(headers, rows);
  utils.copyAndToast(md, '已复制 Markdown');
}

function exportResults() {
  if (!lastResult || lastResult.length === 0) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }
  const report = {
    timestamp: new Date().toISOString(),
    cookies: lastResult.map(function (r) {
      return {
        name: r.cookie.name,
        domain: r.cookie.domain,
        path: r.cookie.path,
        secure: r.cookie.secure,
        httpOnly: r.cookie.httpOnly,
        sameSite: r.cookie.sameSite,
        issues: r.issues,
      };
    }),
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cookie-audit-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  utils.showToast('已导出 JSON', 'success');
}

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function filterBySeverity(filter) {
  currentFilter = filter;
  applyFilter();
}

function searchResults(query) {
  currentSearch = (query || '').toLowerCase();
  applyFilter();
}

function applyFilter() {
  if (!lastResult || lastResult.length === 0) return;
  const filtered = lastResult.filter(function (r) {
    if (currentFilter !== 'all') {
      const sevKey = Object.keys(SEV_ORDER).find(function (k) {
        return SEV_ORDER[k] === r._maxSev;
      });
      if (sevKey !== currentFilter) return false;
    }
    if (currentSearch) {
      const name = (r.cookie.name || '').toLowerCase();
      const domain = (r.cookie.domain || '').toLowerCase();
      if (name.indexOf(currentSearch) === -1 && domain.indexOf(currentSearch) === -1) return false;
    }
    return true;
  });
  var sorted = utils.applySort(filtered, currentSort, CA_SORT_FNS);
  renderResults(sorted);
}

function getFindings() {
  if (!lastResult || lastResult.length === 0) return [];
  var findings = [];
  lastResult.forEach(function (r) {
    r.issues.forEach(function (issue) {
      if (SEV_ORDER[issue.severity] === undefined) return;
      findings.push({
        severity: issue.severity,
        title: 'Cookie 安全问题: ' + r.cookie.name,
        detail: issue.text,
        module: 'cookie',
        url: (r.cookie.domain || '') + (r.cookie.path || '/'),
      });
    });
  });
  return findings;
}

function sortResults(key) {
  currentSort = key;
  applyFilter();
}

export {
  auditCookies,
  copyResults,
  copyMarkdown,
  exportResults,
  filterBySeverity,
  searchResults,
  sortResults,
  getFindings,
};
