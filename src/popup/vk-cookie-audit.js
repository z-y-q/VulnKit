// 灵眸 - Cookie Security Audit
window.VulnKitCookieAudit = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastResult = null;

  var SENSITIVE_NAMES = ['session', 'token', 'auth', 'key', 'secret', 'admin', 'user', 'pass', 'jwt', 'sid', 'uid'];

  function auditCookies() {
    var statusEl = utils.get('cookie-audit-status');
    var statsEl = utils.get('cookie-audit-stats');
    var resultsEl = utils.get('cookie-audit-results');
    var copyBtn = utils.get('cookie-audit-copy-btn');

    if (statusEl) statusEl.textContent = '正在审计 Cookie...';

    utils.getCurrentDomain().then(function (domain) {
      if (!domain) {
        if (statusEl) statusEl.textContent = '无法获取当前域名';
        return;
      }

      chrome.cookies.getAll({ domain: domain }, function (cookies) {
        if (!cookies || cookies.length === 0) {
          if (statusEl) statusEl.textContent = '当前域名没有 Cookie';
          if (resultsEl) resultsEl.innerHTML = '<div class="cookie-no-cookies">当前域名没有 Cookie</div>';
          if (copyBtn) copyBtn.style.display = 'none';
          return;
        }

        var results = cookies.map(analyzeCookie);
        var severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        results.forEach(function (r) {
          var max = r.issues.reduce(function (m, i) {
            var order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
            return Math.max(m, order[i.severity] || 0);
          }, 0);
          var sev = ['', 'info', 'low', 'medium', 'high', 'critical'][max];
          if (sev && severityCounts.hasOwnProperty(sev)) severityCounts[sev]++;
        });

        lastResult = results;
        if (statusEl) statusEl.textContent = '审计完成: ' + cookies.length + ' 个 Cookie';
        if (copyBtn) copyBtn.style.display = '';

        renderStats(severityCounts);
        renderResults(results);
      });
    });
  }

  function analyzeCookie(cookie) {
    var issues = [];
    var isHttps = cookie.secure || (location.protocol === 'https:');

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

    var cookieName = (cookie.name || '').toLowerCase();
    var hasSensitiveKeyword = SENSITIVE_NAMES.some(function (kw) {
      return cookieName.indexOf(kw) !== -1;
    });
    if (hasSensitiveKeyword) {
      if (!cookie.secure) {
        issues.push({ severity: 'critical', text: '敏感 Cookie (' + cookie.name + ') 未设置 Secure' });
      }
      if (!cookie.httpOnly) {
        issues.push({ severity: 'high', text: '敏感 Cookie (' + cookie.name + ') 未设置 HttpOnly' });
      }
    }

    if (cookie.expirationDate) {
      var now = Date.now() / 1000;
      var oneYear = 365 * 24 * 60 * 60;
      if (cookie.expirationDate - now > oneYear) {
        issues.push({ severity: 'low', text: '过期时间超过 1 年 (' + new Date(cookie.expirationDate * 1000).toLocaleDateString() + ')' });
      }
    } else if (cookie.session) {
      issues.push({ severity: 'info', text: '会话 Cookie (关闭浏览器后失效)' });
    }

    if (cookie.path === '/') {
      issues.push({ severity: 'info', text: 'Path 为 / (全站可访问)' });
    }

    if (cookie.domain && cookie.domain.startsWith('.')) {
      issues.push({ severity: 'low', text: '通配符域名 ' + cookie.domain + ' (子域名共享)' });
    }

    return { cookie: cookie, issues: issues };
  }

  function renderStats(counts) {
    var statsEl = utils.get('cookie-audit-stats');
    if (!statsEl) return;
    var html = '';
    var labels = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
    Object.keys(counts).forEach(function (sev) {
      if (counts[sev] > 0) {
        html += '<div class="cookie-audit-stat"><span class="cookie-audit-stat-badge ' + sev + '">' + counts[sev] + '</span><span class="cookie-audit-stat-label">' + labels[sev] + '</span></div>';
      }
    });
    statsEl.innerHTML = html;
    statsEl.style.display = '';
  }

  function renderResults(results) {
    var resultsEl = utils.get('cookie-audit-results');
    if (!resultsEl) return;

    var html = '';
    results.forEach(function (r) {
      var c = r.cookie;
      html += '<div class="cookie-item">';
      html += '<div class="cookie-item-header">';
      html += '<span class="cookie-name">' + utils.escapeHtml(c.name) + '</span>';
      html += '<span class="cookie-domain">' + utils.escapeHtml(c.domain || '') + '</span>';
      html += '</div>';
      html += '<div class="cookie-flags">';
      html += '<span class="cookie-flag ' + (c.secure ? 'ok' : 'warn') + '">Secure</span>';
      html += '<span class="cookie-flag ' + (c.httpOnly ? 'ok' : 'warn') + '">HttpOnly</span>';
      html += '<span class="cookie-flag ' + (c.sameSite && c.sameSite !== 'unspecified' ? 'ok' : 'warn') + '">SameSite: ' + utils.escapeHtml(c.sameSite || '未设置') + '</span>';
      html += '<span class="cookie-flag ' + (c.path ? 'ok' : 'warn') + '">Path: ' + utils.escapeHtml(c.path || '/') + '</span>';
      html += '</div>';

      if (r.issues.length > 0) {
        html += '<div class="cookie-issues">';
        r.issues.forEach(function (issue) {
          html += '<div class="cookie-issue"><span class="cookie-issue-severity ' + issue.severity + '"></span>' + utils.escapeHtml(issue.text) + '</div>';
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
    var lines = lastResult.map(function (r) {
      var c = r.cookie;
      var line = c.name + '=' + (c.value || '').substring(0, 50);
      line += ' | Secure:' + (c.secure ? 'Y' : 'N');
      line += ' HttpOnly:' + (c.httpOnly ? 'Y' : 'N');
      line += ' SameSite:' + (c.sameSite || 'none');
      if (r.issues.length > 0) {
        line += ' | Issues: ' + r.issues.map(function (i) { return '[' + i.severity.toUpperCase() + '] ' + i.text; }).join('; ');
      }
      return line;
    });
    utils.copyAndToast(lines.join('\n'), '已复制 ' + lastResult.length + ' 条审计结果');
  }

  return { auditCookies: auditCookies, copyResults: copyResults, get lastResult() { return lastResult; } };
})();
