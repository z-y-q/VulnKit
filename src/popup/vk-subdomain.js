// 灵眸 - Subdomain Collection
window.VulnKitSubdomain = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastSubdomains = [];

  var COMMON_PREFIXES = [
    'www','mail','ftp','localhost','admin','portal','api','dev','staging','test','uat','prod',
    'vpn','cdn','static','assets','img','images','media','upload','app','m','mobile',
    'blog','forum','wiki','docs','doc','help','support','crm','erp','oa','hr',
    'git','svn','jenkins','ci','cd','monitor','grafana','prometheus','kibana','elasticsearch',
    'redis','mongo','mysql','db','database','proxy','gateway','auth','sso','login','oauth',
    'nas','backup','bak','old','new','v2','v3','api2','internal','intranet','demo',
    'sandbox','preview','stg','pre','prod','release','master','alpha','beta','gamma',
    'redis','mq','rabbitmq','kafka','zookeeper','consul','etcd','nacos',
    'shop','store','pay','payment','order','user','member','search','notify','msg',
    'log','logs','syslog','audit','trace','jaeger','zipkin',
    'img','image','pic','photo','video','file','files','download','res','resource',
    'ws','wss','socket','push','websocket',
  ];

  function collectSubdomains() {
    var statusEl = utils.get('subdomain-status');
    var resultsEl = utils.get('subdomain-results');
    var copyBtn = utils.get('subdomain-copy-btn');
    var exportBtn = utils.get('subdomain-export-btn');

    if (statusEl) statusEl.textContent = '正在通过证书透明度收集子域名...';
    if (resultsEl) resultsEl.innerHTML = '';

    utils.getCurrentDomain().then(function (domain) {
      if (!domain) {
        if (statusEl) statusEl.textContent = '无法获取当前域名';
        return;
      }

      var baseDomain = extractBaseDomain(domain);
      var seen = {};
      lastSubdomains = [];

      // Method 1: Certificate Transparency via crt.sh
      var ctUrl = 'https://crt.sh/?q=%.' + encodeURIComponent(baseDomain) + '&output=json';
      chrome.runtime.sendMessage({ type: 'FETCH_URL', url: ctUrl }, function (resp) {
        if (resp && resp.body) {
          try {
            var entries = JSON.parse(resp.body);
            if (Array.isArray(entries)) {
              entries.forEach(function (entry) {
                var name = (entry.name_value || entry.name || '').trim();
                name.split('\n').forEach(function (n) {
                  n = n.trim().toLowerCase().replace(/^\*\./, '');
                  if (n && n.includes(baseDomain) && !seen[n]) {
                    seen[n] = true;
                    lastSubdomains.push({ host: n, source: 'ct' });
                  }
                });
              });
            }
          } catch (e) {
            // parse error
          }
        }

        if (statusEl) statusEl.textContent = 'CT 收集完成: ' + lastSubdomains.length + ' 个子域名';
        renderSubdomains(lastSubdomains, baseDomain);
        if (copyBtn) copyBtn.style.display = '';
        if (exportBtn) exportBtn.style.display = '';
      });
    });
  }

  function extractFromPage() {
    var statusEl = utils.get('subdomain-status');
    var resultsEl = utils.get('subdomain-results');
    var copyBtn = utils.get('subdomain-copy-btn');
    var exportBtn = utils.get('subdomain-export-btn');

    if (statusEl) statusEl.textContent = '正在从页面提取子域名...';
    if (resultsEl) resultsEl.innerHTML = '';

    utils.getCurrentDomain().then(function (domain) {
      if (!domain) {
        if (statusEl) statusEl.textContent = '无法获取当前域名';
        return;
      }

      var baseDomain = extractBaseDomain(domain);

      utils.requireTabId().then(function (tab) {
        if (!tab) return;

        chrome.tabs.sendMessage(tab.id, { type: 'CONTEXT_EXTRACT_LINKS' }, function (resp) {
          if (chrome.runtime.lastError || !resp) {
            if (statusEl) statusEl.textContent = '提取失败';
            return;
          }

          chrome.storage.local.get(['contextExtractedLinks'], function (result) {
            var links = result.contextExtractedLinks || [];
            var seen = {};
            var pageSubdomains = [];

            links.forEach(function (link) {
              try {
                var hostname = new URL(link.href, 'https://' + baseDomain).hostname.toLowerCase();
                if (hostname !== baseDomain && hostname.endsWith('.' + baseDomain) && !seen[hostname]) {
                  seen[hostname] = true;
                  pageSubdomains.push({ host: hostname, source: 'page' });
                }
              } catch (e) {}
            });

            // Merge with existing
            var existingMap = {};
            lastSubdomains.forEach(function (s) { existingMap[s.host] = true; });
            pageSubdomains.forEach(function (s) {
              if (!existingMap[s.host]) {
                existingMap[s.host] = true;
                lastSubdomains.push(s);
              }
            });

            lastSubdomains.sort(function (a, b) { return a.host.localeCompare(b.host); });
            if (statusEl) statusEl.textContent = '页面提取完成: 新增 ' + pageSubdomains.length + '，共 ' + lastSubdomains.length + ' 个子域名';
            renderSubdomains(lastSubdomains, baseDomain);
            if (copyBtn) copyBtn.style.display = '';
            if (exportBtn) exportBtn.style.display = '';
          });
        });
      });
    });
  }

  function extractBaseDomain(domain) {
    var parts = domain.toLowerCase().split('.');
    if (parts.length <= 2) return domain;
    // Simple heuristic: take last 2 parts (e.g. example.com)
    return parts.slice(-2).join('.');
  }

  function renderSubdomains(subdomains, baseDomain) {
    var resultsEl = utils.get('subdomain-results');
    if (!resultsEl) return;

    var statsEl = utils.get('subdomain-stats');
    var ctCount = subdomains.filter(function (s) { return s.source === 'ct'; }).length;
    var pageCount = subdomains.filter(function (s) { return s.source === 'page'; }).length;
    var dnsCount = subdomains.filter(function (s) { return s.source === 'dns'; }).length;

    if (statsEl) {
      statsEl.innerHTML =
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' + subdomains.length + '</span> 子域名</div>' +
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' + ctCount + '</span> CT</div>' +
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' + pageCount + '</span> 页面</div>' +
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' + dnsCount + '</span> DNS</div>';
      statsEl.style.display = '';
    }

    if (subdomains.length === 0) {
      resultsEl.innerHTML = '<div class="subdomain-empty">未发现子域名</div>';
      return;
    }

    var html = '<div class="subdomain-list">';
    subdomains.forEach(function (s) {
      html += '<div class="subdomain-item">';
      html += '<span class="subdomain-hostname" data-host="' + utils.escapeHtml(s.host) + '">' + utils.escapeHtml(s.host) + '</span>';
      html += '<span class="subdomain-source-badge ' + s.source + '">' + sourceLabel(s.source) + '</span>';
      html += '</div>';
    });
    html += '</div>';
    resultsEl.innerHTML = html;

    // Click to copy single subdomain
    resultsEl.querySelectorAll('.subdomain-hostname').forEach(function (el) {
      el.addEventListener('click', function () {
        utils.copyText(this.dataset.host);
        utils.showToast('已复制: ' + this.dataset.host, 'success', 800);
      });
    });
  }

  function sourceLabel(src) {
    var labels = { ct: 'CT', page: '页面', dns: 'DNS' };
    return labels[src] || src;
  }

  function copyResults() {
    if (lastSubdomains.length === 0) {
      utils.showToast('没有结果', 'warning');
      return;
    }
    var text = lastSubdomains.map(function (s) { return s.host; }).join('\n');
    utils.copyAndToast(text, '已复制 ' + lastSubdomains.length + ' 个子域名');
  }

  function exportResults() {
    if (lastSubdomains.length === 0) {
      utils.showToast('没有结果', 'warning');
      return;
    }
    var json = JSON.stringify(lastSubdomains, null, 2);
    var blob = new Blob([json], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    chrome.downloads.download({ url: url, filename: 'subdomains.json', saveAs: true });
    utils.showToast('导出中...', 'info');
  }

  return {
    collectSubdomains: collectSubdomains,
    extractFromPage: extractFromPage,
    copyResults: copyResults,
    exportResults: exportResults,
    get lastSubdomains() { return lastSubdomains; },
  };
})();
