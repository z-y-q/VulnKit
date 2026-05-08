// 灵眸 - Subdomain Collection
window.VulnKitSubdomain = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastSubdomains = [];
  var lastBaseDomain = '';
  var dnsScanActive = false;
  var dnsScanAborted = false;
  var currentFilter = 'all';
  var currentSearch = '';
  var scanStartTime = 0;
  var CT_TIMEOUT_MS = 30000;
  var DNS_BATCH_SIZE = 10;
  var DNS_BATCH_DELAY_MS = 200;

  var COMMON_PREFIXES = [
    'www',
    'mail',
    'ftp',
    'localhost',
    'admin',
    'portal',
    'api',
    'dev',
    'staging',
    'test',
    'uat',
    'prod',
    'vpn',
    'cdn',
    'static',
    'assets',
    'img',
    'images',
    'media',
    'upload',
    'app',
    'm',
    'mobile',
    'blog',
    'forum',
    'wiki',
    'docs',
    'doc',
    'help',
    'support',
    'crm',
    'erp',
    'oa',
    'hr',
    'git',
    'svn',
    'jenkins',
    'ci',
    'cd',
    'monitor',
    'grafana',
    'prometheus',
    'kibana',
    'elasticsearch',
    'redis',
    'mongo',
    'mysql',
    'db',
    'database',
    'proxy',
    'gateway',
    'auth',
    'sso',
    'login',
    'oauth',
    'nas',
    'backup',
    'bak',
    'old',
    'new',
    'v2',
    'v3',
    'api2',
    'internal',
    'intranet',
    'demo',
    'sandbox',
    'preview',
    'stg',
    'pre',
    'release',
    'master',
    'alpha',
    'beta',
    'gamma',
    'mq',
    'rabbitmq',
    'kafka',
    'zookeeper',
    'consul',
    'etcd',
    'nacos',
    'shop',
    'store',
    'pay',
    'payment',
    'order',
    'user',
    'member',
    'search',
    'notify',
    'msg',
    'log',
    'logs',
    'syslog',
    'audit',
    'trace',
    'jaeger',
    'zipkin',
    'image',
    'pic',
    'photo',
    'video',
    'file',
    'files',
    'download',
    'res',
    'resource',
    'ws',
    'wss',
    'socket',
    'push',
    'websocket',
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
      lastBaseDomain = baseDomain;

      // Method 1: Certificate Transparency via crt.sh
      var ctUrl = 'https://crt.sh/?q=%.' + encodeURIComponent(baseDomain) + '&output=json';
      fetchWithTimeout(ctUrl, CT_TIMEOUT_MS).then(function (resp) {
        var ctFailed = false;
        if (resp && resp.body) {
          try {
            var entries = JSON.parse(resp.body);
            if (Array.isArray(entries)) {
              entries.forEach(function (entry) {
                var name = (entry.name_value || entry.name || '').trim();
                name.split('\n').forEach(function (n) {
                  n = n.trim().toLowerCase().replace(/^\*\./, '');
                  if (n && n.endsWith(baseDomain) && !seen[n]) {
                    seen[n] = true;
                    lastSubdomains.push({ host: n, source: 'ct' });
                  }
                });
              });
            }
          } catch (e) {
            ctFailed = true;
          }
        } else {
          ctFailed = true;
        }

        var statusText = 'CT 收集完成: ' + lastSubdomains.length + ' 个子域名';
        if (ctFailed) {
          statusText += ' — crt.sh 查询超时或失败，请稍后重试';
        } else if (lastSubdomains.length === 0) {
          statusText += ' — 该域名在证书透明度日志中未发现子域名';
        }
        if (statusEl) statusEl.textContent = statusText;
        renderSubdomains(lastSubdomains, baseDomain);
        if (copyBtn) copyBtn.hidden = false;
        if (exportBtn) exportBtn.hidden = false;
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
      lastBaseDomain = baseDomain;

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
                if (
                  hostname !== baseDomain &&
                  hostname.endsWith('.' + baseDomain) &&
                  !seen[hostname]
                ) {
                  seen[hostname] = true;
                  pageSubdomains.push({ host: hostname, source: 'page' });
                }
              } catch (_) {
                /* malformed link href */
              }
            });

            // Merge with existing
            var existingMap = {};
            lastSubdomains.forEach(function (s) {
              existingMap[s.host] = true;
            });
            pageSubdomains.forEach(function (s) {
              if (!existingMap[s.host]) {
                existingMap[s.host] = true;
                lastSubdomains.push(s);
              }
            });

            lastSubdomains.sort(function (a, b) {
              return a.host.localeCompare(b.host);
            });
            if (statusEl)
              statusEl.textContent =
                '页面提取完成: 新增 ' +
                pageSubdomains.length +
                '，共 ' +
                lastSubdomains.length +
                ' 个子域名';
            renderSubdomains(lastSubdomains, baseDomain);
            if (copyBtn) copyBtn.hidden = false;
            if (exportBtn) exportBtn.hidden = false;
          });
        });
      });
    });
  }

  var MULTI_PART_TLDS = [
    'co.uk',
    'com.cn',
    'com.au',
    'com.br',
    'com.mx',
    'co.jp',
    'co.kr',
    'co.in',
    'co.nz',
    'org.cn',
    'net.cn',
    'gov.cn',
    'ac.uk',
    'gov.uk',
    'edu.uk',
    'me.uk',
    'com.tw',
    'org.tw',
    'net.tw',
    'com.hk',
    'org.hk',
    'com.sg',
    'com.my',
    'co.za',
    'co.id',
    'co.th',
    'co.il',
    'com.ph',
    'com.eg',
    'co.ke',
    'com.ar',
    'com.ve',
    'com.co',
    'com.pe',
    'com.cl',
    'com.ec',
    'ne.jp',
    'or.jp',
    'ac.jp',
    'go.jp',
    'org.za',
    'edu.cn',
    'mil.cn',
    'nom.br',
    'adm.br',
    'gov.br',
  ];

  function extractBaseDomain(domain) {
    var d = domain.toLowerCase();
    for (var i = 0; i < MULTI_PART_TLDS.length; i++) {
      var suffix = MULTI_PART_TLDS[i];
      if (d.endsWith('.' + suffix)) {
        var prefix = d.slice(0, -(suffix.length + 1));
        var parts = prefix.split('.');
        return parts[parts.length - 1] + '.' + suffix;
      }
    }
    var parts = d.split('.');
    if (parts.length <= 2) return d;
    return parts.slice(-2).join('.');
  }

  function fetchWithTimeout(url, timeoutMs) {
    return new Promise(function (resolve) {
      var timer = setTimeout(function () {
        resolve(null);
      }, timeoutMs || CT_TIMEOUT_MS);
      chrome.runtime.sendMessage(
        { type: 'FETCH_URL', url: url, timeout: timeoutMs },
        function (resp) {
          clearTimeout(timer);
          resolve(resp || null);
        }
      );
    });
  }

  function filterBySource(filter) {
    currentFilter = filter;
    applyFilter();
  }

  function searchResults(query) {
    currentSearch = (query || '').toLowerCase();
    applyFilter();
  }

  function applyFilter() {
    if (lastSubdomains.length === 0) return;
    var filtered = lastSubdomains.filter(function (s) {
      if (currentFilter !== 'all' && s.source !== currentFilter) return false;
      if (currentSearch && s.host.indexOf(currentSearch) === -1) return false;
      return true;
    });
    renderSubdomains(filtered, lastBaseDomain);
  }

  function renderSubdomains(subdomains, baseDomain) {
    var resultsEl = utils.get('subdomain-results');
    if (!resultsEl) return;

    var statsEl = utils.get('subdomain-stats');
    var ctCount = subdomains.filter(function (s) {
      return s.source === 'ct';
    }).length;
    var pageCount = subdomains.filter(function (s) {
      return s.source === 'page';
    }).length;
    var httpCount = subdomains.filter(function (s) {
      return s.source === 'http';
    }).length;
    var dnsCount = subdomains.filter(function (s) {
      return s.source === 'dns';
    }).length;

    if (statsEl) {
      statsEl.innerHTML =
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' +
        subdomains.length +
        '</span> 子域名</div>' +
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' +
        ctCount +
        '</span> CT</div>' +
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' +
        pageCount +
        '</span> 页面</div>' +
        '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' +
        httpCount +
        '</span> HTTP</div>' +
        (dnsCount > 0
          ? '<div class="subdomain-stat-item"><span class="subdomain-stat-count">' +
            dnsCount +
            '</span> DNS</div>'
          : '');
      statsEl.hidden = false;
    }

    if (subdomains.length === 0) {
      resultsEl.innerHTML = '<div class="subdomain-empty">未发现子域名</div>';
      return;
    }

    var html = '<div class="subdomain-list">';
    subdomains.forEach(function (s) {
      html += '<div class="subdomain-item">';
      html +=
        '<span class="subdomain-hostname" data-host="' +
        utils.escapeHtml(s.host) +
        '">' +
        utils.escapeHtml(s.host) +
        '</span>';
      html +=
        '<span class="subdomain-source-badge ' +
        s.source +
        '">' +
        sourceLabel(s.source) +
        '</span>';
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
    var labels = { ct: 'CT', page: '页面', http: 'HTTP', dns: 'DNS' };
    return labels[src] || src;
  }

  function copyResults() {
    if (lastSubdomains.length === 0) {
      utils.showToast('没有结果', 'warning');
      return;
    }
    var text = lastSubdomains
      .map(function (s) {
        return s.host;
      })
      .join('\n');
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

  function delay(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  function dnsResolve(hostname) {
    return new Promise(function (resolve) {
      chrome.runtime.sendMessage(
        { type: 'FETCH_DNS_RESOLVE', hostname: hostname },
        function (resp) {
          if (chrome.runtime.lastError || !resp || resp.error) {
            resolve(null);
            return;
          }
          resolve(resp);
        }
      );
    });
  }

  function httpProbe(hostname) {
    return new Promise(function (resolve) {
      var timer = setTimeout(function () {
        resolve(null);
      }, 5000);
      chrome.runtime.sendMessage(
        { type: 'FETCH_DNS_PROBE', url: 'https://' + hostname, method: 'HEAD', timeout: 5000 },
        function (resp) {
          clearTimeout(timer);
          if (chrome.runtime.lastError) {
            resolve(null);
            return;
          }
          resolve(resp || null);
        }
      );
    });
  }

  async function detectWildcard(baseDomain, statusEl) {
    if (statusEl) statusEl.textContent = '检测泛解析...';
    var probes = [
      'rnd' + Math.random().toString(36).slice(2, 8),
      'rnd' + Math.random().toString(36).slice(2, 8),
      'rnd' + Math.random().toString(36).slice(2, 8),
    ];
    for (var i = 0; i < probes.length; i++) {
      var result = await dnsResolve(probes[i] + '.' + baseDomain);
      if (result && result.addresses && result.addresses.length > 0) {
        if (statusEl) statusEl.textContent = '检测到泛解析 (wildcard)，将改为 HTTP 探测';
        return true;
      }
    }
    return false;
  }

  async function resolveDnsPrefixes(baseDomain, seen, statusEl) {
    var resolved = [];
    var newDns = [];
    var total = COMMON_PREFIXES.length;
    var tested = 0;
    for (var i = 0; i < total; i += DNS_BATCH_SIZE) {
      if (dnsScanAborted) break;
      var batch = COMMON_PREFIXES.slice(i, Math.min(i + DNS_BATCH_SIZE, total));
      for (var j = 0; j < batch.length; j++) {
        if (dnsScanAborted) break;
        var host = batch[j] + '.' + baseDomain;
        tested++;
        if (seen[host]) continue;
        if (statusEl) {
          var elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
          statusEl.textContent = 'DNS 解析中... (' + tested + '/' + total + ') ' + elapsed + 's';
        }
        var result = await dnsResolve(host);
        if (result && result.addresses && result.addresses.length > 0) {
          seen[host] = true;
          resolved.push({ host: host, addresses: result.addresses });
          newDns.push({ host: host, source: 'dns' });
        }
      }
      if (!dnsScanAborted && i + DNS_BATCH_SIZE < total) await delay(DNS_BATCH_DELAY_MS);
    }
    return { resolved: resolved, newDns: newDns };
  }

  async function probeHttpTargets(targets, seen, wildcardDetected, statusEl) {
    var results = [];
    var wildcardConfirmed = false;
    for (var k = 0; k < targets.length; k++) {
      if (dnsScanAborted) break;
      var host = targets[k];
      if (statusEl) {
        var elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
        statusEl.textContent =
          'HTTP 探测中... (' + (k + 1) + '/' + targets.length + ') ' + elapsed + 's';
      }
      try {
        var probeResult = await httpProbe(host);
        if (probeResult && !probeResult.error && probeResult.status > 0) {
          if (wildcardDetected && !wildcardConfirmed) {
            var httpHits = results.length;
            if (httpHits > 2 && httpHits / (k + 1) > 0.8) {
              wildcardConfirmed = true;
              results = results.slice(0, 2);
              continue;
            }
          }
          if (!seen[host]) {
            seen[host] = true;
            results.push({ host: host, source: 'http', status: probeResult.status });
          }
        }
      } catch (e) {
        /* network failure expected for unreachable hosts */
      }
    }
    return results;
  }

  function mergeScanResults(newDomains) {
    var existingMap = {};
    lastSubdomains.forEach(function (s) {
      existingMap[s.host] = s;
    });
    newDomains.forEach(function (s) {
      if (!existingMap[s.host]) lastSubdomains.push(s);
    });
    lastSubdomains.sort(function (a, b) {
      return a.host.localeCompare(b.host);
    });
  }

  async function bruteForceHttpProbe() {
    var statusEl = utils.get('subdomain-status');
    var copyBtn = utils.get('subdomain-copy-btn');
    var exportBtn = utils.get('subdomain-export-btn');

    if (dnsScanActive) {
      dnsScanAborted = true;
      return;
    }

    var domain = await utils.getCurrentDomain();
    if (!domain) {
      if (statusEl) statusEl.textContent = '无法获取当前域名';
      return;
    }

    var baseDomain = extractBaseDomain(domain);
    dnsScanAborted = false;
    dnsScanActive = true;
    scanStartTime = Date.now();
    lastBaseDomain = baseDomain;
    if (statusEl) statusEl.textContent = '正在探测...';

    var seen = {};
    lastSubdomains.forEach(function (s) {
      seen[s.host] = true;
    });

    // Phase 1: Wildcard detection
    var wildcardDetected = await detectWildcard(baseDomain, statusEl);

    // Phase 2: DNS resolution
    var newDomains = [];
    var dnsResolved = [];
    if (!wildcardDetected) {
      var dnsResult = await resolveDnsPrefixes(baseDomain, seen, statusEl);
      dnsResolved = dnsResult.resolved;
      newDomains = newDomains.concat(dnsResult.newDns);
    }

    // Phase 3: HTTP probe
    var httpTargets = wildcardDetected
      ? COMMON_PREFIXES.map(function (p) {
          return p + '.' + baseDomain;
        }).filter(function (h) {
          return !seen[h];
        })
      : dnsResolved.map(function (d) {
          return d.host;
        });
    var httpResults = await probeHttpTargets(httpTargets, seen, wildcardDetected, statusEl);
    newDomains = newDomains.concat(httpResults);

    // Finalize
    if (dnsScanAborted) {
      if (statusEl) statusEl.textContent = '探测已取消';
    } else {
      mergeScanResults(newDomains);
      if (statusEl) {
        var elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
        var statusText =
          '探测完成 (' +
          elapsed +
          's): 新增 ' +
          newDomains.length +
          '，共 ' +
          lastSubdomains.length +
          ' 个子域名';
        if (newDomains.length === 0 && !wildcardDetected) statusText += ' — 未发现新子域名';
        else if (wildcardDetected) statusText += ' — 检测到泛解析，已过滤';
        statusEl.textContent = statusText;
      }
    }

    dnsScanActive = false;
    renderSubdomains(lastSubdomains, baseDomain);
    if (copyBtn) copyBtn.hidden = false;
    if (exportBtn) exportBtn.hidden = false;
  }

  return {
    collectSubdomains: collectSubdomains,
    extractFromPage: extractFromPage,
    bruteForceDns: bruteForceHttpProbe,
    bruteForceHttpProbe: bruteForceHttpProbe,
    copyResults: copyResults,
    exportResults: exportResults,
    filterBySource: filterBySource,
    searchResults: searchResults,
    get lastSubdomains() {
      return lastSubdomains;
    },
  };
})();
