// 灵眸 - WAF Fingerprint Detection
window.VulnKitWaf = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastWafResult = null;
  var wafScanActive = false;
  var wafScanAborted = false;
  var currentFilter = 'all';
  var currentSearch = '';
  var scanStartTime = 0;
  var lastHeaders = null;

  var WAF_SIGNATURES = [
    {
      name: 'Cloudflare',
      severity: 'high',
      headerMatch: [/cf-ray/i, /cloudflare/i, /cf-cache-status/i, /cf-request-id/i],
      bodyMatch: [
        /cloudflare/i,
        /cf-browser-verification/i,
        /attention required/i,
        /checking your browser/i,
      ],
      cookieMatch: [/__cfduid/i, /cf_clearance/i],
    },
    {
      name: 'AWS WAF',
      severity: 'medium',
      headerMatch: [/x-amzn-requestid/i, /x-amz-cf-id/i, /awselb/i],
      bodyMatch: [/awselb/i, /awswaf/i, /request blocked/i],
      cookieMatch: [/awselb/i],
    },
    {
      name: 'ModSecurity',
      severity: 'high',
      headerMatch: [/mod_security/i, /modsecurity/i, /noyb/i],
      bodyMatch: [
        /mod_security/i,
        /modsecurity/i,
        /not acceptable/i,
        /access denied.*mod_security/i,
      ],
      cookieMatch: [/modsecurity/i],
    },
    {
      name: 'Akamai',
      severity: 'high',
      headerMatch: [/x-akamai/i, /akamai/i, /x-akamai-staging/i],
      bodyMatch: [/akamai/i, /ak_bmsc/i, /reference.*#.*akamai/i],
      cookieMatch: [/ak_bmsc/i],
    },
    {
      name: 'Sucuri',
      severity: 'medium',
      headerMatch: [/x-sucuri-id/i, /sucuri/i],
      bodyMatch: [/sucuri/i, /cloudproxy/i, /website filtered/i],
      cookieMatch: [/sucuri_cloudproxy_cookie/i],
    },
    {
      name: 'Imperva (Incapsula)',
      severity: 'high',
      headerMatch: [/x-iinfo/i, /x-cdn/i, /visid_incap/i, /incap_ses/i],
      bodyMatch: [/incapsula/i, /incap_ses/i, /visid_incap/i],
      cookieMatch: [/incap_ses/i, /visid_incap/i, /utmvc/i],
    },
    {
      name: 'F5 BIG-IP ASM',
      severity: 'high',
      headerMatch: [/bigip/i, /x-wa-info/i, /ts[i0-9]{5,}/i],
      bodyMatch: [/bigip/i, /f5/i, /request rejected/i, /traffic intercepted/i],
      cookieMatch: [/bigipserver/i, /f5_*/i],
    },
    {
      name: '阿里云盾 (Yundun)',
      severity: 'high',
      headerMatch: [/aliyun/i, /yundun/i, /x-yd-*/i],
      bodyMatch: [/yundun/i, /aliyun/i, /error.*yun/i],
      cookieMatch: [/acw_tc/i, /acw_sc__v2/i],
    },
    {
      name: '腾讯云 WAF',
      severity: 'high',
      headerMatch: [/x-tnwaf/i],
      bodyMatch: [/tenpay/i, /tencent/i, /waf/i],
      cookieMatch: [/qcloud_waf/i],
    },
    {
      name: '华为云 WAF',
      severity: 'medium',
      headerMatch: [/x-hw-waf/i, /huaweicloud/i],
      bodyMatch: [/huaweicloud/i, /hwclouds/i],
      cookieMatch: [],
    },
    {
      name: 'SafeLine (雷池)',
      severity: 'medium',
      headerMatch: [/safeline/i, /x-safeline/i],
      bodyMatch: [/safeline/i, /chaitin/i],
      cookieMatch: [/safeline/i],
    },
    {
      name: '长亭 (Chaitin) SafeLine',
      severity: 'medium',
      headerMatch: [/chaitin/i],
      bodyMatch: [/chaitin/i, /safeline/i],
      cookieMatch: [],
    },
    {
      name: 'DenyAll',
      severity: 'medium',
      headerMatch: [/x-denyall/i, /denyall/i],
      bodyMatch: [/denyall/i, /session cookie/i],
      cookieMatch: [/sessioncookie/i],
    },
    {
      name: 'Wallarm',
      severity: 'medium',
      headerMatch: [/x-wallarm/i, /nginx-wallarm/i],
      bodyMatch: [/wallarm/i, /blocked by wallarm/i],
      cookieMatch: [/wallarm/i],
    },
    {
      name: 'Trustwave ModSecurity',
      severity: 'medium',
      headerMatch: [/x-trustwave/i],
      bodyMatch: [/trustwave/i],
      cookieMatch: [],
    },
    {
      name: 'Comodo WAF',
      severity: 'low',
      headerMatch: [/x-comodo-waf/i],
      bodyMatch: [/comodo/i, /security event/i],
      cookieMatch: [/cwaf-session/i],
    },
    {
      name: 'Aqtronix WebKnight',
      severity: 'low',
      headerMatch: [/webknight/i, /x-webknight/i],
      bodyMatch: [/webknight/i, /request rejected/i],
      cookieMatch: [],
    },
    {
      name: 'Barikode (PT Application Firewall)',
      severity: 'low',
      headerMatch: [/x-pt-environment/i],
      bodyMatch: [/barikode/i, /pt application firewall/i],
      cookieMatch: [],
    },
    {
      name: 'Oracle (Barracuda)',
      severity: 'medium',
      headerMatch: [/bnmsg/i, /barracuda/i, /x-barracuda/i],
      bodyMatch: [/barracuda/i, /blocked by barracuda/i],
      cookieMatch: [/barracuda/i, /bnmsg/i],
    },
    {
      name: 'Radware AppWall',
      severity: 'medium',
      headerMatch: [/x-rdwaf/i, /radware/i],
      bodyMatch: [/radware/i, /appwall/i, /request blocked/i],
      cookieMatch: [/rdwaf/i],
    },
    {
      name: 'Fortinet FortiWeb',
      severity: 'medium',
      headerMatch: [/fortiweb/i, /x-fortiweb/i],
      bodyMatch: [/fortiweb/i, /fortinet/i],
      cookieMatch: [/fortiweb/i, /apbfw*_.* Fortiweb/i],
    },
    {
      name: 'Microsoft Azure Front Door',
      severity: 'medium',
      headerMatch: [/x-azurefdid/i, /x-fd-ref/i, /x-msedge-ref/i],
      bodyMatch: [/azure/i, /microsoft/i],
      cookieMatch: [],
    },
    {
      name: 'Palo Alto',
      severity: 'low',
      headerMatch: [/x-pan-waf/i],
      bodyMatch: [/paloalto/i, /panwaf/i],
      cookieMatch: [],
    },
    {
      name: 'Squarespace',
      severity: 'low',
      headerMatch: [/x-sq-*/i],
      bodyMatch: [/squarespace/i],
      cookieMatch: [],
    },
    {
      name: 'Kona (Akamai Bot Manager)',
      severity: 'medium',
      headerMatch: [/x-akamai/i, /ak_bmsc/i],
      bodyMatch: [/akamai/i, /_abck/i],
      cookieMatch: [/_abck/i, /ak_bmsc/i],
    },
  ];

  function matchAgainst(text, patterns) {
    if (!text) return [];
    var matches = [];
    for (var i = 0; i < patterns.length; i++) {
      var m = text.match(patterns[i]);
      if (m) matches.push(m[0]);
    }
    return matches;
  }

  function analyzeResponse(headers, body) {
    var detected = [];
    var headerStr = '';
    if (headers) {
      for (var k in headers) {
        if (headers.hasOwnProperty(k)) {
          var val = headers[k];
          if (Array.isArray(val)) {
            val = val.join('\n');
          }
          headerStr += k + ': ' + val + '\n';
        }
      }
    }
    var cookieStr = '';
    if (headers) {
      var setCookie = headers['set-cookie'] || headers['Set-Cookie'] || '';
      if (Array.isArray(setCookie)) {
        cookieStr = setCookie.join('\n');
      } else {
        cookieStr = setCookie;
      }
    }
    var bodyStr = typeof body === 'string' ? body : '';

    for (var i = 0; i < WAF_SIGNATURES.length; i++) {
      var sig = WAF_SIGNATURES[i];
      var evidence = [];

      var headerHits = matchAgainst(headerStr, sig.headerMatch);
      for (var h = 0; h < headerHits.length; h++) {
        evidence.push({ type: 'header', value: headerHits[h] });
      }

      var bodyHits = matchAgainst(bodyStr, sig.bodyMatch);
      for (var b = 0; b < bodyHits.length; b++) {
        evidence.push({ type: 'body', value: bodyHits[b] });
      }

      var cookieHits = matchAgainst(cookieStr, sig.cookieMatch);
      for (var c = 0; c < cookieHits.length; c++) {
        evidence.push({ type: 'cookie', value: cookieHits[c] });
      }

      if (evidence.length > 0) {
        var confidence = evidence.length >= 3 ? 'high' : evidence.length >= 2 ? 'medium' : 'low';
        detected.push({
          name: sig.name,
          severity: sig.severity,
          confidence: confidence,
          evidence: evidence,
        });
      }
    }
    return detected;
  }

  function renderResults(detected, probeHeaders, probeUrl) {
    var resultsEl = utils.get('waf-results');
    var copyBtn = utils.get('waf-copy-btn');
    var exportBtn = utils.get('waf-export-btn');
    if (!resultsEl) return;

    if (detected.length === 0) {
      resultsEl.innerHTML =
        '<div class="waf-not-detected">' +
        '<div style="font-size:32px;margin-bottom:8px">&#128274;</div>' +
        '<div>未检测到 WAF</div>' +
        '<div style="font-size:11px;margin-top:4px;color:var(--text-secondary)">目标站点可能没有部署 WAF，或使用了自定义规则</div>' +
        '<div style="font-size:11px;margin-top:2px;color:var(--text-secondary)">提示: 探测请求已通过后台发送(不带 Cookie)，如仍无法检测，可尝试手动访问恶意路径</div>' +
        '</div>';
      if (copyBtn) copyBtn.style.display = 'none';
      if (exportBtn) exportBtn.style.display = 'none';
      lastWafResult = null;
      return;
    }

    var html = '<div class="waf-detected-list">';
    for (var i = 0; i < detected.length; i++) {
      var d = detected[i];
      html += '<div class="waf-detected-item">';
      html += '<div class="waf-detected-header">';
      html +=
        '<span class="waf-badge ' +
        d.severity +
        '">' +
        (d.severity === 'high'
          ? '高'
          : d.severity === 'medium'
            ? '中'
            : d.severity === 'low'
              ? '低'
              : '信息') +
        '</span>';
      html += '<span class="waf-name">' + utils.escapeHtml(d.name) + '</span>';
      html +=
        '<span class="waf-confidence">置信度: ' +
        (d.confidence === 'high' ? '高' : d.confidence === 'medium' ? '中' : '低') +
        '</span>';
      html += '</div>';
      html += '<div class="waf-evidence">';
      for (var j = 0; j < d.evidence.length; j++) {
        var e = d.evidence[j];
        html +=
          '<div>[' +
          utils.escapeHtml(e.type) +
          '] <code>' +
          utils.escapeHtml(e.value) +
          '</code></div>';
      }
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';

    if (probeHeaders && Object.keys(probeHeaders).length > 0) {
      html += '<div class="waf-headers-section">';
      html += '<div class="waf-headers-title">响应头信息</div>';
      html +=
        '<table class="waf-header-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
      for (var k in probeHeaders) {
        if (probeHeaders.hasOwnProperty(k)) {
          html +=
            '<tr><td>' +
            utils.escapeHtml(k) +
            '</td><td>' +
            utils.escapeHtml(probeHeaders[k]) +
            '</td></tr>';
        }
      }
      html += '</tbody></table>';
      html += '</div>';
    }

    resultsEl.innerHTML = html;
    if (copyBtn) copyBtn.style.display = '';
    if (exportBtn) exportBtn.style.display = '';
    lastWafResult = detected;
    lastHeaders = probeHeaders || null;
  }

  function filterByStatus(filter) {
    currentFilter = filter;
    applyFilter();
  }

  function searchResults(query) {
    currentSearch = (query || '').toLowerCase();
    applyFilter();
  }

  function applyFilter() {
    if (!lastWafResult) return;
    var filtered = lastWafResult.filter(function (d) {
      if (currentFilter === 'detected') return true;
      if (currentFilter === 'none') return false;
      return true;
    });
    if (currentSearch) {
      filtered = filtered.filter(function (d) {
        return d.name.toLowerCase().indexOf(currentSearch) !== -1;
      });
    }
    renderResults(filtered, lastHeaders);
  }

  async function scanWaf() {
    var scanBtn = utils.get('waf-scan-btn');
    var statusEl = utils.get('waf-status');
    var probeInfoEl = utils.get('waf-probe-info');
    if (!statusEl) return;

    if (wafScanActive) {
      wafScanAborted = true;
      return;
    }

    if (!utils.getActiveTab) {
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }

    if (!confirm('WAF 扫描将向目标发送攻击载荷（SQL注入/XSS/路径穿越等），是否继续？')) {
      return;
    }

    wafScanAborted = false;
    wafScanActive = true;
    scanStartTime = Date.now();
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = '停止扫描';
    }
    statusEl.textContent = '扫描中...';
    if (probeInfoEl) probeInfoEl.style.display = 'none';
    var resultsEl = utils.get('waf-results');
    if (resultsEl)
      resultsEl.innerHTML =
        '<div class="waf-scan-progress"><span class="spinner"></span>正在发送探测请求...</div>';

    try {
      var tab = await utils.requireTabId();
      if (!tab || !tab.url || tab.url.startsWith('chrome')) {
        statusEl.textContent = '无法扫描此页面';
        return;
      }

      var pageUrl = tab.url;
      var detectedMap = {};

      var probePaths = [
        { path: '', desc: '正常请求' },
        { path: '/../../../etc/passwd', desc: '路径穿越探测' },
        { path: "/?id=1' OR '1'='1", desc: 'SQL 注入探测' },
        { path: '/?id=<script>alert(1)</script>', desc: 'XSS 探测' },
      ];

      for (var i = 0; i < probePaths.length; i++) {
        if (wafScanAborted) break;
        var probe = probePaths[i];
        if (statusEl) {
          var elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
          statusEl.textContent =
            '探测中... (' + (i + 1) + '/' + probePaths.length + ') ' + elapsed + 's';
        }
        try {
          var parsedUrl = new URL(pageUrl);
          var probeUrl = parsedUrl.origin + probe.path;
          var probeResult = await new Promise(function (resolve) {
            var timer = setTimeout(function () {
              resolve(null);
            }, 8000);
            chrome.runtime.sendMessage(
              {
                type: 'FETCH_WAF_PROBE',
                url: probeUrl,
                method: 'GET',
                headers: {
                  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                },
                timeout: 8000,
              },
              function (response) {
                clearTimeout(timer);
                if (chrome.runtime.lastError) {
                  resolve(null);
                  return;
                }
                resolve(response || null);
              }
            );
          });

          if (probeResult && probeResult.headers) {
            lastHeaders = probeResult.headers;
            var found = analyzeResponse(probeResult.headers, probeResult.body || '');
            for (var d = 0; d < found.length; d++) {
              var name = found[d].name;
              if (detectedMap[name]) {
                var existingEvidence = detectedMap[name].evidence;
                for (var ev = 0; ev < found[d].evidence.length; ev++) {
                  var evVal = found[d].evidence[ev].value;
                  var alreadySeen = false;
                  for (var ex = 0; ex < existingEvidence.length; ex++) {
                    if (existingEvidence[ex].value === evVal) {
                      alreadySeen = true;
                      break;
                    }
                  }
                  if (!alreadySeen) {
                    existingEvidence.push(found[d].evidence[ev]);
                  }
                }
                var sevOrder = { high: 3, medium: 2, low: 1 };
                if (
                  (sevOrder[found[d].severity] || 0) > (sevOrder[detectedMap[name].severity] || 0)
                ) {
                  detectedMap[name].severity = found[d].severity;
                }
              } else {
                detectedMap[name] = Object.assign({}, found[d], { _probe: probe.desc });
              }
            }
          }
        } catch (err) {
          // probe failed, continue
        }
      }

      var allDetected = Object.values(detectedMap);
      allDetected.sort(function (a, b) {
        var sevOrder = { high: 3, medium: 2, low: 1 };
        return (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      });
      for (var s = 0; s < allDetected.length; s++) {
        var evCount = allDetected[s].evidence.length;
        allDetected[s].confidence = evCount >= 3 ? 'high' : evCount >= 2 ? 'medium' : 'low';
      }

      if (wafScanAborted) {
        statusEl.textContent = '扫描已取消';
      } else {
        if (probeInfoEl) {
          var domain = new URL(pageUrl).hostname;
          probeInfoEl.style.display = '';
          probeInfoEl.innerHTML =
            '<strong>目标:</strong> <span class="probe-url">' +
            utils.escapeHtml(domain) +
            '</span>' +
            '<br><strong>探测次数:</strong> ' +
            probePaths.length +
            '<br><strong>检测结果:</strong> ' +
            (allDetected.length > 0 ? allDetected.length + ' 个 WAF' : '未检测到 WAF');
        }
        renderResults(allDetected, lastHeaders, pageUrl);
        statusEl.textContent =
          allDetected.length > 0 ? '检测到 ' + allDetected.length + ' 个 WAF' : '未检测到 WAF';
      }
    } catch (err) {
      statusEl.textContent = '扫描失败: ' + (err.message || '未知错误');
      if (resultsEl) {
        resultsEl.innerHTML =
          '<div class="empty-state">扫描出错: ' + utils.escapeHtml(err.message || '') + '</div>';
      }
    } finally {
      wafScanActive = false;
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = 'WAF 指纹检测';
      }
    }
  }

  function copyResults() {
    if (!lastWafResult || lastWafResult.length === 0) {
      utils.showToast('没有可复制的结果', 'warning');
      return;
    }
    var text = lastWafResult
      .map(function (d) {
        var lines = [d.name + ' [' + d.severity + '] 置信度: ' + d.confidence];
        for (var i = 0; i < d.evidence.length; i++) {
          lines.push('  [' + d.evidence[i].type + '] ' + d.evidence[i].value);
        }
        return lines.join('\n');
      })
      .join('\n\n');
    utils.copyAndToast(text, '已复制 WAF 检测结果');
  }

  function exportResults() {
    if (!lastWafResult || lastWafResult.length === 0) {
      utils.showToast('没有可导出的结果', 'warning');
      return;
    }
    var report = {
      timestamp: new Date().toISOString(),
      result: lastWafResult.map(function (d) {
        return {
          name: d.name,
          severity: d.severity,
          confidence: d.confidence,
          evidence: d.evidence,
        };
      }),
    };
    var blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'waf-report-' + Date.now() + '.json';
    a.click();
    URL.revokeObjectURL(url);
    utils.showToast('报告已导出', 'success');
  }

  return {
    scanWaf: scanWaf,
    copyResults: copyResults,
    exportResults: exportResults,
    filterByStatus: filterByStatus,
    searchResults: searchResults,
    get lastWafResult() {
      return lastWafResult;
    },
  };
})();
