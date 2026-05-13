// 灵眸 - WAF Fingerprint Detection
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { saveScanResult } from './vk-scan-history.js';
import { loadJsonData } from './vk-data-loader.js';

let lastWafResult = null;
let wafScanActive = false;
let wafScanAborted = false;
let currentFilter = 'all';
let currentSearch = '';
let currentSort = '';
var WAF_SORT_FNS = {
  severity: function (a, b) {
    var o = { critical: 0, high: 1, medium: 2, low: 3 };
    return (o[a.severity] || 3) - (o[b.severity] || 3);
  },
  confidence: function (a, b) {
    var o = { high: 0, medium: 1, low: 2 };
    return (o[a.confidence] || 2) - (o[b.confidence] || 2);
  },
};
let scanStartTime = 0;
let lastHeaders = null;

var _signatures = null;

async function loadWafSignatures() {
  if (_signatures) return _signatures;
  _signatures = await loadJsonData('data/waf-signatures.json') || [];
  return _signatures;
}

function matchAgainst(text, patterns) {
  if (!text) return [];
  let matches = [];
  for (let i = 0; i < patterns.length; i++) {
    let m = text.match(patterns[i]);
    if (m) matches.push(m[0]);
  }
  return matches;
}

function analyzeResponse(headers, body, WAF_SIGNATURES) {
  let detected = [];
  let headerStr = '';
  if (headers) {
    for (let k in headers) {
      if (headers.hasOwnProperty(k)) {
        let val = headers[k];
        if (Array.isArray(val)) {
          val = val.join('\n');
        }
        headerStr += `${k}: ${val}\n`;
      }
    }
  }
  let cookieStr = '';
  if (headers) {
    let setCookie = headers['set-cookie'] || headers['Set-Cookie'] || '';
    if (Array.isArray(setCookie)) {
      cookieStr = setCookie.join('\n');
    } else {
      cookieStr = setCookie;
    }
  }
  let bodyStr = typeof body === 'string' ? body : '';

  for (let i = 0; i < WAF_SIGNATURES.length; i++) {
    let sig = WAF_SIGNATURES[i];
    let evidence = [];

    let headerHits = matchAgainst(headerStr, sig.headerMatch);
    for (let h = 0; h < headerHits.length; h++) {
      evidence.push({ type: 'header', value: headerHits[h] });
    }

    let bodyHits = matchAgainst(bodyStr, sig.bodyMatch);
    for (let b = 0; b < bodyHits.length; b++) {
      evidence.push({ type: 'body', value: bodyHits[b] });
    }

    let cookieHits = matchAgainst(cookieStr, sig.cookieMatch);
    for (let c = 0; c < cookieHits.length; c++) {
      evidence.push({ type: 'cookie', value: cookieHits[c] });
    }

    if (evidence.length > 0) {
      let confidence = evidence.length >= 3 ? 'high' : evidence.length >= 2 ? 'medium' : 'low';
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
  let resultsEl = utils.get('waf-results');
  let copyBtn = utils.get('waf-copy-btn');
  let exportBtn = utils.get('waf-export-btn');
  let copyMdBtn = utils.get('waf-copy-md-btn');
  if (!resultsEl) return;

  if (detected.length === 0) {
    resultsEl.innerHTML = [
      '<div class="waf-not-detected">',
      '<div style="font-size:32px;margin-bottom:8px">&#128274;</div>',
      '<div>未检测到 WAF</div>',
      '<div style="font-size:11px;margin-top:4px;color:var(--text-secondary)">目标站点可能没有部署 WAF，或使用了自定义规则</div>',
      '<div style="font-size:11px;margin-top:2px;color:var(--text-secondary)">提示: 探测请求已通过后台发送(不带 Cookie)，如仍无法检测，可尝试手动访问恶意路径</div>',
      '</div>',
    ].join('');
    if (copyBtn) copyBtn.style.display = 'none';
    if (exportBtn) exportBtn.style.display = 'none';
    if (copyMdBtn) copyMdBtn.style.display = 'none';
    lastWafResult = null;
    return;
  }

  let html = '<div class="waf-detected-list">';
  for (let i = 0; i < detected.length; i++) {
    let d = detected[i];
    html += `<div class="waf-detected-item">
      <div class="waf-detected-header">
        <span class="waf-badge ${d.severity}">${
          d.severity === 'high'
            ? '高'
            : d.severity === 'medium'
              ? '中'
              : d.severity === 'low'
                ? '低'
                : '信息'
        }</span>
        <span class="waf-name">${utils.escapeHtml(d.name)}</span>
        <span class="waf-confidence">置信度: ${
          d.confidence === 'high' ? '高' : d.confidence === 'medium' ? '中' : '低'
        }</span>
      </div>
      <div class="waf-evidence">`;
    for (let j = 0; j < d.evidence.length; j++) {
      let e = d.evidence[j];
      html += `<div>[${utils.escapeHtml(e.type)}] <code>${utils.escapeHtml(e.value)}</code></div>`;
    }
    html += '</div></div>';
  }
  html += '</div>';

  if (probeHeaders && Object.keys(probeHeaders).length > 0) {
    html += `<div class="waf-headers-section">
      <div class="waf-headers-title">响应头信息</div>
      <table class="waf-header-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>`;
    for (let k in probeHeaders) {
      if (probeHeaders.hasOwnProperty(k)) {
        html += `<tr><td>${utils.escapeHtml(k)}</td><td>${utils.escapeHtml(probeHeaders[k])}</td></tr>`;
      }
    }
    html += '</tbody></table></div>';
  }

  resultsEl.innerHTML = html;
  if (copyBtn) copyBtn.style.display = '';
  if (exportBtn) exportBtn.style.display = '';
  if (copyMdBtn) copyMdBtn.style.display = '';
  lastWafResult = detected;
  lastHeaders = probeHeaders || null;
  utils
    .getCurrentDomain()
    .then(function (d) {
      if (d) saveScanResult('waf', d, getFindings());
    })
    .catch(() => {});
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
  let filtered = lastWafResult.filter(function () {
    if (currentFilter === 'detected') return true;
    if (currentFilter === 'none') return false;
    return true;
  });
  if (currentSearch) {
    filtered = filtered.filter(function (d) {
      return d.name.toLowerCase().indexOf(currentSearch) !== -1;
    });
  }
  var sorted = utils.applySort(filtered, currentSort, WAF_SORT_FNS);
  renderResults(sorted, lastHeaders);
}

async function scanWaf() {
  let scanBtn = utils.get('waf-scan-btn');
  let statusEl = utils.get('waf-status');
  let probeInfoEl = utils.get('waf-probe-info');
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

  var WAF_SIGNATURES = await loadWafSignatures();

  wafScanAborted = false;
  wafScanActive = true;
  scanStartTime = Date.now();
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.textContent = '停止扫描';
  }
  statusEl.textContent = '扫描中...';
  if (probeInfoEl) probeInfoEl.style.display = 'none';
  let resultsEl = utils.get('waf-results');
  if (resultsEl)
    resultsEl.innerHTML =
      '<div class="waf-scan-progress"><span class="spinner"></span>正在发送探测请求...</div>';

  try {
    let tab = await utils.requireTabId();
    if (!tab || !tab.url || !/^https?:\/\//i.test(tab.url)) {
      statusEl.textContent = '无法扫描此页面';
      return;
    }

    let pageUrl = tab.url;
    let detectedMap = {};

    let probePaths = [
      { path: '', desc: '正常请求' },
      { path: '/../../../etc/passwd', desc: '路径穿越探测' },
      { path: "/?id=1' OR '1'='1", desc: 'SQL 注入探测' },
      { path: '/?id=<script>alert(1)</script>', desc: 'XSS 探测' },
    ];

    for (let i = 0; i < probePaths.length; i++) {
      if (wafScanAborted) break;
      let probe = probePaths[i];
      if (statusEl) {
        let elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
        statusEl.textContent = `探测中... (${i + 1}/${probePaths.length}) ${elapsed}s`;
      }
      try {
        let parsedUrl = new URL(pageUrl);
        let probeUrl = parsedUrl.origin + probe.path;
        let probeResult = await new Promise(function (resolve) {
          let timer = setTimeout(function () {
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
          let found = analyzeResponse(probeResult.headers, probeResult.body || '', WAF_SIGNATURES);
          for (let d = 0; d < found.length; d++) {
            let name = found[d].name;
            if (detectedMap[name]) {
              let existingEvidence = detectedMap[name].evidence;
              let existingValues = new Set(
                existingEvidence.map(function (e) {
                  return e.value;
                })
              );
              let newEvidence = found[d].evidence.filter(function (e) {
                return !existingValues.has(e.value);
              });
              let updates = {};
              if (newEvidence.length > 0) {
                updates.evidence = existingEvidence.concat(newEvidence);
              }
              let sevOrder = { high: 3, medium: 2, low: 1 };
              if (
                (sevOrder[found[d].severity] || 0) > (sevOrder[detectedMap[name].severity] || 0)
              ) {
                updates.severity = found[d].severity;
              }
              if (Object.keys(updates).length > 0) {
                detectedMap[name] = Object.assign({}, detectedMap[name], updates);
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

    let allDetected = Object.values(detectedMap);
    allDetected.sort(function (a, b) {
      let sevOrder = { high: 3, medium: 2, low: 1 };
      return (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
    });
    for (let s = 0; s < allDetected.length; s++) {
      let evCount = allDetected[s].evidence.length;
      allDetected[s].confidence = evCount >= 3 ? 'high' : evCount >= 2 ? 'medium' : 'low';
    }

    if (wafScanAborted) {
      statusEl.textContent = '扫描已取消';
    } else {
      if (probeInfoEl) {
        let domain = new URL(pageUrl).hostname;
        probeInfoEl.style.display = '';
        probeInfoEl.innerHTML = `<strong>目标:</strong> <span class="probe-url">${utils.escapeHtml(domain)}</span><br><strong>探测次数:</strong> ${probePaths.length}<br><strong>检测结果:</strong> ${allDetected.length > 0 ? `${allDetected.length} 个 WAF` : '未检测到 WAF'}`;
      }
      renderResults(allDetected, lastHeaders, pageUrl);
      statusEl.textContent =
        allDetected.length > 0 ? `检测到 ${allDetected.length} 个 WAF` : '未检测到 WAF';
    }
  } catch (err) {
    statusEl.textContent = `扫描失败: ${err.message || '未知错误'}`;
    if (resultsEl) {
      resultsEl.innerHTML = `<div class="empty-state">扫描出错: ${utils.escapeHtml(err.message || '')}</div>`;
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
  let text = lastWafResult
    .map(function (d) {
      let lines = [`${d.name} [${d.severity}] 置信度: ${d.confidence}`];
      for (let i = 0; i < d.evidence.length; i++) {
        lines.push(`  [${d.evidence[i].type}] ${d.evidence[i].value}`);
      }
      return lines.join('\n');
    })
    .join('\n\n');
  utils.copyAndToast(text, '已复制 WAF 检测结果');
}

function copyMarkdown() {
  if (!lastWafResult || lastWafResult.length === 0) {
    utils.showToast('没有可复制的结果', 'warning');
    return;
  }
  var rows = lastWafResult.map(function (d) {
    return [
      d.name,
      d.severity,
      d.confidence,
      d.evidence
        .map(function (e) {
          return e.value;
        })
        .join('; '),
    ];
  });
  var md =
    '# WAF Detection Results\n\n' +
    utils.buildMarkdownTable(['Name', 'Severity', 'Confidence', 'Evidence'], rows);
  utils.copyAndToast(md, '已复制 Markdown', 'success');
}

function exportResults() {
  if (!lastWafResult || lastWafResult.length === 0) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }
  let report = {
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
  let blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  let url = URL.createObjectURL(blob);
  let a = document.createElement('a');
  a.href = url;
  a.download = `waf-report-${Date.now()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  utils.showToast('报告已导出', 'success');
}

function getFindings() {
  if (!lastWafResult || lastWafResult.length === 0) return [];
  return lastWafResult.map(function (d) {
    var evidenceText = d.evidence
      .map(function (e) {
        return `[${e.type}] ${e.value}`;
      })
      .join(', ');
    return {
      severity: d.severity === 'high' ? 'high' : d.severity === 'medium' ? 'medium' : 'low',
      title: 'WAF 检测: ' + d.name,
      detail: '置信度: ' + d.confidence + ' | ' + evidenceText,
      module: 'waf',
      url: '',
    };
  });
}

function sortResults(key) {
  currentSort = key;
  applyFilter();
}

export {
  scanWaf,
  copyResults,
  copyMarkdown,
  exportResults,
  filterByStatus,
  searchResults,
  sortResults,
  getFindings,
};
