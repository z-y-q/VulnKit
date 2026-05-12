// 灵眸 - XSS Auto Fuzz Engine
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { _xssDefaultTimeout } from './vk-xss-state.js';

var AUTO_FUZZ_PAYLOADS = [
  { name: 'script 标签', value: '<script>console.log(1)</script>' },
  { name: 'img onerror', value: '<img src=x onerror=console.log(1)>' },
  { name: '属性双引号逃逸', value: '"><script>console.log(1)</script>' },
  { name: '属性单引号逃逸', value: "'><script>console.log(1)</script>" },
  { name: '标签闭合', value: '><script>console.log(1)</script>' },
  { name: 'SVG onload', value: '<svg onload=console.log(1)>' },
  { name: 'body onload', value: '</body><body onload=console.log(1)>' },
  { name: '纯文本探针', value: 'vkfuzzprobe123' },
];

var PROBE_PAYLOAD = "vkprobe'\\\"><xyz";

var autofuzzState = {
  scanning: false,
  aborted: false,
  results: [],
  phase: '',
};

function delay(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

function scoreFinding(context) {
  if (!context) return 'info';
  var lower = context.toLowerCase();
  if (lower.indexOf('script') !== -1) return 'critical';
  if (lower.indexOf('tag attribute') !== -1 && lower.indexOf('value') === -1) return 'high';
  if (lower.indexOf('attribute value') !== -1) return 'medium';
  if (lower.indexOf('html text') !== -1) return 'low';
  if (lower.indexOf('tag context') !== -1) return 'medium';
  return 'info';
}

var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
var SEVERITY_COLORS = {
  critical: '#e74c3c',
  high: '#e67e22',
  medium: '#f1c40f',
  low: '#4A90E2',
  info: '#95a5a6',
};
var SEVERITY_LABELS = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

function buildTestCases(points, payloads) {
  var cases = [];
  var id = 0;
  points.forEach(function (point) {
    payloads.forEach(function (p) {
      var raw = typeof p === 'string' ? p : p.value;
      var name = typeof p === 'string' ? p : p.name;
      var tc = {
        id: 'tc_' + id++,
        pointIdx: cases.length,
        paramName: point.param,
        pointUrl: point.url,
        pointMethod: point.method,
        payloadName: name,
        needle: raw,
      };
      if (point.method === 'POST') {
        tc.url = point.url;
        tc.method = 'POST';
        tc.body = encodeURIComponent(point.param) + '=' + encodeURIComponent(raw);
      } else {
        try {
          var urlObj = new URL(point.url);
          urlObj.searchParams.set(point.param, raw);
          tc.url = urlObj.href;
          tc.method = 'GET';
        } catch (_) {
          return;
        }
      }
      cases.push(tc);
    });
  });
  return cases;
}

function batchFetchAndCheck(tabId, testCases, timeoutMs) {
  return new Promise(function (resolve) {
    if (testCases.length === 0) {
      resolve({});
      return;
    }
    try {
      chrome.scripting.executeScript(
        {
          target: { tabId: tabId },
          world: 'ISOLATED',
          func: function (cases, timeout) {
            function htmlDecode(s) {
              if (!s) return '';
              return s
                .replace(/&lt;/g, '<')
                .replace(/&gt;/g, '>')
                .replace(/&amp;/g, '&')
                .replace(/&quot;/g, '"')
                .replace(/&#x27;/g, "'")
                .replace(/&#x2F;/g, '/')
                .replace(/&#39;/g, "'")
                .replace(/&#47;/g, '/')
                .replace(/&#(\d+);/g, function (_, n) {
                  return String.fromCharCode(parseInt(n, 10));
                });
            }

            function isReflected(body, raw) {
              if (!body || !raw) return false;
              if (body.indexOf(raw) !== -1) return true;
              var decoded = htmlDecode(body);
              if (decoded !== body && decoded.indexOf(raw) !== -1) return true;
              try {
                if (decodeURIComponent(body).indexOf(raw) !== -1) return true;
              } catch (_) {}
              var stripped = body.replace(/\s+/g, '');
              var rawStripped = raw.replace(/\s+/g, '');
              if (stripped.indexOf(rawStripped) !== -1) return true;
              var decStripped = decoded.replace(/\s+/g, '');
              if (decStripped !== stripped && decStripped.indexOf(rawStripped) !== -1) return true;
              var marker = 'vkprobe';
              if (raw.indexOf(marker) !== -1) {
                if (body.indexOf(marker) !== -1) return true;
                if (decoded !== body && decoded.indexOf(marker) !== -1) return true;
              }
              return false;
            }

            function analyzeContext(body, needle) {
              var idx = body.indexOf(needle);
              if (idx === -1) return 'unknown';
              var start = Math.max(0, idx - 40);
              var end = Math.min(body.length, idx + needle.length + 40);
              var before = body.substring(start, idx);
              var after = body.substring(idx + needle.length, end);
              if (/<script[^>]*>[\s\S]*$/i.test(before) && /^[\s\S]*<\/script>/i.test(after)) {
                return 'in <script> tag — high risk';
              }
              if (/<\w+[^>]*$/i.test(before)) {
                return 'in HTML tag attribute — possible attribute injection';
              }
              if (/["'][^"'>]*$/i.test(before)) {
                return 'in attribute value — check for quote breakout';
              }
              if (/<[^>]*$/.test(before)) {
                return 'in HTML tag context — possible tag injection';
              }
              return 'in HTML text context';
            }

            var results = {};
            var BATCH = 5;
            var processed = 0;
            var total = cases.length;

            function processBatch() {
              if (processed >= total) return Promise.resolve();
              var batch = cases.slice(processed, processed + BATCH);
              processed += batch.length;

              return Promise.all(
                batch.map(function (tc) {
                  return new Promise(function (res) {
                    var ac = new AbortController();
                    var timer = setTimeout(function () {
                      ac.abort();
                    }, timeout);
                    var opts = {
                      method: tc.method || 'GET',
                      credentials: 'include',
                      signal: ac.signal,
                    };
                    if (tc.body) {
                      opts.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
                      opts.body = tc.body;
                    }
                    fetch(tc.url, opts)
                      .then(function (r) {
                        clearTimeout(timer);
                        return r.text();
                      })
                      .then(function (text) {
                        var body = text.substring(0, 100000);
                        var reflected = isReflected(body, tc.needle);
                        var context = reflected ? analyzeContext(body, tc.needle) : '';
                        results[tc.id] = {
                          reflected: reflected,
                          context: context,
                          status: 0,
                        };
                        res();
                      })
                      .catch(function (e) {
                        clearTimeout(timer);
                        results[tc.id] = {
                          reflected: false,
                          context: '',
                          status: 0,
                          error: e.message || 'fetch failed',
                        };
                        res();
                      });
                  });
                })
              ).then(function () {
                if (processed < total) {
                  return new Promise(function (r) {
                    setTimeout(r, 150);
                  }).then(processBatch);
                }
              });
            }

            return processBatch().then(function () {
              return results;
            });
          },
          args: [testCases, timeoutMs || 10000],
        },
        function (response) {
          if (chrome.runtime.lastError || !response || !response[0]) {
            console.debug('[AutoFuzz] executeScript failed:', chrome.runtime.lastError);
            resolve({});
            return;
          }
          resolve(response[0].result || {});
        }
      );
    } catch (e) {
      console.debug('[AutoFuzz] exception:', e.message);
      resolve({});
    }
  });
}

async function runAutoFuzz(points, concurrency, onProgress) {
  autofuzzState.scanning = true;
  autofuzzState.aborted = false;
  autofuzzState.results = [];
  autofuzzState.phase = '';

  var tab = await utils.requireTabId();
  if (!tab) {
    autofuzzState.scanning = false;
    utils.showToast('无法获取活动标签页', 'error');
    return [];
  }

  var timeout = _xssDefaultTimeout || 10000;
  var reflectedPoints = [];

  // Phase 1: Quick filter with probe
  autofuzzState.phase = 'phase1';
  if (onProgress) onProgress({ text: 'Phase 1: 快速过滤反射点...', phase: 'phase1' });

  var probeCases = buildTestCases(points, [{ name: '探针', value: PROBE_PAYLOAD }]);
  var probeResults = await batchFetchAndCheck(tab.id, probeCases, timeout);

  for (var i = 0; i < points.length; i++) {
    if (autofuzzState.aborted) break;
    var probeCase = probeCases[i];
    var probeRes = probeResults[probeCase.id];
    if (probeRes && probeRes.reflected) {
      reflectedPoints.push({
        point: points[i],
        probeContext: probeRes.context || '',
      });
    }
  }

  if (autofuzzState.aborted) {
    autofuzzState.scanning = false;
    if (onProgress) onProgress({ text: '已停止', phase: 'stopped' });
    return autofuzzState.results;
  }

  if (reflectedPoints.length === 0) {
    autofuzzState.scanning = false;
    if (onProgress)
      onProgress({
        text: '快速过滤完成: ' + points.length + ' 个注入点均无反射',
        phase: 'done',
      });
    return [];
  }

  if (onProgress)
    onProgress({
      text:
        'Phase 1 完成: ' +
        reflectedPoints.length +
        '/' +
        points.length +
        ' 个注入点存在反射，进入 Phase 2...',
      phase: 'phase2',
    });

  // Phase 2: Diverse payloads on reflected points
  autofuzzState.phase = 'phase2';
  var phase2Cases = buildTestCases(
    reflectedPoints.map(function (rp) {
      return rp.point;
    }),
    AUTO_FUZZ_PAYLOADS
  );

  var phase2Results = await batchFetchAndCheck(tab.id, phase2Cases, timeout);

  for (var j = 0; j < reflectedPoints.length; j++) {
    if (autofuzzState.aborted) break;
    var rp = reflectedPoints[j];
    var payloadResults = [];
    var bestSeverity = 'info';
    var bestContext = '';

    for (var k = 0; k < AUTO_FUZZ_PAYLOADS.length; k++) {
      var caseIdx = j * AUTO_FUZZ_PAYLOADS.length + k;
      var tc = phase2Cases[caseIdx];
      if (!tc) continue;
      var res = phase2Results[tc.id];
      var pr = {
        payloadName: tc.payloadName,
        payloadValue: AUTO_FUZZ_PAYLOADS[k].value,
        reflected: !!(res && res.reflected),
        context: res && res.context ? res.context : '',
        error: res && res.error ? res.error : '',
      };
      if (pr.reflected) {
        var sev = scoreFinding(pr.context);
        if (SEVERITY_ORDER[sev] < SEVERITY_ORDER[bestSeverity]) {
          bestSeverity = sev;
          bestContext = pr.context;
        }
      }
      payloadResults.push(pr);
    }

    var finding = {
      point: rp.point,
      severity: bestSeverity,
      context: bestContext,
      payloadResults: payloadResults,
      reflectedCount: payloadResults.filter(function (p) {
        return p.reflected;
      }).length,
    };
    autofuzzState.results.push(finding);

    if (onProgress)
      onProgress({
        text: 'Phase 2: ' + (j + 1) + '/' + reflectedPoints.length + ' 反射点分析完成',
        phase: 'phase2',
      });
  }

  autofuzzState.scanning = false;
  if (onProgress) {
    var criticalCount = autofuzzState.results.filter(function (f) {
      return f.severity === 'critical';
    }).length;
    var highCount = autofuzzState.results.filter(function (f) {
      return f.severity === 'high';
    }).length;
    var summary =
      '完成: ' +
      autofuzzState.results.length +
      ' 个反射点 | ' +
      criticalCount +
      ' Critical | ' +
      highCount +
      ' High';
    onProgress({ text: summary, phase: 'done' });
  }
  return autofuzzState.results;
}

function stopAutoFuzz() {
  autofuzzState.aborted = true;
}

function renderAutoFuzzResults(containerEl, results) {
  if (!containerEl) return;
  if (!results || results.length === 0) {
    containerEl.innerHTML = '<div class="empty-state">未发现反射点</div>';
    return;
  }

  var sorted = results.slice().sort(function (a, b) {
    return (SEVERITY_ORDER[a.severity] || 99) - (SEVERITY_ORDER[b.severity] || 99);
  });

  var html = '<div class="autofuzz-summary">';
  var counts = {};
  sorted.forEach(function (f) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  });
  Object.keys(SEVERITY_LABELS).forEach(function (sev) {
    if (!counts[sev]) return;
    html +=
      '<span class="autofuzz-stat-badge" style="background:' +
      SEVERITY_COLORS[sev] +
      ';color:#fff">' +
      SEVERITY_LABELS[sev] +
      ' ' +
      counts[sev] +
      '</span>';
  });
  html += '</div>';

  sorted.forEach(function (finding) {
    var shortUrl = finding.point.url.length > 50 ? finding.point.url.substring(0, 47) + '...' : finding.point.url;
    var sevColor = SEVERITY_COLORS[finding.severity] || '#95a5a6';
    var sevLabel = SEVERITY_LABELS[finding.severity] || '未知';

    html += '<div class="autofuzz-finding">';
    html +=
      '<div class="autofuzz-finding-header">' +
      '<span class="autofuzz-severity-tag" style="background:' +
      sevColor +
      '">' +
      sevLabel +
      '</span>' +
      '<span class="autofuzz-param">' +
      utils.escapeHtml(finding.point.param) +
      '</span>' +
      '<span class="autofuzz-method">' +
      utils.escapeHtml(finding.point.method) +
      '</span>' +
      '</div>';
    html += '<div class="autofuzz-finding-url" title="' + utils.escapeHtml(finding.point.url) + '">' + utils.escapeHtml(shortUrl) + '</div>';

    if (finding.context) {
      html += '<div class="autofuzz-context">' + utils.escapeHtml(finding.context) + '</div>';
    }

    html += '<div class="autofuzz-payloads">';
    finding.payloadResults.forEach(function (pr) {
      var cls = pr.reflected ? 'autofuzz-payload reflected' : 'autofuzz-payload safe';
      var statusIcon = pr.reflected ? '✓' : '✗';
      html +=
        '<span class="' +
        cls +
        '" title="' +
        utils.escapeHtml(pr.payloadValue) +
        '">' +
        statusIcon +
        ' ' +
        utils.escapeHtml(pr.payloadName) +
        '</span>';
    });
    html += '</div>';
    html += '</div>';
  });

  containerEl.innerHTML = html;
}

function exportAutoFuzzResults(format) {
  if (!autofuzzState.results || autofuzzState.results.length === 0) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }
  var rows = [];
  autofuzzState.results.forEach(function (f) {
    f.payloadResults
      .filter(function (pr) {
        return pr.reflected;
      })
      .forEach(function (pr) {
        rows.push([f.severity, f.point.param, f.point.method, f.point.url, pr.payloadName, pr.context]);
      });
  });
  if (rows.length === 0) {
    utils.showToast('没有反射结果可导出', 'warning');
    return;
  }
  utils.buildCsv(['Severity', 'Param', 'Method', 'URL', 'Payload', 'Context'], rows, 'lingmou-xss-autofuzz-' + Date.now() + '.csv');
}

function getAutoFuzzFindings() {
  if (!autofuzzState.results || autofuzzState.results.length === 0) return [];
  return autofuzzState.results
    .filter(function (f) {
      return f.severity === 'critical' || f.severity === 'high';
    })
    .map(function (f) {
      return {
        severity: f.severity,
        title: 'XSS 自动 Fuzz — ' + f.point.param,
        detail: f.context + ' (' + f.reflectedCount + '/' + f.payloadResults.length + ' payloads reflected)',
        module: 'xss-autofuzz',
        url: f.point.url,
      };
    });
}

export {
  AUTO_FUZZ_PAYLOADS,
  autofuzzState,
  runAutoFuzz,
  stopAutoFuzz,
  renderAutoFuzzResults,
  exportAutoFuzzResults,
  getAutoFuzzFindings,
  scoreFinding,
};
