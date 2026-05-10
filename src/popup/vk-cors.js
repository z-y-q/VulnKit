// 灵眸 - CORS Configuration Detection
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastResult = null;
let scanAborted = false;
let scanActive = false;
let currentFilter = 'all';
let currentSearch = '';
let scanStartTime = 0;

const PROBE_TIMEOUT_MS = 10000;

const ORIGIN_VARIANTS = [
  { value: 'https://evil.example.com', label: '恶意子域' },
  { value: 'null', label: 'Null Origin' },
  { value: 'https://evil.com', label: '跨域恶意' },
];

const METHOD_OPTIONS = [
  { id: 'cors-method-get', value: 'GET' },
  { id: 'cors-method-post', value: 'POST' },
  { id: 'cors-method-put', value: 'PUT' },
  { id: 'cors-method-delete', value: 'DELETE' },
];

function getSelectedMethods() {
  const methods = METHOD_OPTIONS.filter(function (m) {
    const cb = utils.get(m.id);
    return cb && cb.checked;
  }).map(function (m) {
    return m.value;
  });
  return methods.length > 0 ? methods : ['GET'];
}

const DEFAULT_ENDPOINTS = [
  { path: '/', label: '根路径' },
  { path: '/api/', label: '/api/' },
  { path: '/api/v1/', label: '/api/v1/' },
  { path: '/graphql', label: '/graphql' },
  { path: '/api/user', label: '/api/user' },
  { path: '/api/config', label: '/api/config' },
];

function getAllEndpoints() {
  let customInput = utils.get('cors-custom-endpoint');
  let customVal = customInput ? customInput.value.trim() : '';
  let endpoints = DEFAULT_ENDPOINTS.slice();
  if (customVal) {
    const parts = customVal.split(',').map(function (s) {
      return s.trim().replace(/^\//, '');
    });
    parts.forEach(function (p) {
      if (
        p &&
        !endpoints.some(function (e) {
          return e.path === `/${p}`;
        })
      ) {
        endpoints.push({ path: `/${p}`, label: `/${p}` });
      }
    });
  }
  return endpoints;
}

function getSelectedOrigins() {
  const customInput = utils.get('cors-custom-origin');
  let origins = ORIGIN_VARIANTS.slice();
  const customVal = customInput ? customInput.value.trim() : '';
  if (customVal) {
    origins.push({ value: customVal, label: customVal });
  }
  return origins;
}

function sendCorsProbe(url, method, origin, timeoutMs, credentials) {
  return new Promise(function (resolve) {
    const timer = setTimeout(function () {
      resolve({ error: 'timeout' });
    }, timeoutMs || PROBE_TIMEOUT_MS);

    const headers = { Origin: origin };
    if (origin !== 'null') {
      headers['X-Requested-With'] = 'XMLHttpRequest';
    }

    const msg = {
      type: 'FETCH_CORS_PROBE',
      url: url,
      method: method || 'GET',
      headers: headers,
      timeout: timeoutMs || PROBE_TIMEOUT_MS,
    };
    if (credentials) msg.credentials = credentials;

    chrome.runtime.sendMessage(msg, function (resp) {
      clearTimeout(timer);
      if (chrome.runtime.lastError) {
        resolve({ error: chrome.runtime.lastError.message });
        return;
      }
      resolve(resp || { error: 'no response' });
    });
  });
}

function updateScanStatus(statusEl, completed, totalTasks) {
  if (!statusEl) return;
  const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
  statusEl.textContent = `检测中... (${completed}/${totalTasks}) ${elapsed}s`;
}

async function probeEndpointMethods(ep, epUrl, methods, origins, ctx) {
  for (let mi = 0; mi < methods.length; mi++) {
    if (scanAborted) break;
    const method = methods[mi];
    for (let oi = 0; oi < origins.length; oi++) {
      if (scanAborted) break;
      const origin = origins[oi];
      let resp = await sendCorsProbe(epUrl, method, origin.value);
      if (scanAborted) break;
      ctx.completed++;
      updateScanStatus(ctx.statusEl, ctx.completed, ctx.totalTasks);
      if (resp && resp.error) {
        if (resp.error !== 'timeout') {
          ctx.errors.push({
            url: epUrl,
            origin: origin.value,
            method: method,
            error: resp.error,
          });
        }
        continue;
      }
      ctx.allResults.push({
        endpoint: ep,
        url: epUrl,
        origin: origin,
        method: method,
        response: resp,
      });
    }
  }
}

async function probeEndpointOptions(ep, epUrl, origins, ctx) {
  for (let i = 0; i < origins.length; i++) {
    if (scanAborted) break;
    let resp = await sendCorsProbe(epUrl, 'OPTIONS', origins[i].value);
    ctx.completed++;
    updateScanStatus(ctx.statusEl, ctx.completed, ctx.totalTasks);
    if (!resp || resp.error) continue;
    ctx.allResults.push({
      endpoint: ep,
      url: epUrl,
      origin: origins[i],
      method: 'OPTIONS',
      response: resp,
    });
  }
}

async function scanCors() {
  if (scanActive) {
    scanAborted = true;
    return;
  }

  const statusEl = utils.get('cors-status');
  const resultsEl = utils.get('cors-results');
  const copyBtn = utils.get('cors-copy-btn');
  const exportBtn = utils.get('cors-export-btn');
  const scanBtn = utils.get('cors-scan-btn');

  if (statusEl) statusEl.textContent = '正在检测 CORS 配置...';
  if (resultsEl) resultsEl.innerHTML = '';
  scanAborted = false;
  scanActive = true;
  scanStartTime = Date.now();
  if (scanBtn) scanBtn.textContent = '停止检测';
  if (copyBtn) copyBtn.hidden = true;
  if (exportBtn) exportBtn.hidden = true;

  try {
    const tab = await utils.requireTabId();
    if (!tab || !/^https?:/.test(tab.url)) {
      if (statusEl) statusEl.textContent = '请打开一个网页';
      return;
    }

    const baseUrl = new URL(tab.url).origin;
    const endpoints = getAllEndpoints();
    const origins = getSelectedOrigins();
    const methods = getSelectedMethods();
    const totalTasks =
      endpoints.length * origins.length * methods.length + endpoints.length * origins.length;

    const ctx = {
      statusEl: statusEl,
      completed: 0,
      totalTasks: totalTasks,
      allResults: [],
      errors: [],
    };

    for (let ei = 0; ei < endpoints.length; ei++) {
      if (scanAborted) break;
      const ep = endpoints[ei];
      const epUrl = `${baseUrl}${ep.path}`;
      await probeEndpointMethods(ep, epUrl, methods, origins, ctx);
      if (scanAborted) break;
      await probeEndpointOptions(ep, epUrl, origins, ctx);
    }

    if (!scanAborted) {
      const analysis = analyzeResults(ctx.allResults);
      analysis.errors = ctx.errors;
      lastResult = analysis;
      renderResults(analysis);
      if (statusEl) {
        statusEl.textContent = `检测完成: ${ctx.completed} 个请求${ctx.errors.length > 0 ? `，${ctx.errors.length} 个失败` : ''}`;
      }
      if (copyBtn) copyBtn.hidden = false;
      if (exportBtn) exportBtn.hidden = false;
    } else {
      if (statusEl) statusEl.textContent = '检测已取消';
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = `检测失败: ${e.message}`;
  } finally {
    scanActive = false;
    if (scanBtn) scanBtn.textContent = 'CORS 配置检测';
  }
}

function analyzeResults(results) {
  const issues = [];
  let safeCount = 0;

  results.forEach(function (r) {
    const headers = r.response.headers || {};
    let acao = headers['access-control-allow-origin'] || '';
    const acac = headers['access-control-allow-credentials'] || '';
    const acam = headers['access-control-allow-methods'] || '';
    const acah = headers['access-control-allow-headers'] || '';
    const acae = headers['access-control-expose-headers'] || '';
    const acma = headers['access-control-max-age'] || '';

    let severity = 'safe';
    const findings = [];
    const isOptions = r.method === 'OPTIONS';

    // Opaque response (no-cors) — server didn't reflect our Origin
    if (r.response.type === 'opaque' && !acao) {
      findings.push('服务器未返回 CORS 头 (安全)');
      safeCount++;
      issues.push({
        endpoint: r.endpoint,
        url: r.url,
        origin: r.origin,
        method: r.method,
        acao: '',
        acac: '',
        acam: '',
        acah: '',
        acae: '',
        acma: '',
        severity: 'safe',
        findings: findings,
        statusCode: r.response.status || 0,
      });
      return;
    }

    if (!acao) {
      severity = 'safe';
      findings.push('未设置 Access-Control-Allow-Origin');
      safeCount++;
    } else if (acao === '*') {
      severity = 'warning';
      findings.push('ACAO: * (任意来源可访问)');
      if (acac && acac.toLowerCase() === 'true') {
        severity = 'critical';
        findings.push('Allow-Credentials: true + Origin: * — 浏览器会拒绝此配置');
      }
    } else if (acao === r.origin.value) {
      severity = 'danger';
      findings.push(`Origin 被反射: ${acao}`);
      if (acac && acac.toLowerCase() === 'true') {
        severity = 'critical';
        findings.push('Allow-Credentials: true + Origin 反射 — 可跨站窃取数据');
      }
      if (r.origin.value === 'null') {
        findings.push('Null Origin 被信任 — sandbox/iframe 可利用');
      }
      findings.push('恶意 Origin 被信任，可能导致 CSRF/数据泄露');
    } else {
      severity = 'warning';
      findings.push(`ACAO: ${acao} (非反射)`);
    }

    if (acam && isOptions) {
      findings.push(`预检允许方法: ${acam}`);
    }
    if (acah && isOptions) {
      findings.push(`预检允许头: ${acah}`);
    }
    if (acae) {
      findings.push(`暴露头: ${acae}`);
    }
    if (acma) {
      findings.push(`预检缓存: ${acma}s`);
    }
    if (isOptions && !acam && acao) {
      findings.push('预检响应缺少 Allow-Methods');
    }

    issues.push({
      endpoint: r.endpoint,
      url: r.url,
      origin: r.origin,
      method: r.method,
      acao: acao,
      acac: acac,
      acam: acam,
      acah: acah,
      acae: acae,
      acma: acma,
      severity: severity,
      findings: findings,
      statusCode: r.response.status || 0,
    });
  });

  return { issues: issues, safeCount: safeCount, total: results.length, errors: [] };
}

const SEV_MAP = {
  critical: 'critical',
  danger: 'danger',
  warning: 'warning',
  safe: 'safe',
  info: 'info',
};

function filterBySeverity(filter) {
  currentFilter = filter;
  applyCorsFilter();
}

function searchResults(query) {
  currentSearch = (query || '').toLowerCase();
  applyCorsFilter();
}

function applyCorsFilter() {
  if (!lastResult) return;
  const filtered = lastResult.issues.filter(function (issue) {
    if (currentFilter !== 'all') {
      const mappedSev = SEV_MAP[issue.severity] || issue.severity;
      if (mappedSev !== currentFilter) return false;
    }
    if (currentSearch) {
      const url = (issue.url || '').toLowerCase();
      const origin = (issue.origin.value || '').toLowerCase();
      if (url.indexOf(currentSearch) === -1 && origin.indexOf(currentSearch) === -1) return false;
    }
    return true;
  });
  const filteredAnalysis = {
    issues: filtered,
    safeCount: filtered.filter(function (i) {
      return i.severity === 'safe';
    }).length,
    total: filtered.length,
    errors: lastResult.errors,
  };
  renderResults(filteredAnalysis);
}

function renderResults(analysis) {
  const resultsEl = utils.get('cors-results');
  if (!resultsEl) return;

  const dangerItems = analysis.issues.filter(function (i) {
    return i.severity !== 'safe';
  });

  let html =
    `<div class="cors-summary">` +
    `<strong>扫描结果:</strong> 共 ${analysis.total} 个请求，` +
    `<span style="color:#27ae60">${analysis.safeCount} 安全</span>，` +
    `<span style="color:#e74c3c">${dangerItems.length} 存在风险</span>`;
  if (analysis.errors && analysis.errors.length > 0) {
    html += `，<span style="color:#f39c12">${analysis.errors.length} 请求失败</span>`;
  }
  html += `</div>`;

  if (analysis.errors && analysis.errors.length > 0) {
    html +=
      `<div class="cors-error-info" style="color:#f39c12;font-size:11px;margin:4px 0 8px;padding:6px 8px;background:rgba(243,156,18,0.1);border-radius:4px">` +
      `部分请求失败 (网络错误/CORS 阻止)。跨域探测需要目标服务器响应不同 Origin 的请求。` +
      `</div>`;
  }

  analysis.issues.forEach(function (issue) {
    const credId = `cors-cred-${CSS.escape(issue.url + issue.method + issue.origin.value)}`;
    html +=
      `<div class="cors-endpoint-card">` +
      `<div class="cors-endpoint-header">` +
      `<span class="cors-severity-badge ${issue.severity}">${severityLabel(issue.severity)}</span>` +
      `<span class="cors-endpoint-url">${utils.escapeHtml(issue.url)}</span>` +
      `<span class="cors-method-tag">${issue.method}</span>` +
      `<span class="cors-origin-tag">Origin: ${utils.escapeHtml(issue.origin.value)}</span>`;

    if (issue.severity === 'danger' || issue.severity === 'critical') {
      html += `<button class="cors-cred-verify-btn" data-cors-url="${utils.escapeHtml(issue.url)}" data-cors-method="${issue.method}" data-cors-origin="${utils.escapeHtml(issue.origin.value)}">凭据预检</button>`;
    }

    html += `</div>`;

    issue.findings.forEach(function (f) {
      html += `<div class="cors-detail-row"><span class="cors-detail-value">${utils.escapeHtml(f)}</span></div>`;
    });

    html += `<div class="cors-detail-row"><span class="cors-detail-label">HTTP 状态</span><span class="cors-detail-value">${issue.statusCode}</span></div>`;
    if (issue.acae) {
      html += `<div class="cors-detail-row"><span class="cors-detail-label">暴露头</span><span class="cors-detail-value">${utils.escapeHtml(issue.acae)}</span></div>`;
    }
    if (issue.acma) {
      html += `<div class="cors-detail-row"><span class="cors-detail-label">预检缓存</span><span class="cors-detail-value">${issue.acma}s</span></div>`;
    }

    html += `<div id="${credId}"></div>`;
    html += `</div>`;
  });

  resultsEl.innerHTML = html;

  resultsEl.querySelectorAll('.cors-cred-verify-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      verifyCredentials({
        url: btn.dataset.corsUrl,
        method: btn.dataset.corsMethod,
        origin: { value: btn.dataset.corsOrigin },
      });
    });
  });
}

function severityLabel(sev) {
  const labels = { safe: '安全', warning: '警告', danger: '危险', critical: '严重' };
  return labels[sev] || sev;
}

async function verifyCredentials(issue) {
  const statusEl = utils.get('cors-status');
  if (statusEl) {
    statusEl.textContent = '正在进行凭据预检...';
    statusEl.style.color = '#4A90E2';
  }

  try {
    const omitResp = await sendCorsProbe(issue.url, issue.method, issue.origin.value, 8000);
    const includeResp = await sendCorsProbe(
      issue.url,
      issue.method,
      issue.origin.value,
      8000,
      'include'
    );

    let omitAcao = '';
    let omitAcac = '';
    let omitOpaque = true;
    if (omitResp && !omitResp.error) {
      omitOpaque = omitResp.type === 'opaque';
      omitAcao = (omitResp.headers || {})['access-control-allow-origin'] || '';
      omitAcac = (omitResp.headers || {})['access-control-allow-credentials'] || '';
    }

    let includeAcao = '';
    let includeAcac = '';
    let includeOpaque = true;
    if (includeResp && !includeResp.error) {
      includeOpaque = includeResp.type === 'opaque';
      includeAcao = (includeResp.headers || {})['access-control-allow-origin'] || '';
      includeAcac = (includeResp.headers || {})['access-control-allow-credentials'] || '';
    }

    const omitReflects = !omitOpaque && omitAcao === issue.origin.value;
    const includeReflects = !includeOpaque && includeAcao === issue.origin.value;
    const includeAcacTrue = includeAcac && includeAcac.toLowerCase() === 'true';

    let result;
    if (includeReflects && includeAcacTrue) {
      result = {
        exploitable: true,
        detail: '服务端在凭据模式下仍返回 ACAO 反射 + ACAC:true — CORS 策略存在配置缺陷',
        omit: { opaque: omitOpaque, acao: omitAcao, acac: omitAcac },
        include: { opaque: includeOpaque, acao: includeAcao, acac: includeAcac },
      };
    } else if (includeReflects && !includeAcacTrue) {
      result = {
        exploitable: false,
        detail: '凭据模式下 ACAO 反射但无 ACAC — 浏览器会阻断凭据发送',
        omit: { opaque: omitOpaque, acao: omitAcao, acac: omitAcac },
        include: { opaque: includeOpaque, acao: includeAcao, acac: includeAcac },
      };
    } else if (includeOpaque) {
      result = {
        exploitable: false,
        detail: '凭据模式下返回 opaque — 服务端或浏览器安全机制阻止了请求',
        omit: { opaque: omitOpaque, acao: omitAcao, acac: omitAcac },
        include: { opaque: includeOpaque, acao: includeAcao, acac: includeAcac },
      };
    } else if (!includeReflects) {
      result = {
        exploitable: false,
        detail: '凭据模式下 Origin 未被反射 — CORS 配置相对安全',
        omit: { opaque: omitOpaque, acao: omitAcao, acac: omitAcac },
        include: { opaque: includeOpaque, acao: includeAcao, acac: includeAcac },
      };
    } else {
      result = {
        exploitable: false,
        detail: '凭据预检完成，未发现 CORS 凭据泄露风险',
        omit: { opaque: omitOpaque, acao: omitAcao, acac: omitAcac },
        include: { opaque: includeOpaque, acao: includeAcao, acac: includeAcac },
      };
    }

    const credDiv = document.getElementById(
      `cors-cred-${CSS.escape(issue.url + issue.method + issue.origin.value)}`
    );
    if (credDiv) {
      const color = result.exploitable ? '#e74c3c' : '#27ae60';
      const badge = result.exploitable ? '高风险' : '低风险';
      credDiv.innerHTML =
        `<div style="margin-top:6px;padding:6px 8px;border-radius:4px;background:${result.exploitable ? 'rgba(231,76,60,0.1)' : 'rgba(39,174,96,0.1)'};font-size:11px">` +
        `<span style="color:${color};font-weight:bold">[预检结果: ${badge}]</span> ${utils.escapeHtml(result.detail)}` +
        `<br><span style="color:#999">omit: opaque=${omitOpaque} ACAO=${omitAcao || '(空)'} ACAC=${omitAcac || '(空)'}</span>` +
        `<br><span style="color:#999">include: opaque=${includeOpaque} ACAO=${includeAcao || '(空)'} ACAC=${includeAcac || '(空)'}</span>` +
        `<div style="margin-top:4px;padding:3px 6px;background:rgba(243,156,18,0.15);border-radius:3px;color:#b8860b;font-size:10px">` +
        `⚠ 此为服务端 CORS 策略预检。Service Worker 环境无法携带页面 Cookie，实际利用需在浏览器环境中进一步验证。` +
        `</div>` +
        `</div>`;
    }

    if (statusEl) {
      statusEl.textContent = result.exploitable
        ? '预检结果: CORS 策略存在配置缺陷'
        : '预检结果: 未发现凭据泄露风险';
      statusEl.style.color = result.exploitable ? '#e74c3c' : '#27ae60';
    }
    utils.showToast(
      result.exploitable ? 'CORS 策略存在配置缺陷，需进一步验证' : 'CORS 凭据预检相对安全',
      result.exploitable ? 'warning' : 'success'
    );
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = `凭据验证失败: ${e.message}`;
      statusEl.style.color = '#e74c3c';
    }
  }
}

function copyResults() {
  if (!lastResult) {
    utils.showToast('没有检测结果', 'warning');
    return;
  }
  const lines = ['CORS Scan Results', '=================='];
  lines.push(
    `Total: ${lastResult.total} | Safe: ${lastResult.safeCount} | Issues: ${lastResult.total - lastResult.safeCount}`
  );
  lines.push('');
  lastResult.issues.forEach(function (issue) {
    lines.push(
      `[${issue.severity.toUpperCase()}] ${issue.method} ${issue.url} (HTTP ${issue.statusCode}) Origin: ${issue.origin.value}`
    );
    if (issue.acao) lines.push(`  ACAO: ${issue.acao}`);
    if (issue.acac) lines.push(`  ACAC: ${issue.acac}`);
    if (issue.acam) lines.push(`  ACAM: ${issue.acam}`);
    if (issue.acah) lines.push(`  ACAH: ${issue.acah}`);
    issue.findings.forEach(function (f) {
      lines.push(`  - ${f}`);
    });
    lines.push('');
  });
  utils.copyAndToast(lines.join('\n'));
}

function exportJson() {
  if (!lastResult) {
    utils.showToast('没有检测结果', 'warning');
    return;
  }
  const data = lastResult.issues.map(function (issue) {
    return {
      url: issue.url,
      method: issue.method,
      origin: issue.origin.value,
      status: issue.statusCode,
      severity: issue.severity,
      headers: {
        'access-control-allow-origin': issue.acao,
        'access-control-allow-credentials': issue.acac,
        'access-control-allow-methods': issue.acam,
        'access-control-allow-headers': issue.acah,
        'access-control-expose-headers': issue.acae,
        'access-control-max-age': issue.acma,
      },
      findings: issue.findings,
    };
  });
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'cors-results.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const CORS_SEV_MAP = { critical: 'critical', danger: 'critical', warning: 'medium', safe: 'info' };

function getFindings() {
  if (!lastResult || !lastResult.issues) return [];
  return lastResult.issues
    .filter(function (i) {
      return i.severity !== 'safe';
    })
    .map(function (i) {
      return {
        severity: CORS_SEV_MAP[i.severity] || 'medium',
        title: 'CORS 配置风险',
        detail: i.findings.join('; '),
        module: 'cors',
        url: i.url,
      };
    });
}

export {
  scanCors,
  copyResults,
  exportJson,
  filterBySeverity,
  searchResults,
  verifyCredentials,
  getFindings,
};
