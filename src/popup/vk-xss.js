// 灵眸 - XSS Scanner
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { XSS_DATA } from './vk-payload.js';
import { XSS_SCAN_PAYLOADS } from './vk-xss-data.js';
import { analyzeDomSinks } from './vk-xss-sinks.js';

var REFLECTION_PROBE = 'vkprobe\'"><xyz';

let xssPoints = [];
let xssFilterType = 'all';
let xssSearchText = '';
let xssInterceptTimer = null;
let xssInterceptActive = false;
let xssInterceptCountdown = 0;

async function fetchInTab(url, fetchOpts, timeoutMs) {
  const tab = await utils.requireTabId();
  if (!tab) return { error: '无法获取活动标签页' };
  var ms = timeoutMs || 10000;
  try {
    var results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: function (urlStr, opts, timeout) {
        var ac = new AbortController();
        var t = setTimeout(function () {
          ac.abort();
        }, timeout);
        var fo = Object.assign({ credentials: 'include', signal: ac.signal }, opts || {});
        return fetch(urlStr, fo)
          .then(function (r) {
            clearTimeout(t);
            return r.text();
          })
          .then(function (text) {
            return { data: text };
          })
          .catch(function (e) {
            clearTimeout(t);
            return { error: e.message || 'fetch 失败' };
          });
      },
      args: [url, fetchOpts || null, ms],
    });
    var data = results && results[0] && results[0].result;
    return data !== undefined ? data : { error: '执行失败' };
  } catch (e) {
    return { error: e.message };
  }
}

async function harvestXssParamsFromDom() {
  const tab = await utils.requireTabId();
  if (!tab) return [];
  return (
    (await utils.execInTabData(
      tab.id,
      () => {
        const pageUrl = location.href;
        const collected = [];
        const seen = new Set();

        function addPoint(source, url, param, method) {
          if (!url || !param) return;
          let fullUrl;
          try {
            fullUrl = new URL(url, pageUrl).href;
          } catch (_) {
            return;
          }
          const key = `${fullUrl}|${param}|${method}`;
          if (seen.has(key)) return;
          seen.add(key);
          collected.push({ source, url: fullUrl, param, method });
        }

        document.querySelectorAll('a[href]').forEach(a => {
          try {
            const href = new URL(a.href, pageUrl);
            if (href.origin !== location.origin) return;
            href.searchParams.forEach((_, key) => {
              addPoint('link', href.pathname + href.search, key, 'GET');
            });
          } catch (_) {
            console.debug('link URL parse skipped');
          }
        });

        document.querySelectorAll('form').forEach(form => {
          const action = form.getAttribute('action') || pageUrl;
          const method = (form.getAttribute('method') || 'GET').toUpperCase();
          form.querySelectorAll('input[name], select[name], textarea[name]').forEach(el => {
            const name = el.getAttribute('name');
            if (!name) return;
            addPoint('form', action, name, method);
          });
        });

        try {
          const currentUrl = new URL(pageUrl);
          currentUrl.searchParams.forEach((_, key) => {
            addPoint('url', currentUrl.pathname + currentUrl.search, key, 'GET');
          });
        } catch (_) {
          console.debug('URL parse skipped');
        }

        return collected;
      },
      { world: 'ISOLATED' }
    )) || []
  );
}

async function startXssIntercept() {
  xssInterceptActive = true;
  xssInterceptCountdown = 30;
  utils.toggleBtnPair('xssscan-start-intercept-btn', 'xssscan-stop-intercept-btn', true);
  updateXssInterceptStatus();

  let tab = await utils.requireTabId();
  if (!tab) return;
  const tabId = tab.id;

  await utils.execInTab(tabId, () => {
    if (window.__XSS_INTERCEPT__) return 'already_injected';
    window.__XSS_INTERCEPT__ = [];
    window.__XSS_ORIGINAL__ = {
      xhrOpen: XMLHttpRequest.prototype.open,
      xhrSend: XMLHttpRequest.prototype.send,
      fetch: window.fetch,
    };
    function extractJsonParams(body, urlBase, method) {
      try {
        let obj = JSON.parse(body);
        if (typeof obj !== 'object' || obj === null) return;
        Object.keys(obj).forEach(function (k) {
          if (typeof obj[k] === 'object' && obj[k] !== null && !Array.isArray(obj[k])) {
            Object.keys(obj[k]).forEach(function (nk) {
              window.__XSS_INTERCEPT__.push({
                url: urlBase,
                param: `${k}.${nk}`,
                method: method,
              });
            });
          } else {
            window.__XSS_INTERCEPT__.push({ url: urlBase, param: k, method: method });
          }
        });
      } catch (e) {
        console.debug('JSON parse failure in XSS intercept', e);
      }
    }
    function collectQueryParams(rawUrl, method) {
      try {
        const u = new URL(rawUrl, location.href);
        u.searchParams.forEach((_, k) => {
          window.__XSS_INTERCEPT__.push({
            url: u.origin + u.pathname + u.search,
            param: k,
            method: method,
          });
        });
      } catch (_) {
        console.debug('network request interception failed', _);
      }
    }
    function collectBodyParams(body, rawUrl, method) {
      try {
        const params = new URLSearchParams(body);
        params.forEach((_, k) => {
          try {
            const u = new URL(rawUrl, location.href);
            window.__XSS_INTERCEPT__.push({
              url: u.origin + u.pathname,
              param: k,
              method: method,
            });
          } catch (_) {
            console.debug('URL construction failed', _);
          }
        });
      } catch (_) {
        console.debug('response param iteration failed', _);
      }
    }
    function processRequest(rawUrl, method, body) {
      collectQueryParams(rawUrl, method);
      if (typeof body === 'string' && body) {
        collectBodyParams(body, rawUrl, method);
        try {
          let u = new URL(rawUrl, location.href);
          extractJsonParams(body, u.origin + u.pathname, method);
        } catch (e) {
          console.debug('malformed AJAX URL', e);
        }
      }
    }
    const origOpen = window.__XSS_ORIGINAL__.xhrOpen;
    const origSend = window.__XSS_ORIGINAL__.xhrSend;
    const origFetch = window.__XSS_ORIGINAL__.fetch;

    XMLHttpRequest.prototype.open = function (method, url) {
      this.__xss_method = method;
      this.__xss_url = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (body) {
      processRequest(this.__xss_url || location.href, this.__xss_method || 'GET', body);
      return origSend.apply(this, arguments);
    };
    window.fetch = function (input, init) {
      let url =
        typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
      let method = (init && init.method ? init.method : 'GET').toUpperCase();
      processRequest(url, method, init && init.body);
      return origFetch.apply(this, arguments);
    };
    return 'injected';
  });

  async function pollIntercept() {
    if (!xssInterceptActive) return;
    xssInterceptCountdown--;
    updateXssInterceptStatus();
    if (xssInterceptCountdown <= 0) {
      stopXssIntercept();
      return;
    }
    try {
      const captured =
        (await utils.execInTabData(tabId, () => {
          const data = window.__XSS_INTERCEPT__ || [];
          window.__XSS_INTERCEPT__ = [];
          return data;
        })) || [];
      if (captured.length > 0) {
        const existing = new Set(xssPoints.map(p => `${p.url}|${p.param}|${p.method}`));
        const newPoints = captured
          .map(p => ({ ...p, source: 'ajax' }))
          .filter(p => !existing.has(`${p.url}|${p.param}|${p.method}`));
        if (newPoints.length > 0) {
          xssPoints = [...xssPoints, ...newPoints];
          renderXssPoints();
        }
      }
    } catch (_) {
      console.debug('interceptor poll failed', _);
    }
    if (xssInterceptActive) {
      xssInterceptTimer = setTimeout(pollIntercept, 2000);
    }
  }
  pollIntercept();
}

async function stopXssIntercept() {
  if (xssInterceptTimer) {
    clearTimeout(xssInterceptTimer);
    xssInterceptTimer = null;
  }
  xssInterceptActive = false;
  utils.toggleBtnPair('xssscan-start-intercept-btn', 'xssscan-stop-intercept-btn', false);

  let tab = await utils.requireTabId();
  if (!tab) {
    updateXssInterceptStatus();
    return;
  }

  try {
    const captured =
      (await utils.execInTabData(tab.id, () => {
        const data = window.__XSS_INTERCEPT__ || [];
        if (window.__XSS_ORIGINAL__) {
          if (window.__XSS_ORIGINAL__.xhrOpen)
            XMLHttpRequest.prototype.open = window.__XSS_ORIGINAL__.xhrOpen;
          if (window.__XSS_ORIGINAL__.xhrSend)
            XMLHttpRequest.prototype.send = window.__XSS_ORIGINAL__.xhrSend;
          if (window.__XSS_ORIGINAL__.fetch) window.fetch = window.__XSS_ORIGINAL__.fetch;
        }
        delete window.__XSS_INTERCEPT__;
        delete window.__XSS_ORIGINAL__;
        return data;
      })) || [];
    if (captured.length > 0) {
      const existing = new Set(xssPoints.map(p => `${p.url}|${p.param}|${p.method}`));
      const newPoints = captured
        .map(p => ({ ...p, source: 'ajax' }))
        .filter(p => !existing.has(`${p.url}|${p.param}|${p.method}`));
      if (newPoints.length > 0) {
        xssPoints = [...xssPoints, ...newPoints];
        renderXssPoints();
      }
    }
  } catch (e) {
    console.debug('XSS intercept flush failed', e);
  }

  updateXssInterceptStatus();
}

function updateXssInterceptStatus() {
  const el = utils.get('xssscan-status');
  if (!el) return;
  if (xssInterceptActive) {
    el.textContent = `拦截监听中... 剩余 ${xssInterceptCountdown}s — 已捕获 ${xssPoints.length} 个参数点`;
    el.style.color = '#e67e22';
  } else {
    el.textContent =
      xssPoints.length > 0
        ? `监听结束，共 ${xssPoints.length} 个参数点`
        : '点击「采集参数」开始扫描当前页面';
    el.style.color = '';
  }
}

function getFilteredXssPoints() {
  let list = xssPoints;
  if (xssFilterType !== 'all') {
    list = list.filter(function (p) {
      return p.source === xssFilterType;
    });
  }
  if (xssSearchText) {
    let lower = xssSearchText.toLowerCase();
    list = list.filter(function (p) {
      return (
        (p.url && p.url.toLowerCase().indexOf(lower) !== -1) ||
        (p.param && p.param.toLowerCase().indexOf(lower) !== -1) ||
        (p.source && p.source.toLowerCase().indexOf(lower) !== -1)
      );
    });
  }
  return list;
}

function renderXssPoints() {
  const container = utils.get('xssscan-results');
  const countEl = utils.get('xssscan-count');
  if (!container) return;
  const filtered = getFilteredXssPoints();
  if (countEl) {
    let hasFilter = xssFilterType !== 'all' || xssSearchText;
    countEl.textContent = `共发现 ${xssPoints.length} 个注入点${hasFilter ? `（显示: ${filtered.length}）` : ''}`;
  }
  if (filtered.length === 0) {
    utils.setEmpty('xssscan-results', '暂无注入点');
    return;
  }
  const sourceLabels = { link: '链接', form: '表单', url: 'URL', ajax: 'AJAX' };
  const sourceColors = { link: '#4A90E2', form: '#e67e22', url: '#27ae60', ajax: '#e74c3c' };
  let html =
    '<table class="xssscan-table"><thead><tr><th><input type="checkbox" id="xssscan-check-all" checked></th><th>来源</th><th>URL</th><th>参数</th><th>方法</th></tr></thead><tbody>';
  filtered.forEach((p, i) => {
    const shortUrl = p.url.length > 40 ? `${p.url.substring(0, 37)}...` : p.url;
    html += `<tr><td><input type="checkbox" class="xssscan-point-check" data-idx="${i}" checked></td><td><span class="xssscan-source-tag" style="background:${sourceColors[p.source] || '#999'}">${sourceLabels[p.source] || p.source}</span></td><td class="xssscan-url-cell" title="${utils.escapeHtml(p.url)}">${utils.escapeHtml(shortUrl)}</td><td class="xssscan-param-cell">${utils.escapeHtml(p.param)}</td><td>${utils.escapeHtml(p.method)}</td></tr>`;
  });
  html += '</tbody></table>';
  container.innerHTML = html;

  const checkAll = container.querySelector('#xssscan-check-all');
  if (checkAll) {
    checkAll.addEventListener('change', () => {
      container.querySelectorAll('.xssscan-point-check').forEach(cb => {
        cb.checked = checkAll.checked;
      });
    });
  }
}

function getSelectedXssPoints() {
  const filtered = getFilteredXssPoints();
  const checks = document.querySelectorAll('.xssscan-point-check');
  return filtered.filter((_, i) => {
    const cb = checks[i];
    return cb && cb.checked;
  });
}

function encodePayload(payload, encoding) {
  switch (encoding) {
    case 'url':
      return encodeURIComponent(payload);
    case 'html':
      return payload
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    case 'base64':
      return btoa(unescape(encodeURIComponent(payload)));
    default:
      return payload;
  }
}

function buildXssTestUrl(point, payload) {
  try {
    const url = new URL(point.url);
    if (point.method === 'GET') {
      url.searchParams.set(point.param, payload);
      return url.href;
    }
    if (point.method === 'POST') {
      return { url: point.url, method: 'POST', param: point.param, payload: payload };
    }
    return url.href;
  } catch (_) {
    console.debug('URL construction failed', _);
    return null;
  }
}

function getSelectedPayload() {
  const selectEl = utils.get('xssscan-payload-select');
  const customEl = utils.get('xssscan-custom-payload');
  if (customEl && customEl.value.trim()) return customEl.value.trim();
  if (selectEl && selectEl.value) return selectEl.value;
  return XSS_SCAN_PAYLOADS[0].value;
}

function getEncodedPayload() {
  let raw = getSelectedPayload();
  let encoding = (utils.get('xssscan-encoding') || {}).value || 'none';
  return encodePayload(raw, encoding);
}

async function handleXssHarvest() {
  const statusEl = utils.get('xssscan-status');
  if (statusEl) {
    statusEl.textContent = '正在采集页面参数...';
    statusEl.style.color = '#4A90E2';
  }
  try {
    const domPoints = await harvestXssParamsFromDom();
    const existing = new Set(xssPoints.map(p => `${p.url}|${p.param}|${p.method}`));
    const newPoints = domPoints.filter(p => !existing.has(`${p.url}|${p.param}|${p.method}`));
    xssPoints = [...xssPoints, ...newPoints];
    renderXssPoints();
    if (statusEl) {
      statusEl.textContent = `采集完成，新增 ${newPoints.length} 个注入点，共 ${xssPoints.length} 个`;
      statusEl.style.color = '#27ae60';
    }
    if (newPoints.length > 0) utils.showToast(`发现 ${newPoints.length} 个注入点`, 'success');
    else utils.showToast('未发现新的注入点', 'info');
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = `采集失败: ${e.message}`;
      statusEl.style.color = '#e74c3c';
    }
    utils.showToast('采集失败', 'error');
  }
}

async function handleBatchOpenXss() {
  const selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }
  let postCount = selected.filter(p => p.method === 'POST').length;
  let warn =
    postCount > 0
      ? `即将对 ${selected.length} 个注入点进行 XSS 测试（含 ${postCount} 个 POST 表单自动提交），是否继续？`
      : `即将对 ${selected.length} 个注入点打开测试页面，是否继续？`;
  let ok = await utils.confirmDanger(warn);
  if (!ok) return;
  const payload = getEncodedPayload();
  const getPoints = selected.filter(p => p.method !== 'POST');
  const postPoints = selected.filter(p => p.method === 'POST');
  let opened = 0;

  for (const point of getPoints) {
    const result = buildXssTestUrl(point, payload);
    if (!result || typeof result === 'object') continue;
    chrome.tabs.create({ url: result, active: false });
    opened++;
  }

  if (postPoints.length > 0) {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.showToast('无法获取当前标签页', 'error');
      return;
    }
    for (const point of postPoints) {
      const targetUrl = point.url;
      try {
        await utils.execInTab(
          tab.id,
          (url, param, pl) => {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = url;
            form.target = '_blank';
            form.style.display = 'none';
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = param;
            input.value = pl;
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
            form.remove();
          },
          { world: 'ISOLATED', args: [targetUrl, point.param, payload] }
        );
        opened++;
      } catch (_) {
        try {
          const escAttr = s =>
            s
              .replace(/&/g, '&amp;')
              .replace(/"/g, '&quot;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;');
          const formHtml = `<form method="POST" action="${escAttr(targetUrl)}"><input type="hidden" name="${escAttr(point.param)}" value="${escAttr(payload)}"></form><script>document.forms[0].submit()<\/script>`;
          const blobUrl = URL.createObjectURL(new Blob([formHtml], { type: 'text/html' }));
          chrome.tabs.create({ url: blobUrl, active: false });
          opened++;
        } catch (_) {
          console.debug('blob URL fallback also failed', _);
        }
      }
    }
  }

  const methodInfo = postPoints.length > 0 ? '（POST 通过页面内表单提交）' : '';
  utils.showToast(`已打开 ${opened} 个测试页面${methodInfo}`, 'success');
}

function buildTestUrl(point, payload) {
  if (point.method === 'POST') return null;
  try {
    let urlObj = new URL(point.url);
    urlObj.searchParams.set(point.param, payload);
    return urlObj.href;
  } catch (_) {
    console.debug('malformed URL in buildTestUrl', _);
  }
  return null;
}

function buildPostBody(point, payload) {
  if (point.method !== 'POST') return null;
  return `${encodeURIComponent(point.param)}=${encodeURIComponent(payload)}`;
}

function htmlDecode(str) {
  if (!str) return '';
  return str
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

function isReflected(body, rawPayload) {
  if (!body || !rawPayload) return false;
  if (body.indexOf(rawPayload) !== -1) return true;
  var decoded = htmlDecode(body);
  if (decoded !== body && decoded.indexOf(rawPayload) !== -1) return true;
  try {
    if (decodeURIComponent(body).indexOf(rawPayload) !== -1) return true;
  } catch (_) {}
  var stripped = body.replace(/\s+/g, '');
  var rawStripped = rawPayload.replace(/\s+/g, '');
  if (stripped.indexOf(rawStripped) !== -1) return true;
  var decStripped = decoded.replace(/\s+/g, '');
  if (decStripped !== stripped && decStripped.indexOf(rawStripped) !== -1) return true;
  var marker = 'vkprobe';
  if (rawPayload.indexOf(marker) !== -1) {
    if (body.indexOf(marker) !== -1) return true;
    if (decoded !== body && decoded.indexOf(marker) !== -1) return true;
  }
  return false;
}

async function verifySinglePoint(point, payload, rawPayload) {
  let testUrl = buildTestUrl(point, payload);

  if (!testUrl && point.method === 'POST') {
    const postBody = buildPostBody(point, payload);
    if (!postBody) {
      return { point: point, status: 'skip', detail: '不支持的请求方法' };
    }
    try {
      const resp = await fetchInTab(
        point.url,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: postBody,
        },
        10000
      );
      if (resp.error) {
        return { point: point, status: 'error', detail: resp.error };
      }
      const body = resp.data || '';
      if (isReflected(body, rawPayload)) {
        return {
          point: point,
          status: 'reflected',
          detail: 'Payload 在 POST 响应中出现（输入反射，需验证可利用性）',
          context: analyzeReflectionContext(body, rawPayload),
          testUrl: point.url,
        };
      }
      return {
        point: point,
        status: 'safe',
        detail: 'Payload 未在 POST 响应中出现',
        testUrl: point.url,
      };
    } catch (e) {
      return { point: point, status: 'error', detail: e.message };
    }
  }

  if (!testUrl) {
    return { point: point, status: 'skip', detail: '不支持的请求方法' };
  }

  try {
    let resp = await fetchInTab(testUrl, null, 10000);
    if (!resp || resp.error) {
      return { point: point, status: 'error', detail: (resp && resp.error) || '请求失败' };
    }
    let body = resp.data || '';
    console.debug(
      '[XSS verify]',
      point.param,
      testUrl,
      'bodyLen:',
      body.length,
      'payloadLen:',
      rawPayload.length
    );
    if (body.length < 500) console.debug('[XSS verify] full body:', body.substring(0, 500));
    else console.debug('[XSS verify] body snippet:', body.substring(0, 500));
    if (isReflected(body, rawPayload)) {
      return {
        point: point,
        status: 'reflected',
        detail: 'Payload 在响应中出现（输入反射，需验证可利用性）',
        context: analyzeReflectionContext(body, rawPayload),
        testUrl: testUrl,
      };
    }
    return { point: point, status: 'safe', detail: 'Payload 未在响应中出现', testUrl: testUrl };
  } catch (e) {
    return { point: point, status: 'error', detail: e.message };
  }
}

let VERIFY_BADGES = { reflected: '输入反射', safe: '未反射', skip: '跳过', error: '错误' };

function renderVerifyResult(r) {
  let badge = VERIFY_BADGES[r.status] || '错误';
  let html = `<div class="xss-verify-item ${r.status}">
<span class="xss-verify-badge ${r.status}">[${badge}]</span> ${utils.escapeHtml(r.point.param)} @ ${utils.escapeHtml(truncateUrl(r.point.url))}
<div class="xss-verify-detail">${utils.escapeHtml(r.detail)}</div>`;
  if (r.context) {
    html += `<div class="xss-verify-context">上下文: ${utils.escapeHtml(r.context)}</div>`;
  }
  if (r.testUrl && /^https?:/.test(r.testUrl)) {
    html += `<div class="xss-verify-link"><a href="${utils.escapeHtml(r.testUrl)}" target="_blank">打开测试 URL</a></div>`;
  }
  html += '</div>';
  return html;
}

function renderVerifyResults(results, verifyList) {
  if (!verifyList) return;
  verifyList.innerHTML = results.map(renderVerifyResult).join('');
}

function updateVerifyStatus(results, statusEl) {
  if (!statusEl) return;
  let reflected = results.filter(function (r) {
    return r.status === 'reflected';
  }).length;
  let safe = results.filter(function (r) {
    return r.status === 'safe';
  }).length;
  let other = results.length - reflected - safe;
  statusEl.textContent = `反射检查完成: ${reflected} 个输入反射 / ${safe} 个未反射 / ${other} 个其他`;
  statusEl.style.color = reflected > 0 ? '#e74c3c' : '#27ae60';
  if (reflected > 0) {
    utils.showToast(`发现 ${reflected} 个输入反射点，需进一步验证可利用性`, 'warning');
  } else {
    utils.showToast('反射检查完成，未发现输入反射', 'success');
  }
}

async function handleVerifyReflection() {
  let selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }

  let probe = REFLECTION_PROBE;
  let statusEl = utils.get('xssscan-status');
  let verifyPanel = utils.get('xssscan-verify-results');
  let verifyList = utils.get('xssscan-verify-list');

  if (statusEl) {
    statusEl.textContent = '正在检查反射...';
    statusEl.style.color = '#4A90E2';
  }
  if (verifyPanel) verifyPanel.style.display = '';

  let results = [];
  for (let i = 0; i < selected.length; i++) {
    if (statusEl) statusEl.textContent = `检查反射中... (${i + 1}/${selected.length})`;
    results.push(await verifySinglePoint(selected[i], probe, probe));
  }

  renderVerifyResults(results, verifyList);
  updateVerifyStatus(results, statusEl);
  lastVerifyResults = results;
}

var lastVerifyResults = [];

function handleOpenReflected() {
  var reflected = lastVerifyResults.filter(function (r) {
    return r.status === 'reflected';
  });
  if (reflected.length === 0) {
    utils.showToast('没有已验证的反射点', 'warning');
    return;
  }
  var payload = getEncodedPayload();
  var opened = 0;
  reflected.forEach(function (r) {
    var point = r.point;
    if (point.method === 'POST') {
      var targetUrl = buildXssTestUrl(point, payload);
      if (targetUrl && typeof targetUrl === 'object') {
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = targetUrl.url;
        form.target = '_blank';
        form.style.display = 'none';
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = targetUrl.param;
        input.value = targetUrl.payload;
        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
        form.remove();
        opened++;
      }
      return;
    }
    var url = buildXssTestUrl(point, payload);
    if (url && typeof url === 'string') {
      chrome.tabs.create({ url: url, active: false });
      opened++;
    }
  });
  utils.showToast('已打开 ' + opened + ' 个反射点测试页面', 'success');
}

function truncateUrl(url) {
  if (url.length > 60) return `${url.substring(0, 57)}...`;
  return url;
}

function analyzeReflectionContext(body, needle) {
  let idx = body.indexOf(needle);
  if (idx === -1) return 'unknown';

  let start = Math.max(0, idx - 40);
  let end = Math.min(body.length, idx + needle.length + 40);
  let before = body.substring(start, idx);
  let after = body.substring(idx + needle.length, end);

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

function handleCopyXssUrls() {
  const selected = getSelectedXssPoints();
  if (selected.length === 0) {
    utils.showToast('没有选中的注入点', 'warning');
    return;
  }
  const payload = getEncodedPayload();
  const lines = selected
    .map(p => {
      const result = buildXssTestUrl(p, payload);
      if (!result) return null;
      if (typeof result === 'object') {
        return `[POST] ${result.url}\n  参数: ${result.param}=${result.payload}`;
      }
      return result;
    })
    .filter(Boolean);
  if (lines.length === 0) {
    utils.showToast('无法生成测试URL', 'warning');
    return;
  }
  utils.copyText(lines.join('\n'));
  utils.showToast(`已复制 ${lines.length} 个URL`, 'success');
}

function initXssScanPayloadSelect() {
  const select = utils.get('xssscan-payload-select');
  if (!select) return;
  XSS_SCAN_PAYLOADS.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.value;
    opt.textContent = p.name;
    select.appendChild(opt);
  });
  if (XSS_DATA) {
    Object.keys(XSS_DATA).forEach(cat => {
      const group = document.createElement('optgroup');
      group.label = cat;
      XSS_DATA[cat].forEach(payload => {
        const opt = document.createElement('option');
        opt.value = payload;
        opt.textContent = payload.length > 50 ? `${payload.substring(0, 47)}...` : payload;
        group.appendChild(opt);
      });
      select.appendChild(group);
    });
  }
}

function clearResults() {
  xssPoints = [];
  renderXssPoints();
  updateXssInterceptStatus();
}

function exportData() {
  if (xssPoints.length === 0) {
    utils.showToast('没有可导出的注入点', 'warning');
    return;
  }
  let rows = xssPoints.map(function (p) {
    return [p.source, p.url, p.param, p.method];
  });
  utils.buildCsv(['Source', 'URL', 'Param', 'Method'], rows, `lingmou-xss-${Date.now()}.csv`);
}

function setXssFilterType(v) {
  xssFilterType = v;
}

function setXssSearchText(v) {
  xssSearchText = v;
  renderXssPoints();
}

function getFindings() {
  return xssPoints.map(function (p) {
    return {
      severity: 'high',
      title: 'XSS 注入点',
      detail: `${p.source} | ${p.param} (${p.method})`,
      module: 'xss',
      url: p.url,
    };
  });
}

export {
  startXssIntercept,
  stopXssIntercept,
  updateXssInterceptStatus,
  renderXssPoints,
  handleXssHarvest,
  handleBatchOpenXss,
  handleVerifyReflection,
  handleOpenReflected,
  handleCopyXssUrls,
  initXssScanPayloadSelect,
  clearResults,
  exportData,
  analyzeDomSinks,
  xssPoints,
  xssFilterType,
  xssSearchText,
  setXssFilterType,
  setXssSearchText,
  getFindings,
};
