// vk-xss-verify.js -- 灵眸 Chrome Extension
// XSS verification engine — pure functions + simple render helpers

import { utilsProxy as utils } from './vk-namespace.js';
import { _xssDefaultTimeout } from './vk-xss-state.js';

async function fetchInTab(url, fetchOpts, timeoutMs) {
  const tab = await utils.requireTabId();
  if (!tab) return { error: '无法获取活动标签页' };
  var ms = timeoutMs || _xssDefaultTimeout;
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

function truncateUrl(url) {
  if (url.length > 60) return `${url.substring(0, 57)}...`;
  return url;
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

var VERIFY_BADGES = { reflected: '输入反射', safe: '未反射', skip: '跳过', error: '错误' };

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

export {
  fetchInTab,
  buildTestUrl,
  buildPostBody,
  htmlDecode,
  isReflected,
  analyzeReflectionContext,
  truncateUrl,
  verifySinglePoint,
  VERIFY_BADGES,
  renderVerifyResult,
  renderVerifyResults,
  updateVerifyStatus,
};
