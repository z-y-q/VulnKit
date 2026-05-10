// vk-xss-intercept.js -- 灵眸 Chrome Extension
// AJAX interception engine + DOM parameter harvesting

import { utilsProxy as utils } from './vk-namespace.js';
import {
  xssPoints,
  xssInterceptTimer,
  xssInterceptActive,
  xssInterceptCountdown,
  setXssInterceptTimer,
  setXssInterceptActive,
  setXssInterceptCountdown,
  appendXssPoints,
} from './vk-xss-state.js';

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

async function startXssIntercept(renderPoints) {
  setXssInterceptActive(true);
  setXssInterceptCountdown(30);
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
      await stopXssIntercept(renderPoints);
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
          appendXssPoints(newPoints);
          renderPoints();
        }
      }
    } catch (_) {
      console.debug('interceptor poll failed', _);
    }
    if (xssInterceptActive) {
      setXssInterceptTimer(setTimeout(pollIntercept, 2000));
    }
  }
  pollIntercept();
}

async function stopXssIntercept(renderPoints) {
  if (xssInterceptTimer) {
    clearTimeout(xssInterceptTimer);
    setXssInterceptTimer(null);
  }
  setXssInterceptActive(false);
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
        appendXssPoints(newPoints);
        renderPoints();
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

export { startXssIntercept, stopXssIntercept, updateXssInterceptStatus, harvestXssParamsFromDom };
