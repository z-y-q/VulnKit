// 灵眸 - Content Script Bridge
(function () {
  'use strict';

  if (window.__VK_CONTENT_BRIDGE__) return;
  window.__VK_CONTENT_BRIDGE__ = true;

  let pendingResolve = null;
  let storeExploreResolve = null;
  let detecting = false;

  let reactDetectResolve = null;
  let angularDetectResolve = null;
  let sourcemapDetectResolve = null;

  let pendingToken = null;
  let reactDetectToken = null;
  let angularDetectToken = null;
  let sourcemapDetectToken = null;
  let storeExploreToken = null;
  let pageInspectResolve = null;
  let pageInspectToken = null;

  // Window message relay
  window.addEventListener('message', function (e) {
    if (e.origin !== location.origin) return;

    if (e.data && e.data.__vk_detect && pendingResolve) {
      if (pendingToken && e.data.__vk_token === pendingToken) {
        pendingResolve(e.data.result);
        pendingResolve = null;
        pendingToken = null;
        detecting = false;
      }
      return;
    }

    if (e.data && e.data.__vk_react_detect && reactDetectResolve) {
      if (reactDetectToken && e.data.__vk_token === reactDetectToken) {
        reactDetectResolve(e.data.result);
        reactDetectResolve = null;
        reactDetectToken = null;
      }
      return;
    }

    if (e.data && e.data.__vk_angular_detect && angularDetectResolve) {
      if (angularDetectToken && e.data.__vk_token === angularDetectToken) {
        angularDetectResolve(e.data.result);
        angularDetectResolve = null;
        angularDetectToken = null;
      }
      return;
    }

    if (e.data && e.data.__vk_sourcemap_detect && sourcemapDetectResolve) {
      if (sourcemapDetectToken && e.data.__vk_token === sourcemapDetectToken) {
        sourcemapDetectResolve(e.data.result);
        sourcemapDetectResolve = null;
        sourcemapDetectToken = null;
      }
      return;
    }

    if (e.data && e.data.__vk_ruoyi_hook && e.data.event) {
      chrome.runtime
        .sendMessage({
          type: 'VK_RUOYI_HOOK_EVENT',
          event: e.data.event,
          augmented: e.data.augmented,
          injected: e.data.injected,
        })
        .catch(function (e) {
          console.debug('ruoyi hook event forward failed', e);
        });
      return;
    }

    if (e.data && e.data.__vk_vue_store && storeExploreResolve) {
      if (storeExploreToken && e.data.__vk_token === storeExploreToken) {
        storeExploreResolve(e.data.result);
        storeExploreResolve = null;
        storeExploreToken = null;
      }
      return;
    }

    if (e.data && e.data.__vk_page_inspect && pageInspectResolve) {
      if (pageInspectToken && e.data.__vk_token === pageInspectToken) {
        pageInspectResolve(e.data.result);
        pageInspectResolve = null;
        pageInspectToken = null;
      }
      return;
    }
  });

  function injectAndDetect() {
    if (detecting) return Promise.resolve(null);
    detecting = true;
    return new Promise(function (resolve) {
      pendingResolve = resolve;
      pendingToken = Math.random().toString(36).slice(2) + Date.now().toString(36);
      let script = document.createElement('script');
      script.src = chrome.runtime.getURL('src/inject/vue-detect.js');
      script.dataset.vkToken = pendingToken;
      script.onload = function () {
        script.remove();
        setTimeout(function () {
          if (pendingResolve) {
            pendingResolve(null);
            pendingResolve = null;
            detecting = false;
          }
        }, 3000);
      };
      script.onerror = function () {
        script.remove();
        if (pendingResolve) {
          pendingResolve(null);
          pendingResolve = null;
          detecting = false;
        }
      };
      (document.head || document.documentElement).appendChild(script);
    });
  }

  function injectScript(url, resultVarSetter, timeoutMs, tokenSetter) {
    return new Promise(function (resolve) {
      const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
      if (tokenSetter) tokenSetter(token);
      const timer = setTimeout(function () {
        resultVarSetter(null);
        resolve(null);
      }, timeoutMs || 3000);
      const innerResolve = function (result) {
        clearTimeout(timer);
        resolve(result);
      };
      resultVarSetter(innerResolve);
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL(url);
      script.dataset.vkToken = token;
      script.onload = function () {
        script.remove();
      };
      script.onerror = function () {
        script.remove();
        clearTimeout(timer);
        innerResolve(null);
      };
      (document.head || document.documentElement).appendChild(script);
    });
  }

  // ====== API Traffic Monitoring (shared helpers) ======

  let apiTrafficActive = false;
  let apiTrafficData = [];
  let apiOrigFetch = null;
  let apiOrigXhrOpen = null;
  let apiOrigXhrSend = null;

  function stripApiUrl(url) {
    try {
      const u = new URL(url, location.href);
      return u.origin + u.pathname + u.search;
    } catch (e) {
      return url;
    }
  }

  function extractReqHeaders(init) {
    if (!init || !init.headers) return {};
    let h = init.headers;
    const out = {};
    const keys = [
      'content-type',
      'authorization',
      'cookie',
      'x-csrf-token',
      'x-xsrf-token',
      'x-requested-with',
    ];
    if (typeof Headers !== 'undefined' && h instanceof Headers) {
      keys.forEach(function (k) {
        let v = h.get(k);
        if (v) out[k] = v.length > 200 ? v.substring(0, 200) + '...' : v;
      });
    } else if (typeof h === 'object') {
      keys.forEach(function (k) {
        const lk = k.toLowerCase();
        Object.keys(h).forEach(function (hk) {
          if (hk.toLowerCase() === lk) {
            let v = String(h[hk]);
            out[k] = v.length > 200 ? v.substring(0, 200) + '...' : v;
          }
        });
      });
    }
    return out;
  }

  function truncateBody(body, max) {
    if (!body) return '';
    const s =
      typeof body === 'string'
        ? body
        : typeof body === 'object'
          ? JSON.stringify(body)
          : String(body);
    return s.length > max ? s.substring(0, max) + '...' : s;
  }

  function pushApiEntry(entry) {
    apiTrafficData.push(entry);
    if (apiTrafficData.length > 200) {
      apiTrafficData = apiTrafficData.slice(-150);
    }
  }

  function startApiMonitoring() {
    if (apiTrafficActive) return;
    apiTrafficActive = true;
    apiTrafficData = [];
    apiOrigFetch = window.fetch;
    apiOrigXhrOpen = XMLHttpRequest.prototype.open;
    apiOrigXhrSend = XMLHttpRequest.prototype.send;

    window.fetch = function (input, init) {
      const url =
        typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
      const method = ((init && init.method) || 'GET').toUpperCase();
      const start = Date.now();
      let reqBody = '';
      let reqHeaders = {};
      if (init) {
        reqBody = truncateBody(init.body, 3000);
        reqHeaders = extractReqHeaders(init);
      }
      let capturedCt = '';
      let capturedStatus = 0;
      return apiOrigFetch
        .apply(this, arguments)
        .then(function (resp) {
          capturedCt = (resp.headers.get('content-type') || '').split(';')[0];
          capturedStatus = resp.status;
          const clone = resp.clone();
          let bodyPromise = Promise.resolve('');
          if (
            capturedCt &&
            (capturedCt.indexOf('json') !== -1 ||
              capturedCt.indexOf('text') !== -1 ||
              capturedCt.indexOf('xml') !== -1 ||
              capturedCt.indexOf('html') !== -1)
          ) {
            bodyPromise = clone.text().catch(function () {
              return '';
            });
          }
          return bodyPromise.then(function (body) {
            pushApiEntry({
              url: stripApiUrl(url),
              method: method,
              status: capturedStatus,
              contentType: capturedCt,
              duration: Date.now() - start,
              reqBody: reqBody,
              reqHeaders: reqHeaders,
              resBody: truncateBody(body, 2000),
            });
          });
        })
        .catch(function () {
          pushApiEntry({
            url: stripApiUrl(url),
            method: method,
            status: 0,
            contentType: '',
            duration: Date.now() - start,
            reqBody: reqBody,
            reqHeaders: reqHeaders,
            resBody: '',
          });
          throw arguments[0];
        });
    };

    XMLHttpRequest.prototype.open = function (method, url) {
      this._vkM = method;
      this._vkU = stripApiUrl(url);
      this._vkS = Date.now();
      this._vkH = {};
      const origSetHeader = this.setRequestHeader;
      const capturedHeaders = this._vkH;
      const headerKeys = [
        'content-type',
        'authorization',
        'cookie',
        'x-csrf-token',
        'x-xsrf-token',
        'x-requested-with',
      ];
      this.setRequestHeader = function (name, value) {
        const ln = (name || '').toLowerCase();
        if (headerKeys.indexOf(ln) !== -1) {
          const v = String(value || '');
          capturedHeaders[ln] = v.length > 200 ? v.substring(0, 200) + '...' : v;
        }
        return origSetHeader.apply(this, arguments);
      };
      return apiOrigXhrOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function () {
      const xhr = this;
      const sentBody = arguments[0] != null ? truncateBody(arguments[0], 3000) : '';
      xhr.addEventListener('load', function () {
        const ct = (xhr.getResponseHeader('content-type') || '').split(';')[0];
        let resBody = '';
        if (
          ct &&
          (ct.indexOf('json') !== -1 ||
            ct.indexOf('text') !== -1 ||
            ct.indexOf('xml') !== -1 ||
            ct.indexOf('html') !== -1)
        ) {
          try {
            resBody = truncateBody(xhr.responseText, 2000);
          } catch (e) {
            /* ignore */
          }
        }
        pushApiEntry({
          url: xhr._vkU || location.href,
          method: xhr._vkM || 'GET',
          status: xhr.status,
          contentType: ct,
          duration: Date.now() - (xhr._vkS || Date.now()),
          reqBody: sentBody,
          reqHeaders: xhr._vkH || {},
          resBody: resBody,
        });
      });
      return apiOrigXhrSend.apply(this, arguments);
    };
  }

  function stopApiMonitoring() {
    apiTrafficActive = false;
    if (apiOrigFetch) window.fetch = apiOrigFetch;
    if (apiOrigXhrOpen) XMLHttpRequest.prototype.open = apiOrigXhrOpen;
    if (apiOrigXhrSend) XMLHttpRequest.prototype.send = apiOrigXhrSend;
    apiOrigFetch = null;
    apiOrigXhrOpen = null;
    apiOrigXhrSend = null;
  }

  // ====== Message handlers ======

  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.type === 'VK_VUE_DETECT') {
      injectAndDetect().then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'CONTEXT_EXTRACT_LINKS') {
      const pageUrl = location.href;
      const links = [];
      const seen = {};
      function addLink(href, text, tag) {
        if (!href || href === '#' || href.startsWith('javascript:') || seen[href]) return;
        seen[href] = true;
        let domain = '';
        try {
          domain = new URL(href, pageUrl).hostname;
        } catch (e) {
          /* ignore */
        }
        links.push({ href: href, text: text || '', tag: tag, domain: domain });
      }
      document.querySelectorAll('a[href]').forEach(function (el) {
        addLink(
          el.href,
          (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
          'a'
        );
      });
      document.querySelectorAll('script[src]').forEach(function (el) {
        addLink(el.src, '', 'script');
      });
      document.querySelectorAll('link[href]').forEach(function (el) {
        addLink(el.href, el.rel || '', 'link');
      });
      document.querySelectorAll('iframe[src],frame[src]').forEach(function (el) {
        addLink(el.src, '', 'iframe');
      });
      chrome.storage.local.set({ contextExtractedLinks: links, contextExtractedUrl: pageUrl });
      sendResponse({ count: links.length });
      return true;
    }
    if (message.type === 'VK_REACT_DETECT') {
      injectScript(
        'src/inject/react-detect.js',
        function (r) {
          reactDetectResolve = r;
        },
        3000,
        function (t) {
          reactDetectToken = t;
        }
      ).then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'VK_ANGULAR_DETECT') {
      injectScript(
        'src/inject/angular-detect.js',
        function (r) {
          angularDetectResolve = r;
        },
        3000,
        function (t) {
          angularDetectToken = t;
        }
      ).then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'VK_WAF_PROBE') {
      const probeUrl = message.url;
      if (!probeUrl) {
        sendResponse({ error: 'Missing url' });
        return true;
      }
      const controller = new AbortController();
      const timer = setTimeout(function () {
        controller.abort();
      }, message.timeout || 5000);
      fetch(probeUrl, {
        method: message.method || 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: message.headers || {},
      })
        .then(function (resp) {
          clearTimeout(timer);
          const hdrs = {};
          resp.headers.forEach(function (v, k) {
            hdrs[k] = v;
          });
          return resp.text().then(function (body) {
            sendResponse({ status: resp.status, headers: hdrs, body: body });
          });
        })
        .catch(function (e) {
          clearTimeout(timer);
          sendResponse({ error: e.message, status: 0 });
        });
      return true;
    }
    if (message.type === 'VK_VUE_STORE_EXPLORE') {
      storeExploreResolve = null;
      storeExploreToken = Math.random().toString(36).slice(2) + Date.now().toString(36);
      new Promise(function (resolve) {
        storeExploreResolve = resolve;
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('src/inject/vue-store-explorer.js');
        script.dataset.vkToken = storeExploreToken;
        script.onload = function () {
          script.remove();
          setTimeout(function () {
            if (storeExploreResolve) {
              storeExploreResolve({ error: 'Store explorer timeout' });
              storeExploreResolve = null;
            }
          }, 5000);
        };
        script.onerror = function () {
          script.remove();
          if (storeExploreResolve) {
            storeExploreResolve({ error: 'Failed to load store explorer' });
            storeExploreResolve = null;
          }
        };
        (document.head || document.documentElement).appendChild(script);
      })
        .then(function (result) {
          sendResponse(result);
        })
        .catch(function (err) {
          sendResponse({ error: err.message || 'Store explore failed' });
        });
      return true;
    }
    if (message.type === 'VK_SOURCEMAP_DETECT') {
      injectScript(
        'src/inject/sourcemap-detect.js',
        function (r) {
          sourcemapDetectResolve = r;
        },
        3000,
        function (t) {
          sourcemapDetectToken = t;
        }
      ).then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'VK_API_TRAFFIC_START') {
      const alreadyRunning = apiTrafficActive;
      startApiMonitoring();
      sendResponse({ status: alreadyRunning ? 'already_running' : 'started' });
      return true;
    }
    if (message.type === 'VK_API_TRAFFIC_STOP') {
      stopApiMonitoring();
      sendResponse({ status: 'stopped' });
      return true;
    }
    if (message.type === 'VK_API_TRAFFIC_COLLECT') {
      if (!apiTrafficActive) {
        startApiMonitoring();
      }
      const data = apiTrafficData;
      apiTrafficData = [];
      sendResponse({ entries: data, running: apiTrafficActive });
      return true;
    }
    if (message.type === 'VK_PAGE_INSPECT') {
      const action = message.action || '';
      if (!action) {
        sendResponse({ error: 'Missing action' });
        return true;
      }
      pageInspectResolve = null;
      pageInspectToken = Math.random().toString(36).slice(2) + Date.now().toString(36);
      const inspectTimer = setTimeout(function () {
        if (pageInspectResolve) {
          pageInspectResolve(null);
          pageInspectResolve = null;
        }
      }, message.timeout || 5000);
      const inspectResolve = function (result) {
        clearTimeout(inspectTimer);
        pageInspectResolve = null;
        sendResponse(result);
      };
      pageInspectResolve = inspectResolve;
      const piScript = document.createElement('script');
      piScript.src = chrome.runtime.getURL('src/inject/page-inspect.js');
      piScript.dataset.vkToken = pageInspectToken;
      piScript.dataset.vkAction = action;
      piScript.onload = function () {
        piScript.remove();
      };
      piScript.onerror = function () {
        piScript.remove();
        clearTimeout(inspectTimer);
        inspectResolve(null);
      };
      (document.head || document.documentElement).appendChild(piScript);
      return true;
    }
    if (message.type === 'VK_FINGERPRINT_DOM') {
      var metaTags = [];
      document.querySelectorAll('meta').forEach(function (m) {
        var name =
          m.getAttribute('name') ||
          m.getAttribute('http-equiv') ||
          m.getAttribute('property') ||
          '';
        var content = m.getAttribute('content') || '';
        if (name) metaTags.push({ name: name, content: content });
      });
      var bodyHtml = '';
      try {
        bodyHtml = (document.body ? document.body.innerHTML : '').substring(0, 200000);
      } catch (e) {
        /* ignore */
      }
      var scriptSrcs = [];
      document.querySelectorAll('script[src]').forEach(function (s) {
        if (s.src) scriptSrcs.push(s.src);
      });
      var styleHrefs = [];
      document.querySelectorAll('link[rel="stylesheet"]').forEach(function (l) {
        if (l.href) styleHrefs.push(l.href);
      });
      sendResponse({
        metaTags: metaTags,
        bodyHtml: bodyHtml,
        scriptSrcs: scriptSrcs,
        styleHrefs: styleHrefs,
      });
      return true;
    }
  });
})();
