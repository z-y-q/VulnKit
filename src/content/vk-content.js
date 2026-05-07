// 灵眸 - Content Script Bridge
(function () {
  'use strict';

  if (window.__VK_CONTENT_BRIDGE__) return;
  window.__VK_CONTENT_BRIDGE__ = true;

  var extId = chrome.runtime.id;
  var pendingResolve = null;
  var storeExploreResolve = null;
  var detecting = false;

  var reactDetectResolve = null;
  var angularDetectResolve = null;
  var sourcemapDetectResolve = null;

  // Vue detect response relay
  window.addEventListener('message', function (e) {
    if (e.origin !== location.origin) return;

    // Vue detection result
    if (e.data && e.data.__vk_detect && pendingResolve) {
      pendingResolve(e.data.result);
      pendingResolve = null;
      detecting = false;
      return;
    }

    // React detection result
    if (e.data && e.data.__vk_react_detect && reactDetectResolve) {
      reactDetectResolve(e.data.result);
      reactDetectResolve = null;
      return;
    }

    // Angular detection result
    if (e.data && e.data.__vk_angular_detect && angularDetectResolve) {
      angularDetectResolve(e.data.result);
      angularDetectResolve = null;
      return;
    }

    // Sourcemap build tool detection result
    if (e.data && e.data.__vk_sourcemap_detect && sourcemapDetectResolve) {
      sourcemapDetectResolve(e.data.result);
      sourcemapDetectResolve = null;
      return;
    }

    // RuoYi hook events → forward to popup
    if (e.data && e.data.__vk_ruoyi_hook && e.data.event) {
      chrome.runtime
        .sendMessage({
          type: 'VK_RUOYI_HOOK_EVENT',
          event: e.data.event,
          augmented: e.data.augmented,
          injected: e.data.injected,
        })
        .catch(function () {});
      return;
    }

    // Vue store explorer result
    if (e.data && e.data.__vk_vue_store && storeExploreResolve) {
      storeExploreResolve(e.data.result);
      storeExploreResolve = null;
      return;
    }
  });

  function injectAndDetect() {
    if (detecting) return Promise.resolve(null);
    detecting = true;
    return new Promise(function (resolve) {
      pendingResolve = resolve;

      var script = document.createElement('script');
      script.src = chrome.runtime.getURL('src/inject/vue-detect.js');
      script.onload = function () {
        script.remove();
        // Timeout fallback in case postMessage doesn't fire
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

  function injectScript(url, resultVarSetter, timeoutMs) {
    return new Promise(function (resolve) {
      var timer = setTimeout(function () {
        resultVarSetter(null);
        resolve(null);
      }, timeoutMs || 3000);
      var innerResolve = function (result) {
        clearTimeout(timer);
        resolve(result);
      };
      resultVarSetter(innerResolve);
      var script = document.createElement('script');
      script.src = chrome.runtime.getURL(url);
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

  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.type === 'VK_VUE_DETECT') {
      injectAndDetect().then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'CONTEXT_EXTRACT_LINKS') {
      var pageUrl = location.href;
      var pageDomain = location.hostname;
      var links = [];
      var seen = {};
      function addLink(href, text, tag) {
        if (!href || href === '#' || href.startsWith('javascript:') || seen[href]) return;
        seen[href] = true;
        var domain = '';
        try {
          domain = new URL(href, pageUrl).hostname;
        } catch (e) {}
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
      injectScript('src/inject/react-detect.js', function (r) {
        reactDetectResolve = r;
      }).then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'VK_ANGULAR_DETECT') {
      injectScript('src/inject/angular-detect.js', function (r) {
        angularDetectResolve = r;
      }).then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'VK_WAF_PROBE') {
      var probeUrl = message.url;
      if (!probeUrl) {
        sendResponse({ error: 'Missing url' });
        return true;
      }
      var controller = new AbortController();
      var timer = setTimeout(function () {
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
          var hdrs = {};
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
      new Promise(function (resolve) {
        storeExploreResolve = resolve;
        var script = document.createElement('script');
        script.src = chrome.runtime.getURL('src/inject/vue-store-explorer.js');
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
      injectScript('src/inject/sourcemap-detect.js', function (r) {
        sourcemapDetectResolve = r;
      }).then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'VK_API_TRAFFIC_START') {
      if (window.__VK_API_TRAFFIC__) {
        sendResponse({ status: 'already_running' });
        return true;
      }
      window.__VK_API_TRAFFIC__ = true;
      window.__VK_API_TRAFFIC_DATA__ = [];
      var apiOrigFetch = window.fetch;
      var apiOrigXhrOpen = XMLHttpRequest.prototype.open;
      var apiOrigXhrSend = XMLHttpRequest.prototype.send;
      function stripApiUrl(url) {
        try {
          var u = new URL(url, location.href);
          return u.origin + u.pathname + u.search;
        } catch (e) {
          return url;
        }
      }
      function extractReqHeaders(init) {
        if (!init || !init.headers) return {};
        var h = init.headers;
        var out = {};
        var keys = [
          'content-type',
          'authorization',
          'cookie',
          'x-csrf-token',
          'x-xsrf-token',
          'x-requested-with',
        ];
        if (typeof Headers !== 'undefined' && h instanceof Headers) {
          keys.forEach(function (k) {
            var v = h.get(k);
            if (v) out[k] = v.length > 200 ? v.substring(0, 200) + '...' : v;
          });
        } else if (typeof h === 'object') {
          keys.forEach(function (k) {
            var lk = k.toLowerCase();
            Object.keys(h).forEach(function (hk) {
              if (hk.toLowerCase() === lk) {
                var v = String(h[hk]);
                out[k] = v.length > 200 ? v.substring(0, 200) + '...' : v;
              }
            });
          });
        }
        return out;
      }
      function truncateBody(body, max) {
        if (!body) return '';
        var s =
          typeof body === 'string'
            ? body
            : typeof body === 'object'
              ? JSON.stringify(body)
              : String(body);
        return s.length > max ? s.substring(0, max) + '...' : s;
      }
      function pushApiEntry(entry) {
        window.__VK_API_TRAFFIC_DATA__.push(entry);
        if (window.__VK_API_TRAFFIC_DATA__.length > 200) {
          window.__VK_API_TRAFFIC_DATA__ = window.__VK_API_TRAFFIC_DATA__.slice(-150);
        }
      }
      window.fetch = function (input, init) {
        var url =
          typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
        var method = ((init && init.method) || 'GET').toUpperCase();
        var start = Date.now();
        var reqBody = '';
        var reqHeaders = {};
        if (init) {
          reqBody = truncateBody(init.body, 3000);
          reqHeaders = extractReqHeaders(init);
        }
        var capturedCt = '';
        var capturedStatus = 0;
        return apiOrigFetch
          .apply(this, arguments)
          .then(function (resp) {
            capturedCt = (resp.headers.get('content-type') || '').split(';')[0];
            capturedStatus = resp.status;
            var clone = resp.clone();
            var bodyPromise = Promise.resolve('');
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
        this.__vk_method = method;
        this.__vk_url = stripApiUrl(url);
        this.__vk_start = Date.now();
        this.__vk_reqHeaders = {};
        var origSetHeader = this.setRequestHeader;
        var capturedHeaders = this.__vk_reqHeaders;
        var headerKeys = [
          'content-type',
          'authorization',
          'cookie',
          'x-csrf-token',
          'x-xsrf-token',
          'x-requested-with',
        ];
        this.setRequestHeader = function (name, value) {
          var ln = (name || '').toLowerCase();
          if (headerKeys.indexOf(ln) !== -1) {
            var v = String(value || '');
            capturedHeaders[ln] = v.length > 200 ? v.substring(0, 200) + '...' : v;
          }
          return origSetHeader.apply(this, arguments);
        };
        return apiOrigXhrOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        var sentBody = arguments[0] != null ? truncateBody(arguments[0], 3000) : '';
        xhr.addEventListener('load', function () {
          var ct = (xhr.getResponseHeader('content-type') || '').split(';')[0];
          var resBody = '';
          if (
            ct &&
            (ct.indexOf('json') !== -1 ||
              ct.indexOf('text') !== -1 ||
              ct.indexOf('xml') !== -1 ||
              ct.indexOf('html') !== -1)
          ) {
            try {
              resBody = truncateBody(xhr.responseText, 2000);
            } catch (e) {}
          }
          pushApiEntry({
            url: xhr.__vk_url || location.href,
            method: xhr.__vk_method || 'GET',
            status: xhr.status,
            contentType: ct,
            duration: Date.now() - (xhr.__vk_start || Date.now()),
            reqBody: sentBody,
            reqHeaders: xhr.__vk_reqHeaders || {},
            resBody: resBody,
          });
        });
        return apiOrigXhrSend.apply(this, arguments);
      };
      sendResponse({ status: 'started' });
      return true;
    }
    if (message.type === 'VK_API_TRAFFIC_STOP') {
      if (!window.__VK_API_TRAFFIC__) {
        sendResponse({ status: 'not_running' });
        return true;
      }
      delete window.__VK_API_TRAFFIC__;
      sendResponse({ status: 'stopped' });
      return true;
    }
    if (message.type === 'VK_API_TRAFFIC_COLLECT') {
      // Auto-start monitoring on first collect if not already running
      if (!window.__VK_API_TRAFFIC__) {
        var startMsg = { type: 'VK_API_TRAFFIC_START' };
        // Replay start logic inline
        window.__VK_API_TRAFFIC__ = true;
        window.__VK_API_TRAFFIC_DATA__ = [];
        var apiOrigFetch = window.fetch;
        var apiOrigXhrOpen = XMLHttpRequest.prototype.open;
        var apiOrigXhrSend = XMLHttpRequest.prototype.send;
        function stripApiUrl(url) {
          try {
            var u = new URL(url, location.href);
            return u.origin + u.pathname + u.search;
          } catch (e) {
            return url;
          }
        }
        function extractReqHeaders(init) {
          if (!init || !init.headers) return {};
          var h = init.headers;
          var out = {};
          var keys = [
            'content-type',
            'authorization',
            'cookie',
            'x-csrf-token',
            'x-xsrf-token',
            'x-requested-with',
          ];
          if (typeof Headers !== 'undefined' && h instanceof Headers) {
            keys.forEach(function (k) {
              var v = h.get(k);
              if (v) out[k] = v.length > 200 ? v.substring(0, 200) + '...' : v;
            });
          } else if (typeof h === 'object') {
            keys.forEach(function (k) {
              var lk = k.toLowerCase();
              Object.keys(h).forEach(function (hk) {
                if (hk.toLowerCase() === lk) {
                  var v = String(h[hk]);
                  out[k] = v.length > 200 ? v.substring(0, 200) + '...' : v;
                }
              });
            });
          }
          return out;
        }
        function truncateBody(body, max) {
          if (!body) return '';
          var s =
            typeof body === 'string'
              ? body
              : typeof body === 'object'
                ? JSON.stringify(body)
                : String(body);
          return s.length > max ? s.substring(0, max) + '...' : s;
        }
        function pushApiEntry(entry) {
          window.__VK_API_TRAFFIC_DATA__.push(entry);
          if (window.__VK_API_TRAFFIC_DATA__.length > 200) {
            window.__VK_API_TRAFFIC_DATA__ = window.__VK_API_TRAFFIC_DATA__.slice(-150);
          }
        }
        window.fetch = function (input, init) {
          var url =
            typeof input === 'string'
              ? input
              : input instanceof Request
                ? input.url
                : String(input);
          var method = ((init && init.method) || 'GET').toUpperCase();
          var start = Date.now();
          var reqBody = '';
          var reqHeaders = {};
          if (init) {
            reqBody = truncateBody(init.body, 3000);
            reqHeaders = extractReqHeaders(init);
          }
          var capturedCt = '';
          var capturedStatus = 0;
          return apiOrigFetch
            .apply(this, arguments)
            .then(function (resp) {
              capturedCt = (resp.headers.get('content-type') || '').split(';')[0];
              capturedStatus = resp.status;
              var clone = resp.clone();
              var bodyPromise = Promise.resolve('');
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
          this.__vk_method = method;
          this.__vk_url = stripApiUrl(url);
          this.__vk_start = Date.now();
          this.__vk_reqHeaders = {};
          var origSetHeader = this.setRequestHeader;
          var capturedHeaders = this.__vk_reqHeaders;
          var headerKeys = [
            'content-type',
            'authorization',
            'cookie',
            'x-csrf-token',
            'x-xsrf-token',
            'x-requested-with',
          ];
          this.setRequestHeader = function (name, value) {
            var ln = (name || '').toLowerCase();
            if (headerKeys.indexOf(ln) !== -1) {
              var v = String(value || '');
              capturedHeaders[ln] = v.length > 200 ? v.substring(0, 200) + '...' : v;
            }
            return origSetHeader.apply(this, arguments);
          };
          return apiOrigXhrOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function () {
          var xhr = this;
          var sentBody = arguments[0] != null ? truncateBody(arguments[0], 3000) : '';
          xhr.addEventListener('load', function () {
            var ct = (xhr.getResponseHeader('content-type') || '').split(';')[0];
            var resBody = '';
            if (
              ct &&
              (ct.indexOf('json') !== -1 ||
                ct.indexOf('text') !== -1 ||
                ct.indexOf('xml') !== -1 ||
                ct.indexOf('html') !== -1)
            ) {
              try {
                resBody = truncateBody(xhr.responseText, 2000);
              } catch (e) {}
            }
            pushApiEntry({
              url: xhr.__vk_url || location.href,
              method: xhr.__vk_method || 'GET',
              status: xhr.status,
              contentType: ct,
              duration: Date.now() - (xhr.__vk_start || Date.now()),
              reqBody: sentBody,
              reqHeaders: xhr.__vk_reqHeaders || {},
              resBody: resBody,
            });
          });
          return apiOrigXhrSend.apply(this, arguments);
        };
      }
      var data = window.__VK_API_TRAFFIC_DATA__ || [];
      window.__VK_API_TRAFFIC_DATA__ = [];
      sendResponse({ entries: data, running: !!window.__VK_API_TRAFFIC__ });
      return true;
    }
  });
})();
