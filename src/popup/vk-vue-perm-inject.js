// vk-vue-perm-inject.js -- 灵眸 Chrome Extension
// Injected function bodies for store reading and request interception
(function () {
  'use strict';

  var S = window.VulnKitVueState;

  var permStoreReaderFunc = function (MENU_KEYWORDS) {
    if (!window.__PERM_INTERCEPTOR__) return;
    function classifyStr(str, url) {
      var urlLower = (url || '').toLowerCase();
      if (/permission/i.test(urlLower)) return 'permission';
      if (/role/i.test(urlLower)) return 'role';
      if (/menu/i.test(urlLower)) return 'menu';
      for (var i = 0; i < MENU_KEYWORDS.length; i++) {
        if (str.indexOf(MENU_KEYWORDS[i]) !== -1) return 'menu';
      }
      return 'other';
    }
    function sanitizeForTransfer(obj, depth) {
      if (obj === null || obj === undefined) return obj;
      if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean')
        return obj;
      if (typeof obj === 'function') return '[function]';
      if (obj instanceof HTMLElement) return '[HTMLElement]';
      if (obj instanceof RegExp) return '[RegExp]';
      if (depth > 12) return '[max-depth]';
      if (Array.isArray(obj)) {
        return obj.map(function (item) {
          return sanitizeForTransfer(item, depth + 1);
        });
      }
      if (typeof obj === 'object') {
        var skipKeys = {
          component: 1, _Ctor: 1, _compiled: 1, _scopeId: 1,
          staticRenderFns: 1, render: 1, beforeCreate: 1, created: 1,
          beforeMount: 1, mounted: 1, beforeUpdate: 1, updated: 1,
          beforeDestroy: 1, destroyed: 1, activated: 1, deactivated: 1,
          mixins: 1, extends: 1, directives: 1, filters: 1,
          _ssrRegister: 1, __file: 1, _functional: 1, _inject: 1,
          _provided: 1, model: 1, inheritAttrs: 1, comments: 1,
        };
        var result = {};
        try {
          var keys = Object.keys(obj);
          for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            if (skipKeys[k]) {
              if (k === 'component') {
                var v = obj[k];
                result[k] =
                  v && (v.name || v.__name || v.displayName)
                    ? '[component: ' + (v.name || v.__name || v.displayName) + ']'
                    : '[component]';
              }
              continue;
            }
            result[k] = sanitizeForTransfer(obj[k], depth + 1);
          }
        } catch (e) {
          return '[error-reading-keys]';
        }
        return result;
      }
      return String(obj);
    }
    function tryAdd(data, url) {
      if (!data || typeof data === 'string') return;
      var cap = window.__PERM_INTERCEPTOR__.captured;
      for (var di = 0; di < cap.length; di++) {
        if (cap[di].url === url && cap[di].method === 'store-read') return;
      }
      var clean = sanitizeForTransfer(data, 0);
      var str = JSON.stringify(clean);
      var type = classifyStr(str, url);
      if (type !== 'other') {
        cap.push({
          url: url, type: type, subtype: null, data: clean,
          rawText: str, size: str.length, timestamp: Date.now(), method: 'store-read',
        });
      }
    }
    var appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main');
    if (appEl && appEl.__vue_app__) {
      var pinia = appEl.__vue_app__.config.globalProperties.$pinia;
      if (pinia && pinia._s) {
        pinia._s.forEach(function (store, id) {
          var state = store.$state;
          for (var key in state) {
            if (
              /menu|permission|nav|route|sidebar/i.test(key) &&
              (Array.isArray(state[key]) || (typeof state[key] === 'object' && state[key] !== null))
            ) {
              tryAdd(state[key], 'pinia://' + id + '/' + key);
            }
          }
        });
      }
    }
    var allEls = document.querySelectorAll('*');
    for (var i = 0; i < allEls.length; i++) {
      if (allEls[i].__vue__) {
        var vm = allEls[i].__vue__.$root || allEls[i].__vue__;
        if (vm.$store && vm.$store.state) {
          for (var key in vm.$store.state) {
            if (
              /menu|permission|nav|route|sidebar/i.test(key) &&
              (Array.isArray(vm.$store.state[key]) ||
                (typeof vm.$store.state[key] === 'object' && vm.$store.state[key] !== null))
            ) {
              tryAdd(vm.$store.state[key], 'vuex://state/' + key);
            }
          }
        }
        break;
      }
    }
    var storagePrefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar'];
    for (var s = 0; s < localStorage.length; s++) {
      var storageKey = localStorage.key(s);
      if (storageKey) {
        for (var p = 0; p < storagePrefixes.length; p++) {
          if (storageKey.toLowerCase().indexOf(storagePrefixes[p]) !== -1) {
            try {
              var parsed = JSON.parse(localStorage.getItem(storageKey));
              tryAdd(parsed, 'localStorage://' + storageKey);
            } catch (e) {}
            break;
          }
        }
      }
    }
  };

  var permInterceptorFunc = function (MENU_KEYWORDS) {
    if (window.__PERM_INTERCEPTOR__) {
      window.__PERM_INTERCEPTOR__.active = true;
      return 'already_injected';
    }

    var URL_MENU_PATTERNS = [
      /\/api\/.*menu/i, /\/api\/.*permission/i, /\/api\/.*role/i,
      /\/api\/.*user.*info/i, /\/api\/.*auth/i, /\/api\/.*nav/i,
      /\/menu(?:\/|$|[?#])/i, /\/permission(?:\/|$|[?#])/i,
      /\/getMenu/i, /\/getUserInfo/i, /\/getRouters/i,
      /\/getRoutes(?:\/|$|[?#])/i,
    ];

    function classifyResponse(data, url) {
      var urlLower = url.toLowerCase();
      try {
        var json = typeof data === 'string' ? JSON.parse(data) : data;
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          var keys = Object.keys(json);
          for (var k = 0; k < keys.length; k++) {
            if (
              /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
                keys[k]
              )
            )
              return { type: 'role', subtype: 'special_zero' };
          }
          for (var k2 = 0; k2 < keys.length; k2++) {
            for (var i = 0; i < MENU_KEYWORDS.length; i++) {
              if (keys[k2].toLowerCase() === MENU_KEYWORDS[i].toLowerCase())
                return { type: 'menu', subtype: null };
            }
          }
        }
      } catch (e) {}
      if (/permission/i.test(urlLower)) return { type: 'permission', subtype: null };
      if (/role/i.test(urlLower)) return { type: 'role', subtype: null };
      if (/menu/i.test(urlLower)) return { type: 'menu', subtype: null };
      return { type: 'other', subtype: null };
    }

    function parseBody(text) {
      try {
        var json = JSON.parse(text);
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          if (json.data !== undefined) return json.data;
          if (json.result !== undefined) return json.result;
          if (json.Data !== undefined) return json.Data;
          if (json.Result !== undefined) return json.Result;
        }
        return json;
      } catch (e) {
        return text;
      }
    }

    var captured = [];
    function pushCap(url, type, subtype, data, rawText, method) {
      captured.push({
        url: url, type: type, subtype: subtype, data: data,
        rawText: rawText, size: rawText.length, timestamp: Date.now(), method: method,
      });
    }

    var originalFetch = window.fetch;
    window.fetch = function () {
      var args = arguments;
      return originalFetch
        .apply(this, args)
        .then(function (response) {
          if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active) {
            var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
            var isMenuApi = URL_MENU_PATTERNS.some(function (p) { return p.test(url); });
            if (isMenuApi) {
              var override = window.__PERM_INTERCEPTOR__._overrideData;
              if (override !== null && override !== undefined) {
                var overrideBody = JSON.stringify(override);
                try {
                  var info = classifyResponse(override, url);
                  if (info.type !== 'other') {
                    pushCap(url, info.type, info.subtype, override, overrideBody, 'fetch-override');
                  }
                } catch (e) {}
                return new Response(overrideBody, {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                });
              } else {
                var cloned = response.clone();
                cloned
                  .text()
                  .then(function (text) {
                    try {
                      var parsed = parseBody(text);
                      var info = classifyResponse(parsed, url);
                      if (info.type !== 'other') {
                        pushCap(url, info.type, info.subtype, parsed, text, 'fetch');
                      }
                    } catch (e) {}
                  })
                  .catch(function () {});
              }
            }
          }
          return response;
        })
        .catch(function (err) { throw err; });
    };

    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__perm_url = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      var self = this;
      if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active && this.__perm_url) {
        var url = this.__perm_url;
        var isMenuApi = URL_MENU_PATTERNS.some(function (p) { return p.test(url); });
        if (isMenuApi) {
          this.addEventListener('readystatechange', function () {
            if (self.readyState === 4) {
              var override = window.__PERM_INTERCEPTOR__._overrideData;
              var originalText = self.responseText;
              if (override !== null && override !== undefined) {
                try {
                  var overrideBody = JSON.stringify(override);
                  Object.defineProperty(self, 'responseText', {
                    value: overrideBody, writable: true, configurable: true,
                  });
                  Object.defineProperty(self, 'response', {
                    value: overrideBody, writable: true, configurable: true,
                  });
                } catch (e) {}
              }
              try {
                var text =
                  override !== null && override !== undefined
                    ? JSON.stringify(override)
                    : originalText;
                if (!text) return;
                var parsed = parseBody(text);
                var info = classifyResponse(parsed, url);
                if (info.type !== 'other') {
                  pushCap(url, info.type, info.subtype, parsed, text,
                    override != null ? 'xhr-override' : 'xhr');
                }
              } catch (e) {}
            }
          });
        }
      }
      return origSend.apply(this, arguments);
    };

    window.__PERM_INTERCEPTOR__ = {
      active: true,
      captured: captured,
      getCaptured: function () { return captured; },
      clear: function () { captured.length = 0; },
      stop: function () { this.active = false; },
      start: function () { this.active = true; },
      _overrideData: null,
      getOverride: function () { return this._overrideData; },
      setOverride: function (d) { this._overrideData = d; },
    };
    return 'injected';
  };

  S.PermInject = {
    permStoreReaderFunc: permStoreReaderFunc,
    permInterceptorFunc: permInterceptorFunc,
  };
})();
