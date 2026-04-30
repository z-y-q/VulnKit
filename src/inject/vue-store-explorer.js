// VulnKit - Vue Store Explorer (MAIN world injection)
// Reads Vuex/Pinia state, actions/getters, and scans DOM for custom directives
(function () {
  'use strict';

  function exploreStore() {
    var result = { stores: {}, frameworks: [], errors: [] };

    // --- Vuex ---
    try {
      var vuexKeys = Object.keys(window).filter(function (k) {
        return k.indexOf('Vuex') !== -1 || k.indexOf('vuex') !== -1;
      });
      if (vuexKeys.length > 0) result.frameworks.push('Vuex (global)');

      // Find Vue instances and their $store
      var vueRoot = null;
      if (window.__VUE__) vueRoot = window.__VUE__;
      if (!vueRoot && document.querySelector('[data-v-app]')) {
        vueRoot = document.querySelector('[data-v-app]').__vue_app__ || document.querySelector('[data-v-app]').__vue__;
      }
      // Vue 3 app
      if (vueRoot && vueRoot.config && vueRoot.config.globalProperties) {
        result.frameworks.push('Vue 3');
        var store = vueRoot.config.globalProperties.$store;
        if (store) {
          result.stores.root = extractVuexStore(store);
        }
      }
      // Vue 2 instance
      if (!vueRoot || !result.stores.root) {
        var allEls = document.querySelectorAll('*');
        for (var i = 0; i < allEls.length; i++) {
          var el = allEls[i];
          if (el.__vue__ && el.__vue__.$store) {
            result.frameworks.push('Vue 2');
            result.stores.root = extractVuexStore(el.__vue__.$store);
            break;
          }
        }
      }
    } catch (e) {
      result.errors.push('Vuex: ' + e.message);
    }

    // --- Pinia ---
    try {
      if (window.pinia || window.__pinia__) {
        result.frameworks.push('Pinia');
        var piniaInstance = window.pinia || window.__pinia__;
        var state = piniaInstance.state && piniaInstance.state.value ? piniaInstance.state.value : {};
        Object.keys(state).forEach(function (storeId) {
          result.stores[storeId] = {
            state: safeClone(state[storeId]),
            type: 'pinia',
          };
        });
      }
    } catch (e) {
      result.errors.push('Pinia: ' + e.message);
    }

    return result;
  }

  function extractVuexStore(store) {
    var data = { state: {}, getters: [], mutations: [], actions: [], type: 'vuex' };
    try {
      data.state = safeClone(store.state || {});
      if (store._vm) {
        var computed = store._vm.$options.computed || {};
        data.getters = Object.keys(computed);
      }
      if (store._mutations) data.mutations = Object.keys(store._mutations);
      if (store._actions) data.actions = Object.keys(store._actions);
    } catch (e) {
      data.error = e.message;
    }
    return data;
  }

  function safeClone(obj) {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;
    try {
      return JSON.parse(JSON.stringify(obj, function (key, value) {
        if (typeof value === 'function') return '[Function]';
        if (value instanceof HTMLElement) return '[HTMLElement:' + value.tagName + ']';
        if (value instanceof Window) return '[Window]';
        if (value instanceof Error) return '[Error: ' + value.message + ']';
        if (typeof value === 'symbol') return value.toString();
        return value;
      }));
    } catch (e) {
      return String(obj);
    }
  }

  function exploreActionsGetters() {
    var result = { apiEndpoints: [], actionNames: [], getterNames: [] };
    try {
      // Search Vue instances for store
      var store = null;
      var vueRoot = null;
      if (window.__VUE__) vueRoot = window.__VUE__;
      if (!vueRoot && document.querySelector('[data-v-app]')) {
        vueRoot = document.querySelector('[data-v-app]').__vue_app__ || document.querySelector('[data-v-app]').__vue__;
      }
      if (vueRoot && vueRoot.config && vueRoot.config.globalProperties) {
        store = vueRoot.config.globalProperties.$store;
      }
      if (!store) {
        var allEls = document.querySelectorAll('*');
        for (var i = 0; i < allEls.length; i++) {
          if (allEls[i].__vue__ && allEls[i].__vue__.$store) {
            store = allEls[i].__vue__.$store;
            break;
          }
        }
      }
      if (!store) return result;

      if (store._actions) {
        result.actionNames = Object.keys(store._actions);
      }
      if (store._vm && store._vm.$options.computed) {
        result.getterNames = Object.keys(store._vm.$options.computed);
      }

      // Extract API endpoints from action source code
      var actionSrc = [];
      if (store._actions) {
        Object.keys(store._actions).forEach(function (name) {
          var fns = store._actions[name];
          if (Array.isArray(fns)) {
            fns.forEach(function (fn) {
              if (typeof fn === 'function') actionSrc.push(fn.toString());
            });
          } else if (typeof fns === 'function') {
            actionSrc.push(fns.toString());
          }
        });
      }

      var urlPattern = /['"`](\/(?:api|v[0-9]+|admin|system|user|auth|login|query|search|list|get|post|put|delete)\/[^\s'"`)]{2,})['"`]/gi;
      var seen = {};
      actionSrc.forEach(function (src) {
        var match;
        urlPattern.lastIndex = 0;
        while ((match = urlPattern.exec(src)) !== null) {
          var url = match[1];
          if (!seen[url]) {
            seen[url] = true;
            result.apiEndpoints.push(url);
          }
        }
      });
    } catch (e) {
      result.error = e.message;
    }
    return result;
  }

  function scanDirectives() {
    var directives = [];
    var knownDirectives = [
      'v-permission', 'v-auth', 'v-hasPermi', 'v-hasRole',
      'v-access', 'v-role', 'v-permit', 'v-acl',
      'v-if', 'v-show', 'v-model', 'v-slot', 'v-for',
    ];
    var customAttrs = {};
    var allEls = document.querySelectorAll('*');
    for (var i = 0; i < allEls.length; i++) {
      var el = allEls[i];
      var attrs = el.attributes;
      for (var j = 0; j < attrs.length; j++) {
        var name = attrs[j].name;
        if (name.indexOf('v-') === 0 || name.indexOf('data-v-') === -1 && name.indexOf(':') !== -1) {
          if (name.indexOf('v-') === 0 && knownDirectives.indexOf(name.split('=')[0].split(':')[0]) === -1) {
            // Custom directive
            var dirName = name.split('=')[0].split(':')[0];
            if (!customAttrs[dirName]) {
              customAttrs[dirName] = { count: 0, examples: [] };
            }
            customAttrs[dirName].count++;
            if (customAttrs[dirName].examples.length < 3) {
              customAttrs[dirName].examples.push(attrs[j].value.substring(0, 50));
            }
          }
        }
      }
    }
    Object.keys(customAttrs).forEach(function (dir) {
      directives.push({
        name: dir,
        count: customAttrs[dir].count,
        examples: customAttrs[dir].examples,
      });
    });
    directives.sort(function (a, b) { return b.count - a.count; });
    return directives;
  }

  // Execute and return results via postMessage
  var storeData = exploreStore();
  var actionsData = exploreActionsGetters();
  var directivesData = scanDirectives();

  window.postMessage({
    __vk_vue_store: true,
    result: {
      store: storeData,
      actions: actionsData,
      directives: directivesData,
    },
  }, location.origin);
})();
