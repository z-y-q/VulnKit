// 灵眸 - Vue Store Explorer (MAIN world injection)
// Reads Vuex/Pinia state, actions/getters, and scans DOM for custom directives
(function () {
  'use strict';

  const __vk_token: string = document.currentScript ? (document.currentScript as HTMLScriptElement).dataset.vkToken || '' : '';

  function exploreStore(): { stores: Record<string, any>; frameworks: string[]; errors: string[] } {
    const result: { stores: Record<string, any>; frameworks: string[]; errors: string[] } = { stores: {}, frameworks: [], errors: [] };

    // --- Vuex ---
    try {
      const vuexKeys: string[] = Object.keys(window).filter(function (k: string) {
        return k.indexOf('Vuex') !== -1 || k.indexOf('vuex') !== -1;
      });
      if (vuexKeys.length > 0) result.frameworks.push('Vuex (global)');

      // Find Vue instances and their $store
      let vueRoot: any = null;
      if ((window as any).__VUE__) vueRoot = (window as any).__VUE__;
      if (!vueRoot && document.querySelector('[data-v-app]')) {
        const appEl = document.querySelector('[data-v-app]') as HTMLElement;
        vueRoot =
          (appEl as any).__vue_app__ ||
          (appEl as any).__vue__;
      }
      // Vue 3 app
      if (vueRoot && vueRoot.config && vueRoot.config.globalProperties) {
        result.frameworks.push('Vue 3');
        const store: any = vueRoot.config.globalProperties.$store;
        if (store) {
          result.stores.root = extractVuexStore(store);
        }
      }
      // Vue 2 instance (limit scan to 2000 elements)
      if (!vueRoot || !result.stores.root) {
        const allEls: NodeListOf<Element> = document.querySelectorAll('*');
        for (let i = 0; i < Math.min(allEls.length, 2000); i++) {
          const el = allEls[i] as any;
          if (el.__vue__ && el.__vue__.$store) {
            result.frameworks.push('Vue 2');
            result.stores.root = extractVuexStore(el.__vue__.$store);
            break;
          }
        }
      }
    } catch (e: any) {
      result.errors.push(`Vuex: ${(e && e.message) || String(e)}`);
    }

    // --- Pinia ---
    try {
      if ((window as any).pinia || (window as any).__pinia__) {
        result.frameworks.push('Pinia');
        const piniaInstance: any = (window as any).pinia || (window as any).__pinia__;
        const state: any =
          piniaInstance.state && piniaInstance.state.value ? piniaInstance.state.value : {};
        Object.keys(state).forEach(function (storeId: string) {
          result.stores[storeId] = {
            state: safeClone(state[storeId]),
            type: 'pinia',
          };
        });
      }
    } catch (e: any) {
      result.errors.push(`Pinia: ${(e && e.message) || String(e)}`);
    }

    return result;
  }

  function extractVuexStore(store: any): { state: any; getters: string[]; mutations: string[]; actions: string[]; type: string; error?: string } {
    const data: { state: any; getters: string[]; mutations: string[]; actions: string[]; type: string; error?: string } = { state: {}, getters: [], mutations: [], actions: [], type: 'vuex' };
    try {
      data.state = safeClone(store.state || {});
      if (store._vm) {
        const computed: Record<string, any> = store._vm.$options.computed || {};
        data.getters = Object.keys(computed);
      }
      if (store._mutations) data.mutations = Object.keys(store._mutations);
      if (store._actions) data.actions = Object.keys(store._actions);
    } catch (e: any) {
      data.error = e.message;
    }
    return data;
  }

  function safeClone(obj: any): any {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;
    try {
      return JSON.parse(
        JSON.stringify(obj, function (key: string, value: any) {
          if (typeof value === 'function') return '[Function]';
          if (value instanceof HTMLElement) return `[HTMLElement: ${value.tagName || 'unknown'}]`;
          if (value instanceof Window) return '[Window]';
          if (value instanceof Error) return `[Error: ${value.message}]`;
          if (typeof value === 'symbol') return value.toString();
          return value;
        })
      );
    } catch (e) {
      return String(obj);
    }
  }

  function exploreActionsGetters(): { apiEndpoints: string[]; actionNames: string[]; getterNames: string[]; error?: string } {
    const result: { apiEndpoints: string[]; actionNames: string[]; getterNames: string[]; error?: string } = { apiEndpoints: [], actionNames: [], getterNames: [] };
    try {
      // Search Vue instances for store
      let store: any = null;
      let vueRoot: any = null;
      if ((window as any).__VUE__) vueRoot = (window as any).__VUE__;
      if (!vueRoot && document.querySelector('[data-v-app]')) {
        const appEl = document.querySelector('[data-v-app]') as HTMLElement;
        vueRoot =
          (appEl as any).__vue_app__ ||
          (appEl as any).__vue__;
      }
      if (vueRoot && vueRoot.config && vueRoot.config.globalProperties) {
        store = vueRoot.config.globalProperties.$store;
      }
      if (!store) {
        const allEls: NodeListOf<Element> = document.querySelectorAll('*');
        for (let i = 0; i < Math.min(allEls.length, 2000); i++) {
          const el = allEls[i] as any;
          if (el.__vue__ && el.__vue__.$store) {
            store = el.__vue__.$store;
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
      const actionSrc: string[] = [];
      if (store._actions) {
        Object.keys(store._actions).forEach(function (name: string) {
          const fns: any = store._actions[name];
          if (Array.isArray(fns)) {
            fns.forEach(function (fn: any) {
              if (typeof fn === 'function') actionSrc.push(fn.toString());
            });
          } else if (typeof fns === 'function') {
            actionSrc.push(fns.toString());
          }
        });
      }

      const urlPattern =
        /['"`](\/(?:api|v[0-9]+|admin|system|user|auth|login|query|search|list|get|post|put|delete)\/[^\s'"`)]{2,})['"`]/gi;
      const seen: Record<string, boolean> = {};
      actionSrc.forEach(function (src: string) {
        let match: RegExpExecArray | null;
        urlPattern.lastIndex = 0;
        while ((match = urlPattern.exec(src)) !== null) {
          const url: string = match[1];
          if (!seen[url]) {
            seen[url] = true;
            result.apiEndpoints.push(url);
          }
        }
      });
    } catch (e: any) {
      result.error = e.message;
    }
    return result;
  }

  function scanDirectives(): { name: string; count: number; examples: string[] }[] {
    const directives: { name: string; count: number; examples: string[] }[] = [];
    const knownDirectives: string[] = [
      'v-permission',
      'v-auth',
      'v-hasPermi',
      'v-hasRole',
      'v-access',
      'v-role',
      'v-permit',
      'v-acl',
      'v-if',
      'v-show',
      'v-model',
      'v-slot',
      'v-for',
    ];
    const customAttrs: Record<string, { count: number; examples: string[] }> = {};
    const allEls: NodeListOf<Element> = document.querySelectorAll('*');
    for (let i = 0; i < Math.min(allEls.length, 2000); i++) {
      const el: Element = allEls[i];
      const attrs: NamedNodeMap = el.attributes;
      for (let j = 0; j < attrs.length; j++) {
        const name: string = attrs[j].name;
        if (
          name.indexOf('v-') === 0 ||
          (name.indexOf('data-v-') === -1 && name.indexOf(':') !== -1)
        ) {
          if (
            name.indexOf('v-') === 0 &&
            knownDirectives.indexOf(name.split('=')[0].split(':')[0]) === -1
          ) {
            // Custom directive
            const dirName: string = name.split('=')[0].split(':')[0];
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
    Object.keys(customAttrs).forEach(function (dir: string) {
      directives.push({
        name: dir,
        count: customAttrs[dir].count,
        examples: customAttrs[dir].examples,
      });
    });
    directives.sort(function (a: { count: number }, b: { count: number }) {
      return b.count - a.count;
    });
    return directives;
  }

  // Execute and return results via postMessage
  const storeData = exploreStore();
  const actionsData = exploreActionsGetters();
  const directivesData = scanDirectives();

  window.postMessage(
    {
      __vk_vue_store: true,
      __vk_token: __vk_token,
      result: {
        store: storeData,
        actions: actionsData,
        directives: directivesData,
      },
    },
    location.origin
  );
})();
