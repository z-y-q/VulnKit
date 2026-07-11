// 灵眸 v6.0 - RuoYi Route Hook (document_start, MAIN world)
// 拦截 fetch/XHR 捕获并增强 /getRouters 响应。
// 捕获始终被动进行；`enabled` 仅控制增强与 API 日志记录。
// 注意：此脚本由 background 通过 chrome.scripting.registerContentScripts 在
// document_start + MAIN world 注册，不是动态 <script src> 注入，因此无 currentScript/token。
(function () {
  'use strict';

  const W = window as any;
  if (W.__VK_RUOYI_HOOK__) return;

  const defaultRouterUrls: RegExp[] = [
    /\/getRouters/i,
    /\/getRoutes/i,
    /\/system\/menu\/getRouters/i,
  ];

  const userInfoUrls: RegExp[] = [/\/getUserInfo/i, /\/getInfo/i];

  // 从 localStorage 读取持久化配置（跨刷新存活）
  let savedConfig: any = null;
  try {
    const raw = localStorage.getItem('__vk_ruoyi_hook_config');
    if (raw) savedConfig = JSON.parse(raw);
  } catch {
    savedConfig = null;
  }

  // 仅当保存自当前 origin 时恢复（安全校验）
  let configEnabled = false;
  let configAugmentMode = 'auto';
  let configExtraRoutes: any[] = [];
  let configCustomUrls: string[] = [];

  if (savedConfig && savedConfig.origin === location.origin) {
    configEnabled = true;
    configAugmentMode = savedConfig.augmentMode || 'auto';
    configExtraRoutes = savedConfig.extraRoutes || [];
    configCustomUrls = savedConfig.customRouterUrls || [];
  }

  W.__VK_RUOYI_HOOK__ = {
    version: '1.4',
    enabled: configEnabled,
    capturedRouters: null as string | null,
    augmentMode: configAugmentMode,
    extraRoutes: configExtraRoutes,
    customRouterUrls: configCustomUrls,
    requestLog: [] as any[],
    apiLog: [] as any[],
    hookInstalledAt: Date.now(),
    restoredFromStorage: configEnabled,
    alwaysCapture: true,
  };

  function getTime(): string {
    const d = new Date();
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
  }

  let _cachedCustomUrls = '';
  let _cachedPatterns: RegExp[] | null = null;
  const _quickSkipRe = /(?:getRouters?|getUserInfo|getInfo)\b/i;
  const _quickApiSkipRe =
    /\b(?:api|admin|system|monitor|tool|gen|auth|login|logout|captcha|code|user|role|menu|dept|post|dict|config|notice|log)\b|\.(?:json|xml)\b/i;

  function isRouterUrl(url: string): boolean {
    const hook = W.__VK_RUOYI_HOOK__;
    const customKey = (hook.customRouterUrls || []).join('|');
    if (customKey !== _cachedCustomUrls) {
      _cachedCustomUrls = customKey;
      _cachedPatterns = defaultRouterUrls.slice();
      (hook.customRouterUrls || []).forEach(function (custom: string) {
        try {
          _cachedPatterns!.push(new RegExp(custom, 'i'));
        } catch {
          /* ignore */
        }
      });
    }
    return _cachedPatterns!.some(function (p) {
      return p.test(url);
    });
  }

  function isUserInfoUrl(url: string): boolean {
    return userInfoUrls.some(function (p) {
      return p.test(url);
    });
  }

  function isApiUrl(url: string): boolean {
    try {
      const pathname = new URL(url, location.origin).pathname;
      return (
        /^\/(api|admin|system|monitor|tool|gen|auth|login|logout|captcha|code|user|role|menu|dept|post|dict|config|notice|log)\b/i.test(
          pathname,
        ) ||
        /\.(json|xml)$/i.test(pathname) ||
        /\/(get|list|add|edit|update|delete|remove|export|import|upload|download|query)\b/i.test(pathname)
      );
    } catch {
      return false;
    }
  }

  function logApiRequest(url: string, method: string, status: number, body: string) {
    const hook = W.__VK_RUOYI_HOOK__;
    if (!hook) return;
    if (!hook.apiLog) hook.apiLog = [];
    hook.apiLog.push({
      url: url,
      method: method || 'GET',
      status: status || 0,
      body: body ? body.substring(0, 5000) : '',
      time: getTime(),
    });
    if (hook.apiLog.length > 200) hook.apiLog = hook.apiLog.slice(-150);
  }

  function logRequest(type: string, url: string, status: any, method: string) {
    const hook = W.__VK_RUOYI_HOOK__;
    if (!hook) return;
    const entry = {
      type: type,
      url: url,
      status: status || '',
      method: method || '',
      time: getTime(),
    };
    if (!hook.requestLog) hook.requestLog = [];
    hook.requestLog.push(entry);
    if (hook.requestLog.length > 100) hook.requestLog = hook.requestLog.slice(-50);
  }

  function findParentByPath(routes: any[], parentPath: string): any | null {
    for (let i = 0; i < routes.length; i++) {
      if (routes[i].path === parentPath) return routes[i];
      if (routes[i].children) {
        const found = findParentByPath(routes[i].children, parentPath);
        if (found) return found;
      }
    }
    return null;
  }

  function ensureParent(routeArray: any[], parentPath: string): any {
    const existing = findParentByPath(routeArray, parentPath);
    if (existing) return existing;
    const parent = {
      name: parentPath.replace(/\//g, '') || 'Root',
      path: parentPath,
      hidden: false,
      component: 'Layout',
      meta: { title: parentPath, icon: 'menu' },
      children: [] as any[],
    };
    routeArray.push(parent);
    return parent;
  }

  function mergeExtraRoutes(raw: any): any {
    const config = W.__VK_RUOYI_HOOK__;
    if (!config.extraRoutes || config.extraRoutes.length === 0) return raw;
    try {
      const data = typeof raw === 'string' ? JSON.parse(raw) : JSON.parse(JSON.stringify(raw));
      const routeArray = data.data;
      if (!Array.isArray(routeArray)) return raw;

      const existing: Record<string, boolean> = {};
      (function collect(routes: any[]) {
        routes.forEach(function (r) {
          if (r.path) existing[r.path] = true;
          if (r.children) collect(r.children);
        });
      })(routeArray);

      let injected = 0;
      config.extraRoutes.forEach(function (extra: any) {
        if (existing[extra.path]) return;

        const segments = extra.path.replace(/^\/+/, '').split('/');
        const childNode = {
          name: extra.name || segments.join('') || extra.path,
          path: extra.childPath || (segments.length > 1 ? segments.slice(1).join('/') : 'index'),
          hidden: false,
          component: extra.component || '',
          meta: {
            title: extra.title || extra.path,
            icon: extra.icon || 'menu',
            activeMenu: extra.path,
          },
        };

        if (segments.length > 1) {
          const parentPath = `/${segments[0]}`;
          const parent = ensureParent(routeArray, parentPath);
          if (!parent.children) parent.children = [];
          parent.children.push(childNode);
          existing[extra.path] = true;
          injected++;
        } else {
          routeArray.push({
            name: extra.name || extra.path,
            path: extra.path,
            hidden: false,
            component: 'Layout',
            meta: { title: extra.title || extra.path, icon: extra.icon || 'menu' },
            children: [childNode],
          });
          existing[extra.path] = true;
          injected++;
        }
      });

      const modified = JSON.stringify(data);
      return { body: modified, injected: injected };
    } catch {
      return raw;
    }
  }

  // Fetch hook — 无论 enabled 与否，始终捕获 router/userinfo 数据。
  // enabled 仅控制增强（注入额外路由）与 API 流量日志。
  const origFetch = window.fetch;
  W.fetch = function () {
    const args = arguments;
    const url = typeof args[0] === 'string' ? args[0] : args[0] && args[0].url ? args[0].url : '';
    const fetchOpts = args[1] && typeof args[1] === 'object' ? args[1] : {};
    const fetchMethod = (fetchOpts.method || 'GET').toUpperCase();
    const isUserInfo = /(?:getUserInfo|getInfo)\b/i.test(url);
    const isRouter = !isUserInfo && _quickSkipRe.test(url);
    return origFetch.apply(this, args as any).then(function (response: Response) {
      const config = W.__VK_RUOYI_HOOK__;

      // 始终捕获 /getRouters 响应（被动，不修改）
      if (isRouter) {
        if (!response.ok) {
          logRequest('router-error', url, response.status, fetchMethod);
          return response;
        }
        logRequest('router', url, response.status, fetchMethod);
        return response
          .clone()
          .text()
          .then(function (body: string) {
            if (config) config.capturedRouters = body;

            // 增强仅在 enabled 时
            if (
              config &&
              config.enabled &&
              config.augmentMode !== 'off' &&
              config.extraRoutes.length > 0
            ) {
              const result = mergeExtraRoutes(body);
              if (typeof result === 'object' && result.body) {
                logRequest('augment', url, `injected:${result.injected || 0}`, fetchMethod);
                window.postMessage(
                  {
                    __vk_ruoyi_hook: true,
                    event: 'routers_captured',
                    augmented: true,
                    injected: result.injected,
                  },
                  location.origin,
                );
                return new Response(result.body, {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                });
              }
            }
            window.postMessage(
              {
                __vk_ruoyi_hook: true,
                event: 'routers_captured',
                augmented: false,
              },
              location.origin,
            );
            return response;
          })
          .catch(function () {
            return response;
          });
      }

      // 始终捕获 userinfo 响应
      if (isUserInfo) {
        if (!response.ok) {
          logRequest('userinfo-error', url, response.status, fetchMethod);
          return response;
        }
        logRequest('userinfo', url, response.status, fetchMethod);
        window.postMessage({ __vk_ruoyi_hook: true, event: 'userinfo_captured' }, location.origin);
      }

      // API 流量日志仅在 enabled 时（开销较大）
      if (config && config.enabled && _quickApiSkipRe.test(url) && !isRouter && !isUserInfo) {
        response
          .clone()
          .text()
          .then(function (body: string) {
            logApiRequest(url, fetchMethod, response.status, body);
          })
          .catch(function () {
            logApiRequest(url, fetchMethod, response.status, '');
          });
      }

      return response;
    });
  };

  // XHR hook
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method: string, reqUrl: string) {
    (this as any).__vk_ruoyi_url = reqUrl;
    (this as any).__vk_ruoyi_method = method;
    return origOpen.apply(this, arguments as any);
  };
  XMLHttpRequest.prototype.send = function () {
    const self = this as any;
    const config = W.__VK_RUOYI_HOOK__;
    const reqUrl: string = self.__vk_ruoyi_url;
    const xhrIsUserInfo = reqUrl ? /(?:getUserInfo|getInfo)\b/i.test(reqUrl) : false;
    const xhrIsRouter = !xhrIsUserInfo && reqUrl ? _quickSkipRe.test(reqUrl) : false;

    // 始终捕获 router 响应（被动）
    if (xhrIsRouter) {
      const origOnReadyStateChange = self.onreadystatechange;
      self.onreadystatechange = function () {
        if (self.readyState === 4) {
          if (self.status !== 200) {
            logRequest('router-error', self.__vk_ruoyi_url, self.status, self.__vk_ruoyi_method);
            if (typeof origOnReadyStateChange === 'function') origOnReadyStateChange.call(self);
            return;
          }
          const original = self.responseText;
          logRequest('router', self.__vk_ruoyi_url, self.status, self.__vk_ruoyi_method);
          if (config) config.capturedRouters = original;

          // 增强仅在 enabled 时
          if (
            config &&
            config.enabled &&
            config.augmentMode !== 'off' &&
            config.extraRoutes.length > 0
          ) {
            const result = mergeExtraRoutes(original);
            if (typeof result === 'object' && result.body) {
              Object.defineProperty(self, 'responseText', {
                value: result.body,
                writable: true,
                configurable: true,
              });
              try {
                const parsed = JSON.parse(result.body);
                Object.defineProperty(self, 'response', {
                  value: parsed,
                  writable: true,
                  configurable: true,
                });
              } catch {
                Object.defineProperty(self, 'response', {
                  value: result.body,
                  writable: true,
                  configurable: true,
                });
              }
              window.postMessage(
                {
                  __vk_ruoyi_hook: true,
                  event: 'routers_captured',
                  augmented: true,
                  injected: result.injected,
                },
                location.origin,
              );
              if (typeof origOnReadyStateChange === 'function') origOnReadyStateChange.call(self);
              return;
            }
          }
          window.postMessage(
            { __vk_ruoyi_hook: true, event: 'routers_captured', augmented: false },
            location.origin,
          );
        }
        if (typeof origOnReadyStateChange === 'function') origOnReadyStateChange.call(self);
      };
    } else if (
      config &&
      config.enabled &&
      reqUrl &&
      _quickApiSkipRe.test(reqUrl) &&
      !xhrIsRouter &&
      !xhrIsUserInfo
    ) {
      this.addEventListener('load', function () {
        logApiRequest(
          self.__vk_ruoyi_url,
          self.__vk_ruoyi_method,
          self.status,
          self.responseText || '',
        );
      });
    }
    return origSend.apply(this, arguments as any);
  };

  // JS 路由发现辅助
  W.__VK_RUOYI_HOOK__.discoverRoutesFromJs = function () {
    const discovered: any[] = [];
    const seen: Record<string, boolean> = {};
    const routePattern = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
    const compPattern = /component\s*:\s*['"`]((?:views|pages|src)\/[^'"`]+?)['"`]/gi;
    const pathPattern = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+){1,})['"`]/g;
    const skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)|\/login$|\/index$/i;

    function scanText(text: string, source: string) {
      let m: RegExpExecArray | null;
      // 路由定义：path: '/xxx'
      routePattern.lastIndex = 0;
      while ((m = routePattern.exec(text)) !== null) {
        const path = m[1];
        if (skipRe.test(path) || path.length < 4) continue;
        if (!seen[path]) {
          seen[path] = true;
          discovered.push({ path: path, source: source, type: 'route-def' });
        }
      }

      // 组件引用：component: 'views/xxx'
      compPattern.lastIndex = 0;
      while ((m = compPattern.exec(text)) !== null) {
        const comp = m[1];
        if (!seen[comp]) {
          seen[comp] = true;
          discovered.push({ path: '', source: source, type: 'component-ref', component: comp });
        }
      }

      // 通用路径字符串
      pathPattern.lastIndex = 0;
      while ((m = pathPattern.exec(text)) !== null) {
        const p = m[1];
        if (skipRe.test(p) || p.length < 5 || seen[p]) continue;
        seen[p] = true;
        discovered.push({ path: p, source: source, type: 'path-string' });
      }
    }

    document.querySelectorAll('script:not([src])').forEach(function (s, i) {
      const text = s.textContent || '';
      if (text.length > 500000) return;
      scanText(text, `inline#${i + 1}`);
    });

    const extUrls: string[] = [];
    document.querySelectorAll('script[src]').forEach(function (s: any) {
      extUrls.push(s.src);
    });

    return { discovered: discovered, extUrls: extUrls };
  };

  // 通过 localStorage 持久化/恢复 hook 配置（跨刷新存活）
  W.__VK_RUOYI_HOOK__.saveConfig = function (): boolean {
    try {
      localStorage.setItem(
        '__vk_ruoyi_hook_config',
        JSON.stringify({
          origin: location.origin,
          enabled: W.__VK_RUOYI_HOOK__.enabled,
          augmentMode: W.__VK_RUOYI_HOOK__.augmentMode,
          extraRoutes: W.__VK_RUOYI_HOOK__.extraRoutes || [],
          customRouterUrls: W.__VK_RUOYI_HOOK__.customRouterUrls || [],
        }),
      );
      return true;
    } catch {
      return false;
    }
  };

  W.__VK_RUOYI_HOOK__.clearConfig = function (): boolean {
    try {
      localStorage.removeItem('__vk_ruoyi_hook_config');
      return true;
    } catch {
      return false;
    }
  };

  // ====== Vue Router 注入（MaR 式动态路由加载）======

  function findVueRouter(): any {
    let router: any = null;

    // Vue 3: 检查 __vue_app__
    if (W.__vue_app__) {
      try {
        const cfg = W.__vue_app__.config;
        if (cfg && cfg.globalProperties && cfg.globalProperties.$router) {
          return cfg.globalProperties.$router;
        }
      } catch {
        /* ignore */
      }
    }

    // 在 DOM 元素中搜索 Vue 实例
    const selectors = ['#app', '[data-v-app]', '.app-wrapper', '#app-main'];
    for (let si = 0; si < selectors.length && !router; si++) {
      const els = document.querySelectorAll(selectors[si]);
      for (let ei = 0; ei < els.length && !router; ei++) {
        const el = els[ei] as any;
        // Vue 3 app 实例
        if (el.__vue_app__) {
          try {
            router = el.__vue_app__.config.globalProperties.$router;
          } catch {
            /* ignore */
          }
        }
        // Vue 2 实例
        if (!router && el.__vue__) {
          router = el.__vue__.$router || (el.__vue__.$root && el.__vue__.$root.$router);
        }
      }
    }

    // 深度扫描所有元素上的 Vue 2 实例
    if (!router) {
      const allEls = document.querySelectorAll('*');
      for (let ai = 0; ai < allEls.length && !router; ai++) {
        const ael = allEls[ai] as any;
        if (ael.__vue__ && ael.__vue__.$router) {
          router = ael.__vue__.$router;
        } else if (ael.__vue__ && ael.__vue__.$root && ael.__vue__.$root.$router) {
          router = ael.__vue__.$root.$router;
        }
      }
    }

    return router;
  }

  W.__VK_RUOYI_HOOK__.findVueRouter = findVueRouter;

  W.__VK_RUOYI_HOOK__.getRouterInfo = function () {
    const router = findVueRouter();
    if (!router) return { found: false, routes: [] as string[], currentRoutes: [] as string[] };
    const currentRoutes: string[] = [];
    try {
      const rawRoutes = router.getRoutes
        ? router.getRoutes()
        : (router.options && router.options.routes) || [];
      rawRoutes.forEach(function (r: any) {
        if (r.path) currentRoutes.push(r.path);
      });
    } catch {
      /* ignore */
    }
    return {
      found: true,
      mode: router.mode || (router.options && router.options.history ? 'history' : 'hash'),
      routeCount: currentRoutes.length,
      currentRoutes: currentRoutes,
    };
  };

  W.__VK_RUOYI_HOOK__.injectRoutesToVueRouter = function (routes: any[]) {
    const result: any = {
      injected: 0,
      skipped: 0,
      errors: [] as string[],
      routerFound: false,
      routerMode: '',
    };
    const router = findVueRouter();

    if (!router) {
      result.errors.push('Vue Router 实例未找到');
      return result;
    }

    result.routerFound = true;
    result.routerMode = router.mode || 'unknown';

    // 尝试找到 RuoYi 的 loadView 函数用于组件解析
    let loadView: any = null;
    try {
      if (typeof W.loadView === 'function') loadView = W.loadView;
      if (!loadView && typeof W.loadComponent === 'function') loadView = W.loadComponent;
    } catch {
      /* ignore */
    }

    // 获取当前路由路径用于去重
    const existingPaths: Record<string, boolean> = {};
    try {
      const currentRoutes = router.getRoutes ? router.getRoutes() : [];
      currentRoutes.forEach(function (r: any) {
        if (r.path) existingPaths[r.path] = true;
      });
    } catch {
      /* ignore */
    }

    routes.forEach(function (route: any) {
      try {
        const path = route.path;
        if (!path) {
          result.skipped++;
          return;
        }
        if (existingPaths[path]) {
          result.skipped++;
          return;
        }

        // 构建带组件解析的合法路由对象
        const routeObj: any = {
          path: path,
          name: route.name || path.replace(/^\/+/, '').replace(/\//g, '-'),
          meta: route.meta || {},
        };

        // 将组件字符串解析为实际组件
        if (route.component && typeof route.component === 'string') {
          if (loadView) {
            try {
              routeObj.component = loadView(route.component);
            } catch {
              routeObj.component = { template: `<div>Loading: ${path}</div>` };
            }
          } else {
            // 无 loadView — 尝试 webpack 动态 import 模式
            try {
              let viewPath = route.component;
              if (!/^views\//i.test(viewPath) && !/^\//i.test(viewPath)) {
                viewPath = `views/${viewPath}`;
              }
              routeObj.component = function () {
                return import(
                  /* webpackChunkName: "mar-[request]" */ '@/'.concat(viewPath, '.vue')
                );
              };
            } catch {
              routeObj.component = { template: `<div>Loading: ${path}</div>` };
            }
          }
        } else if (route.component) {
          routeObj.component = route.component;
        } else {
          routeObj.component = { template: `<div>Route: ${path}</div>` };
        }

        if (typeof router.addRoute === 'function') {
          router.addRoute(routeObj);
        } else if (typeof router.addRoutes === 'function') {
          router.addRoutes([routeObj]);
        } else {
          result.errors.push('No addRoute/addRoutes method');
          return;
        }
        result.injected++;
        existingPaths[path] = true;
      } catch (e: any) {
        result.errors.push(`${route.path || '?'}: ${e.message}`);
      }
    });

    return result;
  };

  // hook 从存储自动恢复时通知 popup
  if (configEnabled) {
    setTimeout(function () {
      window.postMessage(
        {
          __vk_ruoyi_hook: true,
          event: 'hook_restored',
          augmented: false,
          injected: 0,
        },
        location.origin,
      );
    }, 500);
  }
})();
