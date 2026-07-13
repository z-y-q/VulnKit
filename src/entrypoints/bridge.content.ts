// 灵眸 v6.0 — Content Script Bridge
// 注入到页面 ISOLATED world，负责：
// 1. 把 background/panel 的探测请求转发为 MAIN world 脚本注入，并回传结果
// 2. RuoYi hook 事件转发
// 3. 同步操作：链接提取、DOM 指纹
//
// inject 脚本在 wxt.config 中声明为独立 rollup 输入，输出为 inject/*.js 稳定路径，
// 通过 web_accessible_resources 对页面可访问，运行时用 getURL 解析。

// inject 脚本的 web-accessible 公共路径
const vueDetectUrl = 'inject/vue-detect.js';
const reactDetectUrl = 'inject/react-detect.js';
const angularDetectUrl = 'inject/angular-detect.js';
const svelteDetectUrl = 'inject/svelte-detect.js';
const sourcemapDetectUrl = 'inject/sourcemap-detect.js';
const vueStoreUrl = 'inject/vue-store-explorer.js';
const reactStoreUrl = 'inject/react-store-explorer.js';
const angularStoreUrl = 'inject/angular-store-explorer.js';
const pageInspectUrl = 'inject/page-inspect.js';
const vueAttackUrl = 'inject/vue-attack.js';

export default defineContentScript({
  matches: ['<all_urls>'],
  runAt: 'document_start',
  main() {
    if ((window as any).__VK_CONTENT_BRIDGE__) return;
    (window as any).__VK_CONTENT_BRIDGE__ = true;

    const GEN_TOKEN = (): string =>
      Math.random().toString(36).slice(2) + Date.now().toString(36);

    // token → pending：每次注入独立条目，支持同 dataKey 并发调用互不覆盖。
    interface Pending {
      dataKey: string;
      timer: ReturnType<typeof setTimeout>;
      resolve: (result: unknown) => void;
    }
    const pending = new Map<string, Pending>();

    let vueDetecting = false;

    /** 清理某 token 的待办（成功回执、超时、加载失败共用）。 */
    function settle(token: string, withResult: (p: Pending) => void) {
      const p = pending.get(token);
      if (!p) return;
      pending.delete(token);
      clearTimeout(p.timer);
      if (p.dataKey === '__vk_detect') vueDetecting = false;
      withResult(p);
    }

    window.addEventListener('message', (e: MessageEvent) => {
      // 必须来自当前窗口且同源：防止其它 frame/页面伪造回执
      if (e.source !== window) return;
      if (e.origin !== location.origin) return;
      const data = e.data as any;
      if (!data || typeof data !== 'object') return;

      // RuoYi hook 事件转发（无需 token 匹配）
      if (data.__vk_ruoyi_hook && data.event) {
        browser.runtime
          .sendMessage({
            type: 'VK_RUOYI_HOOK_EVENT',
            event: data.event,
            augmented: data.augmented,
            injected: data.injected,
          })
          .catch(() => {});
        return;
      }

      // token 必须是字符串且存在于 pending；再用 dataKey 二次校验防碰撞
      const token = data.__vk_token;
      if (typeof token !== 'string') return;
      const p = pending.get(token);
      if (!p) return;
      if (!data[p.dataKey]) return;

      // 成功回执：resolve 后立即移除，避免重复结算
      settle(token, (entry) => entry.resolve(data.result));
    });

    // ====== 通用脚本注入（统一 detect / store / inspect / attack） ======
    function injectTracked(opts: {
      url: string;
      dataKey: string;
      timeout: number;
      /** 超时返回值（detect/store/inspect 为 null，attack 为错误对象） */
      fallback?: unknown;
      /** 脚本加载失败返回值（默认同 fallback） */
      loadError?: unknown;
      /** 额外 dataset 写入（如 vkAction / vkTarget） */
      setup?: (script: HTMLScriptElement) => void;
    }): Promise<unknown> {
      const { url, dataKey, timeout, fallback = null, loadError = fallback, setup } = opts;
      // Vue detect 全局单飞：并发探测只跑一次
      if (dataKey === '__vk_detect' && vueDetecting) return Promise.resolve(null);
      if (dataKey === '__vk_detect') vueDetecting = true;

      return new Promise((resolve) => {
        const token = GEN_TOKEN();
        const timer = setTimeout(() => settle(token, () => resolve(fallback)), timeout);
        pending.set(token, {
          dataKey,
          timer,
          resolve: (result: unknown) => resolve(result),
        });

        const script = document.createElement('script');
        script.src = browser.runtime.getURL(url as any);
        script.dataset.vkToken = token;
        setup?.(script);
        script.onload = () => script.remove();
        script.onerror = () => {
          script.remove();
          settle(token, () => resolve(loadError));
        };
        (document.head || document.documentElement).appendChild(script);
      });
    }

    // ====== 注入消息 → { url, dataKey, timeout } ======
    const INJECT_HANDLERS: Record<string, { url: string; dataKey: string; timeout: number }> = {
      VK_VUE_DETECT: { url: vueDetectUrl, dataKey: '__vk_detect', timeout: 3000 },
      VK_REACT_DETECT: { url: reactDetectUrl, dataKey: '__vk_react_detect', timeout: 3000 },
      VK_ANGULAR_DETECT: { url: angularDetectUrl, dataKey: '__vk_angular_detect', timeout: 3000 },
      VK_SOURCEMAP_DETECT: { url: sourcemapDetectUrl, dataKey: '__vk_sourcemap_detect', timeout: 3000 },
      VK_SVELTE_DETECT: { url: svelteDetectUrl, dataKey: '__vk_svelte_detect', timeout: 3000 },
      VK_VUE_STORE_EXPLORE: { url: vueStoreUrl, dataKey: '__vk_vue_store', timeout: 5000 },
      VK_REACT_STORE_EXPLORE: { url: reactStoreUrl, dataKey: '__vk_react_store', timeout: 5000 },
      VK_ANGULAR_STORE_EXPLORE: { url: angularStoreUrl, dataKey: '__vk_angular_store', timeout: 5000 },
    };

    // ====== page-inspect（带额外 action dataset） ======
    function injectPageInspect(action: string, timeout: number): Promise<unknown> {
      return injectTracked({
        url: pageInspectUrl,
        dataKey: '__vk_page_inspect',
        timeout,
        setup: (s) => { s.dataset.vkAction = action; },
      });
    }

    // ====== Vue 攻击层（bypass/navigate/restore，带 action+target dataset） ======
    function injectVueAttack(action: string, target: string, timeout: number): Promise<unknown> {
      return injectTracked({
        url: vueAttackUrl,
        dataKey: '__vk_vue_attack',
        timeout,
        fallback: { success: false, error: '注入超时（页面可能无 Vue Router）' },
        loadError: { success: false, error: '脚本加载失败' },
        setup: (s) => {
          s.dataset.vkAction = action;
          s.dataset.vkTarget = target || '';
        },
      });
    }

    // ====== 同步：链接提取 ======
    function extractLinks(): { count: number } {
      const pageUrl = location.href;
      const links: { href: string; text: string; tag: string; domain: string }[] = [];
      const seen: Record<string, boolean> = {};

      const addLink = (href: string, text: string, tag: string) => {
        if (!href || href === '#' || href.startsWith('javascript:') || seen[href]) return;
        seen[href] = true;
        let domain = '';
        try {
          domain = new URL(href, pageUrl).hostname;
        } catch {
          /* ignore */
        }
        links.push({ href, text, tag, domain });
      };

      document.querySelectorAll<HTMLAnchorElement>('a[href]').forEach((el) => {
        addLink(
          el.href,
          (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
          'a',
        );
      });
      document.querySelectorAll<HTMLScriptElement>('script[src]').forEach((el) => addLink(el.src, '', 'script'));
      document.querySelectorAll<HTMLLinkElement>('link[href]').forEach((el) => addLink(el.href, el.rel || '', 'link'));
      document.querySelectorAll<HTMLFrameElement>('iframe[src],frame[src]').forEach((el) => addLink(el.src, '', 'iframe'));

      browser.storage.local.set({ contextExtractedLinks: links, contextExtractedUrl: pageUrl });
      return { count: links.length };
    }

    // ====== 同步：DOM 指纹 ======
    function fingerprintDom() {
      const metaTags: { name: string; content: string }[] = [];
      document.querySelectorAll('meta').forEach((m) => {
        const name =
          m.getAttribute('name') ||
          m.getAttribute('http-equiv') ||
          m.getAttribute('property') ||
          '';
        const content = m.getAttribute('content') || '';
        if (name) metaTags.push({ name, content });
      });
      let bodyHtml = '';
      try {
        bodyHtml = (document.body ? document.body.innerHTML : '').substring(0, 200000);
      } catch {
        /* ignore */
      }
      const scriptSrcs: string[] = [];
      document.querySelectorAll<HTMLScriptElement>('script[src]').forEach((s) => {
        if (s.src) scriptSrcs.push(s.src);
      });
      const styleHrefs: string[] = [];
      document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]').forEach((l) => {
        if (l.href) styleHrefs.push(l.href);
      });
      return { metaTags, bodyHtml, scriptSrcs, styleHrefs };
    }

    // ====== 消息监听 ======
    browser.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (!message || !message.type) return false;
      const type: string = message.type;

      const handler = INJECT_HANDLERS[type];
      if (handler) {
        injectTracked({ url: handler.url, dataKey: handler.dataKey, timeout: handler.timeout }).then(sendResponse);
        return true;
      }

      if (type === 'VK_PAGE_INSPECT') {
        const action = message.action || '';
        if (!action) {
          sendResponse({ error: 'Missing action' });
          return true;
        }
        injectPageInspect(action, message.timeout || 5000).then(sendResponse);
        return true;
      }

      if (type === 'VK_VUE_ATTACK') {
        injectVueAttack(message.action || 'bypass', message.target || '', message.timeout || 4000).then(sendResponse);
        return true;
      }

      if (type === 'CONTEXT_EXTRACT_LINKS') {
        sendResponse(extractLinks());
        return true;
      }

      if (type === 'VK_FINGERPRINT_DOM') {
        sendResponse(fingerprintDom());
        return true;
      }

      return false;
    });
  },
});
