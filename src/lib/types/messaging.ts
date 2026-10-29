// 类型安全的消息协议
// 所有 background ↔ content ↔ UI 之间的消息在此统一声明为 discriminated union。

// ====== Background 消息（UI/content → background）======
export type BackgroundMessage =
  // —— 抓取代理（绕过 CORS）——
  // maxBytes 由 background 强制夹紧到安全上限，调用方不可突破硬顶。
  | { type: 'FETCH_URL'; url: string; tailOnly?: boolean | number; timeout?: number; maxBytes?: number }
  | { type: 'FETCH_URL_AUTH'; url: string; provider: 'zoomeye'; key: string }
  // —— 探测类（保留响应头/状态/耗时）——
  | { type: 'FETCH_PROBE'; url: string; method?: string; headers?: Record<string, string>; body?: string; timeout?: number; followRedirect?: boolean; includeBody?: boolean }
  | { type: 'FETCH_CORS_PROBE'; url: string; method?: string; headers?: Record<string, string>; body?: string; credentials?: RequestCredentials; timeout?: number }
  | { type: 'FETCH_HEADER_PROBE'; url: string; timeout?: number }
  | { type: 'FETCH_DNS_RESOLVE'; hostname: string; recordType?: string }
  | { type: 'FETCH_WAF_PROBE'; url: string; method?: string; headers?: Record<string, string>; timeout?: number }
  | { type: 'FETCH_IMAGE'; url: string }
  // —— JS 阻断（declarativeNetRequest）——
  | { type: 'QUERY_JS_BLOCK' }
  | { type: 'TOGGLE_JS'; enable: boolean }
  // —— 请求伪造 ——
  | { type: 'SPOOF_UA'; tabId?: number | null; url: string; userAgent: string }
  | { type: 'RESET_SPOOF_UA' }
  | { type: 'SPOOF_HEADERS'; tabId?: number | null; url: string; headers: SpoofHeaders }
  | { type: 'RESET_SPOOF_HEADERS' }
  // —— 若依路由 Hook ——
  | { type: 'REGISTER_RUOYI_HOOK'; origin: string }
  | { type: 'UNREGISTER_RUOYI_HOOK' }
  | { type: 'VK_RUOYI_HOOK_EVENT'; event: string; augmented?: unknown; injected?: unknown };

// 伪造请求头
export interface SpoofHeaders {
  xff?: string;
  referer?: string;
  clientIp?: string;
  custom?: { name: string; value: string }[];
}

// ====== Content Script 消息（UI → content）======
export type ContentMessage =
  | { type: 'VK_VUE_DETECT' }
  | { type: 'VK_REACT_DETECT' }
  | { type: 'VK_ANGULAR_DETECT' }
  | { type: 'VK_SOURCEMAP_DETECT' }
  | { type: 'VK_SVELTE_DETECT' }
  | { type: 'VK_VUE_STORE_EXPLORE' }
  | { type: 'VK_REACT_STORE_EXPLORE' }
  | { type: 'VK_ANGULAR_STORE_EXPLORE' }
  | { type: 'VK_PAGE_INSPECT'; action: string; timeout?: number }
  | { type: 'VK_VUE_ATTACK'; action: 'bypass' | 'disableAuth' | 'navigate' | 'jump' | 'restore'; target?: string; timeout?: number }
  | { type: 'VK_REACT_ATTACK'; action: 'routes' | 'navigate' | 'jump' | 'restore'; target?: string; timeout?: number }
  | { type: 'CONTEXT_EXTRACT_LINKS' }
  | { type: 'VK_FINGERPRINT_DOM' };

// ====== 通用响应 ======
export interface FetchOk<T = string> {
  success: true;
  data: T;
}
export interface FetchErr {
  success: false;
  error: string;
  /** 结构化错误码，便于 UI 区分处理（超限、HTTP、超时、中止） */
  code?: FetchErrorCode;
}

export type FetchErrorCode = 'HTTP_ERROR' | 'TOO_LARGE' | 'TIMEOUT' | 'ABORTED' | 'NETWORK';
export type FetchResult<T = string> = FetchOk<T> | FetchErr;

export interface ProbeResult {
  status: number;
  statusText?: string;
  headers?: Record<string, string>;
  redirected?: boolean;
  url?: string;
  time?: number;
  body?: string;
  type?: ResponseType;
  error?: string;
}

export interface DnsResolveResult {
  addresses?: string[];
  answers?: { type: number; data: string; name: string }[];
  resultCode?: number;
  error?: string;
}

export interface DomFingerprint {
  metaTags: { name: string; content: string }[];
  bodyHtml: string;
  scriptSrcs: string[];
  styleHrefs: string[];
}

export interface ExtractedLink {
  href: string;
  text: string;
  tag: string;
  domain: string;
}

// ====== 注入脚本返回的框架检测结果（inject → content → UI）======
export interface VueDetectResult {
  detected: boolean;
  version: string;
  router: boolean;
  store: boolean;
  routes: unknown[];
  guards: Record<string, number>;
  pageOrigin: string;
  routerInfo?: { base: string; mode: string };
}

export interface RuoYiHookEvent {
  event: string;
  augmented?: unknown;
  injected?: unknown;
}

// ====== React 攻击层响应（inject/react-attack.ts → UI）======
export interface ReactAttackRoute {
  path: string;
  component: string;
  source: string;
  authKeys: string[];
}
export interface ReactMicroApp {
  path: string;
  microApp: string;
}
export interface ReactAttackResponse {
  success: boolean;
  error?: string;
  /** navigate/jump 生效路径 */
  path?: string;
  /** 实际使用的导航器（data-router.navigate / umi.g_history / location.hash 等） */
  via?: string;
  /** routes：fiber 提取的路由行 */
  routes?: ReactAttackRoute[];
  /** routes：bundle 字面量兜底路径 */
  bundlePaths?: string[];
  /** routes：页面锚点（含 hash 路由链接）提取的路径 */
  anchorPaths?: string[];
  /** routes：qiankun 微应用清单 */
  microApps?: ReactMicroApp[];
  /** routes：umi 运行时信息 */
  umi?: { version: string; historyMode: string; hasGlobalHistory: boolean };
  /** routes：可用导航器列表 */
  navigators?: string[];
  /** routes：遍历的 fiber 节点数 */
  fiberCount?: number;
  /** jump：拦截到的登录重定向反弹次数 */
  bounces?: number;
  patched?: number;
  watching?: boolean;
}
