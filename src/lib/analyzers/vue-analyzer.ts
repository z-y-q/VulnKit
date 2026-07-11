/**
 * Vue 分析引擎 — 灵眸 v6.0
 * 从 vk-vue-detect.js / vk-vue-store.js 提取的纯分析逻辑
 * 路由统计、路径展平、Store 树展平均为纯函数，可独立测试
 */

// ===== Detect 结果类型（与 inject/vue-detect.ts 返回值对齐）=====

export interface VueDetectResult {
  detected: boolean;
  version: string;
  router: boolean;
  store: boolean;
  routes: VueRouteNode[];
  guards: Record<string, number>;
  pageOrigin: string;
  routerInfo?: { base: string; mode: string };
}

export interface VueRouteNode {
  path: string;
  name: string;
  meta: Record<string, any>;
  children: VueRouteNode[];
  hasAuth: boolean;
  sensitive: boolean;
  hasBeforeEnter: boolean;
  childCount: number;
  componentKeys: string[];
}

// ===== Store 探索结果类型（与 inject/vue-store-explorer.ts 返回值对齐）=====

export interface VuexStoreData {
  state: any;
  getters?: string[];
  mutations?: string[];
  actions?: string[];
  type: string;
  error?: string;
}

export interface PiniaStoreData {
  state: any;
  type: 'pinia';
}

export interface StoreExploreResult {
  store: {
    stores: Record<string, VuexStoreData | PiniaStoreData>;
    frameworks: string[];
    errors: string[];
  };
  actions: {
    apiEndpoints: string[];
    actionNames: string[];
    getterNames: string[];
    error?: string;
  };
  directives: StoreDirective[];
}

export interface StoreDirective {
  name: string;
  count: number;
  examples: string[];
}

// ===== Store 树展平行（用于表格渲染）=====

export interface StoreTreeRow {
  path: string;
  key: string;
  type: string;
  valuePreview: string;
  sensitive: boolean;
  depth: number;
}

/** 判断 key/value 是否可能包含敏感数据 */
const SENSITIVE_KEYS = /^(token|secret|key|password|credential|auth|session|cookie|private)/i;
const SENSITIVE_VALUE_PATTERNS = [
  /^Bearer\s+/i,
  /^ey[A-Za-z0-9_-]+\./,     // JWT
  /[a-f0-9]{32,}/,           // hex hash
  /-----BEGIN.*KEY-----/,     // PEM
];

export function isSensitiveEntry(key: string, value: any): boolean {
  if (SENSITIVE_KEYS.test(key)) return true;
  if (typeof value !== 'string') return false;
  for (const p of SENSITIVE_VALUE_PATTERNS) {
    if (p.test(value)) return true;
  }
  return false;
}

/** 截断值用于预览展示 */
export function previewValue(value: any, maxLen = 80): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'function') return '[Function]';
  if (typeof value === 'object') {
    try {
      const s = JSON.stringify(value);
      return s.length > maxLen ? s.substring(0, maxLen) + '...' : s;
    } catch {
      return '[Object]';
    }
  }
  const s = String(value);
  return s.length > maxLen ? s.substring(0, maxLen) + '...' : s;
}

/** 递归展平 store state 对象为行列表 */
export function flattenStoreTree(
  obj: any,
  prefix = '',
  depth = 0,
  maxDepth = 8,
): StoreTreeRow[] {
  if (!obj || typeof obj !== 'object' || depth > maxDepth) return [];

  const rows: StoreTreeRow[] = [];
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    const fullPath = prefix ? `${prefix}.${key}` : key;
    const type = Array.isArray(val) ? 'array' : typeof val;

    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      // 递归对象 — 添加一行标题，然后递归
      rows.push({
        path: fullPath,
        key,
        type: 'object',
        valuePreview: `{${Object.keys(val).length} keys}`,
        sensitive: isSensitiveEntry(key, val),
        depth,
      });
      rows.push(...flattenStoreTree(val, fullPath, depth + 1, maxDepth));
    } else {
      rows.push({
        path: fullPath,
        key,
        type,
        valuePreview: previewValue(val),
        sensitive: isSensitiveEntry(key, val),
        depth,
      });
    }
  }
  return rows;
}

// ===== 路由统计 =====

export interface RouteStats {
  total: number;
  authCount: number;
  sensitiveCount: number;
  beforeEnterCount: number;
}

/** 递归统计路由树 */
export function countRouteStats(routes: VueRouteNode[]): RouteStats {
  const stats: RouteStats = { total: 0, authCount: 0, sensitiveCount: 0, beforeEnterCount: 0 };

  function walk(arr: VueRouteNode[]) {
    if (!arr) return;
    for (const r of arr) {
      stats.total++;
      if (r.hasAuth) stats.authCount++;
      if (r.sensitive) stats.sensitiveCount++;
      if (r.hasBeforeEnter) stats.beforeEnterCount++;
      if (r.children && r.children.length > 0) walk(r.children);
    }
  }

  walk(routes);
  return stats;
}

// ===== 路由路径展平（用于导出/复制）=====

export interface FlatRoute {
  path: string;
  url: string;
  name: string;
  isParam: boolean;
  isProbe?: boolean;
}

/** 将嵌套路由树展平为路径列表（含参数替换后的探测路径） */
export function flattenRoutePaths(
  routes: VueRouteNode[],
  pageOrigin: string,
  base: string,
  mode: string,
  prefix = '',
): FlatRoute[] {
  const result: FlatRoute[] = [];
  if (!routes || !Array.isArray(routes)) return result;

  for (const r of routes) {
    let p = r.path || '/';
    if (p.charAt(0) !== '/' && prefix && prefix !== '/') {
      p = `${prefix}/${p}`;
    }

    result.push({
      path: p,
      url: buildRouteUrl(p, pageOrigin, base, mode),
      name: r.name || '',
      isParam: p.indexOf(':') !== -1 || p.indexOf('*') !== -1,
    });

    // 为参数路由生成探测路径
    if (p.indexOf(':') !== -1 || p.indexOf('*') !== -1) {
      const probePath = p.replace(/:[^/]+/g, '1').replace(/\*/g, 'test');
      result.push({
        path: probePath,
        url: buildRouteUrl(probePath, pageOrigin, base, mode),
        name: `${r.name || ''}:probe`,
        isParam: false,
        isProbe: true,
      });
    }

    if (r.children && r.children.length > 0) {
      result.push(...flattenRoutePaths(r.children, pageOrigin, base, mode, p === '/' ? '/' : p));
    }
  }

  return result;
}

/** 构建完整路由 URL */
function buildRouteUrl(path: string, origin: string, base: string, mode: string): string {
  const pageOrigin = origin || 'https://example.com';
  let basePath = base || '/';
  if (basePath.charAt(basePath.length - 1) !== '/') basePath += '/';
  const fullPath = basePath + (path || '/').replace(/^\//, '');

  if (mode === 'hash') {
    return `${pageOrigin}${basePath}#${path || '/'}`;
  }
  return `${pageOrigin}${fullPath}`;
}

/** 权限暴露评分 (0-100) — 基于路由统计数据 */
export function scorePermissionExposure(stats: RouteStats): number {
  if (stats.total === 0) return 0;
  let score = 0;
  // 有路由但无任何认证标记
  if (stats.authCount === 0 && stats.total > 3) score += 30;
  // 敏感路径比例
  score += Math.min(30, Math.round((stats.sensitiveCount / stats.total) * 30));
  // beforeEnter 比例（越多说明有一定保护）
  score -= Math.min(15, Math.round((stats.beforeEnterCount / stats.total) * 15));
  return Math.max(0, Math.min(100, score));
}
