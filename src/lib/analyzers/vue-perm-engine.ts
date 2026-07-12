/**
 * Vue 权限拦截引擎 — 灵眸 v6.0
 * 从 vk-vue-perm.js 提取的纯逻辑：响应分类、权限类型判定、数据变换。
 * MAIN world 注入与 Store 读写由 VuePanel 通过 execInTab 完成。
 */

/** 捕获的权限相关响应/数据 */
export interface PermCapture {
  url: string;
  /** menu / role / permission */
  type: string;
  subtype: string | null;
  /** 解析后的数据（已 sanitize） */
  data: unknown;
  rawText: string;
  size: number;
  timestamp: number;
  /** fetch / xhr / store-read / *-override */
  method: string;
}

/** 权限类型分类结果 */
export type PermType =
  | 'special-zero' // 角色控制字段值为 0，可提权
  | 'role-active' // 角色字段已激活
  | 'menuid-limit' // menuIds 数组受限
  | 'full-open' // 全部菜单已返回
  | 'semi-open' // 部分菜单返回
  | 'zero-open' // 菜单返回为空，需搜 JS
  | 'unknown';

export interface PermClassification {
  type: PermType;
  label: string;
  /** UI 颜色类 */
  cssClass: string;
}

const ROLE_CONTROL_RE =
  /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i;
const MENU_ID_LIST_RE = /^menuIds$|^menu_ids$|^menuIdList$|^permissionIds$|^permIds$/i;
/** 角色值正则（type 字段匹配时用） */
export const ROLE_VALS_RE = /^(admin|root|super|vip|user|normal|guest|管理员|超级|普通|访客|[0-9]{1,2})$/i;

/** v5 MENU_KEYWORDS — 用于识别菜单数据 */
export const MENU_KEYWORDS = [
  'menu', 'menus', 'menuList', 'menu_list', 'menuTree', 'menu_tree',
  'routes', 'routers', 'routerList', 'router_list',
  'children', 'child', 'subList', 'sub_list',
  'sidebar', 'nav', 'navigation',
  'permission', 'permissions', 'permissionList',
];

/**
 * 判定捕获数据的权限类型（v5 classifyPermType）。
 */
export function classifyPermType(data: unknown): PermClassification {
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    const keys = Object.keys(data as object);
    for (const key of keys) {
      if (ROLE_CONTROL_RE.test(key)) {
        const val = (data as any)[key];
        if (val === 0 || val === false || val === '0' || val === '' || val === null) {
          return {
            type: 'special-zero',
            label: `特殊0开放 — ${key}=${val}，可改为 1/true/admin`,
            cssClass: 'text-red-600 dark:text-red-400',
          };
        }
        return {
          type: 'role-active',
          label: `角色控制字段已激活 — ${key}=${String(val)}`,
          cssClass: 'text-blue-600 dark:text-blue-400',
        };
      }
      if (/^type$/i.test(key)) {
        const tval = (data as any)[key];
        if (
          (typeof tval === 'string' && ROLE_VALS_RE.test(tval)) ||
          (typeof tval === 'number' && tval >= 0 && tval <= 10)
        ) {
          if (tval === 0 || /^(user|normal|guest)$/i.test(String(tval))) {
            return {
              type: 'special-zero',
              label: `特殊0开放 — type=${tval}，可改为 admin/1`,
              cssClass: 'text-red-600 dark:text-red-400',
            };
          }
          return {
            type: 'special-zero',
            label: `角色控制字段 — type=${tval}，可尝试改为 admin`,
            cssClass: 'text-amber-600 dark:text-amber-400',
          };
        }
      }
      if (MENU_ID_LIST_RE.test(key)) {
        const arr = (data as any)[key];
        if (Array.isArray(arr) && arr.length > 0 && arr.every((v: unknown) => typeof v === 'number')) {
          return {
            type: 'menuid-limit',
            label: `菜单ID限制 — ${key}: [${arr.join(',')}]，可展开范围`,
            cssClass: 'text-blue-600 dark:text-blue-400',
          };
        }
      }
    }
  }
  if (Array.isArray(data) && data.length > 0) {
    const allHaveShowField = data.every((item: any) =>
      item && typeof item === 'object' &&
      ('isshow' in item || 'isShow' in item || 'hidden' in item || 'display' in item || 'status' in item),
    );
    if (allHaveShowField) {
      const hasHidden = data.some((item: any) =>
        item.isshow === '0' || item.isShow === '0' || item.hidden === true ||
        item.display === false || item.status === 0,
      );
      return {
        type: 'full-open',
        label: hasHidden ? '全开放 — 所有菜单已返回，部分标记隐藏' : '全开放 — 所有菜单已返回且显示',
        cssClass: 'text-green-600 dark:text-green-400',
      };
    }
    return {
      type: 'semi-open',
      label: '半开放 — 返回了部分菜单列表',
      cssClass: 'text-blue-600 dark:text-blue-400',
    };
  }
  if (Array.isArray(data) && data.length === 0) {
    return {
      type: 'zero-open',
      label: '0开放 — 菜单返回为空，需搜索 JS 源码',
      cssClass: 'text-red-600 dark:text-red-400',
    };
  }
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    const d = data as any;
    const inner = d.data || d.result || d.Data;
    if (Array.isArray(inner) && inner.length === 0) {
      return {
        type: 'zero-open',
        label: '0开放 — 菜单返回为空，需搜索 JS 源码',
        cssClass: 'text-red-600 dark:text-red-400',
      };
    }
  }
  return {
    type: 'unknown',
    label: '未知类型 — 请手动检查数据结构',
    cssClass: 'text-gray-500',
  };
}

/**
 * 变换：将所有 isshow/display 改为显示（v5 transformShowAll）。
 * 递归处理 children/child/subList。
 */
export function transformShowAll(data: unknown): unknown {
  if (Array.isArray(data)) {
    return data.map((item) => {
      if (item && typeof item === 'object') {
        const c: any = { ...(item as any) };
        if ('isshow' in c) c.isshow = '1';
        if ('isShow' in c) c.isShow = '1';
        if ('hidden' in c) c.hidden = false;
        if ('display' in c) c.display = true;
        if ('status' in c) c.status = 1;
        if ('visible' in c) c.visible = true;
        if (c.children) c.children = transformShowAll(c.children);
        if (c.child) c.child = transformShowAll(c.child);
        if (c.subList) c.subList = transformShowAll(c.subList);
        return c;
      }
      return item;
    });
  }
  if (data && typeof data === 'object') {
    const c: any = {};
    for (const k in data as object) c[k] = transformShowAll((data as any)[k]);
    return c;
  }
  return data;
}

/**
 * 变换：提权至管理员（v5 transformAdmin）。
 * isadmin/admin/role/userType 等设为 1/'1'，roleId 设为 1，type 匹配角色值时改为 admin/1。
 */
export function transformAdmin(data: unknown): unknown {
  if (typeof data !== 'object' || data === null) return data;
  if (Array.isArray(data)) return data.map(transformAdmin);
  const c: any = {};
  for (const k in data as object) {
    if (ROLE_CONTROL_RE.test(k)) {
      c[k] = typeof (data as any)[k] === 'string' ? '1' : 1;
    } else if (k === 'roleId' || k === 'role_id') {
      c[k] = 1;
    } else if (/^type$/i.test(k)) {
      const tv = (data as any)[k];
      if (
        (typeof tv === 'string' && ROLE_VALS_RE.test(tv)) ||
        (typeof tv === 'number' && tv >= 0 && tv <= 10)
      ) {
        c[k] = typeof tv === 'string' ? 'admin' : 1;
      } else {
        c[k] = tv;
      }
    } else if (typeof (data as any)[k] === 'object') {
      c[k] = transformAdmin((data as any)[k]);
    } else {
      c[k] = (data as any)[k];
    }
  }
  return c;
}

/**
 * 变换：展开 menuIds/permissionIds 数组为 1..max(现有最大,50)（v5 expandMenuIds）。
 */
export function expandMenuIds(data: unknown): unknown {
  if (typeof data !== 'object' || data === null) return data;
  if (Array.isArray(data)) return data.map(expandMenuIds);
  const c: any = {};
  for (const k in data as object) {
    if (/menuIds|menu_ids|menuIdList|permissionIds|permIds/i.test(k) && Array.isArray((data as any)[k])) {
      const arr = (data as any)[k] as unknown[];
      if (arr.length > 0 && arr.every((v) => typeof v === 'number')) {
        const max = Math.max(...(arr as number[]));
        const end = Math.max(max, 50);
        const expanded: number[] = [];
        for (let i = 1; i <= end; i++) expanded.push(i);
        c[k] = expanded;
        if ('total' in (data as any)) c.total = expanded.length;
        else if ('Total' in (data as any)) c.Total = expanded.length;
        continue;
      }
    }
    if (typeof (data as any)[k] === 'object') {
      c[k] = expandMenuIds((data as any)[k]);
    } else {
      c[k] = (data as any)[k];
    }
  }
  return c;
}

// ====== 路由对比（vue-compare 纯逻辑）======

export interface RoutePath { path: string; name?: string }

const PATH_KEYS = ['path', 'url', 'href', 'menuUrl', 'menuPath', 'link', 'index'];

/** 从菜单数据递归提取所有 path/url/href 路径 */
export function extractMenuPaths(data: unknown, paths: Set<string>): void {
  if (typeof data !== 'object' || data === null) return;
  if (Array.isArray(data)) { for (const item of data) extractMenuPaths(item, paths); return; }
  const d = data as any;
  for (const k of PATH_KEYS) {
    const val = d[k];
    if (val && typeof val === 'string' && (val === '/' || /^\/[a-zA-Z0-9_\-]/.test(val))) paths.add(val);
  }
  for (const childKey of ['children', 'subList', 'child', 'childList', 'items']) {
    if (d[childKey]) extractMenuPaths(d[childKey], paths);
  }
}

/** 判断路由路径是否已在菜单中（精确 + 前缀匹配） */
export function isPathInMenu(routePath: string, menuPaths: Set<string>): boolean {
  if (menuPaths.has(routePath)) return true;
  for (const mp of menuPaths) {
    if (routePath.indexOf(mp) === 0 && routePath !== mp) {
      const nextChar = routePath.charAt(mp.length);
      if (nextChar === '/' || !nextChar) return true;
    }
  }
  return false;
}

/** 在嵌套数据中定位菜单数组（最多递归 3 层） */
export function findMenuArray(data: unknown, depth = 0): any[] | null {
  if (depth > 3 || data == null) return null;
  if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && data[0] !== null) return data;
  if (typeof data === 'object' && !Array.isArray(data)) {
    const d = data as any;
    for (const k of Object.keys(d)) {
      if (Array.isArray(d[k]) && d[k].length > 0 && typeof d[k][0] === 'object' && d[k][0] !== null) return d[k];
    }
    for (const k of Object.keys(d)) {
      if (typeof d[k] === 'object' && d[k] !== null && !Array.isArray(d[k])) {
        const found = findMenuArray(d[k], depth + 1);
        if (found) return found;
      }
    }
  }
  return null;
}

/** 从菜单数据提取模板对象 */
export function getTemplateFromMenuData(data: unknown): any | null {
  const arr = findMenuArray(data);
  if (!arr || arr.length === 0) return null;
  return { ...arr[0] };
}

/** 基于模板构造一个新菜单项（用于注入隐藏路由） */
export function constructMenuItemFromRoute(route: { path: string; name?: string }, template: any): any {
  if (!template || typeof template !== 'object') {
    return { path: route.path, name: route.name || route.path, title: route.name || route.path, isshow: '1', status: 1 };
  }
  const item: any = {};
  for (const k of Object.keys(template)) {
    if (PATH_KEYS.includes(k)) item[k] = route.path;
    else if (k === 'name' || k === 'menuName') item[k] = route.name || route.path;
    else if (k === 'title' || k === 'label' || k === 'text') item[k] = route.name || route.path;
    else if (k === 'id' || k === 'menuId' || k === 'key') item[k] = Math.floor(Math.random() * 90000) + 10000;
    else if (k === 'isshow' || k === 'isShow') item[k] = '1';
    else if (k === 'hidden') item[k] = false;
    else if (k === 'display' || k === 'visible') item[k] = true;
    else if (k === 'status') item[k] = 1;
    else if (['children', 'child', 'subList', 'childList', 'items'].includes(k)) item[k] = [];
    else if (k === 'meta' || k === 'component') continue;
    else item[k] = template[k];
  }
  if (!item.path) item.path = route.path;
  return item;
}

/**
 * 把隐藏路由注入到编辑器 JSON 的菜单数组中（原地修改并返回新 JSON 串）。
 */
export function injectRoutesIntoMenu(jsonText: string, hiddenRoutes: RoutePath[]): { text: string; injected: number } {
  let parsed: any;
  try { parsed = JSON.parse(jsonText); } catch { return { text: jsonText, injected: 0 }; }
  const template = getTemplateFromMenuData(parsed);
  const targetArray = Array.isArray(parsed) ? parsed : findMenuArray(parsed);
  if (!targetArray) return { text: jsonText, injected: 0 };
  const menuPaths = new Set<string>();
  extractMenuPaths(parsed, menuPaths);
  let injected = 0;
  for (const route of hiddenRoutes) {
    if (!isPathInMenu(route.path, menuPaths)) {
      targetArray.push(constructMenuItemFromRoute(route, template));
      injected++;
    }
  }
  return { text: JSON.stringify(parsed, null, 2), injected };
}

// ====== JS 搜索路径提取（vue-jssearch 纯逻辑）======

const PATH_FIELD_RE = /(?:path|url|href|route|component)\s*[:=]\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/gi;
const GENERIC_PATH_RE = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+)['"`]/g;

/** 从 JS 匹配上下文中提取路径（排除 /api/ 与静态资源） */
export function extractPathsFromJsContexts(contexts: string[]): string[] {
  const found = new Set<string>();
  for (const ctx of contexts) {
    let m: RegExpExecArray | null;
    PATH_FIELD_RE.lastIndex = 0;
    while ((m = PATH_FIELD_RE.exec(ctx)) !== null) {
      const p = m[1];
      if (p.indexOf('/api/') === -1 && p.length > 2) found.add(p);
    }
    GENERIC_PATH_RE.lastIndex = 0;
    while ((m = GENERIC_PATH_RE.exec(ctx)) !== null) {
      const p = m[1];
      if (p.indexOf('/api/') === -1 && p.length > 3 && !/^\.(js|css|png|jpg|svg|ico|woff)/.test(p)) found.add(p);
    }
  }
  return Array.from(found);
}

const URL_STOPWORDS = /^(api|v1|v2|v3|v4|index|list|detail|page|id|json|html|js|css|get|post|put|delete)$/i;

/** 从捕获的 API URL 中提取搜索关键词（拆段 + 驼峰拆分，最多 8 个） */
export function extractKeywordsFromCapturedUrls(captures: PermCapture[]): string[] {
  const keywords: string[] = [];
  const seen: Record<string, boolean> = {};
  for (const item of captures) {
    if (!item.url) continue;
    const segments = item.url.split(/[\/?#]/);
    let processed = 0;
    for (let s = segments.length - 1; s >= 0 && processed < 2; s--) {
      const seg = segments[s].trim();
      if (!seg || seg.length < 3 || URL_STOPWORDS.test(seg) || /^\d+$/.test(seg)) continue;
      const words = seg.replace(/([a-z])([A-Z])/g, '$1 $2').split(/[\s_\-]+/);
      for (const w of words) {
        if (w.length >= 4 && !seen[w.toLowerCase()]) { seen[w.toLowerCase()] = true; keywords.push(w); }
      }
      if (!seen[seg.toLowerCase()]) { seen[seg.toLowerCase()] = true; keywords.push(seg); }
      processed++;
    }
  }
  return keywords.slice(0, 8);
}

