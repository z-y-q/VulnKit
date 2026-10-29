/**
 * React 路由纯分析逻辑
 * 与 inject/react-attack.ts 的运行时提取配套：
 * - inject 脚本在 MAIN world 拿到原始路由对象/bundle 文本
 * - 本文件负责路径拼接、扁平化、鉴权提示识别、bundle 字面量提取（可单测）
 */

// ====== 类型 ======

/** inject 上报的原始路由节点（fiber routes 数组 / data router 树通用形状） */
export interface ReactRouteNodeInput {
  path?: string;
  index?: boolean;
  component?: string;
  element?: string;
  handle?: Record<string, unknown> | null;
  meta?: Record<string, unknown> | null;
  children?: ReactRouteNodeInput[];
}

/** 扁平化后的路由行（面板展示用） */
export interface ReactRouteRow {
  /** 拼接父链后的完整路径 */
  fullPath: string;
  /** 自身 path 段（相对父级） */
  segment: string;
  component: string;
  /** 鉴权提示（handle/meta 中识别出的 key 列表） */
  authKeys: string[];
  /** 路由层级 */
  depth: number;
}

// ====== 路径拼接 ======

/**
 * 拼接父路径与子路径段。
 * - 子段以 / 开头：绝对路径，直接采用（React Router 语义）
 * - 子段为 *：相对父级（如 /dev/*），父级为空则为 *
 * - index 路由（无 path 或 index=true）：继承父路径；父级为空时为 /
 * - 常规拼接：补 / 分隔，父级为空时子段即为全路径
 */
export function joinReactPath(parent: string, segment?: string | null, isIndex?: boolean): string {
  if (isIndex || segment === undefined || segment === null || segment === '') {
    return parent || '/';
  }
  const seg = String(segment);
  if (seg.charAt(0) === '/') return seg;
  if (seg === '*') return parent === '/' || parent === '' ? '*' : `${parent}/*`;
  if (!parent || parent === '/') return `/${seg}`;
  return `${parent}/${seg}`;
}

// ====== 鉴权提示识别 ======

/** 常见前端鉴权字段名（route.handle / route.meta / umi wrappers 约定） */
const AUTH_KEY_RE =
  /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|authority|access|private|isAdmin|admin|whiteList|noAuth)$/i;

/** 从 handle/meta 对象中识别鉴权相关字段 */
export function detectAuthKeys(meta: Record<string, unknown> | null | undefined): string[] {
  if (!meta || typeof meta !== 'object') return [];
  return Object.keys(meta).filter((k) => AUTH_KEY_RE.test(k));
}

// ====== 路由树扁平化 ======

/**
 * 深度优先扁平化路由树，拼接父链路径。
 * 同一路径只保留首条（component 优先取非空者）。
 */
export function flattenReactRouteTree(
  nodes: ReactRouteNodeInput[] | null | undefined,
  prefix?: string,
): ReactRouteRow[] {
  const rows: ReactRouteRow[] = [];
  const seen = new Set<string>();
  const walk = (list: ReactRouteNodeInput[], parent: string, depth: number): void => {
    if (!Array.isArray(list)) return;
    for (const node of list) {
      if (!node || typeof node !== 'object') continue;
      const seg = typeof node.path === 'string' ? node.path : '';
      const isIndex = node.index === true || seg === '';
      const fullPath = joinReactPath(parent, seg, isIndex);
      const component =
        (typeof node.component === 'string' && node.component) ||
        (typeof node.element === 'string' && node.element) ||
        '';
      const authKeys = detectAuthKeys(node.handle).concat(detectAuthKeys(node.meta));
      if (!seen.has(fullPath)) {
        seen.add(fullPath);
        rows.push({ fullPath, segment: seg, component, authKeys, depth });
      }
      if (Array.isArray(node.children) && node.children.length > 0) {
        walk(node.children, fullPath, depth + 1);
      }
    }
  };
  walk(nodes || [], prefix || '', 0);
  return rows;
}

// ====== bundle 字面量提取（umi 等闭包路由配置的兜底通道）======

/** 路径字面量合法性：以 / 开头，限定字符集，无空白 */
const ROUTE_LITERAL_RE = /path\s*:\s*"([^"\s]{1,120})"/g;

/** umi 微前端路由：path 与 microApp 相邻出现（两种字段顺序都兼容） */
const MICRO_APP_RE =
  /path\s*:\s*"([^"\s]+)"\s*,\s*microApp\s*:\s*"([^"]+)"|microApp\s*:\s*"([^"]+)"\s*,\s*path\s*:\s*"([^"\s]+)"/g;

/** 合法路由字面量判定：/ 开头，仅限路径安全字符 */
function isPlausibleRoutePath(p: string): boolean {
  if (!p || p.charAt(0) !== '/') return false;
  if (!/^[a-zA-Z0-9\-_/:*?.%~+[\]()$@,=&]*$/.test(p)) return false;
  // 排除明显的资源引用（.js/.css/.png 等结尾）
  return !/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|json|html|map)$/i.test(p);
}

/** 从 JS bundle 文本中提取 path:"/xxx" 形式路由字面量，去重排序 */
export function extractPathLiterals(js: string): string[] {
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  ROUTE_LITERAL_RE.lastIndex = 0;
  while ((m = ROUTE_LITERAL_RE.exec(js)) !== null) {
    const p = m[1];
    if (isPlausibleRoutePath(p)) out.add(p);
    if (out.size >= 500) break;
  }
  return Array.from(out).sort();
}

/** 从 JS bundle 文本中提取 umi 微前端路由关联 {path, microApp} */
export function extractMicroApps(js: string): { path: string; microApp: string }[] {
  const out: { path: string; microApp: string }[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  MICRO_APP_RE.lastIndex = 0;
  while ((m = MICRO_APP_RE.exec(js)) !== null) {
    const path = m[1] || m[4];
    const microApp = m[2] || m[3];
    if (!path || !microApp) continue;
    const key = `${path}|${microApp}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ path, microApp });
    if (out.length >= 50) break;
  }
  return out;
}
