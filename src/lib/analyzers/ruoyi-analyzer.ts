/**
 * RuoYi 分析引擎
 * 从 vk-ruoyi-detect.js / vk-ruoyi-mar.js / vk-ruoyi.js 提取的纯分析逻辑
 * 职责：CVE 匹配、路由分类、事件聚合
 */

import cveDb from '../data/ruoyi-cve-db.json';

// ====== CVE 数据类型 ======

export interface RuoYiCveEntry {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  affected: string[];
  description: string;
  refs: string[];
}

// ====== 路由分类类型 ======

export type RouteCategory = 'admin' | 'sensitive' | 'monitor' | 'tool' | 'auth' | 'cloud' | 'normal';

export interface ClassifiedRoute {
  path: string;
  category: RouteCategory;
  title?: string;
}

// ====== Hook 事件类型 ======

export interface HookEvent {
  event: string;
  augmented?: unknown;
  injected?: unknown;
  timestamp: number;
}

export interface CapturedRequest {
  url: string;
  method: string;
  status: number;
  time: string;
  category: 'router' | 'api' | 'userinfo' | 'unknown';
}

// ====== 分析结果类型 ======

export interface RuoYiAnalysisResult {
  cves: RuoYiCveEntry[];
  sensitiveRoutes: ClassifiedRoute[];
  capturedRequests: CapturedRequest[];
  totalCaptured: number;
  routerCount: number;
  apiCount: number;
}

// ====== 敏感路由模式 ======

const ADMIN_ROUTES: ClassifiedRoute[] = [
  { path: '/system/user', category: 'admin', title: '用户管理' },
  { path: '/system/role', category: 'admin', title: '角色管理' },
  { path: '/system/menu', category: 'admin', title: '菜单管理' },
  { path: '/system/dept', category: 'admin', title: '部门管理' },
  { path: '/system/dict', category: 'admin', title: '字典管理' },
  { path: '/system/config', category: 'admin', title: '参数设置' },
  { path: '/system/notice', category: 'admin', title: '通知公告' },
  { path: '/system/log', category: 'admin', title: '日志管理' },
  { path: '/system/user/profile', category: 'admin', title: '用户中心' },
  { path: '/system/user/authRole', category: 'admin', title: '角色授权' },
  { path: '/system/user/resetPwd', category: 'admin', title: '重置密码' },
  { path: '/system/tenant', category: 'admin', title: '租户管理' },
  { path: '/system/tenant/package', category: 'admin', title: '租户套餐' },
  { path: '/system/oss', category: 'admin', title: '文件管理' },
  { path: '/system/oss/config', category: 'admin', title: 'OSS配置' },
  { path: '/system/post', category: 'admin', title: '岗位管理' },
  { path: '/system/mail', category: 'admin', title: '邮箱管理' },
  { path: '/system/dict-data', category: 'admin', title: '字典数据' },
  { path: '/system/role/authUser', category: 'admin', title: '分配用户' },
];

const MONITOR_ROUTES: ClassifiedRoute[] = [
  { path: '/monitor/online', category: 'monitor', title: '在线用户' },
  { path: '/monitor/job', category: 'monitor', title: '定时任务' },
  { path: '/monitor/druid', category: 'monitor', title: '数据监控' },
  { path: '/monitor/server', category: 'monitor', title: '服务监控' },
  { path: '/monitor/cache', category: 'monitor', title: '缓存监控' },
  { path: '/monitor/cache/list', category: 'monitor', title: '缓存列表' },
];

const TOOL_ROUTES: ClassifiedRoute[] = [
  { path: '/tool/gen', category: 'tool', title: '代码生成' },
  { path: '/tool/swagger', category: 'tool', title: '系统接口' },
  { path: '/tool/build', category: 'tool', title: '表单构建' },
  { path: '/tool/edit', category: 'tool', title: '表单编辑' },
];

const AUTH_ROUTES: ClassifiedRoute[] = [
  { path: '/auth/login', category: 'auth', title: '登录' },
  { path: '/auth/logout', category: 'auth', title: '登出' },
  { path: '/auth/register', category: 'auth', title: '注册' },
  { path: '/login', category: 'auth', title: '登录页' },
];

const CLOUD_ROUTES: ClassifiedRoute[] = [
  { path: '/actuator', category: 'cloud', title: 'Actuator' },
  { path: '/actuator/health', category: 'cloud', title: '健康检查' },
  { path: '/actuator/env', category: 'cloud', title: '环境变量' },
  { path: '/actuator/beans', category: 'cloud', title: 'Bean列表' },
  { path: '/actuator/mappings', category: 'cloud', title: '请求映射' },
  { path: '/actuator/gateway/routes', category: 'cloud', title: 'Gateway路由' },
  { path: '/actuator/configprops', category: 'cloud', title: '配置属性' },
  { path: '/actuator/metrics', category: 'cloud', title: '指标' },
  { path: '/actuator/loggers', category: 'cloud', title: '日志级别' },
  { path: '/actuator/heapdump', category: 'cloud', title: '堆转储' },
  { path: '/nacos', category: 'cloud', title: 'Nacos' },
  { path: '/nacos/v1/ns/service/list', category: 'cloud', title: 'Nacos服务列表' },
  { path: '/nacos/v1/ns/instance/list', category: 'cloud', title: 'Nacos实例列表' },
  { path: '/nacos/v1/cs/configs', category: 'cloud', title: 'Nacos配置' },
  { path: '/sentinel/dashboard', category: 'cloud', title: 'Sentinel控制台' },
  { path: '/swagger-ui.html', category: 'cloud', title: 'Swagger UI' },
  { path: '/doc.html', category: 'cloud', title: 'Knife4j' },
  { path: '/v3/api-docs', category: 'cloud', title: 'OpenAPI 3' },
  { path: '/v2/api-docs', category: 'cloud', title: 'Swagger 2' },
  { path: '/druid', category: 'cloud', title: 'Druid监控' },
];

const SENSITIVE_PATTERNS: RegExp[] = [
  /\/common\/download/i,
  /\/common\/upload/i,
  /\/system\/user\/export/i,
  /\/system\/role\/export/i,
  /\/system\/dict\/export/i,
  /\/system\/operlog\/export/i,
  /\/system\/logininfor\/export/i,
];

const ALL_KNOWN_ROUTES = [
  ...ADMIN_ROUTES,
  ...MONITOR_ROUTES,
  ...TOOL_ROUTES,
  ...AUTH_ROUTES,
  ...CLOUD_ROUTES,
];

// ====== CVE 匹配 ======

/**
 * 根据版本号匹配受影响的 CVE
 * 解析 affected 字段如 "<=4.6.2", "<=4.7.0", "Cloud 3.x" 等
 */
export function matchCvesByVersion(version: string): RuoYiCveEntry[] {
  if (!version) return getAllCves();

  const entries = cveDb as RuoYiCveEntry[];
  return entries.filter((cve) => {
    for (const range of cve.affected) {
      if (isVersionAffected(version, range)) return true;
    }
    return false;
  });
}

/** 返回所有 CVE（按严重程度排序） */
export function getAllCves(): RuoYiCveEntry[] {
  const entries = [...(cveDb as RuoYiCveEntry[])];
  return sortCvesBySeverity(entries);
}

/** 搜索 CVE（按 ID 或标题关键词） */
export function searchCves(query: string): RuoYiCveEntry[] {
  if (!query) return getAllCves();
  const q = query.toLowerCase();
  const entries = (cveDb as RuoYiCveEntry[]).filter(
    (cve) =>
      cve.id.toLowerCase().includes(q) ||
      cve.title.toLowerCase().includes(q) ||
      cve.description.toLowerCase().includes(q),
  );
  return sortCvesBySeverity(entries);
}

/** 按指纹/关键词搜索相关 CVE */
export function searchCvesByFingerprint(fingerprints: string[]): RuoYiCveEntry[] {
  if (!fingerprints || fingerprints.length === 0) return [];

  const entries = cveDb as RuoYiCveEntry[];
  const results = new Set<RuoYiCveEntry>();

  for (const fp of fingerprints) {
    const fpLower = fp.toLowerCase();
    for (const cve of entries) {
      if (
        cve.description.toLowerCase().includes(fpLower) ||
        cve.title.toLowerCase().includes(fpLower) ||
        cve.affected.some((a) => a.toLowerCase().includes(fpLower))
      ) {
        results.add(cve);
      }
    }
  }

  return sortCvesBySeverity([...results]);
}

/** 判断指定版本是否在受影响范围内 */
function isVersionAffected(version: string, range: string): boolean {
  const v = version.replace(/^v/i, '').trim();
  const r = range.trim();

  // Cloud 3.x 匹配
  if (/cloud/i.test(r)) {
    const cloudMatch = r.match(/(\d+)/);
    if (cloudMatch && /cloud/i.test(v)) {
      const cloudVer = v.match(/(\d+)/);
      if (cloudVer) return parseInt(cloudVer[1]) <= parseInt(cloudMatch[1]);
    }
    return /cloud/i.test(v);
  }

  // <= X.Y.Z 格式
  const maxMatch = r.match(/^<=?\s*(\d+(?:\.\d+)*)/);
  if (maxMatch) {
    const maxParts = maxMatch[1].split('.').map(Number);
    const verParts = v.split('.').map(Number);
    for (let i = 0; i < Math.max(maxParts.length, verParts.length); i++) {
      const a = verParts[i] || 0;
      const b = maxParts[i] || 0;
      if (a < b) return true;
      if (a > b) return false;
    }
    return true; // equal → affected for <=
  }

  return false;
}

/** 严重程度排序 */
function sortCvesBySeverity(cves: RuoYiCveEntry[]): RuoYiCveEntry[] {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return cves.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));
}

// ====== 路由分类 ======

/** 对单个路径进行分类 */
export function classifyRoute(path: string): ClassifiedRoute {
  const normalized = path.replace(/\/+$/, '');

  // 先查已知路由表
  const known = ALL_KNOWN_ROUTES.find((r) => normalized === r.path || normalized.startsWith(r.path + '/'));
  if (known) return { ...known, path: normalized };

  // 再查敏感模式
  for (const pattern of SENSITIVE_PATTERNS) {
    if (pattern.test(normalized)) {
      return { path: normalized, category: 'sensitive', title: '敏感接口' };
    }
  }

  // 通用分类规则
  if (/^\/(system|admin)\//i.test(normalized)) return { path: normalized, category: 'admin', title: '系统管理' };
  if (/^\/monitor\//i.test(normalized)) return { path: normalized, category: 'monitor', title: '监控' };
  if (/^\/tool\//i.test(normalized)) return { path: normalized, category: 'tool', title: '工具' };
  if (/^\/(auth|login|logout|register|captcha)/i.test(normalized)) return { path: normalized, category: 'auth', title: '认证' };
  if (/^\/(actuator|nacos|sentinel|druid|swagger|doc\.html|api-docs)/i.test(normalized)) {
    return { path: normalized, category: 'cloud', title: '基础设施' };
  }

  return { path: normalized, category: 'normal' };
}

/** 批量分类路由 */
export function classifyRoutes(paths: string[]): ClassifiedRoute[] {
  return paths.map(classifyRoute);
}

/** 获取所有敏感路由（admin + sensitive + cloud） */
export function getSensitiveRoutes(routes: ClassifiedRoute[]): ClassifiedRoute[] {
  return routes.filter((r) => r.category !== 'normal' && r.category !== 'auth');
}

// ====== 事件聚合 ======

/** Hook 事件去重 + 聚合 */
export function aggregateHookEvents(events: HookEvent[]): {
  routerCaptured: boolean;
  userinfoCaptured: boolean;
  augmentCount: number;
  hookRestored: boolean;
  lastEvent: HookEvent | null;
} {
  const seen = new Set<string>();
  let routerCaptured = false;
  let userinfoCaptured = false;
  let augmentCount = 0;
  let hookRestored = false;
  let lastEvent: HookEvent | null = null;

  for (const evt of events) {
    if (seen.has(evt.event)) continue;
    seen.add(evt.event);

    if (evt.event === 'routers_captured') routerCaptured = true;
    if (evt.event === 'userinfo_captured') userinfoCaptured = true;
    if (evt.event === 'hook_restored') hookRestored = true;

    const injected = evt.injected as number | undefined;
    if (typeof injected === 'number' && injected > 0) augmentCount += injected;

    lastEvent = evt;
  }

  return { routerCaptured, userinfoCaptured, augmentCount, hookRestored, lastEvent };
}

/** 对捕获的 API 请求列表进行分类 + 去重 */
export function processCapturedRequests(requests: CapturedRequest[]): {
  deduped: CapturedRequest[];
  routerCount: number;
  apiCount: number;
} {
  const seen = new Set<string>();
  const deduped: CapturedRequest[] = [];

  let routerCount = 0;
  let apiCount = 0;

  for (const req of requests) {
    const key = `${req.method}:${req.url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(req);

    if (req.category === 'router') routerCount++;
    else if (req.category === 'api') apiCount++;
  }

  return { deduped, routerCount, apiCount };
}

/** 对 API 请求 URL 进行分类 */
export function classifyRequest(url: string): CapturedRequest['category'] {
  const lower = url.toLowerCase();
  if (/(?:getRouters?|getRoutes?)\b/i.test(lower)) return 'router';
  if (/(?:getUserInfo|getInfo)\b/i.test(lower)) return 'userinfo';
  if (
    /^(?:api|admin|system|monitor|tool|gen|auth|login|logout|captcha|code|user|role|menu|dept|post|dict|config|notice|log)\b/i.test(
      new URL(lower, 'https://x').pathname,
    )
  ) {
    return 'api';
  }
  return 'unknown';
}

// ====== 辅助函数 ======

/** 从 /getRouters 响应 JSON 中提取所有路由路径 */
export function extractPathsFromRouterData(data: unknown): string[] {
  const paths: string[] = [];
  if (!data) return paths;

  const routeArray = Array.isArray(data) ? data : (data as { data?: unknown[] }).data;
  if (!Array.isArray(routeArray)) return paths;

  function walk(routes: unknown[]) {
    for (const r of routes) {
      if (!r || typeof r !== 'object') continue;
      const route = r as { path?: string; children?: unknown[] };
      if (route.path) paths.push(route.path);
      if (Array.isArray(route.children)) walk(route.children);
    }
  }

  walk(routeArray);
  return paths;
}

/** 严重程度 → 中文标签 */
export function cveSeverityLabel(severity: string): string {
  const map: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  };
  return map[severity] || severity;
}

/** 严重程度 → CSS 颜色类 */
export function cveSeverityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: 'text-red-600 dark:text-red-400',
    high: 'text-orange-500 dark:text-orange-400',
    medium: 'text-yellow-500 dark:text-yellow-400',
    low: 'text-gray-400 dark:text-gray-500',
  };
  return map[severity] || '';
}

/** 路由分类 → 中文标签 */
export function routeCategoryLabel(category: RouteCategory): string {
  const map: Record<RouteCategory, string> = {
    admin: '管理',
    sensitive: '敏感',
    monitor: '监控',
    tool: '工具',
    auth: '认证',
    cloud: '云服务',
    normal: '普通',
  };
  return map[category] || category;
}

/** 路由分类 → badge 颜色 */
export function routeCategoryBadge(category: RouteCategory): string {
  const map: Record<RouteCategory, string> = {
    admin: 'badge-red',
    sensitive: 'badge-orange',
    monitor: 'badge-yellow',
    tool: 'badge-purple',
    auth: 'badge-blue',
    cloud: 'badge-cyan',
    normal: 'badge-gray',
  };
  return map[category] || 'badge-gray';
}

/** 状态码分类（与 v5 classifyStatus 保持一致） */
export function classifyStatus(code: number): 'ok' | 'redirect' | 'auth' | 'notfound' | 'error' | 'other' {
  if (code >= 200 && code < 300) return 'ok';
  if (code >= 300 && code < 400) return 'redirect';
  if (code === 401 || code === 403) return 'auth';
  if (code === 404) return 'notfound';
  if (code === 0 || code >= 500) return 'error';
  return 'other';
}

/** 状态码分类 → CSS 颜色 */
export function statusColor(classification: string): string {
  const map: Record<string, string> = {
    ok: 'text-green-600 dark:text-green-400',
    redirect: 'text-blue-500 dark:text-blue-400',
    auth: 'text-red-500 dark:text-red-400',
    notfound: 'text-gray-400 dark:text-gray-500',
    error: 'text-red-600 dark:text-red-400',
    other: 'text-gray-400 dark:text-gray-500',
  };
  return map[classification] || '';
}
