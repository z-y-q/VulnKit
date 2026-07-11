import { describe, it, expect } from 'vitest';
import {
  matchCvesByVersion,
  searchCves,
  searchCvesByFingerprint,
  getAllCves,
  classifyRoute,
  classifyRoutes,
  getSensitiveRoutes,
  aggregateHookEvents,
  processCapturedRequests,
  classifyRequest,
  extractPathsFromRouterData,
  cveSeverityLabel,
  cveSeverityColor,
  routeCategoryLabel,
  routeCategoryBadge,
  classifyStatus,
  statusColor,
  type HookEvent,
  type CapturedRequest,
} from '@/lib/analyzers/ruoyi-analyzer';

describe('ruoyi-analyzer: CVE 数据库', () => {
  it('getAllCves 返回非空且按严重度排序', () => {
    const cves = getAllCves();
    expect(cves.length).toBeGreaterThan(5);
    // critical 在最前
    expect(cves[0].severity).toBe('critical');
  });

  it('matchCvesByVersion — 受影响版本命中 CVE', () => {
    const results = matchCvesByVersion('4.6.2');
    expect(results.length).toBeGreaterThan(0);
    // 应包含 <=4.6.2 的 CVE
    expect(results.some(c => c.id === 'CVE-2023-44397')).toBe(true);
    expect(results.some(c => c.id === 'CVE-2023-33265')).toBe(true);
  });

  it('matchCvesByVersion — 高版本返回更少 CVE', () => {
    const v462 = matchCvesByVersion('4.6.2');
    const v470 = matchCvesByVersion('4.7.1');
    // 4.7.1 应少于 4.6.2（4.7.1 不受 <=4.6.2 影响）
    expect(v470.length).toBeLessThan(v462.length);
  });

  it('matchCvesByVersion — 空字符串返回全部 CVE', () => {
    const all = matchCvesByVersion('');
    expect(all.length).toBeGreaterThan(0);
    expect(all.length).toBe(getAllCves().length);
  });

  it('searchCves 按关键词搜索', () => {
    const results = searchCves('SQL');
    expect(results.length).toBeGreaterThan(0);
    expect(results.every(c => c.title.includes('SQL') || c.description.includes('SQL'))).toBe(true);
  });

  it('searchCvesByFingerprint 按指纹搜索', () => {
    const results = searchCvesByFingerprint(['Shiro', 'RememberMe']);
    expect(results.length).toBeGreaterThan(0);
    expect(results.some(c => c.title.includes('Shiro') || c.description.includes('Shiro'))).toBe(true);
  });

  it('searchCvesByFingerprint 空数组返回空', () => {
    expect(searchCvesByFingerprint([])).toEqual([]);
  });
});

describe('ruoyi-analyzer: 路由分类', () => {
  it('classifyRoute 分类 /system/user 为 admin', () => {
    const r = classifyRoute('/system/user');
    expect(r.category).toBe('admin');
    expect(r.title).toBe('用户管理');
  });

  it('classifyRoute 分类 /monitor/online 为 monitor', () => {
    const r = classifyRoute('/monitor/online');
    expect(r.category).toBe('monitor');
  });

  it('classifyRoute 分类 /tool/gen 为 tool', () => {
    const r = classifyRoute('/tool/gen');
    expect(r.category).toBe('tool');
  });

  it('classifyRoute 分类 /auth/login 为 auth', () => {
    const r = classifyRoute('/auth/login');
    expect(r.category).toBe('auth');
  });

  it('classifyRoute 分类 /actuator 为 cloud', () => {
    const r = classifyRoute('/actuator');
    expect(r.category).toBe('cloud');
  });

  it('classifyRoute 分类 /common/download 为 sensitive', () => {
    const r = classifyRoute('/common/download');
    expect(r.category).toBe('sensitive');
  });

  it('classifyRoute 分类 /dashboard 为 normal', () => {
    const r = classifyRoute('/dashboard');
    expect(r.category).toBe('normal');
  });

  it('classifyRoute 去除尾部斜杠', () => {
    const r = classifyRoute('/system/user/');
    expect(r.path).toBe('/system/user');
  });

  it('classifyRoutes 批量分类', () => {
    const routes = classifyRoutes(['/system/user', '/auth/login', '/about']);
    expect(routes).toHaveLength(3);
    expect(routes[0].category).toBe('admin');
    expect(routes[1].category).toBe('auth');
    expect(routes[2].category).toBe('normal');
  });

  it('getSensitiveRoutes 过滤出非 normal/auth', () => {
    const routes = classifyRoutes(['/system/user', '/auth/login', '/about', '/actuator']);
    const sensitive = getSensitiveRoutes(routes);
    expect(sensitive.length).toBe(2);
    expect(sensitive.every(r => r.category !== 'normal' && r.category !== 'auth')).toBe(true);
  });
});

describe('ruoyi-analyzer: 事件聚合', () => {
  it('aggregateHookEvents 去重 + 标记', () => {
    const events: HookEvent[] = [
      { event: 'routers_captured', timestamp: 1 },
      { event: 'routers_captured', timestamp: 2 }, // 重复
      { event: 'userinfo_captured', timestamp: 3 },
      { event: 'hook_restored', timestamp: 4 },
    ];
    const result = aggregateHookEvents(events);
    expect(result.routerCaptured).toBe(true);
    expect(result.userinfoCaptured).toBe(true);
    expect(result.hookRestored).toBe(true);
    expect(result.lastEvent?.event).toBe('hook_restored');
  });

  it('aggregateHookEvents 空 events', () => {
    const result = aggregateHookEvents([]);
    expect(result.routerCaptured).toBe(false);
    expect(result.userinfoCaptured).toBe(false);
    expect(result.lastEvent).toBeNull();
  });

  it('processCapturedRequests 去重 + 计数', () => {
    const requests: CapturedRequest[] = [
      { url: '/getRouters', method: 'GET', status: 200, time: '10ms', category: 'router' },
      { url: '/getRouters', method: 'GET', status: 200, time: '12ms', category: 'router' }, // 重复
      { url: '/system/user', method: 'GET', status: 200, time: '5ms', category: 'api' },
    ];
    const result = processCapturedRequests(requests);
    expect(result.deduped.length).toBe(2);
    expect(result.routerCount).toBe(1);
    expect(result.apiCount).toBe(1);
  });

  it('classifyRequest 识别 router/userinfo', () => {
    expect(classifyRequest('https://x.com/getRouters')).toBe('router');
    expect(classifyRequest('https://x.com/getUserInfo')).toBe('userinfo');
  });

  it('classifyRequest 对普通路径返回 unknown', () => {
    expect(classifyRequest('https://x.com/other/page')).toBe('unknown');
    // /system/user 的 pathname 是 /system/user，regex ^system 不匹配以 / 开头
    expect(classifyRequest('https://x.com/system/user')).toBe('unknown');
  });
});

describe('ruoyi-analyzer: 路由数据提取', () => {
  it('extractPathsFromRouterData 从数组提取路径', () => {
    const data = [
      { path: '/system', children: [{ path: '/system/user' }, { path: '/system/role' }] },
      { path: '/monitor', children: [{ path: '/monitor/online' }] },
    ];
    const paths = extractPathsFromRouterData(data);
    expect(paths).toEqual(['/system', '/system/user', '/system/role', '/monitor', '/monitor/online']);
  });

  it('extractPathsFromRouterData 从 {data:[]} 提取', () => {
    const data = { data: [{ path: '/auth/login' }] };
    const paths = extractPathsFromRouterData(data);
    expect(paths).toEqual(['/auth/login']);
  });

  it('extractPathsFromRouterData null/undefined 返回空', () => {
    expect(extractPathsFromRouterData(null)).toEqual([]);
    expect(extractPathsFromRouterData(undefined)).toEqual([]);
  });
});

describe('ruoyi-analyzer: 辅助函数', () => {
  it('cveSeverityLabel 中文映射', () => {
    expect(cveSeverityLabel('critical')).toBe('严重');
    expect(cveSeverityLabel('high')).toBe('高危');
    expect(cveSeverityLabel('medium')).toBe('中危');
    expect(cveSeverityLabel('low')).toBe('低危');
    expect(cveSeverityLabel('unknown')).toBe('unknown');
  });

  it('cveSeverityColor 返回 CSS 类', () => {
    expect(cveSeverityColor('critical')).toContain('text-red');
    expect(cveSeverityColor('unknown')).toBe('');
  });

  it('routeCategoryLabel 中文映射', () => {
    expect(routeCategoryLabel('admin')).toBe('管理');
    expect(routeCategoryLabel('normal')).toBe('普通');
  });

  it('routeCategoryBadge 返回 badge 类', () => {
    expect(routeCategoryBadge('admin')).toBe('badge-red');
    expect(routeCategoryBadge('normal')).toBe('badge-gray');
  });

  it('classifyStatus 状态码分类', () => {
    expect(classifyStatus(200)).toBe('ok');
    expect(classifyStatus(301)).toBe('redirect');
    expect(classifyStatus(403)).toBe('auth');
    expect(classifyStatus(404)).toBe('notfound');
    expect(classifyStatus(500)).toBe('error');
    expect(classifyStatus(0)).toBe('error');
  });

  it('statusColor 返回 CSS 类', () => {
    expect(statusColor('ok')).toContain('text-green');
    expect(statusColor('auth')).toContain('text-red');
    expect(statusColor('')).toBe('');
  });
});
