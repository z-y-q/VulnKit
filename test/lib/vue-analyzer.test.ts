import { describe, it, expect } from 'vitest';
import {
  isSensitiveEntry,
  previewValue,
  flattenStoreTree,
  countRouteStats,
  flattenRoutePaths,
  scorePermissionExposure,
  type VueRouteNode,
} from '@/lib/analyzers/vue-analyzer';

describe('vue-analyzer: isSensitiveEntry', () => {
  it('标记 token 键为敏感', () => {
    expect(isSensitiveEntry('token', 'abc')).toBe(true);
    expect(isSensitiveEntry('password', 'abc')).toBe(true);
    expect(isSensitiveEntry('secret_key', 'abc')).toBe(true);
    expect(isSensitiveEntry('session', 'abc')).toBe(true);
    expect(isSensitiveEntry('credential', 'abc')).toBe(true);
  });

  it('标记 JWT 值为敏感', () => {
    expect(isSensitiveEntry('data', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig')).toBe(true);
  });

  it('标记 Bearer 值为敏感', () => {
    expect(isSensitiveEntry('auth', 'Bearer abc123')).toBe(true);
  });

  it('标记 hex hash 值为敏感', () => {
    expect(isSensitiveEntry('hash', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4')).toBe(true);
  });

  it('普通 key/value 不敏感', () => {
    expect(isSensitiveEntry('theme', 'dark')).toBe(false);
    expect(isSensitiveEntry('lang', 'zh-CN')).toBe(false);
    expect(isSensitiveEntry('count', '42')).toBe(false);
  });
});

describe('vue-analyzer: previewValue', () => {
  it('短值不变', () => {
    expect(previewValue('hello')).toBe('hello');
  });

  it('长值截断', () => {
    const long = 'a'.repeat(200);
    const result = previewValue(long, 80);
    expect(result.length).toBe(83); // 80 + '...'
    expect(result.endsWith('...')).toBe(true);
  });

  it('null/undefined 返回 null 字符串', () => {
    expect(previewValue(null)).toBe('null');
    expect(previewValue(undefined)).toBe('null');
  });

  it('函数返回 [Function]', () => {
    expect(previewValue(() => {})).toBe('[Function]');
  });

  it('对象 JSON 序列化', () => {
    const result = previewValue({ a: 1 });
    expect(result).toBe('{"a":1}');
  });

  it('数字转字符串', () => {
    expect(previewValue(42)).toBe('42');
  });
});

describe('vue-analyzer: flattenStoreTree', () => {
  it('展平嵌套对象', () => {
    const obj = {
      user: {
        token: 'abc123',
        name: 'test',
      },
      app: {
        theme: 'dark',
      },
    };
    const rows = flattenStoreTree(obj);
    // user object row + 2 leaf rows + app object row + 1 leaf row = 5
    expect(rows.length).toBe(5);
    // token 应标记为敏感
    const tokenRow = rows.find(r => r.key === 'token');
    expect(tokenRow?.sensitive).toBe(true);
    // theme 不应标记为敏感
    const themeRow = rows.find(r => r.key === 'theme');
    expect(themeRow?.sensitive).toBe(false);
  });

  it('空对象返回空数组', () => {
    expect(flattenStoreTree({})).toEqual([]);
    expect(flattenStoreTree(null)).toEqual([]);
    expect(flattenStoreTree(undefined)).toEqual([]);
  });

  it('depth 递增', () => {
    const rows = flattenStoreTree({ a: { b: 1 } });
    const aRow = rows.find(r => r.key === 'a');
    const bRow = rows.find(r => r.key === 'b');
    expect(aRow?.depth).toBe(0);
    expect(bRow?.depth).toBe(1);
  });

  it('maxDepth 限制', () => {
    const deep = { a: { b: { c: { d: 1 } } } };
    const rows = flattenStoreTree(deep, '', 0, 2);
    // depth 2 后不再递归: a(0), b(1), c(2) = 3 行
    expect(rows.length).toBe(3);
  });
});

describe('vue-analyzer: countRouteStats', () => {
  const routes: VueRouteNode[] = [
    { path: '/', name: 'home', meta: {}, children: [], hasAuth: true, sensitive: false, hasBeforeEnter: false, childCount: 0, componentKeys: [] },
    { path: '/admin', name: 'admin', meta: {}, children: [
      { path: '/admin/users', name: 'admin-users', meta: {}, children: [], hasAuth: true, sensitive: true, hasBeforeEnter: true, childCount: 0, componentKeys: [] },
    ], hasAuth: false, sensitive: false, hasBeforeEnter: false, childCount: 1, componentKeys: [] },
    { path: '/secret', name: 'secret', meta: {}, children: [], hasAuth: false, sensitive: true, hasBeforeEnter: false, childCount: 0, componentKeys: [] },
  ];

  it('统计总数', () => {
    const stats = countRouteStats(routes);
    expect(stats.total).toBe(4); // 3 + 1 child
  });

  it('统计 authCount', () => {
    const stats = countRouteStats(routes);
    expect(stats.authCount).toBe(2); // home + admin-users
  });

  it('统计 sensitiveCount', () => {
    const stats = countRouteStats(routes);
    expect(stats.sensitiveCount).toBe(2); // admin-users + secret
  });

  it('统计 beforeEnterCount', () => {
    const stats = countRouteStats(routes);
    expect(stats.beforeEnterCount).toBe(1); // admin-users
  });

  it('空数组返回零值', () => {
    const stats = countRouteStats([]);
    expect(stats).toEqual({ total: 0, authCount: 0, sensitiveCount: 0, beforeEnterCount: 0 });
  });
});

describe('vue-analyzer: flattenRoutePaths', () => {
  const routes: VueRouteNode[] = [
    { path: '/', name: 'home', meta: {}, children: [
      { path: 'about', name: 'about', meta: {}, children: [], hasAuth: false, sensitive: false, hasBeforeEnter: false, childCount: 0, componentKeys: [] },
    ], hasAuth: false, sensitive: false, hasBeforeEnter: false, childCount: 1, componentKeys: [] },
    { path: '/user/:id', name: 'user', meta: {}, children: [], hasAuth: true, sensitive: false, hasBeforeEnter: false, childCount: 0, componentKeys: [] },
  ];

  it('展平嵌套路由', () => {
    const result = flattenRoutePaths(routes, 'https://example.com', '/', 'history');
    expect(result.length).toBeGreaterThanOrEqual(3); // /, /about, /user/:id + probe
  });

  it('参数路由标记 isParam', () => {
    const result = flattenRoutePaths(routes, 'https://example.com', '/', 'history');
    const paramRoute = result.find(r => r.path === '/user/:id');
    expect(paramRoute?.isParam).toBe(true);
  });

  it('生成探测路径', () => {
    const result = flattenRoutePaths(routes, 'https://example.com', '/', 'history');
    const probe = result.find(r => r.path === '/user/1');
    expect(probe?.isProbe).toBe(true);
    expect(probe?.isParam).toBe(false);
  });

  it('hash 模式 URL', () => {
    const result = flattenRoutePaths(routes, 'https://example.com', '/', 'hash');
    const home = result.find(r => r.path === '/');
    expect(home?.url).toContain('#/');
  });
});

describe('vue-analyzer: scorePermissionExposure', () => {
  it('无路由返回 0', () => {
    expect(scorePermissionExposure({ total: 0, authCount: 0, sensitiveCount: 0, beforeEnterCount: 0 })).toBe(0);
  });

  it('大量路由无 auth 得高分', () => {
    const score = scorePermissionExposure({ total: 10, authCount: 0, sensitiveCount: 3, beforeEnterCount: 0 });
    expect(score).toBeGreaterThan(0);
  });

  it('全部有 auth + beforeEnter 降低分数', () => {
    const score = scorePermissionExposure({ total: 10, authCount: 10, sensitiveCount: 0, beforeEnterCount: 10 });
    expect(score).toBe(0);
  });

  it('分数范围 0-100', () => {
    const score = scorePermissionExposure({ total: 100, authCount: 0, sensitiveCount: 50, beforeEnterCount: 0 });
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });
});
