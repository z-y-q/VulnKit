import { describe, it, expect } from 'vitest';
import {
  joinReactPath,
  detectAuthKeys,
  flattenReactRouteTree,
  extractPathLiterals,
  extractMicroApps,
  type ReactRouteNodeInput,
} from '@/lib/analyzers/react-analyzer';

describe('react-analyzer: joinReactPath', () => {
  it('常规拼接补分隔符', () => {
    expect(joinReactPath('/dev', 'list')).toBe('/dev/list');
    expect(joinReactPath('', 'login')).toBe('/login');
    expect(joinReactPath('/', 'user')).toBe('/user');
  });

  it('子段为绝对路径时直接采用', () => {
    expect(joinReactPath('/dev', '/absolute')).toBe('/absolute');
  });

  it('通配段相对父级', () => {
    expect(joinReactPath('/dev', '*')).toBe('/dev/*');
    expect(joinReactPath('', '*')).toBe('*');
    expect(joinReactPath('/', '*')).toBe('*');
  });

  it('index 路由继承父路径', () => {
    expect(joinReactPath('/dev', '', true)).toBe('/dev');
    expect(joinReactPath('/dev', undefined, false)).toBe('/dev');
    expect(joinReactPath('', '', true)).toBe('/');
  });
});

describe('react-analyzer: detectAuthKeys', () => {
  it('识别常见鉴权字段', () => {
    expect(detectAuthKeys({ requiresAuth: true, roles: ['admin'], title: 'x' })).toEqual(['requiresAuth', 'roles']);
    expect(detectAuthKeys({ authority: 'admin' })).toEqual(['authority']);
    expect(detectAuthKeys({ access: 'user', permissions: [] })).toEqual(['access', 'permissions']);
  });

  it('空值与非鉴权字段返回空', () => {
    expect(detectAuthKeys(null)).toEqual([]);
    expect(detectAuthKeys(undefined)).toEqual([]);
    expect(detectAuthKeys({ title: 'x', icon: 'y' })).toEqual([]);
  });
});

describe('react-analyzer: flattenReactRouteTree', () => {
  const tree: ReactRouteNodeInput[] = [
    {
      path: '/dev',
      component: 'DevLayout',
      handle: { requiresAuth: true },
      children: [
        { path: '', index: true, component: 'DevHome' },
        { path: 'detail/:id', component: 'DevDetail', meta: { roles: ['ops'] } },
        { path: '/login', component: 'Login' },
      ],
    },
    { path: '*', component: 'NotFound' },
  ];

  it('拼接父链并扁平化', () => {
    const rows = flattenReactRouteTree(tree);
    const paths = rows.map((r) => r.fullPath);
    expect(paths).toContain('/dev');
    expect(paths).toContain('/dev/detail/:id');
    expect(paths).toContain('/login'); // 绝对子段不叠加父级
    expect(paths).toContain('*');
  });

  it('index 路由继承父路径且不重复', () => {
    const rows = flattenReactRouteTree(tree);
    const devRows = rows.filter((r) => r.fullPath === '/dev');
    expect(devRows).toHaveLength(1); // 父级与 index 子级同路径，只留首条
  });

  it('携带鉴权提示与组件名', () => {
    const rows = flattenReactRouteTree(tree);
    const dev = rows.find((r) => r.fullPath === '/dev')!;
    expect(dev.component).toBe('DevLayout');
    expect(dev.authKeys).toEqual(['requiresAuth']);
    const detail = rows.find((r) => r.fullPath === '/dev/detail/:id')!;
    expect(detail.authKeys).toEqual(['roles']);
  });

  it('空输入返回空数组', () => {
    expect(flattenReactRouteTree(null)).toEqual([]);
    expect(flattenReactRouteTree([])).toEqual([]);
  });

  it('umi 微前端形状（microApp 路由）照常扁平化', () => {
    const rows = flattenReactRouteTree([
      { path: '/dev/*', component: '' },
      { path: '/ops/*', component: '' },
    ]);
    expect(rows.map((r) => r.fullPath)).toEqual(['/dev/*', '/ops/*']);
  });
});

describe('react-analyzer: extractPathLiterals', () => {
  it('提取 umi 风格 path:"/xxx" 字面量并去重排序', () => {
    const js = `{name:"cdp-client-pc-dev",path:"/dev/*",microApp:"cdp-client-pc-dev"},{path:"/login",component:"@@/login"},{path:"/dev/*",microApp:"dup"}_history`;
    expect(extractPathLiterals(js)).toEqual(['/dev/*', '/login']);
  });

  it('过滤资源引用与非路径值', () => {
    const js = `path:"/static/app.js",path:"icon.png",path:"relative",path:"/valid/route"`;
    expect(extractPathLiterals(js)).toEqual(['/valid/route']);
  });

  it('空输入返回空数组', () => {
    expect(extractPathLiterals('')).toEqual([]);
    expect(extractPathLiterals('no literals here')).toEqual([]);
  });

  it('限制上限防炸（500 条）', () => {
    let js = '';
    for (let i = 0; i < 600; i++) js += `path:"/r${i}",`;
    expect(extractPathLiterals(js).length).toBe(500);
  });
});

describe('react-analyzer: extractMicroApps', () => {
  it('提取 path 在前 microApp 在后的关联（目标站点真实形状）', () => {
    const js = `{name:"cdp-client-pc-dev",entry:"//x",path:"/dev/*",microApp:"cdp-client-pc-dev"}`;
    expect(extractMicroApps(js)).toEqual([{ path: '/dev/*', microApp: 'cdp-client-pc-dev' }]);
  });

  it('兼容 microApp 在前 path 在后的顺序', () => {
    const js = `{microApp:"sub-app",path:"/sub/*"}`;
    expect(extractMicroApps(js)).toEqual([{ path: '/sub/*', microApp: 'sub-app' }]);
  });

  it('去重', () => {
    const js = `path:"/dev/*",microApp:"app1",path:"/dev/*",microApp:"app1"`;
    expect(extractMicroApps(js)).toEqual([{ path: '/dev/*', microApp: 'app1' }]);
  });

  it('无关联时返回空数组', () => {
    expect(extractMicroApps('path:"/login"')).toEqual([]);
  });
});
