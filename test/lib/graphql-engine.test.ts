import { describe, it, expect } from 'vitest';
import {
  isGraphqlEndpoint,
  analyzeGraphqlResponse,
  extractSchemaInfo,
  severityLabel,
  SEVERITY_ORDER,
  GRAPHQL_SORT_FNS,
  COMMON_GRAPHQL_PATHS,
  INTROSPECTION_QUERIES,
  GRAPHQL_PROBES,
  type GraphqlProbe,
} from '@/lib/scanners/graphql-engine';

interface RawResponse {
  status: number;
  body?: string;
  headers?: Record<string, string>;
  error?: string;
}

// ====== 辅助函数 ======

function makeResponse(overrides: Partial<RawResponse> = {}): RawResponse {
  return { status: 200, body: undefined, headers: {}, error: undefined, ...overrides };
}

// ====== 测试 ======

describe('graphql-engine: 常量', () => {
  it('COMMON_GRAPHQL_PATHS 非空，包含 /graphql', () => {
    expect(COMMON_GRAPHQL_PATHS.length).toBeGreaterThan(0);
    expect(COMMON_GRAPHQL_PATHS).toContain('/graphql');
    expect(COMMON_GRAPHQL_PATHS).toContain('/api/graphql');
  });

  it('INTROSPECTION_QUERIES 包含 __schema', () => {
    expect(INTROSPECTION_QUERIES.length).toBeGreaterThan(0);
    for (const q of INTROSPECTION_QUERIES) {
      expect(q).toContain('__schema');
    }
  });

  it('GRAPHQL_PROBES 非空，每项有 name/body/method', () => {
    expect(GRAPHQL_PROBES.length).toBeGreaterThan(10);
    for (const p of GRAPHQL_PROBES) {
      expect(p.name).toBeTruthy();
      expect(p.body).toBeTruthy();
      expect(['POST', 'GET']).toContain(p.method);
    }
  });
});

describe('graphql-engine: isGraphqlEndpoint', () => {
  it('content-type application/graphql 判定为 GraphQL', () => {
    const resp = makeResponse({
      headers: { 'content-type': 'application/graphql' },
      body: 'null',
    });
    expect(isGraphqlEndpoint(resp)).toBe(true);
  });

  it('响应体含 __schema 且有 data 对象 — GraphQL', () => {
    const body = JSON.stringify({
      data: { __schema: { queryType: { name: 'Query' } } },
    });
    expect(isGraphqlEndpoint(makeResponse({ body }))).toBe(true);
  });

  it('响应含 errors 数组 — GraphQL 错误形状', () => {
    const body = JSON.stringify({ errors: [{ message: 'Unknown field' }] });
    expect(isGraphqlEndpoint(makeResponse({ body }))).toBe(true);
  });

  it('响应含 data 对象（无 __schema）— 仍是 GraphQL', () => {
    const body = JSON.stringify({ data: { user: { id: 1 } } });
    expect(isGraphqlEndpoint(makeResponse({ body }))).toBe(true);
  });

  it('body 中原始 __schema 关键字 — GraphQL', () => {
    expect(isGraphqlEndpoint(makeResponse({ body: '__schema: { queryType: { name: "Query" } }' }))).toBe(true);
  });

  it('404 状态返回 false', () => {
    const resp = makeResponse({
      status: 404,
      body: JSON.stringify({ data: { __schema: {} } }),
    });
    expect(isGraphqlEndpoint(resp)).toBe(false);
  });

  it('403 状态返回 false', () => {
    const resp = makeResponse({
      status: 403,
      body: JSON.stringify({ errors: [] }),
    });
    expect(isGraphqlEndpoint(resp)).toBe(false);
  });

  it('error 字段存在返回 false', () => {
    expect(isGraphqlEndpoint(makeResponse({ error: 'Network timeout' }))).toBe(false);
  });

  it('HTML 响应返回 false', () => {
    expect(
      isGraphqlEndpoint(makeResponse({
        headers: { 'content-type': 'text/html' },
        body: '<html><body>Hello</body></html>',
      })),
    ).toBe(false);
  });

  it('null/undefined 响应返回 false', () => {
    expect(isGraphqlEndpoint(null as any)).toBe(false);
    expect(isGraphqlEndpoint(undefined as any)).toBe(false);
  });

  it('空 body 返回 false', () => {
    expect(isGraphqlEndpoint(makeResponse({ body: '' }))).toBe(false);
  });

  it('非 JSON 纯文本返回 false', () => {
    expect(isGraphqlEndpoint(makeResponse({ body: 'Just some text' }))).toBe(false);
  });
});

describe('graphql-engine: analyzeGraphqlResponse — batch-query', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'batch-query')!;

  it('返回数组 = 批量查询支持，medium', () => {
    const body = JSON.stringify([{ data: { __typename: 'Query' } }, { data: { __typename: 'Query' } }]);
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].detail).toContain('批量');
  });

  it('返回单个对象 = 不支持，无 finding', () => {
    const body = JSON.stringify({ data: { __typename: 'Query' } });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(0);
  });

  it('JSON 解析失败 = 无 finding', () => {
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body: 'not json' }));
    expect(findings.length).toBe(0);
  });
});

describe('graphql-engine: analyzeGraphqlResponse — field-suggestion', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'field-suggestion')!;

  it('"Did you mean" 建议出现 = low', () => {
    const body = JSON.stringify({ errors: [{ message: 'Did you mean "user"?' }] });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].detail).toContain('Did you mean');
  });

  it('小写 "did you mean" 也能匹配', () => {
    const body = JSON.stringify({ errors: [{ message: 'did you mean "email"?' }] });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
  });

  it('无 Did you mean = 无 finding', () => {
    const body = JSON.stringify({ errors: [{ message: 'Unknown field.' }] });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(0);
  });
});

describe('graphql-engine: analyzeGraphqlResponse — depth-dos', () => {
  const depthProbe = GRAPHQL_PROBES.find(p => p.name === 'depth-dos-10')!;

  it('无错误返回 = 未限制，medium', () => {
    const body = JSON.stringify({ data: { a: { b: { c: { d: { e: null } } } } } });
    const findings = analyzeGraphqlResponse(depthProbe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].detail).toContain('DoS');
  });

  it('有错误返回 = 已限制，无 finding', () => {
    const body = JSON.stringify({ errors: [{ message: 'Max depth exceeded' }] });
    const findings = analyzeGraphqlResponse(depthProbe, makeResponse({ body }));
    expect(findings.length).toBe(0);
  });
});

describe('graphql-engine: analyzeGraphqlResponse — circular-fragment', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'circular-fragment')!;

  it('无错误 = 循环片段未限制，medium', () => {
    const body = JSON.stringify({ data: { __typename: 'Query' } });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].detail).toContain('循环');
  });
});

describe('graphql-engine: analyzeGraphqlResponse — dangerous mutations', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'mutation-deleteUser')!;

  it('无错误执行 = high 危险 mutation', () => {
    const body = JSON.stringify({ data: { deleteUser: { id: 1 } } });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].detail).toContain('deleteUser');
  });

  it('有错误 = 鉴权有效，无 finding', () => {
    const body = JSON.stringify({ errors: [{ message: 'Not authenticated' }] });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(0);
  });
});

describe('graphql-engine: analyzeGraphqlResponse — directive 注入', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'directive-skip-include')!;

  it('有 data 返回 = low', () => {
    const body = JSON.stringify({ data: { __typename: 'Query' } });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('low');
  });
});

describe('graphql-engine: analyzeGraphqlResponse — subscription', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'subscription')!;

  it('有 data 返回 = info', () => {
    const body = JSON.stringify({ data: { userUpdated: { id: 1 } } });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('info');
  });

  it('错误消息含 subscription = info', () => {
    const body = JSON.stringify({ errors: [{ message: 'subscriptions are not supported' }] });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('info');
  });
});

describe('graphql-engine: analyzeGraphqlResponse — introspect-type', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'introspect-type')!;

  it('__type 字段存在 = low', () => {
    const body = JSON.stringify({ data: { __type: { name: 'Query', fields: [{ name: 'user' }] } } });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].evidence).toBeDefined();
  });
});

describe('graphql-engine: analyzeGraphqlResponse — introspect-directive', () => {
  const probe = GRAPHQL_PROBES.find(p => p.name === 'introspect-directive')!;

  it('__directive 字段存在 = low', () => {
    const body = JSON.stringify({ data: { __directive: { name: 'include', locations: ['FIELD'] } } });
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('low');
  });
});

describe('graphql-engine: analyzeGraphqlResponse — 无效 probe', () => {
  it('未知 probe name 返回空 findings', () => {
    const probe: GraphqlProbe = { name: 'nonexistent', body: '{}', method: 'POST' };
    const findings = analyzeGraphqlResponse(probe, makeResponse({ body: '{}' }));
    expect(findings.length).toBe(0);
  });
});

describe('graphql-engine: extractSchemaInfo', () => {
  const introspectionResponse = {
    data: {
      __schema: {
        queryType: { name: 'RootQuery' },
        mutationType: { name: 'RootMutation' },
        subscriptionType: { name: 'RootSubscription' },
        types: [
          { name: '__Schema', kind: 'OBJECT', fields: [] },
          { name: 'RootQuery', kind: 'OBJECT', fields: [{ name: 'user' }, { name: 'post' }] },
          { name: 'RootMutation', kind: 'OBJECT', fields: [{ name: 'createUser' }] },
          { name: 'RootSubscription', kind: 'OBJECT', fields: [{ name: 'onUserUpdate' }] },
          { name: 'User', kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'name' }, { name: 'email' }] },
          { name: 'Post', kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'title' }] },
        ],
      },
    },
  };

  it('提取 query/mutation/subscription 类型名称', () => {
    const info = extractSchemaInfo(introspectionResponse);
    expect(info).not.toBeNull();
    expect(info!.queryType).toBe('RootQuery');
    expect(info!.mutationType).toBe('RootMutation');
    expect(info!.subscriptionType).toBe('RootSubscription');
  });

  it('提取 queries 列表', () => {
    const info = extractSchemaInfo(introspectionResponse);
    expect(info!.queries).toEqual(['user', 'post']);
  });

  it('提取 mutations 列表', () => {
    const info = extractSchemaInfo(introspectionResponse);
    expect(info!.mutations).toEqual(['createUser']);
  });

  it('提取 subscriptions 列表', () => {
    const info = extractSchemaInfo(introspectionResponse);
    expect(info!.subscriptions).toEqual(['onUserUpdate']);
  });

  it('统计 totalTypes（含 __Schema 等内部类型）', () => {
    const info = extractSchemaInfo(introspectionResponse);
    expect(info!.totalTypes).toBe(6);
  });

  it('提取 objectTypes（排除 __ 开头的）', () => {
    const info = extractSchemaInfo(introspectionResponse);
    // __Schema 被排除，剩下 5 个
    expect(info!.objectTypes.length).toBe(5);
  });

  it('无 __schema 返回 null', () => {
    expect(extractSchemaInfo({ data: {} })).toBeNull();
    expect(extractSchemaInfo(null)).toBeNull();
    expect(extractSchemaInfo({})).toBeNull();
  });

  it('无 mutationType 时 mutationType 为 null', () => {
    const resp = {
      data: {
        __schema: {
          queryType: { name: 'Query' },
          types: [{ name: 'Query', kind: 'OBJECT', fields: [] }],
        },
      },
    };
    const info = extractSchemaInfo(resp);
    expect(info!.mutationType).toBeNull();
    expect(info!.mutations.length).toBe(0);
  });
});

describe('graphql-engine: severityLabel', () => {
  it('中文映射正确', () => {
    expect(severityLabel('critical')).toBe('严重');
    expect(severityLabel('high')).toBe('高危');
    expect(severityLabel('medium')).toBe('中危');
    expect(severityLabel('low')).toBe('低危');
    expect(severityLabel('info')).toBe('信息');
  });
});

describe('graphql-engine: SEVERITY_ORDER', () => {
  it('critical < high < medium < low < info', () => {
    expect(SEVERITY_ORDER.critical).toBeLessThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeLessThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeLessThan(SEVERITY_ORDER.low);
    expect(SEVERITY_ORDER.low).toBeLessThan(SEVERITY_ORDER.info);
  });
});

describe('graphql-engine: GRAPHQL_SORT_FNS', () => {
  it('按 severity 排序', () => {
    const findings = [
      { test: 'a', severity: 'info' as const, detail: '' },
      { test: 'b', severity: 'critical' as const, detail: '' },
      { test: 'c', severity: 'medium' as const, detail: '' },
    ];
    const sorted = [...findings].sort(GRAPHQL_SORT_FNS.severity);
    expect(sorted[0].severity).toBe('critical');
    expect(sorted[2].severity).toBe('info');
  });

  it('按 test 名称排序', () => {
    const findings = [
      { test: 'zebra', severity: 'info' as const, detail: '' },
      { test: 'alpha', severity: 'info' as const, detail: '' },
    ];
    const sorted = [...findings].sort(GRAPHQL_SORT_FNS.test);
    expect(sorted[0].test).toBe('alpha');
  });
});
