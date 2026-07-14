/**
 * GraphQL 检测引擎
 * 从 vk-graphql.js 提取的纯分析逻辑（不含网络请求与 UI）
 * 探测由调用方发起，引擎只负责常量定义与响应分析
 */

// ====== 类型 ======

export type GraphqlSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface GraphqlProbe {
  /** 测试名称 */
  name: string;
  /** 发送的 JSON body 字符串 */
  body: string;
  /** HTTP method */
  method: 'POST' | 'GET';
  /** 用于匹配成功的指示词（可选） */
  expectedIndicator?: string;
}

export interface GraphqlEndpoint {
  path: string;
  status: number;
  introspection: boolean;
}

export interface GraphqlSchemaInfo {
  queryType: string | null;
  mutationType: string | null;
  subscriptionType: string | null;
  totalTypes: number;
  objectTypes: { name: string; fieldCount: number }[];
  queries: string[];
  mutations: string[];
  subscriptions: string[];
}

export interface GraphqlFinding {
  test: string;
  severity: GraphqlSeverity;
  detail: string;
  evidence?: string;
}

export interface GraphqlScanResult {
  url: string;
  endpoints: GraphqlEndpoint[];
  schemaInfo: GraphqlSchemaInfo | null;
  batchSupported: boolean;
  suggestionsEnabled: boolean;
  findings: GraphqlFinding[];
}

// ====== 常量 ======

/** 常见 GraphQL 端点路径 */
export const COMMON_GRAPHQL_PATHS: string[] = [
  '/graphql',
  '/api/graphql',
  '/query',
  '/v1/graphql',
  '/graphiql',
  '/gql',
  '/api',
  '/api/v1',
  '/graphql/console',
];

/** Introspection 查询 — 用于发现 schema 结构 */
export const INTROSPECTION_QUERIES: string[] = [
  JSON.stringify({
    query: '{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name type { name kind } } } } }',
  }),
];

/** 全部 GraphQL 安全探测 payload 列表 */
export const GRAPHQL_PROBES: GraphqlProbe[] = [
  {
    name: 'batch-query',
    body: JSON.stringify([{ query: '{ __typename }' }, { query: '{ __typename }' }]),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'field-suggestion',
    body: JSON.stringify({ query: '{ _fake_field_that_does_not_exist }' }),
    method: 'POST',
    expectedIndicator: 'Did you mean',
  },
  {
    name: 'depth-dos-10',
    body: JSON.stringify({ query: '{ a{b{c{d{e{f{g{h{i{j}}}}}}}}}}' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'depth-dos-real',
    body: JSON.stringify({ query: '{ user{ posts{ comments{ author{ posts{ comments{ author{ id } } } } } } } }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'depth-dos-alias',
    body: JSON.stringify({ query: '{ n0:n{ n1:n{ n2:n{ n3:n{ n4:n{ n5:n{ n6:n{ n7:n{ n8:n{ n9:n } } } } } } } } } }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'circular-fragment',
    body: JSON.stringify({ query: 'fragment frag on Query { ...frag } query { __typename }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'directive-skip-include',
    body: JSON.stringify({ query: '{ __typename @skip(if: true) @include(if: false) }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'directive-include-user',
    body: JSON.stringify({ query: '{ user @include(if: true) { id @skip(if: false) } }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'directive-injection-vars',
    body: JSON.stringify({
      query: 'query($cond: Boolean!) { user(id: 1) @include(if: $cond) { email } }',
      variables: { cond: true },
    }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'mutation-updatePassword',
    body: JSON.stringify({ query: 'mutation { updatePassword(new: "test") { success } }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'mutation-deleteUser',
    body: JSON.stringify({ query: 'mutation { deleteUser(id: 1) { id } }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'mutation-createAdmin',
    body: JSON.stringify({ query: 'mutation { createAdmin(input: {email:"x",role:ADMIN}) { id } }' }),
    method: 'POST',
    expectedIndicator: '__typename',
  },
  {
    name: 'subscription',
    body: JSON.stringify({ query: 'subscription { userUpdated { id email } }' }),
    method: 'POST',
    expectedIndicator: 'subscription',
  },
  {
    name: 'introspect-type',
    body: JSON.stringify({ query: '{ __type(name: "Query") { fields { name } } }' }),
    method: 'POST',
    expectedIndicator: '__type',
  },
  {
    name: 'introspect-directive',
    body: JSON.stringify({ query: '{ __directive(name: "include") { name locations } }' }),
    method: 'POST',
    expectedIndicator: '__directive',
  },
];

// ====== 排序 ======

export const GRAPHQL_SORT_FNS: Record<string, (a: GraphqlFinding, b: GraphqlFinding) => number> = {
  severity: (a, b) => {
    const o: Record<GraphqlSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return o[a.severity] - o[b.severity];
  },
  test: (a, b) => a.test.localeCompare(b.test),
};

// ====== 纯分析函数 ======

interface RawResponse {
  status: number;
  body?: string;
  headers?: Record<string, string>;
  error?: string;
}

/** 安全解析 JSON body */
function parseJsonBody(resp: RawResponse): any | null {
  if (!resp || resp.error || !resp.body) return null;
  try {
    return JSON.parse(resp.body);
  } catch {
    return null;
  }
}

/**
 * 判断响应是否来自 GraphQL 端点
 * 检测 content-type、错误形状、__schema、data 对象
 */
export function isGraphqlEndpoint(resp: RawResponse): boolean {
  if (!resp || resp.error) return false;
  if (resp.status === 404 || resp.status === 403) return false;

  // Content-Type 检查
  const ct = (resp.headers?.['content-type'] || '').toLowerCase();
  if (ct.includes('application/graphql')) return true;

  // body 中关键字（适用于非 JSON 响应，如错误页/调试输出，需在 JSON 早退之前检测）
  if (resp.body && /"?__schema"?\s*:/.test(resp.body)) return true;

  const json = parseJsonBody(resp);
  if (!json) return false;

  // 标准 GraphQL 响应形状
  if (json.data && json.data.__schema) return true;
  if (json.errors && Array.isArray(json.errors)) return true;
  if (json.data && typeof json.data === 'object') return true;

  return false;
}

/** 提取 schema 信息（ introspection 成功时） */
export function extractSchemaInfo(json: any): GraphqlSchemaInfo | null {
  if (!json?.data?.__schema) return null;
  const schema = json.data.__schema;
  const types: any[] = schema.types || [];
  const queries: string[] = [];
  const mutations: string[] = [];
  const subscriptions: string[] = [];
  const objectTypes: { name: string; fieldCount: number }[] = [];

  for (const t of types) {
    if ((t.name || '').startsWith('__')) continue;

    if (t.kind === 'OBJECT' && t.fields?.length > 0) {
      objectTypes.push({ name: t.name, fieldCount: t.fields.length });
    }
    if (t.name === schema.queryType?.name) {
      queries.push(...t.fields.map((f: any) => f.name));
    }
    if (t.name === schema.mutationType?.name) {
      mutations.push(...t.fields.map((f: any) => f.name));
    }
    if (t.name === schema.subscriptionType?.name) {
      subscriptions.push(...t.fields.map((f: any) => f.name));
    }
  }

  return {
    queryType: schema.queryType?.name ?? null,
    mutationType: schema.mutationType?.name ?? null,
    subscriptionType: schema.subscriptionType?.name ?? null,
    totalTypes: types.length,
    objectTypes,
    queries,
    mutations,
    subscriptions,
  };
}

/**
 * 分析单条探测结果，返回 findings
 * 探测逻辑已由调用方编排，此函数根据 probe name + response 做判定
 */
export function analyzeGraphqlResponse(
  probe: GraphqlProbe,
  resp: RawResponse,
): GraphqlFinding[] {
  const json = parseJsonBody(resp);
  const findings: GraphqlFinding[] = [];

  switch (probe.name) {
    case 'batch-query': {
      // 批量查询：服务端返回数组 = 支持
      if (Array.isArray(json)) {
        findings.push({
          test: probe.name,
          severity: 'medium',
          detail: '服务器接受 JSON 数组格式的批量查询，可用于 DoS 攻击',
        });
      }
      break;
    }

    case 'field-suggestion': {
      // 字段建议：错误消息含 "Did you mean"
      if (json?.errors?.length) {
        const hasSuggestion = json.errors.some(
          (e: any) =>
            (e.message || '').includes('Did you mean') ||
            (e.message || '').includes('did you mean'),
        );
        if (hasSuggestion) {
          findings.push({
            test: probe.name,
            severity: 'low',
            detail: '错误查询返回 "Did you mean" 建议，有助于枚举 schema',
          });
        }
      }
      break;
    }

    case 'depth-dos-10':
    case 'depth-dos-real':
    case 'depth-dos-alias': {
      // 深度嵌套查询：无错误 = 未限制
      if (json && !json.errors) {
        findings.push({
          test: probe.name,
          severity: 'medium',
          detail: '服务端接受 10+ 层嵌套查询，可能导致 DoS',
        });
      }
      break;
    }

    case 'circular-fragment': {
      // 循环 fragment：无错误 = 未限制
      if (json && !json.errors) {
        findings.push({
          test: probe.name,
          severity: 'medium',
          detail: '服务端接受循环 fragment 引用，可能导致无限递归',
        });
      }
      break;
    }

    case 'directive-skip-include':
    case 'directive-include-user':
    case 'directive-injection-vars': {
      // Directive 注入：成功返回 data
      if (json?.data) {
        findings.push({
          test: probe.name,
          severity: 'low',
          detail: '可通过 @skip/@include 操纵查询逻辑绕过权限检查',
        });
      }
      break;
    }

    case 'mutation-updatePassword':
    case 'mutation-deleteUser':
    case 'mutation-createAdmin': {
      // 危险 mutation：无错误 = 未鉴权
      if (json?.data && !json.errors) {
        const match = probe.body.match(/mutation\s+\{ (\w+)/);
        const mutationName = match ? match[1] : probe.name;
        findings.push({
          test: probe.name,
          severity: 'high',
          detail: `mutation "${mutationName}" 可直接调用，无需认证`,
        });
      }
      break;
    }

    case 'subscription': {
      // Subscription：有 data 或错误提到 subscription
      if (json?.data) {
        findings.push({
          test: probe.name,
          severity: 'info',
          detail: '服务端支持 WebSocket subscription，可用于实时数据监控',
        });
      } else if (json?.errors?.[0]?.message?.includes('subscription')) {
        findings.push({
          test: probe.name,
          severity: 'info',
          detail: '服务端确认 subscription 支持，可用于实时数据监控',
        });
      }
      break;
    }

    case 'introspect-type': {
      if (json?.data?.__type) {
        findings.push({
          test: probe.name,
          severity: 'low',
          detail: '__type 内省字段可用，可枚举完整 schema 定义',
          evidence: JSON.stringify(json.data.__type).slice(0, 200),
        });
      }
      break;
    }

    case 'introspect-directive': {
      if (json?.data?.__directive) {
        findings.push({
          test: probe.name,
          severity: 'low',
          detail: '__directive 内省字段可用，可枚举完整 directive 定义',
          evidence: JSON.stringify(json.data.__directive).slice(0, 200),
        });
      }
      break;
    }
  }

  return findings;
}

/** 严重级别 → 中文标签 */
export function severityLabel(sev: GraphqlSeverity): string {
  const map: Record<GraphqlSeverity, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  };
  return map[sev] || sev;
}

/** 严重级别顺序 */
export const SEVERITY_ORDER: Record<GraphqlSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
