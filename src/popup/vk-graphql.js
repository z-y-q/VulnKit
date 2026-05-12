// vk-graphql.js -- 灵眸 Chrome Extension
// GraphQL Security Testing — introspection, batch query, field suggestion detection
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

var lastResult = null;
var scanning = false;

var GRAPHQL_PATHS = [
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

var INTROSPECTION_QUERY =
  '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name type { name kind } } } } }"}';

var BATCH_PAYLOAD = [{ query: '{ __typename }' }, { query: '{ __typename }' }];

var SUGGESTION_QUERY = '{"query":"{ _fake_field_that_does_not_exist }"}';

var DEPTH_DOS_PAYLOADS = [
  '{"query":"{ a{b{c{d{e{f{g{h{i{j}}}}}}}}}}}"}',
  '{"query":"{ user{ posts{ comments{ author{ posts{ comments{ author{ id } } } } } } } }"}',
  '{"query":"{ n0:n{ n1:n{ n2:n{ n3:n{ n4:n{ n5:n{ n6:n{ n7:n{ n8:n{ n9:n } } } } } } } } } }"}',
];

var CIRCULAR_FRAGMENT_PAYLOAD =
  '{"query":"fragment frag on Query { ...frag } query { __typename }"}';

var DIRECTIVE_INJECTION_PAYLOADS = [
  '{"query":"{ __typename @skip(if: true) @include(if: false) }"}',
  '{"query":"{ user @include(if: true) { id @skip(if: false) } }"}',
  '{"query":"query($cond: Boolean!) { user(id: 1) @include(if: $cond) { email } }","variables":{"cond":true}}',
];

var MUTATION_EXFIL_PAYLOADS = [
  '{"query":"mutation { updatePassword(new: \"test\") { success } }"}',
  '{"query":"mutation { deleteUser(id: 1) { id } }"}',
  '{"query":"mutation { createAdmin(input: {email:\"x\",role:ADMIN}) { id } }"}',
];

var SUBSCRIPTION_PROBE = '{"query":"subscription { userUpdated { id email } }"}';

var FIELD_FUZZ_PAYLOADS = [
  '{"query":"{ __typename }"}',
  '{"query":"{ __schema { types { name } } }"}',
  '{"query":"{ __type(name: \"Query\") { fields { name } } }"}',
  '{"query":"{ __directive(name: \"include\") { name locations } }"}',
];

function sendProbe(url, body, timeout) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage(
      {
        type: 'FETCH_PROBE',
        url: url,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        includeBody: true,
        timeout: timeout || 8000,
      },
      function (resp) {
        if (chrome.runtime.lastError) {
          resolve({ error: chrome.runtime.lastError.message });
          return;
        }
        resolve(resp || { error: 'no response' });
      }
    );
  });
}

function parseJsonBody(resp) {
  if (!resp || resp.error || !resp.body) return null;
  try {
    return JSON.parse(resp.body);
  } catch (e) {
    return null;
  }
}

function isGraphqlResponse(resp, json) {
  if (!resp || resp.error) return false;
  if (resp.status === 404 || resp.status === 403) return false;
  if (!json) return false;
  if (json.data && json.data.__schema) return true;
  if (json.errors && Array.isArray(json.errors)) return true;
  if (json.data && typeof json.data === 'object') return true;
  return false;
}

function extractSchemaInfo(json) {
  if (!json || !json.data || !json.data.__schema) return null;
  var schema = json.data.__schema;
  var types = schema.types || [];
  var queries = [];
  var mutations = [];
  var subscriptions = [];
  var objectTypes = [];

  for (var i = 0; i < types.length; i++) {
    var t = types[i];
    var name = (t.name || '').toLowerCase();
    if (name.indexOf('__') === 0) continue;

    if (t.kind === 'OBJECT' && t.fields && t.fields.length > 0) {
      objectTypes.push({ name: t.name, fieldCount: t.fields.length });
    }

    if (t.name === (schema.queryType && schema.queryType.name)) {
      for (var j = 0; j < t.fields.length; j++) {
        queries.push(t.fields[j].name);
      }
    }
    if (t.name === (schema.mutationType && schema.mutationType.name)) {
      for (var k = 0; k < t.fields.length; k++) {
        mutations.push(t.fields[k].name);
      }
    }
    if (t.name === (schema.subscriptionType && schema.subscriptionType.name)) {
      for (var l = 0; l < t.fields.length; l++) {
        subscriptions.push(t.fields[l].name);
      }
    }
  }

  return {
    queryType: schema.queryType ? schema.queryType.name : null,
    mutationType: schema.mutationType ? schema.mutationType.name : null,
    subscriptionType: schema.subscriptionType ? schema.subscriptionType.name : null,
    totalTypes: types.length,
    objectTypes: objectTypes,
    queries: queries,
    mutations: mutations,
    subscriptions: subscriptions,
  };
}

function checkFieldSuggestions(resp) {
  var json = parseJsonBody(resp);
  if (!json || !json.errors) return false;
  for (var i = 0; i < json.errors.length; i++) {
    var msg = json.errors[i].message || '';
    if (msg.indexOf('Did you mean') !== -1 || msg.indexOf('did you mean') !== -1) {
      return true;
    }
  }
  return false;
}

async function scanGraphQL() {
  if (scanning) return null;
  scanning = true;

  var statusEl = utils.get('graphql-status');
  var resultsEl = utils.get('graphql-results');
  var scanBtn = utils.get('graphql-scan-btn');

  if (statusEl) statusEl.textContent = '正在探测 GraphQL 端点...';
  if (resultsEl) resultsEl.innerHTML = '';
  if (scanBtn) scanBtn.disabled = true;

  try {
    var tab = await utils.requireTabId();
    if (!tab || !/^https?:/.test(tab.url)) {
      if (statusEl) statusEl.textContent = '请打开一个网页';
      return null;
    }

    var origin = new URL(tab.url).origin;
    var findings = [];
    var endpoints = [];
    var schemaInfo = null;
    var batchSupported = false;
    var suggestionsEnabled = false;
    var foundEndpoint = null;

    for (var i = 0; i < GRAPHQL_PATHS.length; i++) {
      if (statusEl) statusEl.textContent = '探测 ' + GRAPHQL_PATHS[i] + '...';
      var url = origin + GRAPHQL_PATHS[i];
      var resp = await sendProbe(url, INTROSPECTION_QUERY);
      var json = parseJsonBody(resp);

      if (isGraphqlResponse(resp, json)) {
        endpoints.push({ path: GRAPHQL_PATHS[i], status: resp.status, introspection: false });
        foundEndpoint = url;

        if (json && json.data && json.data.__schema) {
          endpoints[endpoints.length - 1].introspection = true;
          schemaInfo = extractSchemaInfo(json);
          findings.push({
            severity: 'high',
            title: 'Introspection 已开启',
            detail: 'GraphQL schema 可被完整读取，泄露所有类型、查询和变更定义',
            path: GRAPHQL_PATHS[i],
          });
        }
        break;
      }
    }

    if (!foundEndpoint) {
      var customInput = utils.get('graphql-url');
      var customVal = customInput ? customInput.value.trim() : '';
      if (customVal) {
        if (customVal.indexOf('://') === -1) customVal = origin + customVal;
        var customResp = await sendProbe(customVal, INTROSPECTION_QUERY);
        var customJson = parseJsonBody(customResp);
        if (isGraphqlResponse(customResp, customJson)) {
          foundEndpoint = customVal;
          endpoints.push({
            path: customVal.replace(origin, ''),
            status: customResp.status,
            introspection: !!(customJson && customJson.data && customJson.data.__schema),
          });
          if (endpoints[0].introspection) {
            schemaInfo = extractSchemaInfo(customJson);
            findings.push({
              severity: 'high',
              title: 'Introspection 已开启',
              detail: 'GraphQL schema 可被完整读取',
              path: endpoints[0].path,
            });
          }
        }
      }
    }

    if (foundEndpoint) {
      if (statusEl) statusEl.textContent = '测试批量查询...';
      var batchResp = await sendProbe(foundEndpoint, JSON.stringify(BATCH_PAYLOAD));
      var batchJson = parseJsonBody(batchResp);
      if (Array.isArray(batchJson)) {
        batchSupported = true;
        findings.push({
          severity: 'medium',
          title: '批量查询已启用',
          detail: '服务器接受 JSON 数组格式的批量查询，可用于 DoS 攻击',
          path: foundEndpoint.replace(origin, ''),
        });
      }

      if (statusEl) statusEl.textContent = '测试字段建议...';
      var suggestResp = await sendProbe(foundEndpoint, SUGGESTION_QUERY);
      if (checkFieldSuggestions(suggestResp)) {
        suggestionsEnabled = true;
        findings.push({
          severity: 'low',
          title: '字段建议已启用',
          detail: '错误查询返回 "Did you mean" 建议，有助于枚举 schema',
          path: foundEndpoint.replace(origin, ''),
        });
      }

      if (statusEl) statusEl.textContent = '测试深度查询 DoS...';
      for (var di = 0; di < DEPTH_DOS_PAYLOADS.length; di++) {
        var depthResp = await sendProbe(foundEndpoint, DEPTH_DOS_PAYLOADS[di], 12000);
        var depthJson = parseJsonBody(depthResp);
        if (depthJson && !depthJson.errors) {
          findings.push({
            severity: 'medium',
            title: '深度嵌套查询未限制',
            detail: '服务端接受 10+ 层嵌套查询，可能导致 DoS',
            path: foundEndpoint.replace(origin, ''),
          });
          break;
        }
      }

      if (statusEl) statusEl.textContent = '测试循环 fragment...';
      var circResp = await sendProbe(foundEndpoint, CIRCULAR_FRAGMENT_PAYLOAD);
      var circJson = parseJsonBody(circResp);
      if (circJson && !circJson.errors) {
        findings.push({
          severity: 'medium',
          title: '循环 Fragment 未限制',
          detail: '服务端接受循环 fragment 引用，可能导致无限递归',
          path: foundEndpoint.replace(origin, ''),
        });
      }

      if (statusEl) statusEl.textContent = '测试 directive 注入...';
      for (var dri = 0; dri < DIRECTIVE_INJECTION_PAYLOADS.length; dri++) {
        var dirResp = await sendProbe(foundEndpoint, DIRECTIVE_INJECTION_PAYLOADS[dri]);
        var dirJson = parseJsonBody(dirResp);
        if (dirJson && dirJson.data) {
          findings.push({
            severity: 'low',
            title: 'Directive 注入可用',
            detail: '可通过 @skip/@include 操纵查询逻辑绕过权限检查',
            path: foundEndpoint.replace(origin, ''),
          });
          break;
        }
      }

      if (statusEl) statusEl.textContent = '测试 mutation 端点...';
      for (var mi = 0; mi < MUTATION_EXFIL_PAYLOADS.length; mi++) {
        var mutResp = await sendProbe(foundEndpoint, MUTATION_EXFIL_PAYLOADS[mi]);
        var mutJson = parseJsonBody(mutResp);
        if (mutJson && mutJson.data && !mutJson.errors) {
          findings.push({
            severity: 'high',
            title: '危险 Mutation 未鉴权',
            detail:
              'mutation "' +
              MUTATION_EXFIL_PAYLOADS[mi].match(/mutation\s+\{ (\w+)/)[1] +
              '" 可直接调用，无需认证',
            path: foundEndpoint.replace(origin, ''),
          });
          break;
        }
      }

      if (statusEl) statusEl.textContent = '探测 Subscription 端点...';
      var subResp = await sendProbe(foundEndpoint, SUBSCRIPTION_PROBE);
      var subJson = parseJsonBody(subResp);
      if (
        subJson &&
        (subJson.data ||
          (subJson.errors &&
            subJson.errors[0] &&
            subJson.errors[0].message.indexOf('subscription') !== -1))
      ) {
        findings.push({
          severity: 'info',
          title: 'Subscription 端点可用',
          detail: '服务端支持 WebSocket subscription，可用于实时数据监控',
          path: foundEndpoint.replace(origin, ''),
        });
      }

      if (statusEl) statusEl.textContent = '测试内省字段...';
      for (var fi = 0; fi < FIELD_FUZZ_PAYLOADS.length; fi++) {
        var fieldResp = await sendProbe(foundEndpoint, FIELD_FUZZ_PAYLOADS[fi]);
        var fieldJson = parseJsonBody(fieldResp);
        if (fieldJson && fieldJson.data && !fieldJson.errors) {
          var innerField = fieldJson.data;
          if (innerField.__type || innerField.__directive) {
            findings.push({
              severity: 'low',
              title: '高级内省字段可访问',
              detail: '__type/__directive 等内省字段可用，可枚举完整 schema 定义',
              path: foundEndpoint.replace(origin, ''),
            });
            break;
          }
        }
      }

      if (schemaInfo) {
        if (schemaInfo.mutations.length > 0) {
          findings.push({
            severity: 'info',
            title: 'Mutation 端点可用',
            detail:
              '发现 ' +
              schemaInfo.mutations.length +
              ' 个 mutation: ' +
              schemaInfo.mutations.slice(0, 5).join(', ') +
              (schemaInfo.mutations.length > 5 ? '...' : ''),
            path: foundEndpoint.replace(origin, ''),
          });
        }
        if (schemaInfo.subscriptions.length > 0) {
          findings.push({
            severity: 'info',
            title: 'Subscription 端点可用',
            detail: '发现 ' + schemaInfo.subscriptions.length + ' 个 subscription',
            path: foundEndpoint.replace(origin, ''),
          });
        }
      }
    } else {
      findings.push({
        severity: 'info',
        title: '未发现 GraphQL 端点',
        detail: '常见路径均未返回 GraphQL 响应，可尝试手动输入自定义端点',
        path: '',
      });
    }

    lastResult = {
      url: foundEndpoint || origin,
      endpoints: endpoints,
      schemaInfo: schemaInfo,
      batchSupported: batchSupported,
      suggestionsEnabled: suggestionsEnabled,
      findings: findings,
    };

    renderResults(lastResult);

    if (statusEl) {
      statusEl.textContent = foundEndpoint
        ? '扫描完成 — 发现 ' + endpoints.length + ' 个端点，' + findings.length + ' 个发现'
        : '扫描完成 — 未发现 GraphQL 端点';
    }
    return lastResult;
  } catch (e) {
    console.debug('[GraphQL] scan error:', e.message);
    if (statusEl) statusEl.textContent = '扫描出错: ' + e.message;
    return null;
  } finally {
    scanning = false;
    if (scanBtn) scanBtn.disabled = false;
  }
}

async function executeCustomQuery() {
  var queryInput = utils.get('graphql-query');
  var statusEl = utils.get('graphql-status');
  var resultsEl = utils.get('graphql-response');

  if (!queryInput || !queryInput.value.trim()) {
    utils.showToast('请输入 GraphQL 查询', 'warning');
    return;
  }

  var url = lastResult ? lastResult.url : '';
  if (!url) {
    var tab = await utils.requireTabId();
    if (!tab || !/^https?:/.test(tab.url)) {
      utils.showToast('请先执行扫描或打开网页', 'warning');
      return;
    }
    url = new URL(tab.url).origin + '/graphql';
  }

  if (statusEl) statusEl.textContent = '执行查询...';

  var payload = JSON.stringify({ query: queryInput.value.trim() });
  var resp = await sendProbe(url, payload);
  var json = parseJsonBody(resp);

  if (resultsEl) {
    if (json) {
      resultsEl.textContent = JSON.stringify(json, null, 2);
      resultsEl.classList.add('has-response');
    } else if (resp && resp.body) {
      resultsEl.textContent = resp.body;
      resultsEl.classList.add('has-response');
    } else {
      resultsEl.textContent = '无响应或响应解析失败';
      resultsEl.classList.remove('has-response');
    }
  }

  if (statusEl) {
    statusEl.textContent =
      resp && !resp.error
        ? '查询完成 — HTTP ' + resp.status
        : '查询失败: ' + (resp ? resp.error : '无响应');
  }
}

function renderResults(result) {
  var resultsEl = utils.get('graphql-results');
  if (!resultsEl) return;

  var html = '';

  if (result.endpoints.length > 0) {
    html += '<div class="graphql-section"><div class="graphql-section-title">发现端点</div>';
    for (var i = 0; i < result.endpoints.length; i++) {
      var ep = result.endpoints[i];
      html += '<div class="graphql-endpoint-row">';
      html += '<span class="graphql-endpoint-path">' + utils.escapeHtml(ep.path) + '</span>';
      html +=
        '<span class="graphql-badge ' + (ep.introspection ? 'badge-high' : 'badge-info') + '">';
      html += ep.introspection ? 'Introspection 开启' : 'Introspection 关闭';
      html += '</span>';
      html += '<span class="graphql-status-tag">HTTP ' + ep.status + '</span>';
      html += '</div>';
    }
    html += '</div>';
  }

  if (result.schemaInfo) {
    var si = result.schemaInfo;
    html += '<div class="graphql-section"><div class="graphql-section-title">Schema 概览</div>';
    html += '<div class="graphql-schema-summary">';
    html += '<span>类型: ' + si.totalTypes + '</span>';
    html += '<span>Query: ' + si.queries.length + '</span>';
    html += '<span>Mutation: ' + si.mutations.length + '</span>';
    html += '<span>Subscription: ' + si.subscriptions.length + '</span>';
    html += '</div>';

    if (si.queries.length > 0) {
      html += '<div class="graphql-type-group"><div class="graphql-type-label">Queries</div>';
      for (var q = 0; q < si.queries.length; q++) {
        html +=
          '<span class="graphql-type-item query">' + utils.escapeHtml(si.queries[q]) + '</span>';
      }
      html += '</div>';
    }
    if (si.mutations.length > 0) {
      html += '<div class="graphql-type-group"><div class="graphql-type-label">Mutations</div>';
      for (var m = 0; m < si.mutations.length; m++) {
        html +=
          '<span class="graphql-type-item mutation">' +
          utils.escapeHtml(si.mutations[m]) +
          '</span>';
      }
      html += '</div>';
    }
    if (si.subscriptions.length > 0) {
      html += '<div class="graphql-type-group"><div class="graphql-type-label">Subscriptions</div>';
      for (var s = 0; s < si.subscriptions.length; s++) {
        html +=
          '<span class="graphql-type-item subscription">' +
          utils.escapeHtml(si.subscriptions[s]) +
          '</span>';
      }
      html += '</div>';
    }

    html += '</div>';
  }

  if (result.findings.length > 0) {
    html += '<div class="graphql-section"><div class="graphql-section-title">安全发现</div>';
    for (var f = 0; f < result.findings.length; f++) {
      var finding = result.findings[f];
      html += '<div class="graphql-finding-row ' + finding.severity + '">';
      html +=
        '<span class="graphql-badge badge-' +
        finding.severity +
        '">' +
        sevLabel(finding.severity) +
        '</span>';
      html += '<span class="graphql-finding-title">' + utils.escapeHtml(finding.title) + '</span>';
      html += '<div class="graphql-finding-detail">' + utils.escapeHtml(finding.detail) + '</div>';
      html += '</div>';
    }
    html += '</div>';
  }

  if (result.batchSupported) {
    html +=
      '<div class="graphql-section"><div class="graphql-info-tag">批量查询: 已启用</div></div>';
  }
  if (result.suggestionsEnabled) {
    html +=
      '<div class="graphql-section"><div class="graphql-info-tag">字段建议: 已启用</div></div>';
  }

  resultsEl.innerHTML = html;
}

function sevLabel(sev) {
  var map = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
  return map[sev] || sev;
}

function copyResults() {
  if (!lastResult) {
    utils.showToast('没有扫描结果', 'warning');
    return;
  }
  var lines = ['GraphQL Security Scan Results', '=================='];
  lines.push('Target: ' + lastResult.url);
  lines.push('');
  if (lastResult.endpoints.length > 0) {
    lines.push('Endpoints:');
    for (var i = 0; i < lastResult.endpoints.length; i++) {
      var ep = lastResult.endpoints[i];
      lines.push(
        '  ' + ep.path + ' (HTTP ' + ep.status + ', introspection: ' + ep.introspection + ')'
      );
    }
    lines.push('');
  }
  if (lastResult.schemaInfo) {
    var si = lastResult.schemaInfo;
    lines.push(
      'Schema: ' +
        si.totalTypes +
        ' types, ' +
        si.queries.length +
        ' queries, ' +
        si.mutations.length +
        ' mutations'
    );
    if (si.queries.length > 0) lines.push('Queries: ' + si.queries.join(', '));
    if (si.mutations.length > 0) lines.push('Mutations: ' + si.mutations.join(', '));
    lines.push('');
  }
  lines.push('Findings:');
  for (var f = 0; f < lastResult.findings.length; f++) {
    var finding = lastResult.findings[f];
    lines.push('[' + finding.severity.toUpperCase() + '] ' + finding.title);
    lines.push('  ' + finding.detail);
  }
  utils.copyAndToast(lines.join('\n'));
}

function exportResults() {
  if (!lastResult) {
    utils.showToast('没有扫描结果', 'warning');
    return;
  }
  var data = {
    url: lastResult.url,
    endpoints: lastResult.endpoints,
    schemaInfo: lastResult.schemaInfo,
    batchSupported: lastResult.batchSupported,
    suggestionsEnabled: lastResult.suggestionsEnabled,
    findings: lastResult.findings,
  };
  utils.downloadBlob(
    new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
    'graphql-scan-' + Date.now() + '.json'
  );
  utils.showToast('结果已导出', 'success');
}

function getFindings() {
  if (!lastResult || !lastResult.findings) return [];
  return lastResult.findings.map(function (f) {
    return {
      severity: f.severity,
      title: 'GraphQL: ' + f.title,
      detail: f.detail,
      module: 'graphql',
      url: lastResult.url || '',
    };
  });
}

export { scanGraphQL, executeCustomQuery, copyResults, exportResults, getFindings };
