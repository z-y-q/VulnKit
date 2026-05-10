// vk-leak-rules-exposure.js -- 灵眸 Chrome Extension
// Exposure + Security Misconfiguration leak detection rules
'use strict';

import { isPlaceholder, shannonEntropy } from './vk-leak-utils.js';

var RULES_EXPOSURE = [
  // ============ Exposure ============
  {
    id: 'internal-ip',
    name: '内网 IP 地址',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex:
      /(?<![0-9.])\b(?:(?:10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168)(?:\.\d{1,3}){2})\b(?![0-9.])/g,
    description: '内网 IP 地址暴露。',
    exploit: '结合 SSRF 可能访问内网服务。',
    recommendation: '移除前端中的内网地址引用。',
  },
  {
    id: 'internal-domain',
    name: '内部域名',
    category: 'exposure',
    severity: 'high',
    confidence: 'suspected',
    regex:
      /(?<![0-9A-Za-z\-])(?:https?:\/\/)?(?:[a-z0-9-]+\.)?(?:internal|intranet|staging|dev|test|local|corp)\.[a-z0-9\-]+/gi,
    description: '内部域名暴露。',
    exploit: '可能发现内部管理后台、API 接口。',
    recommendation: '前端不应引用内部域名。',
  },
  {
    id: 'source-map-reference',
    name: 'Source Map 引用',
    category: 'exposure',
    severity: 'medium',
    confidence: 'confirmed',
    regex: /\/\/[#@]\s*sourceMappingURL=\S+\.map\b/g,
    description: 'Source Map 文件引用暴露，可还原前端源码。',
    exploit: '下载 .map 文件可完整还原前端源码结构。',
    recommendation: '生产环境应移除 sourceMappingURL。',
  },
  {
    id: 'git-exposure',
    name: '.git 暴露',
    category: 'exposure',
    severity: 'high',
    confidence: 'confirmed',
    regex: /['"]\/\.git(?:\/|['"])/g,
    description: '.git 目录路径引用暴露。',
    exploit: '可下载 .git 目录还原整个代码仓库。',
    recommendation: '确保 .git 目录不可通过 Web 访问。',
  },
  {
    id: 'debugger-statement',
    name: '调试断点 (debugger)',
    category: 'exposure',
    severity: 'low',
    confidence: 'suspected',
    regex: /\bdebugger\s*;/g,
    description: '代码中残留 debugger 语句。',
    exploit: '可能导致浏览器暂停执行。',
    recommendation: '生产构建前移除所有 debugger 语句。',
  },
  {
    id: 'console-log-remnant',
    name: '调试代码 (console.log)',
    category: 'exposure',
    severity: 'low',
    confidence: 'suspected',
    regex: /\bconsole\.(?:log|debug|info)\s*\(/g,
    description: '代码中残留 console.log 调试输出。',
    exploit: '可能泄漏敏感数据到浏览器控制台。',
    recommendation: '生产构建前移除所有 console.log。',
  },
  {
    id: 'todo-fixme',
    name: 'TODO/FIXME/HACK 注释',
    category: 'exposure',
    severity: 'info',
    confidence: 'suspected',
    regex: /\/\/\s*(?:TODO|FIXME|XXX|HACK|BUG)\b/i,
    description: '代码注释中的 TODO/FIXME 标记。',
    exploit: '可能暗示未完成的功能或已知缺陷。',
    recommendation: '生产构建前清理或评估这些标记。',
  },
  {
    id: 'session-cookie-token',
    name: 'Session/Cookie Token',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /(?:sessionid|session_id|connect\.sid|JSESSIONID|PHPSESSID|remember[\-_]?token|csrf[\-_]?token|xsrf[\-_]?token)["'\s:=]+["']?([A-Za-z0-9.~+\/=\-_]{20,200})["']?/gi,
    description: '会话、CSRF/XSRF 或记住登录 Token 硬编码。',
    exploit: '可能用于复用会话、绕过 CSRF。',
    recommendation: '会话类 Token 必须由服务端动态签发。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    },
  },

  // ============ Security Misconfiguration ============
  {
    id: 'cors-wildcard',
    name: 'CORS 通配符',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /Access-Control-Allow-Origin["']\s*[:=]\s*["']\*["']/gi,
    description: 'CORS 配置为允许所有来源。',
    exploit: '任意域均可跨域访问该资源。',
    recommendation: '限制 CORS 来源为可信域名。',
  },
  {
    id: 'csp-unsafe',
    name: 'CSP 禁用',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /Content-Security-Policy["']\s*[:=]\s*["']unsafe/gi,
    description: 'CSP 策略包含 unsafe 指令。',
    exploit: '可能允许执行内联脚本。',
    recommendation: '移除 unsafe-inline/unsafe-eval，使用 nonce/hash。',
  },
  {
    id: 'postMessage-no-origin',
    name: 'postMessage 无 origin 校验',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /postMessage\s*\([^)]*\)/g,
    description: 'postMessage 调用可能未校验来源。',
    exploit: '可能遭受跨域消息注入攻击。',
    recommendation: '使用 event.origin 校验消息来源。',
  },
  {
    id: 'eval-usage',
    name: 'eval() 使用',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /\beval\s*\(/g,
    description: '使用 eval() 动态执行代码。',
    exploit: '若输入可控则可能产生代码注入。',
    recommendation: '避免使用 eval()，改用 JSON.parse 或显式函数调用。',
  },
  {
    id: 'innerhtml-assignment',
    name: 'innerHTML 赋值',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /innerHTML\s*=/g,
    description: '直接使用 innerHTML 赋值。',
    exploit: '若值包含用户输入则可能产生 XSS。',
    recommendation: '使用 textContent 或 DOM API 替代。',
  },
  {
    id: 'localStorage-sensitive',
    name: 'localStorage 敏感数据',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /localStorage\.(?:setItem|set)\s*\(\s*["'](?:token|auth|session|password|secret|key)/gi,
    description: '将敏感数据存入 localStorage。',
    exploit: 'XSS 攻击可直接读取 localStorage 中的敏感数据。',
    recommendation: '敏感数据不存 localStorage；使用 HttpOnly Cookie。',
  },
  {
    id: 'swagger-endpoint',
    name: 'Swagger/OpenAPI 端点',
    category: 'exposure',
    severity: 'info',
    confidence: 'suspected',
    regex: /["']\/(?:swagger|api-docs|openapi|graphql)(?:\/)?["']/gi,
    description: 'API 文档端点引用。',
    exploit: '可能暴露完整 API 文档。',
    recommendation: '生产环境关闭 API 文档端点。',
  },
  {
    id: 'spring-actuator',
    name: 'Spring Actuator',
    category: 'exposure',
    severity: 'info',
    confidence: 'suspected',
    regex: /["']\/(?:actuator|env|health|metrics|trace|beans|mappings)(?:\/)?["']/gi,
    description: 'Spring Boot Actuator 端点引用。',
    exploit: '可能暴露环境变量、堆栈信息等敏感数据。',
    recommendation: '生产环境禁用或保护 Actuator 端点。',
  },
  {
    id: 'backup-file-path',
    name: '备份文件路径',
    category: 'exposure',
    severity: 'info',
    confidence: 'suspected',
    regex: /["'](?:backup|\.bak|\.old|\.orig|\.save|\.tar|\.zip|\.sql|\.dump)["']/gi,
    description: '备份文件路径引用。',
    exploit: '可能下载备份文件获取敏感数据。',
    recommendation: '清理生产环境中的备份文件。',
  },
  {
    id: 'env-config-reference',
    name: '环境配置引用',
    category: 'exposure',
    severity: 'info',
    confidence: 'suspected',
    regex: /process\.env\.[A-Z_]+/g,
    description: 'Node.js 环境变量引用可能泄漏配置名。',
    exploit: '了解配置名可辅助定向攻击。',
    recommendation: '前端构建时替换环境变量为实际值或移除。',
  },
  {
    id: 'huawei-oss-config',
    name: '华为云 OBS 配置凭证',
    category: 'secret',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /huawei\.oss\.(?:ak|sk|bucket\.name|endpoint|local\.path)["'\s:=]+["']?([A-Za-z0-9_.\-]{8,160})["']?/gi,
    description: '华为云对象存储相关 AK/SK、bucket 或 endpoint 配置。',
    exploit: '若同时存在 AK/SK，可直接访问对象存储资源。',
    recommendation: 'AK/SK 只允许存放在服务端密钥管理中。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (/bucket|endpoint|local/i.test(ctx.match))
        return {
          severity: 'medium',
          confidence: 'likely',
          evidence: '对象存储 bucket/endpoint 配置暴露',
        };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    },
  },
  {
    id: 'twilio-account-sid',
    name: 'Twilio Account SID',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex: /\bAC[a-f0-9]{32}\b/g,
    description: 'Twilio Account SID（仅 SID 不足以调用 API）。',
    exploit: '需配合 Auth Token；若同源出现 Auth Token 则可发短信/拨电话。',
    recommendation: '若同源含 Auth Token 应立即轮换。',
    validate: function (ctx) {
      var w = 800;
      var seg = ctx.source.slice(
        Math.max(0, ctx.offset - w),
        Math.min(ctx.source.length, ctx.offset + w)
      );
      if (/(?:auth[\-_]?token|TWILIO_AUTH_TOKEN)["'\s:=]+["']?[a-f0-9]{32}/i.test(seg)) {
        return {
          severity: 'critical',
          confidence: 'confirmed',
          evidence: '同源出现 AuthToken，构成完整凭证',
        };
      }
      return null;
    },
  },
  {
    id: 'docker-token',
    name: 'Docker/Registry Token 或密码',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /docker[\-_]?(?:token|password|key|hub[\-_]?password)["'\s:=]+["']?([A-Za-z0-9._~+\/=\-_]{16,180})["']?/gi,
    description: 'Docker Hub 或私有镜像仓库相关 token/password。',
    exploit: '可用于拉取/推送镜像，造成供应链污染或私有镜像泄露。',
    recommendation: '撤销并重建 Docker/Registry Token。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    },
  },
  {
    id: 'gcp-service-account-json',
    name: 'GCP Service Account 密钥 JSON',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"-----BEGIN/g,
    description: 'GCP 服务账号密钥完整 JSON 块，包含 RSA 私钥。',
    exploit: '直接加载该 JSON 即可调用 GCP API，权限等同于该服务账号。',
    recommendation: '立即在 GCP IAM 中删除该密钥，改用 Workload Identity。',
  },
  {
    id: 'kubernetes-service-account-token',
    name: 'Kubernetes Service Account Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex:
      /eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9\-_]{10,}\.eyJpc3MiOiJrdWJlcm5ldGVz\/serviceaccount[A-Za-z0-9\-_.]*/g,
    description: 'Kubernetes Service Account JWT Token，可用于 API Server 认证。',
    exploit: '携带 Token 调用 kube-apiserver，权限取决于 SA 绑定的 RBAC。',
    recommendation: '删除泄露的 SA Secret，审查 RBAC 权限，启用审计日志。',
  },
  {
    id: 'kubernetes-config-yaml',
    name: 'Kubernetes kubeconfig 内容',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /certificate-authority-data\s*:\s*[A-Za-z0-9+\/=]{100,}[\s\S]{0,200}client-certificate-data\s*:\s*[A-Za-z0-9+\/=]{100,}/g,
    description: 'kubeconfig 中的集群 CA 证书和客户端证书同时出现。',
    exploit: '配合可能的 client-key-data 可获得集群访问权限。',
    recommendation: '轮换集群证书，审查 RBAC，删除泄露的 kubeconfig。',
  },
  {
    id: 'elastic-search-password',
    name: 'Elasticsearch 凭据',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /(?:ELASTIC(?:SEARCH)?[_-]?PASSWORD|elastic[_-]?password|x-pack[_-]?password)["'\s:=]+["']?([^\s"'`,;}{]{8,120})["']?/gi,
    description: 'Elasticsearch 密码或 X-Pack 凭据。',
    exploit: '访问 Elasticsearch API（9200 端口）查询/删除索引数据。',
    recommendation: '轮换密码，启用 TLS，限制网络访问。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.5) return { drop: true };
      return null;
    },
  },
  {
    id: 'redis-standalone-uri',
    name: 'Redis 独立连接串',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /redis:\/\/(?::([^@"'\s<>]{4,}))?@([A-Za-z0-9.\-]+)(?::\d{1,5})?(?:\/\d*)?/g,
    description: 'Redis 连接串（含可选密码）。',
    exploit: '直接 `redis-cli -a password -h host -p port` 连接，可读写缓存数据。',
    recommendation: '启用 requirepass + ACL，禁用 FLUSHALL，限制访问源 IP。',
    validate: function (ctx) {
      var m = ctx.match.match(/redis:\/\/:([^@"'\s<>]+)/);
      if (!m) return null;
      if (isPlaceholder(m[1])) return { drop: true };
      return { evidence: '含密码: redis://:****@' };
    },
  },
  {
    id: 'ssh-private-key-inline',
    name: 'SSH 私钥（非 PEM 格式）',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /ssh-(?:rsa|ed25519|ecdsa|dss)\s+[A-Za-z0-9+/=.@\-_]{100,}/g,
    description: 'OpenSSH 单行格式私钥（ssh-rsa / ssh-ed25519 等）。',
    exploit: '写入 ~/.ssh/id_rsa 后可直接 SSH 登录对应服务器。',
    recommendation: '立即吊销对应公钥授权，轮换服务器 SSH 密钥。',
  },
  {
    id: 'jenkins-crumb-secret',
    name: 'Jenkins CRUMB/凭据',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /(?:JENKINS[_-]?TOKEN|jenkins[_-]?crumb|\.crumb)["'\s:=]+["']?([A-Za-z0-9\-_\.]{16,120})["']?/gi,
    description: 'Jenkins CSRF crumb 或 API token。',
    exploit: '配合 crumb 可发送 CSRF 保护的请求（触发构建等）。',
    recommendation: '轮换 Jenkins API Token，限制 who-can-use。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.5) return { drop: true };
      return null;
    },
  },
  {
    id: 'grafana-api-key',
    name: 'Grafana API Key',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex: /(?:GRAFANA[_-]?API[_-]?KEY|grafana[_-]?token|eyJrIjoi[A-Za-z0-9\-_]{20,})/gi,
    description: 'Grafana API Key 或 Service Account Token（eyJrIjoi 前缀）。',
    exploit: '调用 Grafana API 查询/修改 Dashboard、数据源配置。',
    recommendation: 'Grafana > Service Accounts 中撤销 Token。',
    validate: function (ctx) {
      if (/eyJrIjoi[A-Za-z0-9\-_]{20,}/.test(ctx.match))
        return {
          confidence: 'confirmed',
          evidence: 'Grafana Service Account Token (eyJrIjoi 前缀)',
        };
      if (ctx.captured && isPlaceholder(ctx.captured)) return { drop: true };
      return null;
    },
  },
  {
    id: 'azure-ad-client-secret',
    name: 'Azure AD Client Secret',
    category: 'secret',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:AZURE[_-]?AD[_-]?SECRET|azure[_-]?client[_-]?secret|MICROSOFT[_-]?CLIENT[_-]?SECRET)["'\s:=]+["']?([A-Za-z0-9\-_~.]{24,120})["']?/gi,
    description: 'Azure Active Directory / Entra ID 应用 Client Secret。',
    exploit: '结合 tenant_id 和 client_id 可获取 access_token 访问 Microsoft Graph / Azure API。',
    recommendation: 'Azure Portal > App registrations 轮换 Client Secret。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    },
  },
];

export { RULES_EXPOSURE };
