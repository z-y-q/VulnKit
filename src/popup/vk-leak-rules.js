// vk-leak-rules.js -- 灵眸 Chrome Extension
// Leak detection rules migrated from AegisScope + original VulnKit rules
// Each rule: { id, name, category, severity, confidence, regex, description, exploit, recommendation, validate? }

// ---------- Utility functions ----------

function b64urlToStr(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    var bin = atob(s);
    try {
      return decodeURIComponent(escape(bin));
    } catch (_) {
      return bin;
    }
  } catch (_) {
    return null;
  }
}

function luhnOk(num) {
  var d = String(num).replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  var sum = 0,
    alt = false;
  for (var i = d.length - 1; i >= 0; i--) {
    var n = d.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function shannonEntropy(str) {
  if (!str) return 0;
  var f = {};
  for (var i = 0; i < str.length; i++) {
    var c = str[i];
    f[c] = (f[c] || 0) + 1;
  }
  var h = 0,
    L = str.length;
  for (var k in f) {
    var p = f[k] / L;
    h -= p * Math.log2(p);
  }
  return h;
}

var PLACEHOLDER_LITERALS = [
  'your-api-key',
  'your_api_key',
  'xxxxxxxx',
  'changeme',
  'placeholder',
  'example',
  'test',
  'demo',
  'todo',
  'replace-me',
  'null',
  'undefined',
  'password',
  'string',
  '',
  'secret',
  'apikey',
  'token',
  '00000000000000000000',
  '11111111111111111111',
];

function isPlaceholder(v) {
  var s = String(v || '')
    .trim()
    .toLowerCase();
  if (PLACEHOLDER_LITERALS.indexOf(s) !== -1) return true;
  if (/^(.)\1+$/.test(s)) return true;
  if (/^x+$/i.test(s)) return true;
  if (/^<[^>]+>$/.test(s)) return true;
  if (/^(?:abcdef|123456|qwerty)/i.test(s) && s.length < 16) return true;
  return false;
}

function inCryptoContext(source, offset, len) {
  var w = 300;
  var lo = Math.max(0, offset - w);
  var hi = Math.min(source.length, offset + len + w);
  var ctx = source.slice(lo, hi);
  return /(?:CryptoJS\.(?:AES|DES|TripleDES|RC4)\s*\.\s*(?:encrypt|decrypt)|crypto\.(?:createCipher(?:iv)?|createDecipher(?:iv)?)|crypto\.subtle\.(?:encrypt|decrypt|importKey)|JSEncrypt|forge\.cipher|sm[234]\.(?:encrypt|decrypt|do(?:En|De)crypt))/i.test(
    ctx
  );
}

// ---------- Rule definitions ----------

var RULES = [
  // ============ Cloud / SaaS Credentials ============
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g,
    description: 'AWS 访问密钥 ID 格式精确匹配，泄漏可直接用于 AWS 控制平面调用。',
    exploit: '`aws sts get-caller-identity` 立即验证账户/权限；若同时泄漏 SecretKey 即可完全控制。',
    recommendation: '在 IAM 控制台 deactivate 该 Key，审计 CloudTrail。',
    validate: function (ctx) {
      if (
        ctx.match.startsWith('ASIA') &&
        !/(?:x-amz-security-token|sessionToken|session_token)/i.test(
          ctx.source.slice(
            Math.max(0, ctx.offset - 500),
            Math.min(ctx.source.length, ctx.offset + 500)
          )
        )
      ) {
        return { confidence: 'likely', evidence: 'STS 临时凭证但未见配套 SessionToken' };
      }
      return null;
    },
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex:
      /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key|SecretAccessKey)["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/g,
    description: '与 AWS Access Key 配套的密钥本体，泄漏后等同于完整凭证。',
    exploit: '配合 Access Key ID 即可直接 sign API 请求。',
    recommendation: '立即吊销并轮换；前端绝不可硬编码。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 4.0) return { drop: true };
      return null;
    },
  },
  {
    id: 'aliyun-accesskey-id',
    name: '阿里云 AccessKey ID',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bLTAI(?:5t|4G|4F)[A-Za-z0-9]{12,20}\b/g,
    description: '阿里云 AccessKey ID（LTAI 前缀含子类型）。',
    exploit:
      '使用 aliyun-cli `aliyun sts GetCallerIdentity` 验证；若搭配 Secret 可直接控制 ECS/OSS/RAM。',
    recommendation: 'RAM 控制台禁用 Key，迁至 STS 临时凭证。',
  },
  {
    id: 'tencent-secret-id',
    name: '腾讯云 SecretId',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bAKID[A-Za-z0-9]{32,40}\b/g,
    description: '腾讯云 API SecretId。',
    exploit: '搭配 SecretKey 可调用 TencentCloud API。',
    recommendation: 'CAM 控制台禁用 Key。',
  },
  {
    id: 'gcp-api-key',
    name: 'Google API Key',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    description: 'Google/Firebase API Key（39 字符精确格式）。',
    exploit: '调用未限制 referer 的 Google Maps/YouTube API 产生费用。',
    recommendation: '在 GCP 控制台为 Key 配置 HTTP referer / IP / API 白名单。',
  },
  {
    id: 'gcp-oauth-token',
    name: 'Google OAuth Access Token',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /\bya29\.[0-9A-Za-z\-_]{30,}\b/g,
    description: 'Google OAuth 2.0 访问令牌。',
    exploit: '直接 `Authorization: Bearer ya29.xxx` 调用 Google APIs。',
    recommendation: '吊销 token 并审计 OAuth 授权应用。',
  },
  {
    id: 'azure-storage-conn',
    name: 'Azure Storage 连接字符串',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex:
      /DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+\/=]{86,90}(?:;EndpointSuffix=[\w.]+)?/g,
    description: 'Azure 存储账户完整连接串。',
    exploit: '使用 Azure Storage Explorer 直接登录。',
    recommendation: '轮换 Account Key，改用 SAS 短期令牌。',
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{24,99}\b/g,
    description: 'Stripe 生产环境私钥。',
    exploit: '调用 Stripe API 创建/退款/导出客户付款数据。',
    recommendation: 'Dashboard 立即 roll key；前端只能使用 pk_ 公钥。',
    validate: function (ctx) {
      if (ctx.match.startsWith('sk_test_') || ctx.match.startsWith('rk_test_'))
        return { severity: 'medium', confidence: 'likely', evidence: '测试环境 Key' };
      return null;
    },
  },
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
    description: 'SendGrid API Key（前缀 SG. + 两段固定长度）。',
    exploit: '直接调用 SendGrid 发送任意邮件。',
    recommendation: 'Dashboard 删除该 Key 并轮换。',
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b/g,
    description: 'GitHub PAT / OAuth / Refresh / App Token。',
    exploit: '直接调用 GitHub API 验证身份，可读写授权范围内的仓库。',
    recommendation: 'Settings > Developer settings 立即吊销。',
  },
  {
    id: 'gitlab-pat',
    name: 'GitLab Personal Access Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bglpat-[A-Za-z0-9\-_]{20,}\b/g,
    description: 'GitLab PAT。',
    exploit: '调用 GitLab API 读写仓库、CI 变量。',
    recommendation: '吊销并启用 IP 限制。',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bxox[abprs]-(?:\d+-){2,}[A-Za-z0-9]{24,40}\b/g,
    description: 'Slack Bot/User/App/Refresh Token。',
    exploit: '调用 chat.postMessage、users.list 等 API。',
    recommendation: 'Slack App 控制台 revoke token。',
  },
  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
    description: 'Slack 入站 Webhook URL。',
    exploit: 'POST JSON 到该 URL 即可向绑定频道发送任意消息。',
    recommendation: 'Slack App 删除该 Webhook 并替换。',
  },
  {
    id: 'discord-webhook',
    name: 'Discord Webhook',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[\w-]{60,}/g,
    description: 'Discord Webhook URL。',
    exploit: 'POST 即可发消息/上传文件到目标频道。',
    recommendation: '服务器设置删除该 Webhook。',
  },
  {
    id: 'wechat-work-webhook',
    name: '企业微信 Webhook',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /https:\/\/qyapi\.weixin\.qq\.com\/cgi-bin\/webhook\/send\?key=[A-Za-z0-9\-]{25,80}/g,
    description: '企业微信机器人 Webhook URL。',
    exploit: 'POST JSON 到该 URL 可向绑定群发送消息。',
    recommendation: '删除或轮换 Webhook key，并限制机器人使用范围。',
  },
  {
    id: 'dingtalk-robot-webhook',
    name: '钉钉机器人 Webhook',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /https:\/\/oapi\.dingtalk\.com\/robot\/send\?access_token=[a-f0-9]{50,90}/g,
    description: '钉钉机器人 Webhook access_token。',
    exploit: '可向钉钉群发送任意消息。',
    recommendation: '重置 access_token，并开启加签和关键词限制。',
  },
  {
    id: 'feishu-bot-webhook',
    name: '飞书机器人 Webhook',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /https:\/\/open\.feishu\.cn\/open-apis\/bot\/v2\/hook\/[A-Za-z0-9\-]{25,90}/g,
    description: '飞书机器人 Webhook URL。',
    exploit: '可向飞书群发送任意消息，造成钓鱼或告警污染。',
    recommendation: '重置 Webhook 并开启签名校验。',
  },
  {
    id: 'npm-token',
    name: 'npm Access Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    description: 'npm 发布令牌。',
    exploit: '`npm whoami --registry ...` 验证；可发布恶意包到所属 scope。',
    recommendation: 'npmjs.com 立即 revoke。',
  },
  {
    id: 'mailgun-key',
    name: 'Mailgun API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bkey-[a-f0-9]{32}\b/g,
    description: 'Mailgun API Key（key- + 32 hex）。',
    exploit: '直接调用 Mailgun 发邮件 API。',
    recommendation: 'Dashboard 轮换 Key。',
  },
  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9\-_]{32,}\b/g,
    description: 'OpenAI API Key，泄露后可直接调用模型接口产生费用和数据风险。',
    exploit: '使用 Authorization: Bearer 调用 OpenAI API 验证权限。',
    recommendation: '立即在 OpenAI 控制台撤销并轮换 Key。',
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g,
    description: 'Anthropic API Key，泄露后可直接调用 Claude API。',
    exploit: '携带 x-api-key 请求 Anthropic API 即可验证。',
    recommendation: '立即 revoke 并改为服务端保存。',
  },
  {
    id: 'telegram-bot-token',
    name: 'Telegram Bot Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\b\d{8,10}:[A-Za-z0-9\-_]{35}\b/g,
    description: 'Telegram Bot Token，泄露后可控制机器人发送消息、读取更新。',
    exploit: '访问 https://api.telegram.org/bot/getMe 验证机器人身份。',
    recommendation: '通过 BotFather revoke 并重新生成 Token。',
  },
  {
    id: 'discord-bot-token',
    name: 'Discord Bot/User Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex:
      /\b(?:mfa\.[A-Za-z0-9\-_]{80,}|[MN][A-Za-z0-9\-_]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})\b/g,
    description: 'Discord Bot 或用户 Token，泄露后可控制账号或机器人。',
    exploit: '使用 Authorization 头访问 Discord API 验证身份。',
    recommendation: '在 Discord Developer Portal 轮换 Bot Token。',
  },
  {
    id: 'notion-integration-token',
    name: 'Notion Integration Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bsecret_[A-Za-z0-9]{43}\b/g,
    description: 'Notion 内部集成 Token，泄露后可访问已授权 workspace 页面和数据库。',
    exploit: '携带 `Authorization: Bearer secret_xxx` 调用 Notion API。',
    recommendation: '立即在 Notion integrations 中 rotate/revoke。',
  },
  {
    id: 'linear-api-key',
    name: 'Linear API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\blin_api_[A-Za-z0-9]{32,}\b/g,
    description: 'Linear API Key，可访问组织 issue、团队和项目数据。',
    exploit: '携带 `Authorization: ` 调用 Linear GraphQL API。',
    recommendation: '立即撤销并重新生成 Linear API Key。',
  },
  {
    id: 'shopify-access-token',
    name: 'Shopify Access Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\bshp(?:at|ss|ca|ua)_[a-fA-F0-9]{32}\b/g,
    description: 'Shopify Admin/Storefront/Custom App Token。',
    exploit: '携带 `X-Shopify-Access-Token` 调用对应店铺 Admin API。',
    recommendation: '在 Shopify 后台撤销应用 Token。',
  },
  {
    id: 'sentry-dsn',
    name: 'Sentry DSN',
    category: 'secret',
    severity: 'low',
    confidence: 'confirmed',
    regex: /https:\/\/[A-Fa-f0-9]{16,64}@o\d+\.ingest\.sentry\.io\/\d+/g,
    description: 'Sentry DSN 暴露通常不是高危凭证，但可能被用于污染错误日志。',
    exploit: '向 DSN 发送伪造事件，观察是否污染告警。',
    recommendation: '配置速率限制、来源过滤和告警降噪。',
  },
  {
    id: 'cloudflare-token',
    name: 'Cloudflare Token / API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|CF_TOKEN|cloudflare[\-_]?(?:api[\-_]?)?(?:token|key))["'\s:=]+["']?([A-Za-z0-9\-_]{30,120})["']?/gi,
    description: 'Cloudflare API Token 或 Global API Key。',
    exploit: '可调用 Cloudflare API 修改 DNS、Worker、Zone 配置。',
    recommendation: 'Cloudflare Dashboard 立即撤销 Token。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.2) return { drop: true };
      return null;
    },
  },
  {
    id: 'vercel-token',
    name: 'Vercel Token',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex: /(?:VERCEL_TOKEN|vercel[\-_]?token)["'\s:=]+["']?([A-Za-z0-9\-_]{24,120})["']?/gi,
    description: 'Vercel API Token，可能访问项目、部署、环境变量。',
    exploit: '使用 `Authorization: Bearer` 调用 Vercel API。',
    recommendation: 'Vercel Account Settings 中撤销 Token。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.1) return { drop: true };
      return null;
    },
  },
  {
    id: 'netlify-token',
    name: 'Netlify Access Token',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /(?:NETLIFY_AUTH_TOKEN|NETLIFY_TOKEN|netlify[\-_]?(?:auth[\-_]?)?token)["'\s:=]+["']?([A-Za-z0-9\-_]{32,120})["']?/gi,
    description: 'Netlify Personal Access Token。',
    exploit: '携带 Bearer Token 调用 Netlify API。',
    recommendation: 'Netlify User Settings 中撤销 Token。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.1) return { drop: true };
      return null;
    },
  },
  {
    id: 'huggingface-token',
    name: 'HuggingFace Access Token',
    category: 'secret',
    severity: 'high',
    confidence: 'confirmed',
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    description: 'HuggingFace 访问令牌，可能拥有模型、数据集或推理 API 权限。',
    exploit: '调用 HuggingFace API /whoami-v2 验证令牌权限。',
    recommendation: '在 HuggingFace Settings > Access Tokens 中撤销并重建。',
  },
  {
    id: 'supabase-service-role-key',
    name: 'Supabase Service Role Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:supabase(?:ServiceRole|_SERVICE_ROLE)?|service[\-_]?role(?:[\-_]?key)?|SUPABASE_SERVICE_ROLE_KEY)["'\s:=]+["']?(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["']?/gi,
    description: 'Supabase service_role JWT 具备绕过 RLS 的高权限。',
    exploit: '携带 apikey/Authorization Bearer 调用 Supabase REST API，可绕过行级安全策略。',
    recommendation: '仅在后端环境变量中保存 service_role。',
  },
  {
    id: 'firebase-config-exposure',
    name: 'Firebase 配置暴露',
    category: 'secret',
    severity: 'medium',
    confidence: 'likely',
    regex:
      /apiKey\s*:\s*["'](AIza[0-9A-Za-z\-_]{35})["'][\s\S]{0,600}authDomain\s*:\s*["'][^"']+firebaseapp\.com["']/g,
    description: 'Firebase Web 配置暴露。apiKey 本身不等同私钥，但常用于定位项目。',
    exploit:
      '结合 projectId/authDomain 测试 Firestore/Realtime Database/Storage Rules 是否允许未授权读写。',
    recommendation: '确认 Firebase Security Rules 严格限制读写。',
  },
  {
    id: 'bearer-auth-token',
    name: 'Bearer 认证 Token',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex: /["']Bearer\s+([A-Za-z0-9.~+\/=\-_]{20,500})["']/g,
    description: '硬编码 Bearer Token，可能是 OAuth/JWT/API 访问令牌。',
    exploit: '直接放入 `Authorization: Bearer` 请求头复用。',
    recommendation: 'Bearer Token 不应写入前端源码。',
    validate: function (ctx) {
      var token = ctx.captured;
      if (isPlaceholder(token)) return { drop: true };
      if (/^eyJ[A-Za-z0-9\-_]+\./.test(token))
        return {
          severity: 'critical',
          confidence: 'confirmed',
          evidence: 'Bearer 中包含 JWT 结构',
        };
      if (shannonEntropy(token) < 3.2) return { drop: true };
      return null;
    },
  },
  {
    id: 'api-key-header',
    name: 'API Key 请求头',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /["'](?:x-api-key|api-key|apikey|x-auth-token|authorization)["']\s*:\s*["']([A-Za-z0-9.~+\/=\-_]{16,180})["']/gi,
    description: '常见认证请求头中硬编码 API Key / Token。',
    exploit: '复用对应 Header 即可尝试访问后端 API。',
    recommendation: '认证 Header 值应由后端签发或运行时短期下发。',
    validate: function (ctx) {
      var v = ctx.captured;
      if (/^(?:Bearer|Basic)\s+/i.test(v)) return { drop: true };
      if (isPlaceholder(v)) return { drop: true };
      if (shannonEntropy(v) < 3.0) return { drop: true };
      return null;
    },
  },
  {
    id: 'oauth-client-secret',
    name: 'OAuth Client Secret',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex:
      /(?:client[\-_]?secret|oauth[\-_]?secret|OIDC_CLIENT_SECRET|GOOGLE_CLIENT_SECRET)["'\s:=]+["']?([A-Za-z0-9_\-./+=]{20,160})["']?/gi,
    description: 'OAuth/OIDC Client Secret 硬编码。',
    exploit: '结合 client_id、redirect_uri、授权码流程尝试换取 access_token。',
    recommendation: 'Client Secret 仅存后端；公开客户端使用 PKCE。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    },
  },
  {
    id: 'jwt-session-signing-secret',
    name: 'JWT/Session 签名密钥',
    category: 'secret',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:jwt[\-_]?secret|secretOrKey|signing[\-_]?key|session[\-_]?secret|cookie[\-_]?secret|csrf[\-_]?secret)["'\s:=]+["']?([^"'\s,;}{]{16,160})["']?/gi,
    description: 'JWT、Session、Cookie 或 CSRF 签名密钥硬编码。',
    exploit: '攻击者可离线签发 JWT、伪造 Session Cookie 或 CSRF Token。',
    recommendation: '立即轮换签名密钥并使旧 Token/Session 失效。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (/^(?:true|false|null|undefined)$/i.test(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
      return null;
    },
  },
  {
    id: 'wechat-app-id',
    name: '微信/企业微信 AppID',
    category: 'exposure',
    severity: 'low',
    confidence: 'likely',
    regex: /\b(?:wx[a-z0-9]{15,18}|ww[a-z0-9]{15,18})\b/g,
    description: '微信小程序、公众号或企业微信 AppID 暴露。',
    exploit: '结合 AppSecret、回调地址可用于进一步攻击面定位。',
    recommendation: '确认仅暴露允许公开的 AppID。',
  },

  // ============ Crypto Vulnerabilities ============
  {
    id: 'aes-ecb-mode',
    name: 'AES ECB 模式',
    category: 'crypto-vuln',
    severity: 'high',
    confidence: 'confirmed',
    regex:
      /\b(?:mode\s*[:=]\s*CryptoJS\.mode\.ECB|"aes-(?:128|192|256)-ecb\"|'aes-(?:128|192|256)-ecb')\b/g,
    description: 'AES ECB 模式相同明文块产生相同密文块，泄漏明文模式。',
    exploit: '相同 16 字节块加密结果完全一致，攻击者可通过频率分析恢复明文结构。',
    recommendation: '改用 GCM（AEAD）或 CBC + 随机 IV + HMAC。',
  },
  {
    id: 'hardcoded-aes-key',
    name: '硬编码 AES 密钥',
    category: 'crypto-vuln',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:key|KEY|secretKey|aesKey|encryptKey|cryptoKey)\s*[:=]\s*(?:CryptoJS\.enc\.\w+\.parse\(\s*)?["']([A-Za-z0-9+/=_\-]{16,64})["']/g,
    description: '位于加密调用上下文中的对称密钥字面量。',
    exploit: '直接复制密钥即可解密所有由前端加密的请求/响应。',
    recommendation: '密钥不应硬编码在前端；改为后端下发的会话密钥。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.5) return { drop: true };
      if (!inCryptoContext(ctx.source, ctx.offset, ctx.match.length)) return { drop: true };
      return { evidence: 'key 位于实际加密调用 ±300 字符内' };
    },
  },
  {
    id: 'hardcoded-iv',
    name: '硬编码 IV / Nonce',
    category: 'crypto-vuln',
    severity: 'high',
    confidence: 'likely',
    regex:
      /\b(?:iv|IV|nonce)\s*[:=]\s*(?:CryptoJS\.enc\.\w+\.parse\(\s*)?["']([0-9a-fA-F]{16,64}|[A-Za-z0-9+/=_\-]{12,32})["']/g,
    description: '加密 IV/Nonce 看起来是固定的字面量。',
    exploit: 'CBC 固定 IV → 同明文同密文；GCM/CTR 固定 IV+key → 灾难性。',
    recommendation: 'IV 必须使用 crypto.getRandomValues 随机生成。',
    validate: function (ctx) {
      var isAllSame = /^(.)\1+$/.test(ctx.captured);
      if (!inCryptoContext(ctx.source, ctx.offset, ctx.match.length)) return { drop: true };
      if (isAllSame) {
        return {
          confidence: 'confirmed',
          evidence:
            (/^0+$/.test(ctx.captured) ? '全 0' : '全相同字符') + ' IV，加密上下文中确定可利用',
        };
      }
      if (isPlaceholder(ctx.captured)) return { drop: true };
      return null;
    },
  },
  {
    id: 'weak-md5-security',
    name: 'MD5 用于安全场景',
    category: 'crypto-vuln',
    severity: 'high',
    confidence: 'likely',
    regex: /\b(?:CryptoJS\.MD5|md5)\s*\(\s*([^)]{1,200})\)/g,
    description: 'MD5 抗碰撞已破，禁止用于密码哈希、签名、消息认证。',
    exploit: '彩虹表/碰撞攻击可在分钟级恢复弱口令。',
    recommendation: '密码用 bcrypt/argon2/scrypt；消息认证用 HMAC-SHA256。',
    validate: function (ctx) {
      var arg = ctx.captured || '';
      if (!/(?:password|passwd|pwd|secret|token|sign|signature|key|salt|auth|hmac)/i.test(arg))
        return { drop: true };
      return { evidence: '参数含 password/token/secret 等安全敏感关键字' };
    },
  },
  {
    id: 'weak-sha1-security',
    name: 'SHA-1 用于安全场景',
    category: 'crypto-vuln',
    severity: 'medium',
    confidence: 'likely',
    regex: /\b(?:CryptoJS\.SHA1|sha1)\s*\(\s*([^)]{1,200})\)/g,
    description: 'SHA-1 已被构造碰撞（SHAttered），不应用于签名/证书/HMAC。',
    exploit: '可构造两份不同内容产生相同 SHA-1。',
    recommendation: '替换为 SHA-256 或 SHA-3。',
    validate: function (ctx) {
      var arg = ctx.captured || '';
      if (!/(?:password|passwd|pwd|secret|token|sign|signature|key|salt|auth)/i.test(arg))
        return { drop: true };
      return null;
    },
  },
  {
    id: 'weak-cipher-des-rc4',
    name: '使用 DES / 3DES / RC4',
    category: 'crypto-vuln',
    severity: 'high',
    confidence: 'confirmed',
    regex:
      /\b(?:CryptoJS\.(?:DES|TripleDES|RC4|Rabbit)\.(?:encrypt|decrypt)|"des-ede3?-(?:cbc|ecb)"|'des-ede3?-(?:cbc|ecb)')\b/g,
    description: 'DES/3DES/RC4 均已淘汰。',
    exploit: 'DES 56 位密钥可暴破，RC4 流密码已被多种攻击攻破。',
    recommendation: '统一替换为 AES-256-GCM。',
  },
  {
    id: 'rsa-pkcs1-v15',
    name: 'RSA PKCS#1 v1.5 / NoPadding',
    category: 'crypto-vuln',
    severity: 'medium',
    confidence: 'likely',
    regex:
      /(?:setOptions\s*\(\s*\{\s*encryptionScheme\s*:\s*["']pkcs1["']|RSA(?:[-_])?(?:PKCS1Padding|NoPadding))/g,
    description: 'PKCS#1 v1.5 易受 Bleichenbacher padding oracle。',
    exploit: '若服务端能区分填充错误，可在百万级请求内恢复明文。',
    recommendation: '加密用 RSA-OAEP，签名用 RSA-PSS。',
  },
  {
    id: 'math-random-as-crypto',
    name: 'Math.random 用作密码学随机',
    category: 'crypto-vuln',
    severity: 'high',
    confidence: 'confirmed',
    regex:
      /\b(?:key|iv|IV|nonce|salt|token|secret|sessionId|csrf)\s*=\s*(?:[^=;\n]{0,80}?)Math\.random\s*\(/gi,
    description: 'Math.random 是非密码学伪随机数生成器，输出可预测。',
    exploit: 'V8 的 Math.random 使用 xorshift128+，已有论文展示通过几个连续输出恢复内部状态。',
    recommendation: '使用 crypto.getRandomValues(new Uint8Array(n))。',
  },
  {
    id: 'eval-on-decrypted',
    name: 'eval 解密后内容（动态执行）',
    category: 'crypto-vuln',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /\beval\s*\(\s*(?:[A-Za-z\_$][\w$]*\.)?(?:decrypt|atob|JSON\.parse\s*\(\s*atob)/g,
    description: '将解密/解码结果直接送入 eval，等同于 RCE 通道。',
    exploit: '攻击者控制密文/Base64 输入即可注入任意 JS 代码。',
    recommendation: '禁止 eval；解密后用 JSON.parse 处理结构化数据。',
  },
  {
    id: 'hardcoded-symmetric-crypto-key',
    name: '硬编码对称加密密钥',
    category: 'crypto-vuln',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:aes|des|3des|sm4|crypto|encrypt|decrypt|cipher)[\-_]?(?:key|secret)["'\s:=]+["']?([A-Za-z0-9+/=_\.\-]{16,128})["']?/gi,
    description: 'AES/DES/3DES/SM4 等对称加密密钥硬编码。',
    exploit: '结合识别到的算法、模式、IV/nonce，可离线解密前端加密请求。',
    recommendation: '密钥不得写入前端；使用服务端密钥管理。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
      return null;
    },
  },
  {
    id: 'hardcoded-signature-key',
    name: '硬编码签名/HMAC 密钥',
    category: 'secret',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:hmac|sign|signature|mac|sha256|sha1|md5)[\-_]?(?:key|secret|salt)["'\s:=]+["']?([A-Za-z0-9+/=_\.\-]{16,160})["']?/gi,
    description: '签名、HMAC、摘要盐值或验签密钥硬编码。',
    exploit: '攻击者可重算 sign/signature 参数，篡改金额、用户 ID 等关键参数。',
    recommendation: '签名密钥只放服务端。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
      return null;
    },
  },
  {
    id: 'wechat-alipay-app-secret',
    name: '微信/支付宝 AppSecret 或商户密钥',
    category: 'secret',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:app[\-_]?secret|wechat[\-_]?secret|wx[\-_]?secret|alipay[\-_]?private[\-_]?key|mch[\-_]?key|pay[\-_]?secret)["'\s:=]+["']?([A-Za-z0-9_\-+=/]{24,160})["']?/gi,
    description: '微信、支付宝或支付商户相关密钥硬编码。',
    exploit: '结合商户号/appid 对支付请求进行伪造测试。',
    recommendation: '密钥必须保存在服务端，立即轮换并审计。',
    validate: function (ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    },
  },

  // ============ Database Connections ============
  {
    id: 'db-conn-string',
    name: '数据库连接串（含明文密码）',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex:
      /\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql):\/\/([^:\s\"'<>\s]+):([^@\s\"'<>\s]{4,})@([A-Za-z0-9.\-]+(?::\d+)?)(?:\/[\w.-]*)?/g,
    description: 'URL 形式数据库连接串，含用户名+密码+主机。',
    exploit: '直接 `mongo "mongodb+srv://..."` / `psql "postgres://..."` 连接。',
    recommendation: '改用后端代理；密码不应出现在前端。',
    validate: function (ctx) {
      var m = ctx.match.match(/:\/\/[^:]+:([^@]+)@/);
      var pwd = m ? m[1] : null;
      if (!pwd || isPlaceholder(pwd)) return { drop: true };
      return null;
    },
  },

  // ============ JWT ============
  {
    id: 'jwt-token',
    name: 'JWT Token',
    category: 'secret',
    severity: 'medium',
    confidence: 'likely',
    regex: /eyJ[A-Za-z0-9\-_]{8,}\.eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]*/g,
    description: 'JWT；进一步校验 alg、敏感载荷、过期时间。',
    exploit: '若 alg=none 可任意伪造；payload 含敏感字段说明信息泄漏。',
    recommendation: '强制 HS256/RS256；设置 exp。',
    validate: function (ctx) {
      var parts = ctx.match.split('.');
      var head = b64urlToStr(parts[0]);
      var body = b64urlToStr(parts[1]);
      var header, payload;
      try {
        header = JSON.parse(head);
        payload = JSON.parse(body);
      } catch (_) {
        return { drop: true };
      }
      var evidences = [];
      var severity = 'low',
        confidence = 'likely';
      if (header.alg && String(header.alg).toLowerCase() === 'none') {
        evidences.push('alg=none — 可任意伪造');
        severity = 'critical';
        confidence = 'confirmed';
      }
      var sensitiveKeys = [
        'password',
        'pwd',
        'pass',
        'secret',
        'private_key',
        'privatekey',
        'apikey',
        'api_key',
        'access_key',
        'ssn',
        'creditcard',
        'card_number',
      ];
      var payloadKeys = Object.keys(payload || {});
      for (var i = 0; i < payloadKeys.length; i++) {
        if (sensitiveKeys.indexOf(String(payloadKeys[i]).toLowerCase()) !== -1) {
          evidences.push('payload 含敏感字段: ' + payloadKeys[i]);
          if (severity === 'low') severity = 'high';
          confidence = 'confirmed';
        }
      }
      if (payload && typeof payload.exp !== 'number') {
        evidences.push('无 exp — 永不过期');
        if (severity === 'low') severity = 'medium';
        confidence = 'confirmed';
      }
      if (!evidences.length) return { drop: true };
      return {
        severity: severity,
        confidence: confidence,
        evidence: evidences.join('；') + ' | alg=' + header.alg,
      };
    },
  },
  {
    id: 'jwt-alg-none-config',
    name: 'JWT 配置允许 alg=none',
    category: 'crypto-vuln',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /["']alg["']\s*:\s*["']none["']/gi,
    description: 'JWT 头部出现 alg=none。',
    exploit: '若服务端按 alg 字段处理且支持 none，可任意伪造任意用户 token。',
    recommendation: '服务端强制白名单算法，明确拒绝 none。',
  },

  // ============ PEM Private Key ============
  {
    id: 'pem-private-key',
    name: 'PEM 私钥块',
    category: 'secret',
    severity: 'critical',
    confidence: 'confirmed',
    regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/g,
    description: '完整 PEM 格式私钥（要求 BEGIN/END 配对且中间是有效 base64 块）。',
    exploit: '直接用 openssl/ssh 加载即可签名/解密。',
    recommendation: '立即从代码中移除并轮换证书。',
    validate: function (ctx) {
      var after = ctx.source.slice(ctx.offset, Math.min(ctx.source.length, ctx.offset + 8192));
      var endRe = /-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/;
      var m = endRe.exec(after);
      if (!m) return { drop: true };
      var body = after.slice(ctx.match.length, m.index);
      if (!/[A-Za-z0-9+\/=\s]{80,}/.test(body)) return { drop: true };
      return { evidence: '已校验 BEGIN/END 配对与 base64 内容' };
    },
  },

  // ============ Hardcoded Vulnerabilities ============
  {
    id: 'hardcoded-admin-credentials',
    name: '硬编码管理员凭证',
    category: 'hardcode',
    severity: 'critical',
    confidence: 'likely',
    regex:
      /(?:username|user|account|admin|administrator)\s*[:=]\s*["'](?:admin|administrator|root|superuser|sa)["'][\s,;}]+(?:[^=\n]{0,80})?(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,64})["']/gi,
    description: '同一对象/作用域内同时出现管理员账号与口令字面量。',
    exploit: '直接尝试该账号登录。',
    recommendation: '前端绝不应包含任何账号密码。',
    validate: function (ctx) {
      var pwd = ctx.captured;
      if (isPlaceholder(pwd)) return { drop: true };
      if (/^(?:admin|root|123456|password|qwerty|admin123|root123|test|demo)$/i.test(pwd)) {
        return {
          confidence: 'confirmed',
          severity: 'critical',
          evidence: '弱口令 + 管理员账号同时硬编码',
        };
      }
      return null;
    },
  },
  {
    id: 'hardcoded-password-assignment',
    name: '硬编码密码/口令字段',
    category: 'hardcode',
    severity: 'high',
    confidence: 'likely',
    regex:
      /["']?(?:password|passwd|pwd|passphrase|loginPass|defaultPassword)["']?\s*[:=]\s*["']([^"'\s]{6,128})["']/gi,
    description: '源码中出现密码/口令字段字面量赋值。',
    exploit: '可用于尝试默认账号、测试环境后台。',
    recommendation: '移除硬编码密码，改为服务端配置。',
    validate: function (ctx) {
      var v = ctx.captured;
      if (isPlaceholder(v) || /^[\*•]+$/.test(v)) return { drop: true };
      if (/^(?:123456|12345678|password|qwerty|admin123|root123|test123|demo123)$/i.test(v)) {
        return { severity: 'critical', confidence: 'confirmed', evidence: '常见弱口令硬编码' };
      }
      if (shannonEntropy(v) < 2.3) return { confidence: 'suspected' };
      return null;
    },
  },

  // ============ PII ============
  {
    id: 'cn-id-card',
    name: '中国身份证号',
    category: 'pii',
    severity: 'high',
    confidence: 'suspected',
    regex:
      /(?<![0-9A-Za-z])\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b(?![0-9A-Za-z])/g,
    description: '中国大陆居民身份证号（18 位）。',
    exploit: '可用于身份冒用、社工、精准钓鱼。',
    recommendation: '对 PII 进行脱敏处理（仅显示后 4 位），前端不应暴露完整证件号。',
  },
  {
    id: 'bank-card-number',
    name: '银行卡号',
    category: 'pii',
    severity: 'high',
    confidence: 'suspected',
    regex: /(?<![0-9A-Za-z])\b(?:62|4\d|5[1-5]|3[47])\d{14,17}\b(?![0-9A-Za-z])/g,
    description: '银行卡号（Luhn 校验过滤误报）。',
    exploit: '可用于支付欺诈、测试支付接口。',
    recommendation: '对银行卡号脱敏（仅显示后 4 位），前端不应暴露完整卡号。',
    validate: function (ctx) {
      if (!luhnOk(ctx.match)) return { drop: true };
      return null;
    },
  },
  {
    id: 'phone-number-cn',
    name: '手机号码',
    category: 'pii',
    severity: 'medium',
    confidence: 'suspected',
    regex: /(?<![0-9A-Za-z\-])\b1[3-9]\d{9}\b(?![0-9A-Za-z])/g,
    description: '中国大陆手机号码（11 位）。',
    exploit: '可用于精准钓鱼、社工、短信轰炸。',
    recommendation: '对手机号脱敏处理。',
  },
  {
    id: 'basic-auth-credential',
    name: 'Basic Auth 凭据 (Base64)',
    category: 'secret',
    severity: 'high',
    confidence: 'likely',
    regex: /(?:Authorization|WWW-Authenticate)["'\s]*:\s*["']?Basic\s+([A-Za-z0-9+/=_\-]{8,200})/gi,
    description: 'Basic Auth 头中的 Base64 凭据，解码即为 user:pass。',
    exploit: '`echo | base64 -d` 直接拿到明文用户名/密码。',
    recommendation: '改为 Bearer Token + OAuth。',
    validate: function (ctx) {
      var dec = b64urlToStr(ctx.captured.replace(/-/g, '+').replace(/_/g, '/'));
      if (!dec || dec.indexOf(':') === -1) return { drop: true };
      var parts = dec.split(':', 2);
      var u = parts[0],
        p = parts[1];
      if (!u || !p || isPlaceholder(p)) return { drop: true };
      return { evidence: '解码后 user=' + u + ', pass.len=' + p.length };
    },
  },

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

// ---------- DOM Leak Rules (applied to DOM HTML) ----------

var DOM_LEAK_RULES = [
  {
    id: 'dom-html-comment-secret',
    name: 'HTML 注释中的秘密',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /<!--\s*(?:(?:password|secret|key|token|todo|fixme)[^>]*?)\s*-->/gi,
    description: 'HTML 注释中可能包含敏感信息。',
    exploit: '直接查看页面源码即可获取。',
    recommendation: '清理 HTML 注释中的敏感内容。',
  },
  {
    id: 'dom-email',
    name: '邮箱地址',
    category: 'pii',
    severity: 'low',
    confidence: 'suspected',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    description: '页面中暴露的邮箱地址。',
    exploit: '可用于社工或钓鱼。',
    recommendation: '对公开页面中的邮箱进行评估。',
  },
  {
    id: 'dom-hidden-input',
    name: '隐藏表单域',
    category: 'exposure',
    severity: 'low',
    confidence: 'suspected',
    regex: /<input[^>]+type\s*=\s*["']hidden["'][^>]+value\s*=\s*["'][^"']+["']/gi,
    description: '隐藏表单域可能包含敏感值。',
    exploit: '修改隐藏域值可能绕过前端验证。',
    recommendation: '服务端必须验证所有表单提交值。',
  },
  {
    id: 'dom-data-attribute',
    name: 'data-* 属性中的敏感值',
    category: 'exposure',
    severity: 'medium',
    confidence: 'suspected',
    regex: /data-(?:token|key|secret|config|api)\s*=\s*["']([^"']+)["']/gi,
    description: 'HTML data 属性中可能包含敏感数据。',
    exploit: '直接查看 DOM 即可获取。',
    recommendation: '避免在 data 属性中存储敏感信息。',
  },
  {
    id: 'dom-srcdoc',
    name: 'srcdoc 中的内容',
    category: 'exposure',
    severity: 'low',
    confidence: 'suspected',
    regex: /srcdoc\s*=\s*["']/gi,
    description: 'srcdoc 属性使用（可能嵌入任意 HTML）。',
    exploit: '如果内容可控则可能产生 XSS。',
    recommendation: '确保 srcdoc 内容经过适当转义。',
  },
];

// ---------- Constants ----------

var SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
var CONFIDENCE_ORDER = { confirmed: 3, likely: 2, suspected: 1 };

var SEVERITY_LABELS = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

var CONFIDENCE_LABELS = {
  confirmed: '确认',
  likely: '可能',
  suspected: '疑似',
};

var SEVERITY_COLOR = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'cyan',
  info: 'grey',
};

var CATEGORY_LABELS = {
  secret: '密钥/凭证',
  'crypto-vuln': '加解密漏洞',
  hardcode: '硬编码漏洞',
  pii: '敏感信息 (PII)',
  exposure: '信息暴露',
};

var MAX_STORAGE_ITEMS = 200;
var MAX_GLOBAL_SCANS = 100;

// ---------- Backward-compatibility tuple format for vk-leakscan-scanner ----------

function rulesToTuples(rules) {
  return rules.map(function (r) {
    return [r.name, r.regex, r.severity];
  });
}

var LEAK_RULES_LEGACY = rulesToTuples(RULES);
var DOM_LEAK_RULES_LEGACY = rulesToTuples(DOM_LEAK_RULES);

export {
  RULES,
  DOM_LEAK_RULES,
  LEAK_RULES_LEGACY,
  DOM_LEAK_RULES_LEGACY,
  SEVERITY_ORDER,
  CONFIDENCE_ORDER,
  SEVERITY_LABELS,
  CONFIDENCE_LABELS,
  SEVERITY_COLOR,
  CATEGORY_LABELS,
  MAX_STORAGE_ITEMS,
  MAX_GLOBAL_SCANS,
  b64urlToStr,
  luhnOk,
  shannonEntropy,
  isPlaceholder,
  inCryptoContext,
};
