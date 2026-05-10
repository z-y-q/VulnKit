// vk-leak-rules-crypto.js -- 灵眸 Chrome Extension
// Crypto / DB / JWT / PEM / Hardcoded / PII leak detection rules
'use strict';

import { b64urlToStr, luhnOk, shannonEntropy, isPlaceholder, inCryptoContext } from './vk-leak-utils.js';

var RULES_CRYPTO = [
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
];

export { RULES_CRYPTO };
