// vk-leak-rules-crypto.js -- 灵眸 Chrome Extension
// Crypto / DB / JWT / PEM / Hardcoded / PII leak detection rules
'use strict';

import { loadJsonData, attachValidateFns } from './vk-data-loader.js';
import { b64urlToStr, luhnOk, shannonEntropy, isPlaceholder, inCryptoContext } from './vk-leak-utils.js';

var VALIDATE_FNS = {
  'hardcoded-aes-key': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 2.5) return { drop: true };
    if (!inCryptoContext(ctx.source, ctx.offset, ctx.match.length)) return { drop: true };
    return { evidence: 'key 位于实际加密调用 ±300 字符内' };
  },
  'hardcoded-iv': function (ctx) {
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
  'weak-md5-security': function (ctx) {
    var arg = ctx.captured || '';
    if (!/(?:password|passwd|pwd|secret|token|sign|signature|key|salt|auth|hmac)/i.test(arg))
      return { drop: true };
    return { evidence: '参数含 password/token/secret 等安全敏感关键字' };
  },
  'weak-sha1-security': function (ctx) {
    var arg = ctx.captured || '';
    if (!/(?:password|passwd|pwd|secret|token|sign|signature|key|salt|auth)/i.test(arg))
      return { drop: true };
    return null;
  },
  'hardcoded-symmetric-crypto-key': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
    return null;
  },
  'hardcoded-signature-key': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
    return null;
  },
  'wechat-alipay-app-secret': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
    return null;
  },
  'db-conn-string': function (ctx) {
    var m = ctx.match.match(/:\/\/[^:]+:([^@]+)@/);
    var pwd = m ? m[1] : null;
    if (!pwd || isPlaceholder(pwd)) return { drop: true };
    return null;
  },
  'jwt-token': function (ctx) {
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
  'pem-private-key': function (ctx) {
    var after = ctx.source.slice(ctx.offset, Math.min(ctx.source.length, ctx.offset + 8192));
    var endRe = /-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/;
    var m = endRe.exec(after);
    if (!m) return { drop: true };
    var body = after.slice(ctx.match.length, m.index);
    if (!/[A-Za-z0-9+\/=\s]{80,}/.test(body)) return { drop: true };
    return { evidence: '已校验 BEGIN/END 配对与 base64 内容' };
  },
  'hardcoded-admin-credentials': function (ctx) {
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
  'hardcoded-password-assignment': function (ctx) {
    var v = ctx.captured;
    if (isPlaceholder(v) || /^[\*•]+$/.test(v)) return { drop: true };
    if (/^(?:123456|12345678|password|qwerty|admin123|root123|test123|demo123)$/i.test(v)) {
      return { severity: 'critical', confidence: 'confirmed', evidence: '常见弱口令硬编码' };
    }
    if (shannonEntropy(v) < 2.3) return { confidence: 'suspected' };
    return null;
  },
  'bank-card-number': function (ctx) {
    if (!luhnOk(ctx.match)) return { drop: true };
    return null;
  },
  'basic-auth-credential': function (ctx) {
    var dec = b64urlToStr(ctx.captured.replace(/-/g, '+').replace(/_/g, '/'));
    if (!dec || dec.indexOf(':') === -1) return { drop: true };
    var parts = dec.split(':', 2);
    var u = parts[0],
      p = parts[1];
    if (!u || !p || isPlaceholder(p)) return { drop: true };
    return { evidence: '解码后 user=' + u + ', pass.len=' + p.length };
  },
};

var _rules = null;

async function ensureLoaded() {
  if (_rules) return _rules;
  _rules = await loadJsonData('data/leak-rules-crypto.json');
  attachValidateFns(_rules, VALIDATE_FNS);
  return _rules;
}

async function getCryptoRules() {
  return ensureLoaded();
}

export { ensureLoaded, getCryptoRules };
