// vk-leak-rules-exposure.js -- 灵眸 Chrome Extension
// Exposure + Security Misconfiguration leak detection rules (externalized)
'use strict';

import { loadJsonData, attachValidateFns } from './vk-data-loader.js';
import { isPlaceholder, shannonEntropy } from './vk-leak-utils.js';

var VALIDATE_FNS = {
  'session-cookie-token': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
    return null;
  },

  'huawei-oss-config': function (ctx) {
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

  'twilio-account-sid': function (ctx) {
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

  'docker-token': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
    return null;
  },

  'elastic-search-password': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 2.5) return { drop: true };
    return null;
  },

  'redis-standalone-uri': function (ctx) {
    var m = ctx.match.match(/redis:\/\/:([^@"'\s<>]+)/);
    if (!m) return null;
    if (isPlaceholder(m[1])) return { drop: true };
    return { evidence: '含密码: redis://:****@' };
  },

  'jenkins-crumb-secret': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 2.5) return { drop: true };
    return null;
  },

  'grafana-api-key': function (ctx) {
    if (/eyJrIjoi[A-Za-z0-9\-_]{20,}/.test(ctx.match))
      return {
        confidence: 'confirmed',
        evidence: 'Grafana Service Account Token (eyJrIjoi 前缀)',
      };
    if (ctx.captured && isPlaceholder(ctx.captured)) return { drop: true };
    return null;
  },

  'azure-ad-client-secret': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
    return null;
  },
};

var _rules = null;

async function ensureLoaded() {
  if (_rules) return _rules;
  _rules = await loadJsonData('data/leak-rules-exposure.json');
  attachValidateFns(_rules, VALIDATE_FNS);
  return _rules;
}

async function getExposureRules() {
  return ensureLoaded();
}

export { ensureLoaded, getExposureRules };
