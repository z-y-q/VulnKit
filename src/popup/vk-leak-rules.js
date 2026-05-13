// vk-leak-rules.js -- 灵眸 Chrome Extension
// Barrel: re-exports from split modules + async-loaded Cloud/SaaS rules
'use strict';

import {
  b64urlToStr,
  luhnOk,
  shannonEntropy,
  isPlaceholder,
  inCryptoContext,
} from './vk-leak-utils.js';
import { loadJsonData, attachValidateFns } from './vk-data-loader.js';
import {
  SEVERITY_ORDER,
  CONFIDENCE_ORDER,
  SEVERITY_LABELS,
  CONFIDENCE_LABELS,
  SEVERITY_COLOR,
  CATEGORY_LABELS,
} from './vk-leak-constants.js';
import { getDomLeakRules } from './vk-leak-dom-rules.js';
import { getCryptoRules } from './vk-leak-rules-crypto.js';
import { getExposureRules } from './vk-leak-rules-exposure.js';

// ---------- Validate callbacks (cannot be serialized to JSON) ----------

var VALIDATE_FNS = {
  'aws-access-key-id': function (ctx) {
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

  'aws-secret-access-key': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 4.0) return { drop: true };
    return null;
  },

  'stripe-secret-key': function (ctx) {
    if (ctx.match.startsWith('sk_test_') || ctx.match.startsWith('rk_test_'))
      return { severity: 'medium', confidence: 'likely', evidence: '测试环境 Key' };
    return null;
  },

  'cloudflare-token': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.2) return { drop: true };
    return null;
  },

  'vercel-token': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.1) return { drop: true };
    return null;
  },

  'netlify-token': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.1) return { drop: true };
    return null;
  },

  'bearer-auth-token': function (ctx) {
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

  'api-key-header': function (ctx) {
    var v = ctx.captured;
    if (/^(?:Bearer|Basic)\s+/i.test(v)) return { drop: true };
    if (isPlaceholder(v)) return { drop: true };
    if (shannonEntropy(v) < 3.0) return { drop: true };
    return null;
  },

  'oauth-client-secret': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
    return null;
  },

  'jwt-session-signing-secret': function (ctx) {
    if (isPlaceholder(ctx.captured)) return { drop: true };
    if (/^(?:true|false|null|undefined)$/i.test(ctx.captured)) return { drop: true };
    if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
    return null;
  },
};

// ---------- Async data loading ----------

var _rules = null;

async function ensureLoaded() {
  if (_rules) return _rules;
  _rules = await loadJsonData('data/leak-rules-cloud.json');
  attachValidateFns(_rules, VALIDATE_FNS);
  return _rules;
}

async function getAllRules() {
  var cloud = await ensureLoaded();
  var crypto = await getCryptoRules();
  var exposure = await getExposureRules();
  return cloud.concat(crypto, exposure);
}

// ---------- Combined rules + legacy compat ----------

function rulesToTuples(rules) {
  return rules.map(function (r) {
    return [r.name, r.regex, r.severity];
  });
}

async function getLeakRulesLegacy() {
  var rules = await getAllRules();
  return rulesToTuples(rules);
}

export {
  ensureLoaded,
  getAllRules,
  getLeakRulesLegacy,
  getDomLeakRules,
  getCryptoRules,
  getExposureRules,
  SEVERITY_ORDER,
  CONFIDENCE_ORDER,
  SEVERITY_LABELS,
  CONFIDENCE_LABELS,
  SEVERITY_COLOR,
  CATEGORY_LABELS,
  b64urlToStr,
  luhnOk,
  shannonEntropy,
  isPlaceholder,
  inCryptoContext,
};
