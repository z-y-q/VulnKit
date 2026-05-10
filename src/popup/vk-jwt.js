// 灵眸 - JWT Decoder (Deep Analysis)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) base64 += '=';
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function base64UrlToUint8(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) base64 += '=';
  const raw = atob(base64);
  var arr = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

var JWT_HMAC_MAP = {
  HS256: { hash: 'SHA-256', name: 'HMAC' },
  HS384: { hash: 'SHA-384', name: 'HMAC' },
  HS512: { hash: 'SHA-512', name: 'HMAC' },
};

var JWT_RSA_MAP = {
  RS256: { hash: 'SHA-256', name: 'RSASSA-PKCS1-v1_5' },
  RS384: { hash: 'SHA-384', name: 'RSASSA-PKCS1-v1_5' },
  RS512: { hash: 'SHA-512', name: 'RSASSA-PKCS1-v1_5' },
};

var JWT_ECDSA_MAP = {
  ES256: { hash: 'SHA-256', name: 'ECDSA', curve: 'P-256' },
  ES384: { hash: 'SHA-384', name: 'ECDSA', curve: 'P-384' },
  ES512: { hash: 'SHA-512', name: 'ECDSA', curve: 'P-521' },
};

var ALL_ALGO_MAP = Object.assign({}, JWT_HMAC_MAP, JWT_RSA_MAP, JWT_ECDSA_MAP);

var lastDecodedJwt = { header: null, payload: null, token: '' };

var SENSITIVE_CLAIMS = ['email', 'password', 'secret', 'token', 'api_key', 'apikey', 'admin', 'role', 'privilege', 'credit_card', 'ssn', 'phone'];

function pemToArrayBuffer(pem) {
  var b64 = pem.replace(/-----BEGIN[^-]+-----/, '').replace(/-----END[^-]+-----/, '').replace(/\s/g, '');
  var raw = atob(b64);
  var buf = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}

function detectAlgorithmConfusion(header, payload) {
  var vulnerabilities = [];
  var alg = (header.alg || '').toLowerCase();

  if (alg === 'none' || alg === 'non' || alg === 'nil') {
    vulnerabilities.push({
      severity: 'critical',
      title: 'alg: none 无签名攻击',
      detail: 'JWT 使用 "none" 算法，意味着无签名验证。攻击者可伪造任意 payload。',
    });
  }

  if (header.jku) {
    vulnerabilities.push({
      severity: 'high',
      title: 'jku 外部密钥 URL',
      detail: 'Header 包含 "jku" (JWK Set URL)，可能指向攻击者控制的密钥服务器。URL: ' + header.jku,
    });
  }

  if (header.x5u) {
    vulnerabilities.push({
      severity: 'high',
      title: 'x5u 外部证书 URL',
      detail: 'Header 包含 "x5u" (X.509 URL)，可能指向攻击者控制的证书。URL: ' + header.x5u,
    });
  }

  if (header.kid && typeof header.kid === 'string' && /['";\\]/.test(header.kid)) {
    vulnerabilities.push({
      severity: 'high',
      title: 'kid SQL 注入风险',
      detail: 'Header "kid" 参数包含可疑字符，可能存在 SQL 注入漏洞。kid: ' + header.kid,
    });
  }

  if (header.kid && typeof header.kid === 'string' && /^(path|file|\/|\.\.)/i.test(header.kid)) {
    vulnerabilities.push({
      severity: 'high',
      title: 'kid 路径遍历风险',
      detail: 'Header "kid" 参数疑似文件路径，可能存在路径遍历漏洞。kid: ' + header.kid,
    });
  }

  if (header.typ && header.alg) {
    var algFamily = header.alg.substring(0, 2);
    if ((algFamily === 'RS' || algFamily === 'ES') && header.typ === 'JWT') {
      // typ: JWT with asymmetric is common, but worth noting if HS256 expected
    }
  }

  if (!header.alg) {
    vulnerabilities.push({
      severity: 'medium',
      title: '缺少 alg 声明',
      detail: 'JWT Header 未声明签名算法，可能导致验证时使用不安全的默认算法。',
    });
  }

  var now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    vulnerabilities.push({
      severity: 'medium',
      title: 'Token 已过期',
      detail: 'exp=' + payload.exp + ' (' + new Date(payload.exp * 1000).toLocaleString('zh-CN') + ')，当前时间戳=' + now,
    });
  }

  if (payload.nbf && payload.nbf > now) {
    vulnerabilities.push({
      severity: 'medium',
      title: 'Token 尚未生效',
      detail: 'nbf=' + payload.nbf + '，当前时间戳=' + now,
    });
  }

  if (payload.exp && payload.nbf && payload.exp - payload.nbf > 86400 * 365) {
    vulnerabilities.push({
      severity: 'low',
      title: 'Token 有效期过长',
      detail: '有效期超过 1 年（' + Math.round((payload.exp - payload.nbf) / 86400) + ' 天），建议缩短有效期。',
    });
  }

  if (!payload.exp && !payload.iat) {
    vulnerabilities.push({
      severity: 'low',
      title: '缺少时间控制',
      detail: 'Token 没有 exp 和 iat 声明，无法判断有效性和过期时间。',
    });
  }

  return vulnerabilities;
}

function analyzeJwtClaims(header, payload) {
  var findings = [];
  var keys = Object.keys(payload || {});

  for (var k = 0; k < keys.length; k++) {
    var key = keys[k].toLowerCase();
    if (SENSITIVE_CLAIMS.indexOf(key) !== -1) {
      var val = payload[keys[k]];
      var displayVal = typeof val === 'string' ? val.substring(0, 20) + (val.length > 20 ? '...' : '') : JSON.stringify(val);
      findings.push({
        severity: key === 'password' || key === 'secret' || key === 'credit_card' || key === 'ssn' ? 'high' : 'medium',
        title: '敏感 Claim: ' + keys[k],
        detail: 'Payload 包含敏感字段 "' + keys[k] + '"，值: ' + displayVal,
      });
    }
  }

  var registered = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];
  var privateClaims = keys.filter(function (k) { return registered.indexOf(k) === -1; });
  if (privateClaims.length > 15) {
    findings.push({
      severity: 'low',
      title: '过多私有 Claim',
      detail: 'Payload 包含 ' + privateClaims.length + ' 个非标准 Claim，可能包含冗余敏感数据。',
    });
  }

  return findings;
}

function decodeJwt(token) {
  var resultEl = utils.get('jwt-result');
  var errorEl = utils.get('jwt-error');
  var headerEl = utils.get('jwt-header');
  var payloadEl = utils.get('jwt-payload');
  var sigEl = utils.get('jwt-signature');
  var claimsEl = utils.get('jwt-claims');
  var warningsEl = utils.get('jwt-warnings');

  if (!resultEl || !errorEl || !headerEl || !payloadEl || !claimsEl || !sigEl) return;
  resultEl.classList.add('hidden');
  errorEl.classList.add('hidden');
  if (warningsEl) warningsEl.innerHTML = '';

  var trimmed = token.trim();
  var parts = trimmed.split('.');
  if (parts.length !== 3) {
    errorEl.textContent = '无效的 JWT 格式（需 3 段，用 . 分隔）';
    errorEl.classList.remove('hidden');
    return;
  }

  var header;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
    headerEl.textContent = JSON.stringify(header, null, 2);
  } catch (e) {
    errorEl.textContent = 'Header 解析失败: ' + e.message;
    errorEl.classList.remove('hidden');
    return;
  }

  var payload;
  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
    payloadEl.textContent = JSON.stringify(payload, null, 2);
  } catch (e) {
    errorEl.textContent = 'Payload 解析失败: ' + e.message;
    errorEl.classList.remove('hidden');
    return;
  }

  sigEl.textContent = parts[2];
  lastDecodedJwt = { header: header, payload: payload, token: trimmed };

  var now = Math.floor(Date.now() / 1000);
  var claimsHtml = '';

  if (payload.exp) {
    var expDate = new Date(payload.exp * 1000);
    var isExpired = payload.exp < now;
    claimsHtml += '<div class="jwt-claim ' + (isExpired ? 'jwt-claim-expired' : 'jwt-claim-valid') + '"><span>过期时间 (exp)</span><span>' + expDate.toLocaleString('zh-CN') + (isExpired ? ' — 已过期' : ' — 有效') + '</span></div>';
  }
  if (payload.iat) {
    claimsHtml += '<div class="jwt-claim"><span>签发时间 (iat)</span><span>' + new Date(payload.iat * 1000).toLocaleString('zh-CN') + '</span></div>';
  }
  if (payload.nbf) {
    var isNbfValid = payload.nbf <= now;
    claimsHtml += '<div class="jwt-claim ' + (isNbfValid ? 'jwt-claim-valid' : 'jwt-claim-expired') + '"><span>生效时间 (nbf)</span><span>' + new Date(payload.nbf * 1000).toLocaleString('zh-CN') + (isNbfValid ? ' — 已生效' : ' — 尚未生效') + '</span></div>';
  }

  if (payload.iss) {
    claimsHtml += '<div class="jwt-claim"><span>签发者 (iss)</span><span>' + utils.escapeHtml(String(payload.iss)) + '</span></div>';
  }
  if (payload.sub) {
    claimsHtml += '<div class="jwt-claim"><span>主题 (sub)</span><span>' + utils.escapeHtml(String(payload.sub)) + '</span></div>';
  }
  if (payload.aud) {
    claimsHtml += '<div class="jwt-claim"><span>受众 (aud)</span><span>' + utils.escapeHtml(JSON.stringify(payload.aud)) + '</span></div>';
  }
  if (payload.jti) {
    claimsHtml += '<div class="jwt-claim"><span>JWT ID (jti)</span><span>' + utils.escapeHtml(String(payload.jti)) + '</span></div>';
  }

  claimsEl.innerHTML = claimsHtml;

  var confusions = detectAlgorithmConfusion(header, payload);
  var claimFindings = analyzeJwtClaims(header, payload);
  var allWarnings = confusions.concat(claimFindings);

  if (warningsEl && allWarnings.length > 0) {
    var warnHtml = '';
    for (var w = 0; w < allWarnings.length; w++) {
      var warn = allWarnings[w];
      warnHtml += '<div class="jwt-warning-item ' + warn.severity + '">';
      warnHtml += '<strong>' + utils.escapeHtml(warn.title) + '</strong>';
      warnHtml += '<span>' + utils.escapeHtml(warn.detail) + '</span>';
      warnHtml += '</div>';
    }
    warningsEl.innerHTML = warnHtml;
  }

  resultEl.classList.remove('hidden');
  utils.showToast('JWT 解码成功', 'success');
}

function clearJwt() {
  var inputEl = utils.get('jwt-input');
  var resultEl = utils.get('jwt-result');
  var errorEl = utils.get('jwt-error');
  var warningsEl = utils.get('jwt-warnings');
  if (inputEl) inputEl.value = '';
  if (resultEl) resultEl.classList.add('hidden');
  if (errorEl) errorEl.classList.add('hidden');
  if (warningsEl) warningsEl.innerHTML = '';
  lastDecodedJwt = { header: null, payload: null, token: '' };
}

function copyJwtHeader() {
  var el = utils.get('jwt-header');
  if (!el || !el.textContent) {
    utils.showToast('请先解码 JWT', 'warning');
    return;
  }
  utils.copyAndToast(el.textContent, '已复制 Header');
}

function copyJwtPayload() {
  var el = utils.get('jwt-payload');
  if (!el || !el.textContent) {
    utils.showToast('请先解码 JWT', 'warning');
    return;
  }
  utils.copyAndToast(el.textContent, '已复制 Payload');
}

async function verifyJwtSignature() {
  var inputEl = utils.get('jwt-input');
  var keyEl = utils.get('jwt-verify-key');
  var algoTypeEl = utils.get('jwt-algo-type');
  var resultEl = utils.get('jwt-verify-result');
  if (!inputEl || !keyEl || !resultEl) return;

  var token = inputEl.value.trim();
  var secret = keyEl.value.trim();
  var algoType = algoTypeEl ? algoTypeEl.value : 'hmac';

  if (!token) {
    utils.showToast('请先输入 JWT Token', 'warning');
    return;
  }
  if (!secret) {
    utils.showToast(algoType === 'hmac' ? '请输入验证密钥' : '请粘贴 PEM 公钥', 'warning');
    return;
  }

  var parts = token.split('.');
  if (parts.length !== 3) {
    showVerifyResult(resultEl, '无效的 JWT 格式', 'error');
    return;
  }

  var header;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
  } catch (e) {
    showVerifyResult(resultEl, 'Header 解析失败', 'error');
    return;
  }

  var alg = header.alg || '';
  var valid = false;

  try {
    if (algoType === 'hmac') {
      valid = await verifyHmac(token, parts, alg, secret);
    } else if (algoType === 'rsa') {
      valid = await verifyRsa(token, parts, alg, secret);
    } else if (algoType === 'ecdsa') {
      valid = await verifyEcdsa(token, parts, alg, secret);
    }
    showVerifyResult(
      resultEl,
      valid ? '签名有效 (' + alg + ')' : '签名无效',
      valid ? 'valid' : 'invalid'
    );
  } catch (e) {
    showVerifyResult(resultEl, '验证出错: ' + e.message, 'error');
  }
}

async function verifyHmac(token, parts, alg, secret) {
  if (!JWT_HMAC_MAP[alg]) {
    throw new Error('不支持的 HMAC 算法: ' + alg);
  }
  var spec = JWT_HMAC_MAP[alg];
  var enc = new TextEncoder();
  var key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: spec.hash },
    false,
    ['verify']
  );
  var data = enc.encode(parts[0] + '.' + parts[1]);
  var sigBytes = base64UrlToUint8(parts[2]);
  return crypto.subtle.verify('HMAC', key, sigBytes, data);
}

async function verifyRsa(token, parts, alg, pem) {
  if (!JWT_RSA_MAP[alg]) {
    throw new Error('不支持的 RSA 算法: ' + alg);
  }
  var spec = JWT_RSA_MAP[alg];
  var keyData = pemToArrayBuffer(pem);
  var key = await crypto.subtle.importKey(
    'spki',
    keyData,
    { name: spec.name, hash: spec.hash },
    false,
    ['verify']
  );
  var enc = new TextEncoder();
  var data = enc.encode(parts[0] + '.' + parts[1]);
  var sigBytes = base64UrlToUint8(parts[2]);
  return crypto.subtle.verify(spec.name, key, sigBytes, data);
}

async function verifyEcdsa(token, parts, alg, pem) {
  if (!JWT_ECDSA_MAP[alg]) {
    throw new Error('不支持的 ECDSA 算法: ' + alg);
  }
  var spec = JWT_ECDSA_MAP[alg];
  var keyData = pemToArrayBuffer(pem);
  var key = await crypto.subtle.importKey(
    'spki',
    keyData,
    { name: 'ECDSA', namedCurve: spec.curve },
    false,
    ['verify']
  );
  var enc = new TextEncoder();
  var data = enc.encode(parts[0] + '.' + parts[1]);
  var sigBytes = base64UrlToUint8(parts[2]);
  return crypto.subtle.verify({ name: 'ECDSA', hash: spec.hash }, key, sigBytes, data);
}

function showVerifyResult(el, msg, cls) {
  el.textContent = msg;
  el.className = 'jwt-verify-result ' + cls;
  el.classList.remove('hidden');
}

function getFindings() {
  if (!lastDecodedJwt.header || !lastDecodedJwt.payload) return [];

  var findings = [];
  var confusions = detectAlgorithmConfusion(lastDecodedJwt.header, lastDecodedJwt.payload);
  var claimFindings = analyzeJwtClaims(lastDecodedJwt.header, lastDecodedJwt.payload);
  var all = confusions.concat(claimFindings);

  for (var i = 0; i < all.length; i++) {
    var item = all[i];
    var severity = item.severity;
    if (severity === 'critical') severity = 'critical';
    else if (severity === 'high') severity = 'high';
    else if (severity === 'medium') severity = 'medium';
    else severity = 'low';
    findings.push({
      severity: severity,
      title: item.title,
      detail: item.detail,
      module: 'jwt',
      url: '',
    });
  }
  return findings;
}

export { decodeJwt, clearJwt, copyJwtHeader, copyJwtPayload, verifyJwtSignature, getFindings };
