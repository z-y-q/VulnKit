// 灵眸 - JWT Decoder
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

function decodeJwt(token) {
  let resultEl = utils.get('jwt-result');
  let errorEl = utils.get('jwt-error');
  const headerEl = utils.get('jwt-header');
  const payloadEl = utils.get('jwt-payload');
  const sigEl = utils.get('jwt-signature');
  const claimsEl = utils.get('jwt-claims');

  if (!resultEl || !errorEl || !headerEl || !payloadEl || !claimsEl || !sigEl) return;
  resultEl.classList.add('hidden');
  errorEl.classList.add('hidden');

  const trimmed = token.trim();
  let parts = trimmed.split('.');
  if (parts.length !== 3) {
    errorEl.textContent = '无效的 JWT 格式（需 3 段，用 . 分隔）';
    errorEl.classList.remove('hidden');
    return;
  }

  try {
    let header = JSON.parse(base64UrlDecode(parts[0]));
    headerEl.textContent = JSON.stringify(header, null, 2);
  } catch (e) {
    errorEl.textContent = `Header 解析失败: ${e.message}`;
    errorEl.classList.remove('hidden');
    return;
  }

  let payload = null;
  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
    payloadEl.textContent = JSON.stringify(payload, null, 2);
  } catch (e) {
    errorEl.textContent = `Payload 解析失败: ${e.message}`;
    errorEl.classList.remove('hidden');
    return;
  }

  sigEl.textContent = parts[2];

  const now = Math.floor(Date.now() / 1000);
  let claimsHtml = '';

  if (payload.exp) {
    const expDate = new Date(payload.exp * 1000);
    const isExpired = payload.exp < now;
    claimsHtml += `<div class="jwt-claim ${isExpired ? 'jwt-claim-expired' : 'jwt-claim-valid'}"><span>过期时间 (exp)</span><span>${expDate.toLocaleString('zh-CN')}${isExpired ? ' — 已过期' : ' — 有效'}</span></div>`;
  }
  if (payload.iat) {
    claimsHtml += `<div class="jwt-claim"><span>签发时间 (iat)</span><span>${new Date(payload.iat * 1000).toLocaleString('zh-CN')}</span></div>`;
  }
  if (payload.nbf) {
    const isNbfValid = payload.nbf <= now;
    claimsHtml += `<div class="jwt-claim ${isNbfValid ? 'jwt-claim-valid' : 'jwt-claim-expired'}"><span>生效时间 (nbf)</span><span>${new Date(payload.nbf * 1000).toLocaleString('zh-CN')}${isNbfValid ? ' — 已生效' : ' — 尚未生效'}</span></div>`;
  }

  claimsEl.innerHTML = claimsHtml;
  resultEl.classList.remove('hidden');
  utils.showToast('JWT 解码成功', 'success');
}

function clearJwt() {
  let inputEl = utils.get('jwt-input');
  let resultEl = utils.get('jwt-result');
  const errorEl = utils.get('jwt-error');
  if (inputEl) inputEl.value = '';
  if (resultEl) resultEl.classList.add('hidden');
  if (errorEl) errorEl.classList.add('hidden');
}

function copyJwtHeader() {
  let el = utils.get('jwt-header');
  if (!el || !el.textContent) {
    utils.showToast('请先解码 JWT', 'warning');
    return;
  }
  utils.copyAndToast(el.textContent, '已复制 Header');
}

function copyJwtPayload() {
  const el = utils.get('jwt-payload');
  if (!el || !el.textContent) {
    utils.showToast('请先解码 JWT', 'warning');
    return;
  }
  utils.copyAndToast(el.textContent, '已复制 Payload');
}

const JWT_ALGO_MAP = {
  HS256: { hash: 'SHA-256', name: 'HMAC', length: 256 },
  HS384: { hash: 'SHA-384', name: 'HMAC', length: 384 },
  HS512: { hash: 'SHA-512', name: 'HMAC', length: 512 },
};

async function verifyJwtSignature() {
  const inputEl = utils.get('jwt-input');
  const keyEl = utils.get('jwt-verify-key');
  const resultEl = utils.get('jwt-verify-result');
  if (!inputEl || !keyEl || !resultEl) return;

  const token = inputEl.value.trim();
  const secret = keyEl.value;
  if (!token) {
    utils.showToast('请先输入 JWT Token', 'warning');
    return;
  }
  if (!secret) {
    utils.showToast('请输入验证密钥', 'warning');
    return;
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    showVerifyResult(resultEl, '无效的 JWT 格式', 'error');
    return;
  }

  let header;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
  } catch (e) {
    showVerifyResult(resultEl, 'Header 解析失败', 'error');
    return;
  }

  const alg = header.alg;
  if (!alg || !JWT_ALGO_MAP[alg]) {
    showVerifyResult(resultEl, `不支持 ${alg || '无'} 算法（仅支持 HS256/HS384/HS512）`, 'error');
    return;
  }

  try {
    const algoSpec = JWT_ALGO_MAP[alg];
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: algoSpec.hash },
      false,
      ['sign', 'verify']
    );

    const data = enc.encode(`${parts[0]}.${parts[1]}`);
    const sigBytes = Uint8Array.from(
      atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')),
      function (c) {
        return c.charCodeAt(0);
      }
    );

    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
    showVerifyResult(
      resultEl,
      valid ? `签名有效 (${alg})` : '签名无效',
      valid ? 'valid' : 'invalid'
    );
  } catch (e) {
    showVerifyResult(resultEl, `验证出错: ${e.message}`, 'error');
  }
}

function showVerifyResult(el, msg, cls) {
  el.textContent = msg;
  el.className = `jwt-verify-result ${cls}`;
  el.classList.remove('hidden');
}

export { decodeJwt, clearJwt, copyJwtHeader, copyJwtPayload, verifyJwtSignature };
