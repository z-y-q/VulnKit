// vk-leak-utils.js -- 灵眸 Chrome Extension
// Shared utility functions for leak detection rules
'use strict';

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

export { b64urlToStr, luhnOk, shannonEntropy, PLACEHOLDER_LITERALS, isPlaceholder, inCryptoContext };
