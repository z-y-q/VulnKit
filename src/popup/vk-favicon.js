// 灵眸 - Favicon (Per-Platform Hash Generation)
window.VulnKitFavicon = (function () {
  'use strict';

  // MurmurHash3 (32-bit) — matches Shodan/FOFA/ZoomEye/Quake/Hunter
  // Input: UTF-8 bytes of a string
  function mm3hash32(str) {
    var rawBytes = new TextEncoder().encode(str);
    var c1 = 0xcc9e2d51;
    var c2 = 0x1b873593;
    var h1 = 0;
    var round = function (h, k) {
      k = Math.imul(k, c1);
      k = (k << 15) | (k >>> 17);
      k = Math.imul(k, c2);
      h ^= k;
      h = (h << 13) | (h >>> 19);
      return (Math.imul(h, 5) + 0xe6546b64) | 0;
    };
    var len = rawBytes.length;
    var nblocks = len >> 2;
    for (var i = 0; i < nblocks; i++) {
      var off = i * 4;
      var k =
        rawBytes[off] |
        (rawBytes[off + 1] << 8) |
        (rawBytes[off + 2] << 16) |
        (rawBytes[off + 3] << 24);
      h1 = round(h1, k);
    }
    var k1 = 0;
    var tail = nblocks * 4;
    switch (len & 3) {
      case 3:
        k1 ^= rawBytes[tail + 2] << 16;
      case 2:
        k1 ^= rawBytes[tail + 1] << 8;
      case 1:
        k1 ^= rawBytes[tail];
        h1 = round(h1, k1);
    }
    h1 ^= len;
    h1 ^= h1 >>> 16;
    h1 = Math.imul(h1, 0x85ebca6b);
    h1 ^= h1 >>> 13;
    h1 = Math.imul(h1, 0xc2b2ae35);
    h1 ^= h1 >>> 16;
    return h1 | 0;
  }

  // Python's base64.encodebytes() inserts \n every 76 characters.
  // This is CRITICAL — favihunter uses encodebytes, not b64encode.
  function encodebytes(b64str) {
    var lines = [];
    for (var i = 0; i < b64str.length; i += 76) {
      lines.push(b64str.slice(i, i + 76));
    }
    return lines.join('\n');
  }

  // Pure JS MD5 (Web Crypto does not support MD5)
  function md5(bytes) {
    var K = [
      0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
      0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
      0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
      0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
      0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
      0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
      0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
      0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
      0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
      0xeb86d391,
    ];
    var S = [
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
      14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
      21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    function add32(a, b) {
      return (a + b) | 0;
    }
    function cmn(q, a, b, x, s, t) {
      a = add32(add32(a, q), add32(x, t));
      return add32((a << s) | (a >>> (32 - s)), b);
    }
    function ff(a, b, c, d, x, s, t) {
      return cmn((b & c) | (~b & d), a, b, x, s, t);
    }
    function gg(a, b, c, d, x, s, t) {
      return cmn((b & d) | (c & ~d), a, b, x, s, t);
    }
    function hh(a, b, c, d, x, s, t) {
      return cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function ii(a, b, c, d, x, s, t) {
      return cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    // Pre-processing: pad to 512-bit boundary
    var msgLen = bytes.length;
    var padLen = (56 - ((msgLen + 1) % 64) + 64) % 64;
    var padded = new Uint8Array(msgLen + 1 + padLen + 8);
    padded.set(bytes);
    padded[msgLen] = 0x80;
    var dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, (msgLen * 8) >>> 0, true);
    dv.setUint32(padded.length - 4, ((msgLen * 8) / 0x100000000) >>> 0, true);

    var a0 = 0x67452301,
      b0 = 0xefcdab89,
      c0 = 0x98badcfe,
      d0 = 0x10325476;
    for (var offset = 0; offset < padded.length; offset += 64) {
      var M = [];
      for (var j = 0; j < 16; j++) M[j] = dv.getUint32(offset + j * 4, true);
      var A = a0,
        B = b0,
        C = c0,
        D = d0;
      for (var i = 0; i < 64; i++) {
        var q, r;
        if (i < 16) {
          r = i;
          q = ff(A, B, C, D, M[r], S[i], K[i]);
        } else if (i < 32) {
          r = (5 * i + 1) % 16;
          q = gg(A, B, C, D, M[r], S[i], K[i]);
        } else if (i < 48) {
          r = (3 * i + 5) % 16;
          q = hh(A, B, C, D, M[r], S[i], K[i]);
        } else {
          r = (7 * i) % 16;
          q = ii(A, B, C, D, M[r], S[i], K[i]);
        }
        A = D;
        D = C;
        C = B;
        B = q;
      }
      a0 = add32(a0, A);
      b0 = add32(b0, B);
      c0 = add32(c0, C);
      d0 = add32(d0, D);
    }
    function hex32(v) {
      return Array.from(new Uint8Array(new Uint32Array([v]).buffer))
        .map(function (b) {
          return ('0' + b.toString(16)).slice(-2);
        })
        .join('');
    }
    return hex32(a0) + hex32(b0) + hex32(c0) + hex32(d0);
  }

  // SHA-256 via Web Crypto — returns lowercase hex string
  function sha256(bytes) {
    return crypto.subtle.digest('SHA-256', bytes).then(function (buf) {
      return Array.from(new Uint8Array(buf))
        .map(function (b) {
          return ('0' + b.toString(16)).slice(-2);
        })
        .join('');
    });
  }

  // Base64 data URI → raw Uint8Array
  function dataUriToBytes(dataUri) {
    var b64 = dataUri.replace(/^data:[^;]+;base64,/, '');
    var binary = atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Generate all hash types from favicon data URI
  async function computeHashes(dataUri) {
    var b64Plain = dataUri.replace(/^data:[^;]+;base64,/, '');
    var rawBytes = dataUriToBytes(dataUri);

    // MMH3: hash of base64 WITH newlines every 76 chars (Python encodebytes)
    var b64WithNewlines = encodebytes(b64Plain);
    var mmh3Val = mm3hash32(b64WithNewlines);

    // MD5 (pure JS — Web Crypto does not support MD5)
    var md5Hash = md5(rawBytes);
    // SHA-256 via Web Crypto
    var sha256Hash = await sha256(rawBytes);

    return {
      mmh3: mmh3Val,
      md5: md5Hash,
      sha256: sha256Hash,
    };
  }

  // Platform definitions — each uses the correct hash type for its search engine
  function getPlatformLinks(hashes) {
    return [
      {
        name: 'ZoomEye',
        hash: 'md5',
        url: 'https://www.zoomeye.org/searchResult?q=iconhash%3D%22' + hashes.md5 + '%22',
      },
    ];
  }

  function renderHashDetails(hashEl, hashes) {
    if (!hashEl) return;
    hashEl.innerHTML =
      '<div class="hash-detail-row"><span class="detail-label">MMH3</span><span class="detail-value hash-value">' +
      hashes.mmh3 +
      '</span></div>' +
      '<div class="hash-detail-row"><span class="detail-label">MD5</span><span class="detail-value hash-value">' +
      hashes.md5 +
      '</span></div>' +
      '<div class="hash-detail-row"><span class="detail-label">SHA256</span><span class="detail-value hash-value">' +
      hashes.sha256 +
      '</span></div>';
  }

  function renderPlatformLinks(linksEl, platforms, utils) {
    if (!linksEl) return;
    linksEl.innerHTML =
      platforms
        .map(function (p) {
          return (
            '<a class="favicon-search-link" href="' +
            utils.escapeHtml(p.url) +
            '" target="_blank">' +
            utils.escapeHtml(p.name) +
            '<span class="hash-tag md5-tag">' +
            p.hash +
            '</span></a>'
          );
        })
        .join('') + '<div class="favicon-hint">点击平台名称跳转搜索</div>';
  }

  async function extractFavicon() {
    var utils = window.VulnKitUtils.utilsProxy;
    var btn = utils.get('extract-favicon-btn');
    var hashEl = utils.get('favicon-hash');
    var linksEl = utils.get('favicon-search-links');

    try {
      var tab = await utils.getActiveTab();
      if (!tab || !tab.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      // Reset UI
      if (hashEl) hashEl.innerHTML = '-';
      if (linksEl) linksEl.innerHTML = '';
      if (btn) {
        btn.disabled = true;
        btn.textContent = '提取中...';
      }

      var url = new URL(tab.url);
      var domain = url.hostname;

      var faviconUrl =
        (await utils.execInTabData(
          tab.id,
          function () {
            var links = Array.from(document.querySelectorAll('link[rel*="icon"]')).filter(
              function (l) {
                return !l.rel.includes('apple-touch') && !l.rel.includes('mask');
              }
            );
            if (links.length > 0) return links[0].href;
            return '/favicon.ico';
          },
          { world: 'ISOLATED' }
        )) || 'https://' + domain + '/favicon.ico';
      var resolvedUrl = new URL(faviconUrl, tab.url).href;

      var faviconImg = utils.get('favicon-img');
      var faviconPlaceholder = utils.get('favicon-placeholder');
      var faviconUrlEl = utils.get('favicon-url');
      if (faviconUrlEl) faviconUrlEl.textContent = resolvedUrl;

      var response = await new Promise(function (resolve) {
        chrome.runtime.sendMessage({ type: 'FETCH_IMAGE', url: resolvedUrl }, function (resp) {
          resolve(resp);
        });
      });

      if (!response || !response.data) {
        if (hashEl) hashEl.textContent = '获取失败';
        utils.showToast(
          '图标获取失败: ' + (response && response.error ? response.error : '网络错误'),
          'error'
        );
        return;
      }

      // Compute all hash types
      var hashes = await computeHashes(response.data);

      // Display hash values
      renderHashDetails(hashEl, hashes);

      // Show preview
      if (faviconImg) {
        faviconImg.src = response.data;
        faviconImg.classList.remove('hidden');
        faviconImg.onerror = function () {
          faviconImg.classList.add('hidden');
          if (faviconPlaceholder) faviconPlaceholder.classList.remove('hidden');
        };
      }
      if (faviconPlaceholder) faviconPlaceholder.classList.add('hidden');

      // SVG favicon warning
      if (response.data.startsWith('data:image/svg+xml')) {
        utils.showToast('SVG 图标哈希可能与平台结果不匹配', 'warning');
      }

      // Generate per-platform search links
      var platforms = getPlatformLinks(hashes);
      renderPlatformLinks(linksEl, platforms, utils);

      utils.showToast('图标提取成功，点击平台名称搜索', 'success');
    } catch (e) {
      utils.showToast('提取失败: ' + e.message, 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '提取当前页面图标';
      }
    }
  }

  function copyFaviconUrl() {
    var utils = window.VulnKitUtils.utilsProxy;
    var urlEl = utils.get('favicon-url');
    if (!urlEl || urlEl.textContent === '-') {
      utils.showToast('请先提取图标', 'warning');
      return;
    }
    utils.copyAndToast(urlEl.textContent, '已复制图标 URL');
  }

  function copyFaviconHash() {
    var utils = window.VulnKitUtils.utilsProxy;
    var hashEl = utils.get('favicon-hash');
    if (!hashEl || hashEl.textContent === '-' || hashEl.textContent === '获取失败') {
      utils.showToast('请先提取图标', 'warning');
      return;
    }
    // Extract MMH3 value for copy (first hash-value element)
    var mmh3El = hashEl.querySelector('.hash-value');
    var text = mmh3El ? mmh3El.textContent : hashEl.textContent;
    utils.copyAndToast(text, '已复制 MMH3 Hash');
  }

  return { extractFavicon, copyFaviconUrl, copyFaviconHash };
})();
