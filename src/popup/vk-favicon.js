// 灵眸 - Favicon (MMH3 Hash)
window.VulnKitFavicon = (function () {
  'use strict';

  // MurmurHash3 (32-bit) on raw Uint8Array — matches Shodan/FOFA/ZoomEye implementation
  function mm3hash32(rawBytes) {
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;
    let h1 = 0;
    const round = (h, k) => {
      k = Math.imul(k, c1);
      k = (k << 15) | (k >>> 17);
      k = Math.imul(k, c2);
      h ^= k;
      h = (h << 13) | (h >>> 19);
      return (Math.imul(h, 5) + 0xe6546b64) | 0;
    };
    const len = rawBytes.length;
    const nblocks = len >> 2;
    for (let i = 0; i < nblocks; i++) {
      const off = i * 4;
      const k =
        rawBytes[off] |
        (rawBytes[off + 1] << 8) |
        (rawBytes[off + 2] << 16) |
        (rawBytes[off + 3] << 24);
      h1 = round(h1, k);
    }
    let k1 = 0;
    const tail = nblocks * 4;
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
    return h1 | 0; // signed int32 — may be negative
  }

  function base64ToUint8(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function urlSafeBtoa(str) {
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  async function extractFavicon() {
    const utils = window.VulnKitUtils.utilsProxy;
    const btn = utils.get('extract-favicon-btn');
    const hashEl = utils.get('favicon-hash');
    const linksEl = utils.get('favicon-search-links');

    try {
      const tab = await utils.getActiveTab();
      if (!tab?.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      // Reset UI + loading state
      if (hashEl) hashEl.textContent = '-';
      if (linksEl) linksEl.innerHTML = '';
      if (btn) { btn.disabled = true; btn.textContent = '提取中...'; }

      const url = new URL(tab.url);
      const domain = url.hostname;

      const faviconUrl =
        (await utils.execInTabData(
          tab.id,
          () => {
            const links = Array.from(
              document.querySelectorAll('link[rel*="icon"]')
            ).filter(
              l => !l.rel.includes('apple-touch') && !l.rel.includes('mask')
            );
            if (links.length > 0) return links[0].href;
            return '/favicon.ico';
          },
          { world: 'ISOLATED' }
        )) || `https://${domain}/favicon.ico`;
      const resolvedUrl = new URL(faviconUrl, tab.url).href;

      const faviconImg = utils.get('favicon-img');
      const faviconPlaceholder = utils.get('favicon-placeholder');
      const faviconUrlEl = utils.get('favicon-url');
      if (faviconUrlEl) faviconUrlEl.textContent = resolvedUrl;

      const response = await new Promise(function (resolve) {
        chrome.runtime.sendMessage({ type: 'FETCH_IMAGE', url: resolvedUrl }, function (resp) {
          resolve(resp);
        });
      });

      if (!response || !response.data) {
        if (hashEl) hashEl.textContent = '获取失败';
        utils.showToast('图标获取失败: ' + (response?.error || '网络错误'), 'error');
        return;
      }

      // Decode base64 → raw bytes, then hash (matches Shodan/FOFA implementation)
      const b64Data = response.data.replace(/^data:[^;]+;base64,/, '');
      const rawBytes = base64ToUint8(b64Data);
      const faviconHash = mm3hash32(rawBytes);
      if (hashEl) hashEl.textContent = String(faviconHash);

      // Show preview using data URI from background (avoids CORS issues)
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

      const hashStr = String(faviconHash);
      const platforms = [
        {
          name: 'Shodan',
          url: 'https://www.shodan.io/search?query=http.favicon.hash%3A' + hashStr,
        },
        {
          name: 'FOFA',
          url:
            'https://fofa.info/result?qbase64=' +
            urlSafeBtoa('icon_hash="' + hashStr + '"'),
        },
        {
          name: 'ZoomEye',
          url: 'https://www.zoomeye.org/searchResult?q=iconhash%3A' + hashStr,
        },
        {
          name: 'Quake',
          url:
            'https://quake.360.net/quake/#/searchResult?q=app.iconhash%3A%22' +
            hashStr +
            '%22',
        },
        {
          name: 'Hunter',
          url:
            'https://hunter.qianxin.com/searchResult?q=web.icon%3D%22' + hashStr + '%22',
        },
      ];

      if (linksEl) {
        linksEl.innerHTML = platforms
          .map(
            p =>
              '<a class="favicon-search-link" href="' +
              utils.escapeHtml(p.url) +
              '" target="_blank">' +
              utils.escapeHtml(p.name) +
              '</a>'
          )
          .join('');
      }

      utils.showToast('图标提取成功', 'success');
    } catch (e) {
      utils.showToast('提取失败: ' + e.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '提取当前页面图标'; }
    }
  }

  function copyFaviconUrl() {
    const utils = window.VulnKitUtils.utilsProxy;
    const urlEl = utils.get('favicon-url');
    if (!urlEl || urlEl.textContent === '-') {
      utils.showToast('请先提取图标', 'warning');
      return;
    }
    utils.copyAndToast(urlEl.textContent, '已复制图标 URL');
  }

  return { extractFavicon, copyFaviconUrl };
})();
