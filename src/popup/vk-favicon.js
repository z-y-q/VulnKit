// VulnKit - Favicon (MMH3 Hash)
window.VulnKitFavicon = (function () {
  'use strict';

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  function mm3hash32(str) {
    const seed = 0;
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;
    const h1 = seed | 0;
    const round = (h1, k1) => {
      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
      h1 = (h1 << 13) | (h1 >>> 19);
      return (Math.imul(h1, 5) + 0xe6546b64) | 0;
    };
    let h = h1;
    const bytes = new TextEncoder().encode(str);
    const len = bytes.length;
    const nblocks = len >> 2;
    for (let i = 0; i < nblocks; i++) {
      const k1 =
        bytes[i * 4] |
        (bytes[i * 4 + 1] << 8) |
        (bytes[i * 4 + 2] << 16) |
        (bytes[i * 4 + 3] << 24);
      h = round(h, k1);
    }
    let k1 = 0;
    const tail = nblocks * 4;
    switch (len & 3) {
      case 3:
        k1 ^= bytes[tail + 2] << 16;
      case 2:
        k1 ^= bytes[tail + 1] << 8;
      case 1:
        k1 ^= bytes[tail];
        h = round(h, k1);
    }
    h ^= len;
    h ^= h >>> 16;
    h = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13;
    h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return (h >>> 0).toString(10);
  }

  async function extractFavicon() {
    try {
      const utils = getUtils();
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      const url = new URL(tab.url);
      const domain = url.hostname;

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const links = document.querySelectorAll('link[rel*="icon"], link[rel="shortcut icon"]');
          if (links.length > 0) return links[0].href;
          return '/favicon.ico';
        },
      });

      const faviconUrl = results?.[0]?.result || `https://${domain}/favicon.ico`;
      const resolvedUrl = new URL(faviconUrl, tab.url).href;

      utils.get('favicon-img').src = resolvedUrl;
      utils.get('favicon-img').classList.remove('hidden');
      utils.get('favicon-placeholder').classList.add('hidden');
      utils.get('favicon-url').textContent = resolvedUrl;

      try {
        const resp = await fetch(resolvedUrl);
        const buf = await resp.arrayBuffer();
        const bytes = new Uint8Array(buf);

        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        const b64 = btoa(binary);
        const faviconHash = mm3hash32(b64);
        utils.get('favicon-hash').textContent = '-' + faviconHash;

        const platforms = [
          {
            name: 'Shodan',
            url: 'https://www.shodan.io/search?query=http.favicon.hash%3A' + faviconHash,
            color: '#4A90E2',
          },
          {
            name: 'FOFA',
            url: 'https://fofa.info/result?qbase64=' + btoa('icon_hash="-' + faviconHash + '"'),
            color: '#10b981',
          },
          {
            name: 'ZoomEye',
            url: 'https://www.zoomeye.org/searchResult?q=iconhash%3A' + faviconHash,
            color: '#f59e0b',
          },
          {
            name: 'Quake',
            url:
              'https://quake.360.net/quake/#/searchResult?q=app.iconhash%3A%22' +
              faviconHash +
              '%22',
            color: '#ef4444',
          },
          {
            name: 'Hunter',
            url: 'https://hunter.qianxin.com/searchResult?q=web.icon%3D%22' + faviconHash + '%22',
            color: '#8b5cf6',
          },
        ];

        const linksContainer = utils.get('favicon-search-links');
        linksContainer.innerHTML = platforms
          .map(
            p =>
              '<a class="favicon-search-link" href="' +
              p.url +
              '" target="_blank">' +
              p.name +
              '</a>'
          )
          .join('');
      } catch {
        utils.get('favicon-hash').textContent = '获取失败';
      }

      utils.showToast('图标提取成功', 'success');
    } catch (e) {
      getUtils().showToast('提取失败: ' + e.message, 'error');
    }
  }

  return { extractFavicon };
})();
