// VulnKit v5.0
(function () {
  'use strict';

  const ENCODING_NAMES = { base64: 'Base64', url: 'URL', html: 'HTML', hex: 'Hex' };
  let currentEncodingType = 'base64';
  let currentAssetSource = 'fofa';

  const utils = {
    cache: new Map(),
    get(id) {
      if (!this.cache.has(id)) {
        this.cache.set(id, document.getElementById(id));
      }
      return this.cache.get(id);
    },
    escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },
    copyText(text) {
      navigator.clipboard.writeText(text).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
    },
    showToast: (() => {
      let current = null;
      const types = ['success', 'error', 'warning', 'info'];
      return function (message, type) {
        if (current && current.parentNode) current.parentNode.removeChild(current);
        current = document.createElement('div');
        current.className = 'toast toast-' + (types.includes(type) ? type : 'info');
        current.textContent = message;
        document.body.appendChild(current);
        requestAnimationFrame(() => {
          if (current) current.classList.add('toast-show');
        });
        setTimeout(() => {
          if (current) {
            current.classList.remove('toast-show');
            setTimeout(() => {
              if (current && current.parentNode) {
                current.parentNode.removeChild(current);
                current = null;
              }
            }, 200);
          }
        }, 2000);
      };
    })(),
  };

  // ====== Encoding Tools ======
  const encodingTools = {
    base64: {
      encode(t) {
        try {
          return btoa(unescape(encodeURIComponent(t)));
        } catch (e) {
          return 'Error: ' + e.message;
        }
      },
      decode(t) {
        try {
          const d = atob(t);
          const b = new Uint8Array(d.length);
          for (let i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
          return new TextDecoder().decode(b);
        } catch (e) {
          return 'Error: invalid Base64';
        }
      },
    },
    url: { encode: encodeURIComponent, decode: decodeURIComponent },
    html: {
      encode(t) {
        const d = document.createElement('div');
        d.textContent = t;
        return d.innerHTML;
      },
      decode(t) {
        const d = document.createElement('div');
        d.innerHTML = t;
        return d.textContent || '';
      },
    },
    hex: {
      encode(t) {
        return Array.from(new TextEncoder().encode(t))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      },
      decode(t) {
        return new TextDecoder().decode(
          new Uint8Array(t.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || [])
        );
      },
    },
  };

  function handleEncode() {
    const input = utils.get('encoding-input').value;
    if (!input) {
      utils.showToast('请输入文本', 'warning');
      return;
    }
    const result = encodingTools[currentEncodingType]?.encode(input);
    if (result === undefined) {
      utils.showToast('未知编码类型', 'error');
      return;
    }
    utils.get('encoding-output').value = result;
    utils.showToast('编码成功', 'success');
  }

  function handleDecode() {
    const input = utils.get('encoding-input').value;
    if (!input) {
      utils.showToast('请输入文本', 'warning');
      return;
    }
    const result = encodingTools[currentEncodingType]?.decode(input);
    if (result === undefined) {
      utils.showToast('未知编码类型', 'error');
      return;
    }
    utils.get('encoding-output').value = result;
    utils.showToast('解码成功', 'success');
  }

  function clearEncodingFields() {
    utils.get('encoding-input').value = '';
    utils.get('encoding-output').value = '';
  }

  function switchEncodingTab(type) {
    currentEncodingType = type;
    document
      .querySelectorAll('.sub-tab-btn')
      .forEach(b => b.classList.toggle('active', b.dataset.type === type));
    utils.get('card-title').textContent = ENCODING_NAMES[type] + ' 编码/解码';
  }

  // ====== Favicon (MMH3 Hash) ======
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
      utils.showToast('提取失败: ' + e.message, 'error');
    }
  }

  // ====== Asset Mapping ======
  async function getApiKey(source) {
    return new Promise(resolve => {
      chrome.storage.local.get(['pentest_keys'], result => {
        const keys = result.pentest_keys || {};
        if (source === 'fofa') resolve({ email: keys.fofa_email, key: keys.fofa_key });
        else if (source === 'zoomeye') resolve(keys.zoomeye);
        else if (source === 'shodan') resolve(keys.shodan);
        else resolve(null);
      });
    });
  }

  async function getCurrentUrl() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url || null;
  }

  async function getCurrentDomain() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return null;
    try {
      return new URL(tab.url).hostname;
    } catch {
      return null;
    }
  }

  function setAssetStatus(text) {
    utils.get('asset-status').textContent = text;
  }

  function renderAssetResults(data) {
    const container = utils.get('asset-results');
    if (!data || data.length === 0) {
      container.innerHTML = '<div class="empty-state">未找到结果</div>';
      return;
    }
    let html = '<div class="asset-count">共 ' + data.length + ' 条结果</div>';
    html +=
      '<table class="asset-table"><thead><tr><th>IP/域名</th><th>端口</th><th>协议</th><th>标题</th></tr></thead><tbody>';
    data.forEach(item => {
      html += '<tr>';
      html +=
        '<td title="' +
        utils.escapeHtml(item.host || '') +
        '">' +
        utils.escapeHtml(item.host || '-') +
        '</td>';
      html += '<td>' + utils.escapeHtml(String(item.port || '-')) + '</td>';
      html += '<td>' + utils.escapeHtml(item.protocol || '-') + '</td>';
      html +=
        '<td title="' +
        utils.escapeHtml(item.title || '') +
        '">' +
        utils.escapeHtml(item.title || '-') +
        '</td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;
  }

  async function scanFofa(query) {
    const keys = await getApiKey('fofa');
    if (!keys?.email || !keys?.key) {
      utils.showToast('请先配置 FOFA API Key', 'warning');
      return;
    }
    setAssetStatus('正在查询 FOFA...');
    const qbase64 = btoa(unescape(encodeURIComponent('domain="' + query + '"')));
    const url =
      'https://fofa.info/api/v1/search/all?email=' +
      encodeURIComponent(keys.email) +
      '&key=' +
      encodeURIComponent(keys.key) +
      '&qbase64=' +
      qbase64 +
      '&fields=host,port,protocol,title&size=100';

    chrome.runtime.sendMessage({ type: 'FETCH_URL', url }, response => {
      if (response?.error) {
        setAssetStatus('查询失败: ' + response.error);
        return;
      }
      try {
        const json = JSON.parse(response.data);
        if (json.error) {
          setAssetStatus('API 错误: ' + json.error);
          return;
        }
        const results = (json.results || []).map(r => ({
          host: r[0],
          port: r[1],
          protocol: r[2],
          title: r[3],
        }));
        setAssetStatus('FOFA: 查询完成');
        renderAssetResults(results);
      } catch {
        setAssetStatus('解析结果失败');
      }
    });
  }

  async function scanZoomEye(query) {
    const key = await getApiKey('zoomeye');
    if (!key) {
      utils.showToast('请先配置 ZoomEye API Key', 'warning');
      return;
    }
    setAssetStatus('正在查询 ZoomEye...');
    const url =
      'https://api.zoomeye.org/host/search?query=' +
      encodeURIComponent('hostname:' + query) +
      '&page=1';

    chrome.runtime.sendMessage(
      { type: 'FETCH_URL_AUTH', url, key, header: 'API-KEY' },
      response => {
        if (response?.error) {
          setAssetStatus('查询失败: ' + response.error);
          return;
        }
        try {
          const json = JSON.parse(response.data);
          const results = (json.matches || []).map(r => ({
            host: r.ip || '-',
            port: r.portinfo?.port || '-',
            protocol: r.portinfo?.type || '-',
            title: r.webinfo?.title || '-',
          }));
          setAssetStatus('ZoomEye: 查询完成');
          renderAssetResults(results);
        } catch {
          setAssetStatus('解析结果失败');
        }
      }
    );
  }

  async function scanShodan(query) {
    const key = await getApiKey('shodan');
    if (!key) {
      utils.showToast('请先配置 Shodan API Key', 'warning');
      return;
    }
    setAssetStatus('正在查询 Shodan...');
    const url = 'https://api.shodan.io/shodan/host/' + query + '?key=' + encodeURIComponent(key);

    chrome.runtime.sendMessage({ type: 'FETCH_URL', url }, response => {
      if (response?.error) {
        setAssetStatus('查询失败: ' + response.error);
        return;
      }
      try {
        const json = JSON.parse(response.data);
        if (json.error) {
          setAssetStatus('API 错误: ' + json.error);
          return;
        }
        const results = (json.data || []).map(d => ({
          host: json.ip_str || query,
          port: d.port || '-',
          protocol: d._shodan?.module || '-',
          title: d.http?.title || '-',
        }));
        setAssetStatus('Shodan: 查询完成');
        renderAssetResults(results);
      } catch {
        setAssetStatus('解析结果失败');
      }
    });
  }

  async function handleAssetScan() {
    let query = utils.get('asset-query').value.trim();
    if (!query) {
      query = await getCurrentDomain();
      if (!query) {
        utils.showToast('请输入目标或打开一个网页', 'warning');
        return;
      }
      utils.get('asset-query').value = query;
    }

    const scanners = { fofa: scanFofa, zoomeye: scanZoomEye, shodan: scanShodan };
    const scanner = scanners[currentAssetSource];
    if (scanner) scanner(query);
  }

  function switchAssetSource(source) {
    currentAssetSource = source;
    document
      .querySelectorAll('.source-btn')
      .forEach(b => b.classList.toggle('active', b.dataset.source === source));
    utils.get('asset-results').innerHTML = '';
    setAssetStatus('');
  }

  function saveApiKeys() {
    const keys = {
      fofa_email: utils.get('key-fofa-email').value.trim(),
      fofa_key: utils.get('key-fofa-key').value.trim(),
      zoomeye: utils.get('key-zoomeye').value.trim(),
      shodan: utils.get('key-shodan').value.trim(),
    };
    chrome.storage.local.set({ pentest_keys: keys }, () => {
      utils.showToast('配置已保存', 'success');
    });
  }

  function loadApiKeys() {
    chrome.storage.local.get(['pentest_keys'], result => {
      const keys = result.pentest_keys || {};
      if (utils.get('key-fofa-email')) utils.get('key-fofa-email').value = keys.fofa_email || '';
      if (utils.get('key-fofa-key')) utils.get('key-fofa-key').value = keys.fofa_key || '';
      if (utils.get('key-zoomeye')) utils.get('key-zoomeye').value = keys.zoomeye || '';
      if (utils.get('key-shodan')) utils.get('key-shodan').value = keys.shodan || '';
    });
  }

  function clearApiKeys() {
    chrome.storage.local.remove(['pentest_keys'], () => {
      utils.get('key-fofa-email').value = '';
      utils.get('key-fofa-key').value = '';
      utils.get('key-zoomeye').value = '';
      utils.get('key-shodan').value = '';
      utils.showToast('配置已清除', 'success');
    });
  }

  // ====== URL Multi-Open ======
  function parseUrls() {
    const text = utils.get('multiurl-input').value;
    return text
      .split(/[\n\r]+/)
      .map(line => {
        let url = line.trim();
        if (!url) return null;
        if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
        return url;
      })
      .filter(Boolean);
  }

  function updateMultiurlInfo(count) {
    const el = utils.get('multiurl-info');
    if (el) el.textContent = count > 0 ? '已识别 ' + count + ' 个 URL' : '';
  }

  function handleMultiurlOpen() {
    const urls = parseUrls();
    if (urls.length === 0) {
      utils.showToast('请输入URL', 'warning');
      return;
    }
    if (urls.length > 50) {
      utils.showToast('一次最多打开 50 个', 'warning');
      return;
    }
    urls.forEach(url => chrome.tabs.create({ url, active: false }));
    utils.showToast('已打开 ' + urls.length + ' 个标签页', 'success');
  }

  function handleMultiurlDedup() {
    const urls = parseUrls();
    const unique = [...new Set(urls)];
    if (unique.length === urls.length) {
      utils.showToast('没有重复URL', 'info');
      return;
    }
    utils.get('multiurl-input').value = unique.join('\n');
    updateMultiurlInfo(unique.length);
    utils.showToast('去重完成，移除 ' + (urls.length - unique.length) + ' 个重复', 'success');
  }

  // ====== Info Gather ======
  let gatherData = { api: [], domain: [], sensitive: [], ip: [] };
  let currentGatherTab = 'api';

  function renderGatherTab() {
    const list = gatherData[currentGatherTab] || [];
    const container = utils.get('gather-results');
    const statusEl = utils.get('gather-status');

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">点击「收集当前页面」开始</div>';
      statusEl.textContent = '';
      return;
    }

    statusEl.textContent = '共 ' + list.length + ' 条';
    let html = '';
    list.forEach(item => {
      html += '<div class="gather-item">';
      html +=
        '<span class="gather-item-type type-' +
        (item.type || 'other') +
        '">' +
        item.type +
        '</span>';
      html +=
        '<span class="gather-item-value" title="' +
        utils.escapeHtml(item.value) +
        '">' +
        utils.escapeHtml(item.value) +
        '</span>';
      html +=
        '<button class="gather-item-copy" data-copy="' +
        utils.escapeHtml(item.value) +
        '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.gather-item-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.copyText(btn.dataset.copy);
        utils.showToast('已复制', 'success');
      });
    });
  }

  function switchGatherTab(tab) {
    currentGatherTab = tab;
    document
      .querySelectorAll('.gather-tab')
      .forEach(b => b.classList.toggle('active', b.dataset.gather === tab));
    renderGatherTab();
  }

  async function gatherInfo() {
    const statusEl = utils.get('gather-status');
    statusEl.textContent = '正在收集...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        statusEl.textContent = '无法获取当前页面';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const pageUrl = location.href;
          const pageHtml = document.documentElement.outerHTML;
          const collected = { api: [], domain: [], sensitive: [], ip: [] };
          const seen = { api: new Set(), domain: new Set(), sensitive: new Set(), ip: new Set() };

          function add(cat, type, value) {
            if (!value || seen[cat].has(value)) return;
            seen[cat].add(value);
            collected[cat].push({ type, value });
          }

          // 1. API endpoints
          document.querySelectorAll('form').forEach(form => {
            const action = form.getAttribute('action') || '';
            const method = (form.method || 'GET').toUpperCase();
            if (action) {
              const fullUrl = new URL(action, pageUrl).href;
              add('api', method.toLowerCase(), fullUrl);
            }
          });

          // Script src as potential API base
          document.querySelectorAll('script[src]').forEach(s => {
            const src = s.src;
            if (src) {
              const m = src.match(/^(https?:\/\/[^/]+)/i);
              if (m) add('api', 'src', m[1]);
            }
          });

          // Extract API paths from inline scripts
          document.querySelectorAll('script:not([src])').forEach(s => {
            const text = s.textContent || '';
            const apiMatches = text.match(/["'](\/api\/[^"']+)["']/g) || [];
            apiMatches.forEach(m => add('api', 'api', m.replace(/["']/g, '')));
            const pathMatches = text.match(/["'](\/[a-zA-Z0-9_/{}-]+)["']/g) || [];
            pathMatches.forEach(m => {
              const p = m.replace(/["']/g, '');
              if (p.length > 2 && /\/(v\d|api|rest|graphql|json|ws|socket)/i.test(p)) {
                add('api', 'api', p);
              }
            });
            const fetchMatches = text.match(/fetch\s*\(\s*["']([^"']+)["']/gi) || [];
            fetchMatches.forEach(m =>
              add('api', 'get', m.replace(/^fetch\s*\(\s*["']/i, '').replace(/["']\s*\)$/i, ''))
            );
            const ajaxMatches =
              text.match(/\$?\.(?:get|post|put|delete|ajax|fetch)\s*\(\s*["']([^"']+)["']/gi) || [];
            ajaxMatches.forEach(m => {
              const url = m.replace(/^.*\(\s*["']/, '').replace(/["']/, '');
              if (url) {
                const method = /\.(post|put|delete)/i.test(m)
                  ? m.match(/\.(post|put|delete)/i)[1]
                  : 'get';
                add('api', method.toLowerCase(), url);
              }
            });
            const wsMatches = text.match(/wss?:\/\/[^"'\s]+/g) || [];
            wsMatches.forEach(u => add('api', 'ws', u));
          });

          // Link[href] endpoints
          document.querySelectorAll('link[href]').forEach(l => {
            const href = l.href;
            if (href && /\.(json|xml|yaml)$/i.test(href)) add('api', 'api', href);
          });

          // 2. Domains
          document.querySelectorAll('[href]').forEach(el => {
            try {
              const url = new URL(el.href, pageUrl);
              if (url.hostname !== location.hostname) add('domain', 'link', url.hostname);
            } catch {}
          });
          document.querySelectorAll('[src]').forEach(el => {
            try {
              const url = new URL(el.src, pageUrl);
              if (url.hostname !== location.hostname) add('domain', 'src', url.hostname);
            } catch {}
          });
          document.querySelectorAll('iframe[src],frame[src]').forEach(el => {
            try {
              const url = new URL(el.src, pageUrl);
              add('domain', 'frame', url.hostname);
            } catch {}
          });

          // 3. Sensitive info
          // Meta generator
          document.querySelectorAll('meta[name="generator"]').forEach(m => {
            if (m.content) add('sensitive', 'meta', 'Generator: ' + m.content);
          });

          // Emails
          const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
          const emails = pageHtml.match(emailRegex) || [];
          emails.forEach(e => add('sensitive', 'email', e));

          // API keys/tokens in meta or inline scripts
          const tokenPatterns = [
            /(?:api[_-]?key|apikey|token|secret|access[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*["']([^"']{8,})["']/gi,
            /(?:sk|pk|rk)[_-][a-zA-Z0-9]{20,}/g,
            /(?:AIza|ya29)[a-zA-Z0-9_-]{30,}/g,
            /ghp_[a-zA-Z0-9]{30,}/g,
            /glpat-[a-zA-Z0-9_-]{20,}/g,
            /xox[bpras]-[a-zA-Z0-9-]{10,}/g,
          ];
          tokenPatterns.forEach(pattern => {
            const matches = pageHtml.match(pattern) || [];
            matches.forEach(m => {
              const val =
                m.includes('=') || m.includes(':')
                  ? m
                      .split(/[:=]/)
                      .pop()
                      .trim()
                      .replace(/^["']|["']$/g, '')
                  : m;
              add('sensitive', 'token', val);
            });
          });

          // Comments with sensitive info
          const commentRegex = /<!--([\s\S]*?)-->/g;
          let commentMatch;
          while ((commentMatch = commentRegex.exec(pageHtml)) !== null) {
            const comment = commentMatch[1].trim();
            if (comment.length > 5 && comment.length < 200) {
              if (/todo|fixme|hack|bug|password|key|secret|temp/i.test(comment)) {
                add('sensitive', 'comment', comment);
              }
            }
          }

          // Cookies
          document.cookie.split(';').forEach(c => {
            const name = c.split('=')[0].trim();
            if (name) add('sensitive', 'cookie', name);
          });

          // localStorage keys
          try {
            for (let i = 0; i < localStorage.length; i++) {
              const key = localStorage.key(i);
              if (/token|key|secret|session|auth|user|admin/i.test(key)) {
                add('sensitive', 'storage', 'localStorage: ' + key);
              }
            }
          } catch {}

          // 4. IP addresses
          const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
          const ips = pageHtml.match(ipRegex) || [];
          ips.forEach(ip => {
            const parts = ip.split('.').map(Number);
            if (parts[0] !== 0 && parts[0] !== 127 && parts.every(p => p >= 0 && p <= 255)) {
              add('ip', 'ip', ip);
            }
          });

          // Internal/private IPs
          ips.forEach(ip => {
            const p = ip.split('.').map(Number);
            if (
              p[0] === 10 ||
              (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
              (p[0] === 192 && p[1] === 168)
            ) {
              add('ip', 'ip', ip);
            }
          });

          // Cloud/hosting domains hint
          const domainStr = collected.domain.map(d => d.value).join(' ');
          const cloudHints = [
            { pattern: /aws\.amazon/i, label: 'AWS' },
            { pattern: /azure\.microsoft/i, label: 'Azure' },
            { pattern: /googleapis\.com/i, label: 'GCP' },
            { pattern: /aliyuncs\.com/i, label: 'Aliyun' },
            { pattern: /tencentcloud/i, label: 'Tencent' },
            { pattern: /cloudflare/i, label: 'Cloudflare' },
            { pattern: /fastly/i, label: 'Fastly' },
            { pattern: /cdn\.|c\.cloudfront\.net/i, label: 'CDN' },
          ];
          cloudHints.forEach(h => {
            if (h.pattern.test(pageHtml + domainStr)) add('ip', 'cloud', h.label);
          });

          return collected;
        },
      });

      if (results?.[0]?.result) {
        gatherData = results[0].result;
        renderGatherTab();
        const total = Object.values(gatherData).reduce((s, a) => s + a.length, 0);
        statusEl.textContent = '收集完成，共 ' + total + ' 条';
        utils.showToast('收集完成', 'success');
        chrome.storage.local.set({ gatherData: gatherData, gatherDataUrl: tab.url });
      } else {
        statusEl.textContent = '收集失败';
      }
    } catch (e) {
      statusEl.textContent = '收集失败: ' + e.message;
      utils.showToast('收集失败', 'error');
    }
  }

  // ====== Link Extract ======
  let allLinks = [];

  function getTagInfo(el) {
    if (!el) return { tag: 'a', label: 'a' };
    const name = el.tagName.toLowerCase();
    if (name === 'a') return { tag: 'a', label: 'a' };
    if (name === 'img') return { tag: 'img', label: 'img' };
    if (name === 'script') return { tag: 'script', label: 'script' };
    if (name === 'link') return { tag: 'link', label: 'link' };
    if (name === 'iframe' || name === 'frame') return { tag: 'iframe', label: 'iframe' };
    return { tag: 'other', label: name };
  }

  async function extractLinks() {
    const statusEl = utils.get('links-count');
    statusEl.textContent = '正在提取...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        statusEl.textContent = '无法获取当前页面';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const pageUrl = location.href;
          const pageDomain = location.hostname;
          const links = [];

          // <a href>
          document.querySelectorAll('a[href]').forEach(el => {
            const href = el.href;
            if (!href || href === '#' || href.startsWith('javascript:')) return;
            let domain = '';
            try {
              domain = new URL(href, pageUrl).hostname;
            } catch {}
            links.push({
              href,
              text:
                (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
              tag: 'a',
              domain,
              isExternal: domain !== pageDomain,
              isJS: href.startsWith('javascript:'),
              isMailto: href.startsWith('mailto:'),
            });
          });

          // <img src>
          document.querySelectorAll('img[src]').forEach(el => {
            links.push({
              href: el.src,
              text: el.alt || '',
              tag: 'img',
              domain: '',
              isExternal: false,
              isJS: false,
              isMailto: false,
            });
            try {
              links[links.length - 1].domain = new URL(el.src, pageUrl).hostname;
              links[links.length - 1].isExternal = links[links.length - 1].domain !== pageDomain;
            } catch {}
          });

          // <script src>
          document.querySelectorAll('script[src]').forEach(el => {
            const src = el.src;
            let domain = '';
            try {
              domain = new URL(src, pageUrl).hostname;
            } catch {}
            links.push({
              href: src,
              text: '',
              tag: 'script',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          // <link href>
          document.querySelectorAll('link[href]').forEach(el => {
            const href = el.href;
            let domain = '';
            try {
              domain = new URL(href, pageUrl).hostname;
            } catch {}
            links.push({
              href,
              text: el.rel || '',
              tag: 'link',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          // <iframe src>
          document.querySelectorAll('iframe[src],frame[src]').forEach(el => {
            const src = el.src;
            let domain = '';
            try {
              domain = new URL(src, pageUrl).hostname;
            } catch {}
            links.push({
              href: src,
              text: '',
              tag: 'iframe',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          // Deduplicate by href
          const seen = new Set();
          return links.filter(l => {
            if (seen.has(l.href)) return false;
            seen.add(l.href);
            return true;
          });
        },
      });

      if (results?.[0]?.result) {
        allLinks = results[0].result;
        renderLinks();
        statusEl.textContent = '提取完成，共 ' + allLinks.length + ' 个链接';
        utils.showToast('提取完成', 'success');
        chrome.storage.local.set({ allLinks: allLinks, allLinksUrl: tab.url });
      }
    } catch (e) {
      utils.get('links-count').textContent = '提取失败: ' + e.message;
      utils.showToast('提取失败', 'error');
    }
  }

  function getFilteredLinks() {
    const filterText = utils.get('links-filter').value.trim().toLowerCase();
    const filterType = utils.get('links-filter-type').value;

    return allLinks.filter(link => {
      if (filterType !== 'all' && link.tag !== filterType && filterType !== 'script') return false;
      if (filterType === 'script' && !link.isJS && link.tag !== 'script') return false;
      if (filterType === 'external' && !link.isExternal) return false;
      if (filterType === 'internal' && link.isExternal) return false;
      if (
        filterText &&
        !link.href.toLowerCase().includes(filterText) &&
        (!link.text || !link.text.toLowerCase().includes(filterText)) &&
        (!link.domain || !link.domain.toLowerCase().includes(filterText))
      )
        return false;
      return true;
    });
  }

  function renderLinks() {
    const filtered = getFilteredLinks();
    const container = utils.get('links-results');
    const countEl = utils.get('links-count');

    const existingText = countEl.textContent;
    if (!existingText.includes('正在')) {
      countEl.textContent = '显示 ' + filtered.length + ' / ' + allLinks.length + ' 个链接';
    }

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">没有匹配的链接</div>';
      return;
    }

    let html = '';
    filtered.forEach(link => {
      const tagClass = 'tag-' + link.tag;
      html += '<div class="link-item">';
      html += '<span class="link-item-tag ' + tagClass + '">' + link.tag + '</span>';
      html += '<span class="link-item-text">';
      html +=
        '<span class="link-item-href" title="' +
        utils.escapeHtml(link.href) +
        '">' +
        utils.escapeHtml(link.href) +
        '</span>';
      if (link.domain)
        html +=
          '<span class="link-item-domain">' +
          utils.escapeHtml(link.domain) +
          (link.text ? ' - ' + utils.escapeHtml(link.text) : '') +
          '</span>';
      html += '</span>';
      html +=
        '<button class="link-item-copy" data-href="' +
        utils.escapeHtml(link.href) +
        '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.link-item-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.copyText(btn.dataset.href);
        utils.showToast('已复制', 'success');
      });
    });
  }

  // ====== EXIF Viewer ======
  let lastExifData = null;

  const EXIF_SECTIONS = [
    {
      title: '拍摄信息',
      fields: [
        { key: 'DateTimeOriginal', label: '拍摄时间', format: 'date' },
        { key: 'ISO', label: 'ISO 感光度' },
        { key: 'FNumber', label: '光圈', format: 'fnumber' },
        { key: 'ExposureTime', label: '快门速度', format: 'exposure' },
        { key: 'ExposureCompensation', label: '曝光补偿', format: 'ev' },
        { key: 'FocalLength', label: '焦距', format: 'focal' },
        { key: 'FocalLengthIn35mmFormat', label: '等效焦距', format: 'focal' },
        { key: 'MeteringMode', label: '测光模式' },
        { key: 'WhiteBalance', label: '白平衡' },
        { key: 'Flash', label: '闪光灯' },
        { key: 'ExposureProgram', label: '曝光程序' },
      ],
    },
    {
      title: '相机信息',
      fields: [
        { key: 'Make', label: '品牌' },
        { key: 'Model', label: '型号' },
        { key: 'LensModel', label: '镜头' },
        { key: 'LensMake', label: '镜头品牌' },
        { key: 'Software', label: '软件' },
        { key: 'ImageWidth', label: '图像宽度', format: 'pixel' },
        { key: 'ImageHeight', label: '图像高度', format: 'pixel' },
        { key: 'ColorSpace', label: '色彩空间' },
      ],
    },
    {
      title: 'GPS 信息',
      fields: [
        { key: 'latitude', label: '纬度', format: 'gps' },
        { key: 'longitude', label: '经度', format: 'gps' },
        { key: 'GPSAltitude', label: '海拔', format: 'altitude' },
      ],
    },
  ];

  function formatExifValue(value, format) {
    if (value === undefined || value === null) return null;
    switch (format) {
      case 'date':
        if (value instanceof Date) return value.toLocaleString('zh-CN');
        return String(value);
      case 'fnumber':
        return 'f/' + value;
      case 'exposure':
        if (value < 1) {
          const denom = Math.round(1 / value);
          return '1/' + denom + 's';
        }
        return value + 's';
      case 'ev':
        return (value >= 0 ? '+' : '') + value + ' EV';
      case 'focal':
        return value + 'mm';
      case 'pixel':
        return value + ' px';
      case 'altitude':
        return value + ' m';
      case 'gps':
        return value;
      default:
        return String(value);
    }
  }

  function formatGpsDms(value) {
    const abs = Math.abs(value);
    const d = Math.floor(abs);
    const m = Math.floor((abs - d) * 60);
    const s = ((abs - d) * 60 - m) * 60;
    const dir = value > 0 ? 'N' : 'S';
    return d + '\u00B0' + m + "'" + s.toFixed(2) + '"' + dir;
  }

  async function handleExifFile(file) {
    const resultEl = utils.get('exif-result');
    const emptyEl = utils.get('exif-empty');
    const sectionsEl = utils.get('exif-sections');
    const previewImg = utils.get('exif-preview-img');
    const fileNameEl = utils.get('exif-file-name');
    const fileSizeEl = utils.get('exif-file-size');

    resultEl.classList.add('hidden');
    emptyEl.classList.add('hidden');
    sectionsEl.innerHTML = '<div class="empty-state">正在解析...</div>';

    const objectUrl = URL.createObjectURL(file);
    previewImg.src = objectUrl;
    fileNameEl.textContent = file.name;
    fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';

    try {
      const exif = await exifr.parse(file, {
        tiff: true,
        exif: true,
        gps: true,
        ifd1: true,
        interop: false,
        translateValues: true,
        translateKeys: true,
        reviveValues: true,
      });

      if (!exif || Object.keys(exif).length === 0) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        sectionsEl.innerHTML = '';
        lastExifData = null;
        return;
      }

      lastExifData = exif;
      resultEl.classList.remove('hidden');

      let html = '';
      EXIF_SECTIONS.forEach(section => {
        const hasData = section.fields.some(f => exif[f.key] !== undefined && exif[f.key] !== null);
        if (!hasData) return;

        html += '<div class="exif-section">';
        html += '<div class="exif-section-title">' + section.title + '</div>';

        section.fields.forEach(field => {
          if (exif[field.key] === undefined || exif[field.key] === null) return;

          if (field.format === 'gps' && (field.key === 'latitude' || field.key === 'longitude')) {
            const lat = exif.latitude;
            const lon = exif.longitude;
            const latStr = formatGpsDms(lat) + ' (' + lat.toFixed(6) + ')';
            const lonStr =
              formatGpsDms(lon).replace('N', 'E').replace('S', 'W') + ' (' + lon.toFixed(6) + ')';
            if (field.key === 'latitude') {
              html +=
                '<div class="exif-row"><span class="exif-label">纬度</span><span class="exif-value" title="' +
                utils.escapeHtml(String(lat)) +
                '">' +
                utils.escapeHtml(latStr) +
                '</span></div>';
            } else {
              html +=
                '<div class="exif-row"><span class="exif-label">经度</span><span class="exif-value" title="' +
                utils.escapeHtml(String(lon)) +
                '">' +
                utils.escapeHtml(lonStr) +
                '</span></div>';
            }
            return;
          }

          const formatted = formatExifValue(exif[field.key], field.format);
          if (!formatted) return;

          html += '<div class="exif-row">';
          html += '<span class="exif-label">' + field.label + '</span>';
          html +=
            '<span class="exif-value" title="' +
            String(exif[field.key]) +
            '">' +
            formatted +
            '</span>';
          html += '</div>';
        });

        if (
          exif.latitude !== undefined &&
          exif.longitude !== undefined &&
          section.title === 'GPS 信息'
        ) {
          const mapUrl = 'https://www.google.com/maps?q=' + exif.latitude + ',' + exif.longitude;
          html +=
            '<div class="exif-gps-row"><a class="exif-gps-link" href="' +
            mapUrl +
            '" target="_blank">在地图中查看</a></div>';
        }

        html += '</div>';
      });

      sectionsEl.innerHTML = html || '';
      utils.showToast('EXIF 解析完成', 'success');
    } catch (e) {
      resultEl.classList.remove('hidden');
      emptyEl.classList.remove('hidden');
      emptyEl.textContent = '解析失败: ' + e.message;
      sectionsEl.innerHTML = '';
      lastExifData = null;
    }
  }

  function initExifDragDrop() {
    const area = utils.get('exif-upload-area');
    const fileInput = utils.get('exif-file-input');
    if (!area || !fileInput) return;

    area.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', e => {
      if (e.target.files[0]) handleExifFile(e.target.files[0]);
    });
    area.addEventListener('dragover', e => {
      e.preventDefault();
      area.classList.add('dragover');
    });
    area.addEventListener('dragleave', () => area.classList.remove('dragover'));
    area.addEventListener('drop', e => {
      e.preventDefault();
      area.classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file) handleExifFile(file);
    });
  }

  function switchExifMode(mode) {
    document
      .querySelectorAll('.exif-mode-btn')
      .forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
    utils.get('exif-mode-local').classList.toggle('hidden', mode !== 'local');
    utils.get('exif-mode-url').classList.toggle('hidden', mode !== 'url');
    utils.get('exif-mode-page').classList.toggle('hidden', mode !== 'page');
  }

  async function fetchExifFromUrl(url) {
    const resultEl = utils.get('exif-result');
    const emptyEl = utils.get('exif-empty');
    const sectionsEl = utils.get('exif-sections');
    const previewImg = utils.get('exif-preview-img');
    const fileNameEl = utils.get('exif-file-name');
    const fileSizeEl = utils.get('exif-file-size');

    resultEl.classList.add('hidden');
    emptyEl.classList.add('hidden');
    sectionsEl.innerHTML = '<div class="empty-state">正在获取图片...</div>';

    previewImg.src = url;
    fileNameEl.textContent = url.split('/').pop() || url;
    fileSizeEl.textContent = '';

    chrome.runtime.sendMessage({ type: 'FETCH_IMAGE', url }, response => {
      if (!response || response.error) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        emptyEl.textContent = '获取失败: ' + (response?.error || '无响应，请检查网络');
        sectionsEl.innerHTML = '';
        return;
      }
      if (!response.data) {
        resultEl.classList.remove('hidden');
        emptyEl.classList.remove('hidden');
        emptyEl.textContent = '获取失败: 图片数据为空';
        sectionsEl.innerHTML = '';
        return;
      }
      const bytes = Uint8Array.from(atob(response.data), c => c.charCodeAt(0));
      const mime = url.match(/\.(jpe?g|png|webp|tiff?|heic)/i)
        ? 'image/' + RegExp.$1.toLowerCase().replace('jpg', 'jpeg')
        : 'image/jpeg';
      const blob = new Blob([bytes], { type: mime });
      const file = new File([blob], fileNameEl.textContent, { type: mime });
      fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';
      handleExifFile(file);
    });
  }

  async function scanPageImages() {
    const container = utils.get('exif-page-images');
    container.innerHTML = '<div class="empty-state">正在扫描...</div>';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        container.innerHTML = '<div class="empty-state">无法获取当前页面</div>';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const imgs = [];
          document.querySelectorAll('img[src]').forEach(img => {
            if (img.src && img.naturalWidth > 50 && img.naturalHeight > 50) {
              imgs.push({
                src: img.src,
                alt: img.alt || '',
                w: img.naturalWidth,
                h: img.naturalHeight,
              });
            }
          });
          document.querySelectorAll('[style*="background"]').forEach(el => {
            const m = el.style.backgroundImage.match(/url\(["']?(.*?)["']?\)/);
            if (m && m[1]) imgs.push({ src: m[1], alt: '', w: 0, h: 0 });
          });
          const unique = [...new Map(imgs.map(i => [i.src, i])).values()];
          return unique.slice(0, 50);
        },
      });

      const images = results?.[0]?.result || [];
      if (images.length === 0) {
        container.innerHTML = '<div class="empty-state">未找到图片</div>';
        return;
      }

      let html =
        '<div class="exif-page-count">找到 ' + images.length + ' 张图片（点击查看 EXIF）</div>';
      images.forEach(img => {
        html += '<div class="exif-page-item" data-url="' + utils.escapeHtml(img.src) + '">';
        html += '<img class="exif-page-thumb" src="' + utils.escapeHtml(img.src) + '" alt="">';
        html += '<div class="exif-page-info">';
        if (img.w) html += '<span>' + img.w + ' x ' + img.h + '</span>';
        html +=
          '<span class="exif-page-src">' +
          utils.escapeHtml(img.alt || img.src.split('/').pop()) +
          '</span>';
        html += '</div></div>';
      });
      container.innerHTML = html;

      container.querySelectorAll('.exif-page-item').forEach(item => {
        item.addEventListener('click', () => {
          fetchExifFromUrl(item.dataset.url);
        });
      });
    } catch (e) {
      container.innerHTML =
        '<div class="empty-state">扫描失败: ' + utils.escapeHtml(e.message) + '</div>';
    }
  }

  function checkExifPending() {
    chrome.storage.local.get(['exif_pending_url'], result => {
      const url = result.exif_pending_url;
      if (!url) return;
      chrome.storage.local.remove(['exif_pending_url']);
      switchExifMode('url');
      utils.get('exif-url-input').value = url;
      fetchExifFromUrl(url);
    });
  }

  // ====== History Archive ======
  let lastHistoryResults = [];

  function showHistoryQuickLinks(domain) {
    if (!domain) return;
    const quickLinks = utils.get('history-quick-links');
    quickLinks.innerHTML =
      '<button class="quick-link-btn" data-url="https://web.archive.org/web/*/' +
      encodeURIComponent(domain) +
      '/*">Wayback Machine 日历</button>' +
      '<button id="history-latest-btn" class="quick-link-btn quick-latest hidden" data-url="">查看最新快照</button>';

    if (!showHistoryQuickLinks._bound) {
      const panel = document.getElementById('panel-history');
      if (panel) {
        panel.addEventListener('click', e => {
          const btn = e.target.closest('[data-url]');
          if (btn && btn.dataset.url) {
            chrome.tabs.create({ url: btn.dataset.url });
            e.preventDefault();
          }
        });
        showHistoryQuickLinks._bound = true;
      }
    }
  }

  function buildCdxUrl(domain) {
    const matchType = utils.get('history-match-type').value;
    const outputType = utils.get('history-output-type').value;
    const fields = utils.get('history-fields').value;
    const from = utils.get('history-from').value;
    const to = utils.get('history-to').value;
    const typeFilter = utils.get('history-type-filter').value.trim();

    let url = 'https://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(domain);
    url += '&collapse=urlkey';
    url += '&matchType=' + matchType;
    url += '&output=' + outputType;
    url += '&fl=' + encodeURIComponent(fields);
    if (from) url += '&from=' + from;
    if (to) url += '&to=' + to;
    if (typeFilter) {
      const types = typeFilter
        .toLowerCase()
        .split(/[,，\s]+/)
        .filter(Boolean);
      types.forEach(t => {
        url += '&filter=original:.*\\.' + encodeURIComponent(t) + '($|\\?.*)';
      });
    }
    url += '&limit=100000';
    return url;
  }

  function getFileType(url) {
    try {
      const pathname = new URL(url).pathname;
      const ext = pathname.split('.').pop().toLowerCase().split('?')[0].split('#')[0];
      if (ext && ext.length < 10) return ext;
      return '';
    } catch {
      return '';
    }
  }

  function filterByType(items, typeFilter) {
    if (!typeFilter) return items;
    const types = typeFilter
      .toLowerCase()
      .split(/[,，\s]+/)
      .filter(Boolean);
    if (types.length === 0) return items;
    return items.filter(item => {
      const fileType = getFileType(item.url || '');
      return types.some(t => fileType === t || (item.mimetype || '').includes(t));
    });
  }

  function parseCdxText(text) {
    return text
      .split('\n')
      .filter(line => line.trim())
      .map(line => {
        const parts = line.split(' ');
        return { raw: line, url: parts[parts.length - 1] || line };
      });
  }

  function parseCdxJson(data) {
    if (!Array.isArray(data) || data.length < 2) return [];
    const fieldCount = data[0].length;
    return data.slice(1).map(row => {
      const obj = { raw: row.join(' ') };
      row.forEach((val, i) => {
        obj[data[0][i]] = val;
      });
      obj.url = row[fieldCount - 1] || '';
      return obj;
    });
  }

  function renderHistoryResults(items) {
    lastHistoryResults = items;
    const container = utils.get('history-timeline');
    const statusEl = utils.get('history-status');
    const fields = utils.get('history-fields').value;
    const hasTs = fields.includes('timestamp');

    if (items.length === 0) {
      container.innerHTML = '<div class="empty-state">未找到历史档案</div>';
      statusEl.textContent = '无结果';
      return;
    }

    statusEl.textContent = '共 ' + items.length + ' 条记录';
    utils.get('history-total').textContent = items.length;

    if (hasTs) {
      const timestamps = items
        .map(i => i.timestamp || '')
        .filter(Boolean)
        .sort();
      if (timestamps.length > 0) {
        const fmt = ts => ts.substring(0, 4) + '-' + ts.substring(4, 6) + '-' + ts.substring(6, 8);
        utils.get('history-first').textContent = fmt(timestamps[0]);
        utils.get('history-last').textContent = fmt(timestamps[timestamps.length - 1]);
        utils.get('history-summary').classList.remove('hidden');
      }
    }

    let html = '';
    items.slice(0, 200).forEach(item => {
      const url = item.url || item.raw;
      const ts = item.timestamp || '';
      const status = item.statuscode || '';
      const mime = item.mimetype || '';
      const dateStr = ts
        ? ts.substring(0, 4) +
          '-' +
          ts.substring(4, 6) +
          '-' +
          ts.substring(6, 8) +
          ' ' +
          ts.substring(8, 10) +
          ':' +
          ts.substring(10, 12)
        : '';
      const waybackUrl = ts
        ? 'https://web.archive.org/web/' + ts + '/' + url
        : 'https://web.archive.org/web/*/' + encodeURIComponent(url);

      let statusClass = 'status-other';
      if (status === '200') statusClass = 'status-200';
      else if (status === '301' || status === '302') statusClass = 'status-301';
      else if (status === '404') statusClass = 'status-404';

      html += '<div class="timeline-item">';
      if (hasTs) html += '<span class="timeline-date">' + utils.escapeHtml(dateStr) + '</span>';
      if (status)
        html +=
          '<span class="timeline-status ' +
          utils.escapeHtml(statusClass) +
          '">' +
          utils.escapeHtml(status) +
          '</span>';
      if (mime)
        html += '<span class="timeline-status status-other">' + utils.escapeHtml(mime) + '</span>';
      html +=
        '<span class="timeline-url" data-wayback="' +
        utils.escapeHtml(waybackUrl) +
        '" title="' +
        utils.escapeHtml(url) +
        '">' +
        utils.escapeHtml(url) +
        '</span>';
      html +=
        '<button class="timeline-open" data-url="' +
        utils.escapeHtml(waybackUrl) +
        '">查看</button>';
      html += '</div>';
    });
    if (items.length > 200) html += '<div class="empty-state">仅显示前 200 条</div>';
    container.innerHTML = html;
  }

  function extractDomain(input) {
    try {
      const url = new URL(/^https?:\/\//i.test(input) ? input : 'https://' + input);
      return url.hostname;
    } catch {
      return input.trim();
    }
  }

  async function queryHistory() {
    let raw = utils.get('history-domain').value.trim();
    if (!raw) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('请输入域名或打开一个网页', 'warning');
        return;
      }
      raw = tab.url;
    }
    const domain = extractDomain(raw);
    utils.get('history-domain').value = domain;

    showHistoryQuickLinks(domain);
    utils.get('history-status').textContent = '正在查询...';
    utils.get('history-timeline').innerHTML = '';

    const cdxUrl = buildCdxUrl(domain);
    chrome.runtime.sendMessage({ type: 'FETCH_URL', url: cdxUrl }, response => {
      if (response?.error) {
        utils.get('history-status').textContent = '查询失败: ' + response.error;
        return;
      }
      try {
        const outputType = utils.get('history-output-type').value;
        const items =
          outputType === 'json'
            ? parseCdxJson(JSON.parse(response.data))
            : parseCdxText(response.data);
        renderHistoryResults(items);
        utils.showToast('查询完成', 'success');

        // Update "最新快照" button
        const latest = items[items.length - 1];
        if (latest && latest.timestamp) {
          const latestBtn = document.getElementById('history-latest-btn');
          if (latestBtn) {
            latestBtn.dataset.url =
              'https://web.archive.org/web/' + latest.timestamp + '/' + latest.url;
            latestBtn.classList.remove('hidden');
          }
        }
      } catch {
        utils.get('history-status').textContent = '解析结果失败';
      }
    });
  }

  // ====== Request Spoofing ======
  let currentSpoofTab = 'ua';
  let spoofState = {
    ua: { enabled: false, current: '', original: '' },
    headers: { xff: '', referer: '', clientIp: '', custom: [] },
  };

  const UA_PRESETS = {
    mobile: [
      {
        label: 'iPhone 15 (iOS 17)',
        value:
          'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
      },
      {
        label: 'iPhone 14 Pro',
        value:
          'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
      },
      {
        label: 'Samsung Galaxy S24',
        value:
          'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
      },
      {
        label: 'Pixel 8 Pro',
        value:
          'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
      },
      {
        label: 'Huawei Mate 60',
        value:
          'Mozilla/5.0 (Linux; Android 12; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36',
      },
      {
        label: 'Xiaomi 14',
        value:
          'Mozilla/5.0 (Linux; Android 14; 23127PN0CC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
      },
    ],
    desktop: [
      {
        label: 'Chrome (Windows)',
        value:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
      },
      {
        label: 'Chrome (macOS)',
        value:
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
      },
      {
        label: 'Firefox (Windows)',
        value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
      },
      {
        label: 'Safari (macOS)',
        value:
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
      },
      {
        label: 'Edge (Windows)',
        value:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
      },
    ],
    brand: [
      {
        label: 'Googlebot',
        value: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      },
      {
        label: 'Bingbot',
        value: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
      },
      {
        label: 'Facebookbot',
        value:
          'Mozilla/5.0 (compatible; FacebookExternalHit/1.1; +http://www.facebook.com/externalhit_uatext.php)',
      },
      { label: 'Twitterbot', value: 'Mozilla/5.0 (compatible; Twitterbot/1.0)' },
      {
        label: 'Baiduspider',
        value:
          'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
      },
      { label: 'curl/8.4', value: 'curl/8.4.0' },
      { label: 'Python requests', value: 'python-requests/2.31.0' },
      { label: 'Go HTTP Client', value: 'Go-http-client/1.1' },
    ],
  };

  function switchSpoofTab(tab) {
    currentSpoofTab = tab;
    document
      .querySelectorAll('.spoof-tab')
      .forEach(b => b.classList.toggle('active', b.dataset.spoof === tab));
    document.querySelectorAll('.spoof-panel').forEach(p => p.classList.remove('active'));
    const target = document.getElementById('spoof-' + tab);
    if (target) target.classList.add('active');
  }

  function renderUaList(category) {
    const container = utils.get('ua-list');
    const customGroup = utils.get('ua-custom-group');
    if (!container) return;

    if (category === 'custom') {
      container.innerHTML = '';
      customGroup.classList.remove('hidden');
      return;
    }
    customGroup.classList.add('hidden');

    const presets = UA_PRESETS[category] || [];
    if (presets.length === 0) {
      container.innerHTML = '<div class="empty-state">无预设项</div>';
      return;
    }

    let html = '';
    presets.forEach((preset, idx) => {
      const isSelected = spoofState.ua.current === preset.value;
      html +=
        '<div class="ua-item' + (isSelected ? ' ua-selected' : '') + '" data-idx="' + idx + '">';
      html += '<span class="ua-item-label">' + preset.label + '</span>';
      html += '<span class="ua-item-value" title="' + preset.value.replace(/"/g, '&quot;') + '">';
      html += preset.value.length > 80 ? preset.value.substring(0, 80) + '...' : preset.value;
      html += '</span></div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.ua-item').forEach(item => {
      item.addEventListener('click', () => {
        const i = parseInt(item.dataset.idx, 10);
        const preset = presets[i];
        if (preset) {
          utils.get('ua-custom-input').value = preset.value;
          container.querySelectorAll('.ua-item').forEach(el => el.classList.remove('ua-selected'));
          item.classList.add('ua-selected');
        }
      });
    });
  }

  function updateUaStatus() {
    const el = utils.get('spoof-ua-status');
    if (!el) return;
    el.innerHTML = spoofState.ua.enabled
      ? '<span class="spoof-status-active">UA 伪造已启用</span>'
      : '';
  }

  async function applyUserAgent() {
    const input = utils.get('ua-custom-input');
    if (!input) return;
    const ua = input.value.trim();
    if (!ua) {
      utils.showToast('请选择或输入 User-Agent', 'warning');
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      if (!spoofState.ua.enabled) {
        spoofState.ua.original = navigator.userAgent;
      }
      spoofState.ua.enabled = true;
      spoofState.ua.current = ua;

      chrome.runtime.sendMessage(
        { type: 'SPOOF_UA', tabId: tab.id, url: tab.url, userAgent: ua },
        response => {
          if (response?.success) {
            updateUaStatus();
            utils.showToast('UA 已应用', 'success');
          } else {
            utils.showToast('应用失败: ' + (response?.error || '未知错误'), 'error');
          }
        }
      );

      chrome.storage.local.set({ pentest_spoof: spoofState });
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  async function resetUserAgent() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      spoofState.ua.enabled = false;
      spoofState.ua.current = '';

      chrome.runtime.sendMessage({ type: 'RESET_SPOOF_UA', tabId: tab?.id }, response => {
        if (response?.success) {
          updateUaStatus();
          utils.showToast('UA 已恢复', 'success');
        } else {
          utils.showToast('恢复失败: ' + (response?.error || '未知错误'), 'error');
        }
      });

      chrome.storage.local.set({ pentest_spoof: spoofState });
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  async function loadCookies() {
    const domainEl = utils.get('cookie-domain-info');
    const listEl = utils.get('cookie-list');
    if (!domainEl || !listEl) return;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        domainEl.textContent = '无法获取当前页面';
        return;
      }

      const url = new URL(tab.url);
      const domain = url.hostname;
      domainEl.textContent = '当前域名: ' + domain;

      const cookies = await chrome.cookies.getAll({ domain: domain });

      if (cookies.length === 0) {
        listEl.innerHTML = '<div class="empty-state">当前域名无 Cookie</div>';
        return;
      }

      let html = '<div class="cookie-count">共 ' + cookies.length + ' 个 Cookie</div>';
      cookies.forEach(cookie => {
        html += '<div class="cookie-item" data-name="' + utils.escapeHtml(cookie.name) + '">';
        html += '<div class="cookie-item-main">';
        html += '<span class="cookie-item-name">' + utils.escapeHtml(cookie.name) + '</span>';
        html += '<span class="cookie-item-value" title="' + utils.escapeHtml(cookie.value) + '">';
        html += utils.escapeHtml(
          cookie.value.length > 60 ? cookie.value.substring(0, 60) + '...' : cookie.value
        );
        html += '</span></div>';
        html += '<div class="cookie-item-meta">';
        html +=
          '<span>' +
          utils.escapeHtml(cookie.domain || '') +
          utils.escapeHtml(cookie.path || '') +
          '</span>';
        if (cookie.httpOnly) html += '<span class="cookie-badge">HttpOnly</span>';
        if (cookie.secure) html += '<span class="cookie-badge">Secure</span>';
        html +=
          '<span class="cookie-badge">' +
          utils.escapeHtml(cookie.sameSite || 'unspecified') +
          '</span>';
        html += '</div>';
        html += '<div class="cookie-item-actions">';
        html +=
          '<button class="btn btn-sm btn-outline cookie-edit-btn" data-name="' +
          utils.escapeHtml(cookie.name) +
          '">编辑</button>';
        html +=
          '<button class="btn btn-sm btn-outline cookie-delete-btn" data-name="' +
          utils.escapeHtml(cookie.name) +
          '">删除</button>';
        html += '</div></div>';
      });
      listEl.innerHTML = html;

      listEl.querySelectorAll('.cookie-edit-btn').forEach(btn => {
        btn.addEventListener('click', () => showCookieEditor(btn.dataset.name, cookies));
      });
      listEl.querySelectorAll('.cookie-delete-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteCookie(btn.dataset.name, domain));
      });

      utils.showToast('Cookie 加载完成', 'success');
    } catch (e) {
      listEl.innerHTML =
        '<div class="empty-state">加载失败: ' + utils.escapeHtml(e.message) + '</div>';
      utils.showToast('加载 Cookie 失败', 'error');
    }
  }

  function renderCookieEditor(cookieData, isNew) {
    const listEl = utils.get('cookie-list');
    if (!listEl) return;

    const c = cookieData || {};
    const title = isNew ? '添加 Cookie' : '编辑 Cookie: ' + c.name;
    const nameReadonly = isNew ? '' : ' readonly';

    let html = '<div class="cookie-editor">';
    html += '<div class="card-title">' + utils.escapeHtml(title) + '</div>';
    html += '<div class="settings-grid">';
    html +=
      '<div class="setting-item"><label>Name</label><input type="text" class="input cookie-edit-name" value="' +
      utils.escapeHtml(c.name || '') +
      '"' +
      nameReadonly +
      ' placeholder="cookie名称"></div>';
    html +=
      '<div class="setting-item"><label>Value</label><textarea class="textarea cookie-edit-value" rows="2" placeholder="cookie值">' +
      utils.escapeHtml(c.value || '') +
      '</textarea></div>';
    html +=
      '<div class="setting-item"><label>Domain</label><input type="text" class="input cookie-edit-domain" value="' +
      utils.escapeHtml((c.domain || '').replace(/^\./, '')) +
      '" placeholder="自动获取"></div>';
    html +=
      '<div class="setting-item"><label>Path</label><input type="text" class="input cookie-edit-path" value="' +
      utils.escapeHtml(c.path || '/') +
      '"></div>';
    html +=
      '<div class="setting-item"><label>Expires (秒, 0=会话)</label><input type="number" class="input cookie-edit-expires" value="' +
      (c.expirationDate ? Math.floor(c.expirationDate - Date.now() / 1000) : 0) +
      '"></div>';
    html +=
      '<div class="setting-item"><label>SameSite</label><select class="select-filter cookie-edit-samesite">';
    ['unspecified', 'no_restriction', 'lax', 'strict'].forEach(opt => {
      const sel = c.sameSite === opt || (!c.sameSite && opt === 'lax') ? ' selected' : '';
      html += '<option value="' + opt + '"' + sel + '>' + opt + '</option>';
    });
    html += '</select></div>';
    html += '</div>';
    html += '<div class="cookie-edit-flags">';
    html +=
      '<label><input type="checkbox" class="cookie-edit-httponly"' +
      (c.httpOnly ? ' checked' : '') +
      '> HttpOnly</label> ';
    html +=
      '<label><input type="checkbox" class="cookie-edit-secure"' +
      (c.secure ? ' checked' : '') +
      '> Secure</label>';
    html += '</div>';
    html += '<div class="form-actions">';
    html +=
      '<button class="btn btn-primary cookie-save-btn">' + (isNew ? '添加' : '保存') + '</button>';
    html += '<button class="btn btn-outline cookie-cancel-btn">取消</button>';
    html += '</div></div>';
    listEl.innerHTML = html;

    listEl.querySelector('.cookie-cancel-btn').addEventListener('click', () => loadCookies());
    listEl.querySelector('.cookie-save-btn').addEventListener('click', () => saveCookieEdit(isNew));
  }

  function showCookieEditor(cookieName, existingCookies) {
    const cookie = existingCookies.find(c => c.name === cookieName);
    if (!cookie) return;
    renderCookieEditor(cookie, false);
  }

  function showCookieAddEditor() {
    renderCookieEditor({}, true);
  }

  async function saveCookieEdit(isNew) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);

    const name = document.querySelector('.cookie-edit-name').value;
    const value = document.querySelector('.cookie-edit-value').value;
    const domain = document.querySelector('.cookie-edit-domain').value || url.hostname;
    const path = document.querySelector('.cookie-edit-path').value || '/';
    const expiresSec = parseInt(document.querySelector('.cookie-edit-expires').value, 10) || 0;
    const sameSite = document.querySelector('.cookie-edit-samesite').value;
    const httpOnly = document.querySelector('.cookie-edit-httponly').checked;
    const secure =
      document.querySelector('.cookie-edit-secure').checked || url.protocol === 'https:';

    if (!name) {
      utils.showToast('Cookie 名称不能为空', 'warning');
      return;
    }

    try {
      await chrome.cookies.set({
        url: url.origin + path,
        name: name,
        value: value,
        domain: domain,
        path: path,
        secure: secure,
        httpOnly: httpOnly,
        sameSite: sameSite,
        expirationDate: expiresSec > 0 ? Date.now() / 1000 + expiresSec : undefined,
      });
      utils.showToast('Cookie 已' + (isNew ? '添加' : '保存'), 'success');
      loadCookies();
    } catch (e) {
      utils.showToast('保存失败: ' + e.message, 'error');
    }
  }

  async function deleteCookie(cookieName) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);

    try {
      await chrome.cookies.remove({ url: url.origin, name: cookieName });
      utils.showToast('Cookie 已删除', 'success');
      loadCookies();
    } catch (e) {
      utils.showToast('删除失败: ' + e.message, 'error');
    }
  }

  function showCookieImportDialog() {
    const listEl = utils.get('cookie-list');
    if (!listEl) return;

    let html = '<div class="cookie-editor">';
    html += '<div class="card-title">导入 Cookie 字符串</div>';
    html += '<div class="form-group">';
    html += '<label>Cookie 字符串（name=value; name2=value2 格式）</label>';
    html +=
      '<textarea class="textarea cookie-import-textarea" rows="4" placeholder="session_id=abc123; token=eyJhbG...; user=admin"></textarea>';
    html += '</div>';
    html += '<div class="form-actions">';
    html += '<button class="btn btn-primary" id="cookie-import-do">导入</button>';
    html += '<button class="btn btn-outline cookie-cancel-btn">取消</button>';
    html += '</div></div>';
    listEl.innerHTML = html;

    listEl.querySelector('.cookie-cancel-btn').addEventListener('click', () => loadCookies());
    listEl.querySelector('#cookie-import-do').addEventListener('click', async () => {
      const text = document.querySelector('.cookie-import-textarea').value.trim();
      if (!text) {
        utils.showToast('请输入 Cookie 字符串', 'warning');
        return;
      }
      await importCookieString(text);
    });
  }

  async function importCookieString(cookieStr) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);
    let count = 0;

    const pairs = cookieStr
      .split(';')
      .map(s => s.trim())
      .filter(Boolean);
    for (const pair of pairs) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx < 1) continue;
      const name = pair.substring(0, eqIdx).trim();
      const value = pair.substring(eqIdx + 1).trim();
      try {
        await chrome.cookies.set({
          url: url.origin,
          name: name,
          value: value,
          path: '/',
          secure: url.protocol === 'https:',
        });
        count++;
      } catch (e) {
        /* skip invalid */
      }
    }
    utils.showToast('已导入 ' + count + ' 个 Cookie', 'success');
    loadCookies();
  }

  async function clearAllCookies() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    const url = new URL(tab.url);
    const domain = url.hostname;

    const cookies = await chrome.cookies.getAll({ domain: domain });
    let count = 0;
    for (const cookie of cookies) {
      await chrome.cookies.remove({ url: url.origin, name: cookie.name });
      count++;
    }
    utils.showToast('已清除 ' + count + ' 个 Cookie', 'success');
    loadCookies();
  }

  async function applyHeaders() {
    const xffEl = utils.get('header-xff');
    const refererPresetEl = utils.get('referer-preset');
    const refererEl = utils.get('header-referer');
    const clientIpEl = utils.get('header-client-ip');
    if (!xffEl || !refererPresetEl || !refererEl || !clientIpEl) return;

    const xff = xffEl.value.trim();
    const refererPreset = refererPresetEl.value;
    let referer = refererEl.value.trim();

    if (refererPreset === 'none') referer = '';
    else if (refererPreset === 'same') referer = 'same';
    const clientIp = clientIpEl.value.trim();

    const customHeaders = [];
    document.querySelectorAll('.custom-header-row').forEach(row => {
      const key = row.querySelector('.custom-header-key').value.trim();
      const val = row.querySelector('.custom-header-value').value.trim();
      if (key && val) customHeaders.push({ name: key, value: val });
    });

    spoofState.headers = { xff, referer, clientIp, custom: customHeaders };

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        utils.showToast('无法获取当前页面', 'error');
        return;
      }

      chrome.runtime.sendMessage(
        { type: 'SPOOF_HEADERS', tabId: tab.id, url: tab.url, headers: spoofState.headers },
        response => {
          if (response?.success) {
            utils.showToast('Header 伪造已应用', 'success');
          } else {
            utils.showToast('应用失败: ' + (response?.error || '未知错误'), 'error');
          }
        }
      );

      chrome.storage.local.set({ pentest_spoof: spoofState });
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  function addCustomHeaderRow() {
    const container = utils.get('custom-headers');
    if (!container) return;
    const row = document.createElement('div');
    row.className = 'custom-header-row';
    row.innerHTML =
      '<input type="text" class="input custom-header-key" placeholder="Header Name">' +
      '<input type="text" class="input custom-header-value" placeholder="Header Value">' +
      '<button class="btn btn-sm btn-outline custom-header-remove" title="删除">-</button>';
    container.appendChild(row);
    row.querySelector('.custom-header-remove').addEventListener('click', () => row.remove());
  }

  async function resetHeaders() {
    const xffEl = utils.get('header-xff');
    const refererEl = utils.get('header-referer');
    const refererPresetEl = utils.get('referer-preset');
    const clientIpEl = utils.get('header-client-ip');
    const customHeadersEl = utils.get('custom-headers');
    if (xffEl) xffEl.value = '';
    if (refererEl) refererEl.value = '';
    if (refererPresetEl) refererPresetEl.value = '';
    if (clientIpEl) clientIpEl.value = '';

    if (customHeadersEl) {
      customHeadersEl.innerHTML =
        '<div class="custom-header-row">' +
        '<input type="text" class="input custom-header-key" placeholder="Header Name">' +
        '<input type="text" class="input custom-header-value" placeholder="Header Value">' +
        '<button class="btn btn-sm btn-outline custom-header-remove" title="删除">-</button></div>';
      const rmBtn = customHeadersEl.querySelector('.custom-header-remove');
      if (rmBtn)
        rmBtn.addEventListener('click', function () {
          this.closest('.custom-header-row').remove();
        });
    }

    spoofState.headers = { xff: '', referer: '', clientIp: '', custom: [] };

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      chrome.runtime.sendMessage({ type: 'RESET_SPOOF_HEADERS', tabId: tab?.id });
      chrome.storage.local.set({ pentest_spoof: spoofState });
      utils.showToast('Header 已重置', 'success');
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  // ====== Vue Analysis ======
  let lastVueResult = '';
  let permInterceptActive = false;
  let permCapturedData = [];
  let permSelectedIndex = -1;
  let permViewMode = 'list';

  async function detectVue() {
    const statusEl = utils.get('vue-status');
    const resultsEl = utils.get('vue-results');
    if (!statusEl || !resultsEl) return;

    statusEl.textContent = '检测中...';
    resultsEl.innerHTML = '';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) {
        statusEl.textContent = '无法获取当前标签页';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          const info = { detected: false, version: '', router: false, store: false, routes: [] };

          // Vue 3
          const appEl = document.querySelector('#app') || document.querySelector('[data-v-app]');
          if (appEl && appEl.__vue_app__) {
            const app = appEl.__vue_app__;
            info.detected = true;
            info.version = app.version || '3.x';
            const router = app.config.globalProperties.$router;
            if (router) {
              info.router = true;
              info.routes = router.options.routes || [];
            }
            const store = app.config.globalProperties.$pinia || app.config.globalProperties.$store;
            if (store) info.store = true;
            return info;
          }

          // Vue 2: walk elements to find __vue__
          const allEls = document.querySelectorAll('*');
          for (const el of allEls) {
            if (el.__vue__) {
              const vm = el.__vue__.$root || el.__vue__;
              info.detected = true;
              info.version = vm.constructor.version || '2.x';
              const router = vm.$router;
              if (router) {
                info.router = true;
                info.routes = router.options ? router.options.routes || [] : [];
              }
              if (vm.$store) info.store = true;
              break;
            }
          }

          return info;
        },
      });

      const data = results?.[0]?.result;
      if (!data) {
        statusEl.textContent = '检测失败';
        return;
      }

      if (!data.detected) {
        statusEl.textContent = '未检测到 Vue';
        resultsEl.innerHTML = '<div class="empty-state">当前页面未使用 Vue 框架</div>';
        return;
      }

      statusEl.textContent = '检测到 Vue ' + data.version;

      let html = '';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">版本</span><span class="vue-info-value"><span class="vue-badge vue-badge-ok">Vue ' +
        data.version +
        '</span></span></div>';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">Vue Router</span><span class="vue-info-value">' +
        (data.router ? '<span class="vue-badge vue-badge-ok">已检测</span>' : '未检测到') +
        '</span></div>';
      html +=
        '<div class="vue-info-row"><span class="vue-info-label">状态管理</span><span class="vue-info-value">' +
        (data.store ? '<span class="vue-badge vue-badge-warn">已检测</span>' : '未检测到') +
        '</span></div>';

      if (data.router && data.routes.length > 0) {
        html +=
          '<div class="card-spacing"><div class="card-title">路由列表 (' +
          data.routes.length +
          ')</div></div>';
        html += renderRouteTree(data.routes, 0);
      }

      resultsEl.innerHTML = html;
      lastVueResult = JSON.stringify(data, null, 2);
      permLastRoutes = data.routes || [];
    } catch (e) {
      statusEl.textContent = '检测出错';
      resultsEl.innerHTML = '<div class="empty-state">' + utils.escapeHtml(e.message) + '</div>';
    }
  }

  function renderRouteTree(routes, depth) {
    let html = '';
    if (!routes || !Array.isArray(routes)) return html;
    routes.forEach(route => {
      const indent = depth * 16;
      html += '<div class="vue-route-item vue-depth-' + depth + '">';
      html += '<span class="vue-route-path">' + utils.escapeHtml(route.path || '/') + '</span>';
      if (route.name)
        html += '<span class="vue-route-name">' + utils.escapeHtml(route.name) + '</span>';
      if (route.meta)
        html +=
          '<span class="vue-route-meta">meta: ' +
          utils.escapeHtml(JSON.stringify(route.meta).substring(0, 60)) +
          '</span>';
      html += '</div>';
      if (route.children && route.children.length > 0) {
        html += renderRouteTree(route.children, depth + 1);
      }
    });
    return html;
  }

  async function exportVueRoutes() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          const appEl = document.querySelector('#app') || document.querySelector('[data-v-app]');
          if (appEl && appEl.__vue_app__) {
            const router = appEl.__vue_app__.config.globalProperties.$router;
            if (router) return router.options.routes || [];
          }
          const allEls = document.querySelectorAll('*');
          for (const el of allEls) {
            if (el.__vue__) {
              const vm = el.__vue__.$root || el.__vue__;
              if (vm.$router && vm.$router.options) return vm.$router.options.routes || [];
            }
          }
          return null;
        },
      });

      const routes = results?.[0]?.result;
      if (!routes) {
        utils.showToast('未找到 Vue Router', 'warning');
        return;
      }

      const json = JSON.stringify(routes, null, 2);
      utils.copyText(json);
      lastVueResult = json;
      utils.showToast('路由已复制 (' + routes.length + ' 条)', 'success');
    } catch (e) {
      utils.showToast('导出失败: ' + e.message, 'error');
    }
  }

  async function bypassVueGuards() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const bypassResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          // Vue 3
          const appEl = document.querySelector('#app') || document.querySelector('[data-v-app]');
          if (appEl && appEl.__vue_app__) {
            const router = appEl.__vue_app__.config.globalProperties.$router;
            if (router) {
              router.beforeEach.length = 0;
              router.beforeResolve.length = 0;
              router.afterEach.length = 0;
              router.beforeGuards.length = 0;
              router.afterGuards.length = 0;
              return 'vue3';
            }
          }
          // Vue 2
          const allEls = document.querySelectorAll('*');
          for (const el of allEls) {
            if (el.__vue__) {
              const vm = el.__vue__.$root || el.__vue__;
              if (vm.$router) {
                vm.$router.beforeHooks.length = 0;
                vm.$router.afterHooks.length = 0;
                vm.$router.beforeResolveHooks.length = 0;
                return 'vue2';
              }
            }
          }
          return null;
        },
      });

      const result = bypassResults?.[0]?.result;
      if (!result) {
        utils.showToast('未找到 Vue Router', 'warning');
        return;
      }
      utils.showToast('路由守卫已清除 (Vue ' + (result === 'vue3' ? '3' : '2') + ')', 'success');
    } catch (e) {
      utils.showToast('绕过失败: ' + e.message, 'error');
    }
  }

  // ====== Vue Sub-tab Switching ======
  let permLastRoutes = [];

  function switchVueSubTab(tab) {
    document.querySelectorAll('.vue-stab').forEach(function (b) {
      b.classList.toggle('active', b.dataset.vstab === tab);
    });
    document.querySelectorAll('.vue-subpanel').forEach(function (p) {
      p.classList.remove('active');
    });
    var target = document.getElementById('vstab-' + tab);
    if (target) target.classList.add('active');
  }

  // ====== Permission Menu Interceptor ======
  var permInterceptorFunc = function () {
    if (window.__PERM_INTERCEPTOR__) {
      window.__PERM_INTERCEPTOR__.active = true;
      return 'already_injected';
    }

    var MENU_KEYWORDS = [
      'menu',
      'menulist',
      'menuList',
      'menuData',
      'permission',
      'permissions',
      'permList',
      'menuIds',
      'menu_ids',
      'menuId',
      'isAdmin',
      'isadmin',
      'role',
      'roles',
      'getMenu',
      'getMenus',
      'getPermission',
      'getUserInfo',
      'navList',
      'sideMenu',
      'sidebar',
    ];

    var URL_MENU_PATTERNS = [
      /\/api\/.*menu/i,
      /\/api\/.*permission/i,
      /\/api\/.*role/i,
      /\/api\/.*user.*info/i,
      /\/api\/.*auth/i,
      /\/api\/.*nav/i,
      /\/menu/,
      /\/permission/,
      /\/getMenu/i,
      /\/getUserInfo/i,
      /\/getRouters/i,
      /\/getRoutes/,
    ];

    function classifyResponse(data, url) {
      var str = typeof data === 'string' ? data : JSON.stringify(data);
      var urlLower = url.toLowerCase();
      try {
        var json = typeof data === 'string' ? JSON.parse(data) : data;
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          var keys = Object.keys(json);
          for (var k = 0; k < keys.length; k++) {
            if (/^(isadmin|admin|is_superuser)$/i.test(keys[k]))
              return { type: 'role', subtype: 'special_zero' };
          }
        }
      } catch (e) {}
      if (/permission/i.test(urlLower)) return { type: 'permission', subtype: null };
      if (/role/i.test(urlLower)) return { type: 'role', subtype: null };
      if (/menu/i.test(urlLower)) return { type: 'menu', subtype: null };
      for (var i = 0; i < MENU_KEYWORDS.length; i++) {
        if (str.indexOf(MENU_KEYWORDS[i]) !== -1) return { type: 'menu', subtype: null };
      }
      return { type: 'other', subtype: null };
    }

    function parseBody(text) {
      try {
        var json = JSON.parse(text);
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          if (json.data !== undefined) return json.data;
          if (json.result !== undefined) return json.result;
          if (json.Data !== undefined) return json.Data;
          if (json.Result !== undefined) return json.Result;
        }
        return json;
      } catch (e) {
        return text;
      }
    }

    var captured = [];

    var originalFetch = window.fetch;
    window.fetch = function () {
      var args = arguments;
      return originalFetch.apply(this, args).then(function (response) {
        if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active) {
          var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
          var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
            return p.test(url);
          });
          if (isMenuApi) {
            var cloned = response.clone();
            cloned.text().then(function (text) {
              try {
                var parsed = parseBody(text);
                var info = classifyResponse(parsed, url);
                if (info.type !== 'other') {
                  captured.push({
                    url: url,
                    type: info.type,
                    subtype: info.subtype,
                    data: parsed,
                    rawText: text,
                    size: text.length,
                    timestamp: Date.now(),
                    method: 'fetch',
                  });
                }
              } catch (e) {}
            });
          }
        }
        return response;
      });
    };

    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__perm_url = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      var self = this;
      if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active && this.__perm_url) {
        var url = this.__perm_url;
        var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
          return p.test(url);
        });
        if (isMenuApi) {
          this.addEventListener('load', function () {
            try {
              var text = self.responseText;
              if (!text) return;
              var parsed = parseBody(text);
              var info = classifyResponse(parsed, url);
              if (info.type !== 'other') {
                captured.push({
                  url: url,
                  type: info.type,
                  subtype: info.subtype,
                  data: parsed,
                  rawText: text,
                  size: text.length,
                  timestamp: Date.now(),
                  method: 'xhr',
                });
              }
            } catch (e) {}
          });
        }
      }
      return origSend.apply(this, arguments);
    };

    window.__PERM_INTERCEPTOR__ = {
      active: true,
      captured: captured,
      getCaptured: function () {
        return captured;
      },
      clear: function () {
        captured.length = 0;
      },
      stop: function () {
        this.active = false;
      },
      start: function () {
        this.active = true;
      },
      _overrideData: null,
      getOverride: function () {
        return this._overrideData;
      },
      setOverride: function (d) {
        this._overrideData = d;
      },
    };
    return 'injected';
  };

  async function startPermInterception() {
    var statusEl = utils.get('perm-status');
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: permInterceptorFunc,
      });
      var status = results && results[0] && results[0].result;
      if (status === 'already_injected') {
        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.start();
          },
        });
      }
      permInterceptActive = true;
      chrome.storage.local.set({ permInterceptTabId: tab.id });
      utils.get('perm-start-btn').disabled = true;
      utils.get('perm-stop-btn').disabled = false;
      if (statusEl) statusEl.textContent = '拦截中... 请操作页面触发菜单API请求，或刷新页面';
      utils.showToast('拦截已启动，请操作页面或刷新页面', 'success');
    } catch (e) {
      if (statusEl) statusEl.textContent = '启动失败: ' + e.message;
    }
  }

  async function stopPermInterception() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.stop();
        },
      });
      permInterceptActive = false;
      chrome.storage.local.remove('permInterceptTabId');
      utils.get('perm-start-btn').disabled = false;
      utils.get('perm-stop-btn').disabled = true;
      var statusEl = utils.get('perm-status');
      if (statusEl) statusEl.textContent = '拦截已停止';
      utils.showToast('拦截已停止', 'info');
    } catch (e) {}
  }

  async function refreshPermCaptured() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          return window.__PERM_INTERCEPTOR__ ? window.__PERM_INTERCEPTOR__.getCaptured() : [];
        },
      });
      permCapturedData = (results && results[0] && results[0].result) || [];
      renderPermList();
    } catch (e) {
      utils.showToast('获取捕获数据失败', 'error');
    }
  }

  function renderPermList() {
    var container = utils.get('perm-captured-list');
    var countEl = utils.get('perm-count');
    if (!container) return;
    var filterVal = (utils.get('perm-filter') ? utils.get('perm-filter').value : '').toLowerCase();
    var typeFilter = utils.get('perm-type-filter') ? utils.get('perm-type-filter').value : 'all';

    var filtered = permCapturedData.filter(function (item) {
      if (filterVal && item.url.toLowerCase().indexOf(filterVal) === -1) return false;
      if (typeFilter !== 'all' && item.type !== typeFilter) return false;
      return true;
    });

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">暂无捕获数据，请先操作页面触发菜单请求</div>';
      if (countEl)
        countEl.textContent =
          permCapturedData.length > 0 ? '共 ' + permCapturedData.length + ' 条 (筛选后 0)' : '';
      return;
    }

    if (countEl)
      countEl.textContent =
        '共 ' +
        permCapturedData.length +
        ' 条' +
        (filtered.length < permCapturedData.length ? ' (显示 ' + filtered.length + ')' : '');

    var html = '';
    for (var i = 0; i < filtered.length; i++) {
      var item = filtered[i];
      var realIdx = permCapturedData.indexOf(item);
      html += '<div class="perm-item" data-idx="' + realIdx + '">';
      html += '<span class="perm-item-type type-' + item.type + '">' + item.type + '</span>';
      html += '<span class="perm-item-url" title="' + utils.escapeHtml(item.url) + '">';
      html += utils.escapeHtml(item.url) + '</span>';
      html += '<span class="perm-item-size">' + (item.size / 1024).toFixed(1) + 'KB</span>';
      html += '</div>';
    }
    container.innerHTML = html;

    container.querySelectorAll('.perm-item').forEach(function (el) {
      el.addEventListener('click', function () {
        permSelectedIndex = parseInt(this.dataset.idx);
        showPermDetail(permSelectedIndex);
      });
    });
  }

  function showPermDetail(idx) {
    var item = permCapturedData[idx];
    if (!item) return;
    permViewMode = 'detail';
    utils.get('perm-captured-list').classList.add('hidden');
    var filterRow = utils.get('perm-filter-row');
    if (filterRow) filterRow.classList.add('hidden');
    utils.get('perm-detail').classList.remove('hidden');
    utils.get('perm-detail-url').textContent = item.url;
    utils.get('perm-detail-type').textContent = item.type.toUpperCase();

    var classification = classifyPermType(item.data);
    var classifyEl = utils.get('perm-classify');
    classifyEl.textContent = classification.label;
    classifyEl.style.background = classification.bgColor;
    classifyEl.style.color = classification.textColor;

    utils.get('perm-json-editor').value = JSON.stringify(item.data, null, 2);
  }

  function classifyPermType(data) {
    var str = JSON.stringify(data);
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var keys = Object.keys(data);
      for (var k = 0; k < keys.length; k++) {
        if (/^(isadmin|admin|is_superuser)$/i.test(keys[k])) {
          var val = data[keys[k]];
          if (val === 0 || val === false) {
            return {
              label: '特殊0开放 - ' + keys[k] + '=' + val + '，可修改为1/true',
              bgColor: '#F8D7DA',
              textColor: '#721C24',
            };
          }
          return {
            label: '特殊0开放 - 检测到角色控制字段',
            bgColor: '#FFF3CD',
            textColor: '#856404',
          };
        }
      }
    }
    if (Array.isArray(data) && data.length > 0) {
      var allHaveShowField = data.every(function (item) {
        return (
          item &&
          typeof item === 'object' &&
          ('isshow' in item ||
            'isShow' in item ||
            'hidden' in item ||
            'display' in item ||
            'status' in item)
        );
      });
      if (allHaveShowField) {
        var hasHidden = data.some(function (item) {
          return (
            item.isshow === '0' ||
            item.isShow === '0' ||
            item.hidden === true ||
            item.display === false ||
            item.status === 0
          );
        });
        if (hasHidden) {
          return {
            label: '全开放 - 所有菜单已返回，部分标记为隐藏 (isshow/display)',
            bgColor: '#D4EDDA',
            textColor: '#155724',
          };
        }
        return {
          label: '全开放 - 所有菜单已返回且均已显示',
          bgColor: '#D4EDDA',
          textColor: '#155724',
        };
      }
      return { label: '半开放 - 返回了部分菜单列表', bgColor: '#E6F0FA', textColor: '#1E3A5F' };
    }
    if (Array.isArray(data) && data.length === 0) {
      return {
        label: '0开放 - 菜单返回为空，需要搜索JS源码',
        bgColor: '#F8D7DA',
        textColor: '#721C24',
      };
    }
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var inner = data.data || data.result || data.Data;
      if (Array.isArray(inner) && inner.length === 0) {
        return {
          label: '0开放 - 菜单返回为空，需要搜索JS源码',
          bgColor: '#F8D7DA',
          textColor: '#721C24',
        };
      }
    }
    return { label: '未知类型 - 请手动检查数据结构', bgColor: '#F5F5F5', textColor: '#666' };
  }

  function transformShowAll(data) {
    if (Array.isArray(data)) {
      return data.map(function (item) {
        if (item && typeof item === 'object') {
          var c = {};
          for (var k in item) {
            if (item.hasOwnProperty(k)) c[k] = item[k];
          }
          if ('isshow' in c) c.isshow = '1';
          if ('isShow' in c) c.isShow = '1';
          if ('hidden' in c) c.hidden = false;
          if ('display' in c) c.display = true;
          if ('status' in c) c.status = 1;
          if ('visible' in c) c.visible = true;
          if (c.children) c.children = transformShowAll(c.children);
          if (c.child) c.child = transformShowAll(c.child);
          if (c.subList) c.subList = transformShowAll(c.subList);
          return c;
        }
        return item;
      });
    }
    if (data && typeof data === 'object') {
      var c = {};
      for (var k in data) {
        if (data.hasOwnProperty(k)) c[k] = transformShowAll(data[k]);
      }
      return c;
    }
    return data;
  }

  function permOpenAll() {
    var editor = utils.get('perm-json-editor');
    try {
      var data = JSON.parse(editor.value);
      data = transformShowAll(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已将所有 isshow/display 改为显示', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  function transformAdmin(data) {
    if (typeof data !== 'object' || data === null) return data;
    if (Array.isArray(data)) return data.map(transformAdmin);
    var c = {};
    for (var k in data) {
      if (!data.hasOwnProperty(k)) continue;
      if (/^(isadmin|admin|is_superuser)$/i.test(k)) {
        c[k] = typeof data[k] === 'string' ? '1' : 1;
      } else if (k === 'roleId' || k === 'role_id') {
        c[k] = 1;
      } else if (typeof data[k] === 'object') {
        c[k] = transformAdmin(data[k]);
      } else {
        c[k] = data[k];
      }
    }
    return c;
  }

  function permChangeAdmin() {
    var editor = utils.get('perm-json-editor');
    try {
      var data = JSON.parse(editor.value);
      data = transformAdmin(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast('已修改管理员/角色字段', 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  async function applyPermOverride() {
    var editor = utils.get('perm-json-editor');
    var modifiedData;
    try {
      modifiedData = JSON.parse(editor.value);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (overrideData) {
          if (!window.__PERM_INTERCEPTOR__) return false;
          window.__PERM_INTERCEPTOR__.setOverride(overrideData);
          // Also try to update Vue/Pinia reactive state
          var appEl = document.querySelector('#app') || document.querySelector('[data-v-app]');
          if (appEl && appEl.__vue_app__) {
            var pinia = appEl.__vue_app__.config.globalProperties.$pinia;
            if (pinia && pinia._s) {
              pinia._s.forEach(function (store, id) {
                var state = store.$state;
                for (var key in state) {
                  if (/menu|permission|route|nav/i.test(key) && Array.isArray(state[key])) {
                    if (store.$patch) {
                      var patch = {};
                      patch[key] = overrideData;
                      store.$patch(patch);
                    } else {
                      state[key] = overrideData;
                    }
                  }
                }
              });
            }
          }
          return true;
        },
        args: [modifiedData],
      });
      utils.showToast('已应用修改，请刷新页面或重新操作触发', 'success');
    } catch (e) {
      utils.showToast('应用失败: ' + e.message, 'error');
    }
  }

  // ====== JS Keyword Search ======
  async function searchJsKeywords(keyword) {
    var statusEl = utils.get('jssearch-status');
    var resultsEl = utils.get('jssearch-results');
    if (!keyword || keyword.length < 2) {
      utils.showToast('请输入至少2个字符', 'warning');
      return;
    }
    if (statusEl) statusEl.textContent = '搜索中...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      // 1. Search inline scripts
      var inlineResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: function (kw) {
          var matches = [];
          var seen = {};
          var scripts = document.querySelectorAll('script:not([src])');
          for (var i = 0; i < scripts.length; i++) {
            var text = scripts[i].textContent || '';
            if (text.indexOf(kw) === -1) continue;
            var lines = text.split('\n');
            for (var j = 0; j < lines.length; j++) {
              var idx = lines[j].indexOf(kw);
              while (idx !== -1) {
                var start = Math.max(0, idx - 40);
                var end = Math.min(text.length, idx + kw.length + 60);
                var context = text.substring(start, end).replace(/^\S*\s*/, '');
                var key = i + ':' + idx;
                if (!seen[key]) {
                  seen[key] = true;
                  matches.push({
                    source: '(inline script #' + (i + 1) + ')',
                    line: j + 1,
                    context: context,
                  });
                }
                if (matches.length >= 50) break;
                idx = lines[j].indexOf(kw, idx + 1);
              }
              if (matches.length >= 50) break;
            }
            if (matches.length >= 50) break;
          }
          // Also return external script URLs for further fetching
          var extUrls = [];
          document.querySelectorAll('script[src]').forEach(function (s) {
            extUrls.push(s.src);
          });
          return { matches: matches, extUrls: extUrls };
        },
        args: [keyword],
      });

      var inlineData = (inlineResults && inlineResults[0] && inlineResults[0].result) || {};
      var matchList = inlineData.matches || [];
      var extUrls = inlineData.extUrls || [];

      // 2. Search external scripts via background fetch proxy
      for (var u = 0; u < extUrls.length && matchList.length < 50; u++) {
        var url = extUrls[u];
        try {
          var resp = await chrome.runtime.sendMessage({ type: 'FETCH_URL', url: url });
          if (!resp || resp.error) continue;
          var text = resp.data;
          if (text && text.indexOf(keyword) !== -1) {
            var shortUrl = url;
            if (shortUrl.length > 60) shortUrl = '...' + shortUrl.substring(shortUrl.length - 57);
            var lines = text.split('\n');
            for (var j = 0; j < lines.length && matchList.length < 50; j++) {
              var idx = lines[j].indexOf(keyword);
              while (idx !== -1 && matchList.length < 50) {
                var start = Math.max(0, idx - 40);
                var end = Math.min(text.length, idx + keyword.length + 60);
                var context = text.substring(start, end).replace(/^\S*\s*/, '');
                matchList.push({ source: shortUrl, line: j + 1, context: context });
                idx = lines[j].indexOf(keyword, idx + 1);
              }
            }
          }
        } catch (e) {
          /* skip failed fetch */
        }
      }

      if (matchList.length === 0) {
        if (statusEl) statusEl.textContent = '未找到匹配';
        if (resultsEl)
          resultsEl.innerHTML =
            '<div class="empty-state">在页面JS中未找到「' + utils.escapeHtml(keyword) + '」</div>';
        return;
      }

      if (statusEl) statusEl.textContent = '找到 ' + matchList.length + ' 处匹配';
      var html = '';
      for (var i = 0; i < matchList.length; i++) {
        var m = matchList[i];
        var kwRegex = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var highlighted = m.context.replace(
          new RegExp('(' + kwRegex + ')', 'gi'),
          '<mark>$1</mark>'
        );
        html += '<div class="jssearch-match">';
        html +=
          '<div class="jssearch-match-source">' +
          utils.escapeHtml(m.source) +
          ' : line ' +
          m.line +
          '</div>';
        html += '<div class="jssearch-match-code">' + highlighted + '</div>';
        html += '</div>';
      }
      resultsEl.innerHTML = html;
    } catch (e) {
      if (statusEl) statusEl.textContent = '搜索出错';
      utils.showToast('搜索失败: ' + e.message, 'error');
    }
  }

  // ====== Route vs Menu Comparison ======
  function extractMenuPaths(data, paths) {
    if (typeof data !== 'object' || data === null) return;
    var pathKeys = ['path', 'url', 'href', 'component', 'menuUrl', 'menuPath', 'link', 'index'];
    if (Array.isArray(data)) {
      for (var i = 0; i < data.length; i++) extractMenuPaths(data[i], paths);
      return;
    }
    for (var k = 0; k < pathKeys.length; k++) {
      var val = data[pathKeys[k]];
      if (val && typeof val === 'string' && /^\//.test(val)) paths.add(val);
    }
    if (data.children) extractMenuPaths(data.children, paths);
    if (data.subList) extractMenuPaths(data.subList, paths);
    if (data.child) extractMenuPaths(data.child, paths);
  }

  function isPathInMenu(routePath, menuPaths) {
    if (menuPaths.has(routePath)) return true;
    var iter = menuPaths.values();
    var mp = iter.next();
    while (!mp.done) {
      if (routePath.indexOf(mp.value) === 0 && routePath !== mp.value) return true;
      mp = iter.next();
    }
    return false;
  }

  async function compareRoutesAndMenu() {
    var statusEl = utils.get('compare-status');
    var resultsEl = utils.get('compare-results');
    if (statusEl) statusEl.textContent = '对比中...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      var routeResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var routes = [];
          function extract(rts, prefix) {
            rts.forEach(function (r) {
              var path = prefix + (r.path || '/');
              if (r.path && r.path !== '*') routes.push({ path: path, name: r.name || '' });
              if (r.children) extract(r.children, path === '/' ? '/' : path + '/');
            });
          }
          var appEl = document.querySelector('#app') || document.querySelector('[data-v-app]');
          if (appEl && appEl.__vue_app__) {
            var router = appEl.__vue_app__.config.globalProperties.$router;
            if (router) extract(router.options.routes || [], '');
          } else {
            var els = document.querySelectorAll('*');
            for (var i = 0; i < els.length; i++) {
              if (els[i].__vue__) {
                var vm = els[i].__vue__.$root || els[i].__vue__;
                if (vm.$router && vm.$router.options) {
                  extract(vm.$router.options.routes || [], '');
                  break;
                }
              }
            }
          }
          return routes;
        },
      });

      var routeList = (routeResults && routeResults[0] && routeResults[0].result) || [];

      var menuResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          return window.__PERM_INTERCEPTOR__ ? window.__PERM_INTERCEPTOR__.getCaptured() : [];
        },
      });
      var captured = (menuResults && menuResults[0] && menuResults[0].result) || [];

      var menuPaths = new Set();
      for (var i = 0; i < captured.length; i++) extractMenuPaths(captured[i].data, menuPaths);

      if (routeList.length === 0) {
        if (statusEl) statusEl.textContent = '未找到路由';
        resultsEl.innerHTML = '<div class="empty-state">请先在「基础检测」中检测 Vue 路由</div>';
        return;
      }

      var hiddenRoutes = [];
      var visibleRoutes = [];
      for (var j = 0; j < routeList.length; j++) {
        var r = routeList[j];
        if (isPathInMenu(r.path, menuPaths)) {
          visibleRoutes.push(r);
        } else {
          hiddenRoutes.push(r);
        }
      }

      var html = '';
      if (hiddenRoutes.length > 0) {
        html +=
          '<div class="compare-section-title">隐藏路由 (路由存在但菜单中未显示) - ' +
          hiddenRoutes.length +
          ' 条</div>';
        for (var h = 0; h < hiddenRoutes.length; h++) {
          html += '<div class="compare-route-item">';
          html += '<span class="compare-route-hidden">[隐藏]</span> ';
          html +=
            '<span class="compare-route-path">' +
            utils.escapeHtml(hiddenRoutes[h].path) +
            '</span>';
          if (hiddenRoutes[h].name)
            html +=
              '<span class="compare-route-status">' +
              utils.escapeHtml(hiddenRoutes[h].name) +
              '</span>';
          html += '</div>';
        }
      }
      if (visibleRoutes.length > 0) {
        html +=
          '<div class="compare-section-title">已显示路由 - ' + visibleRoutes.length + ' 条</div>';
        for (var v = 0; v < visibleRoutes.length; v++) {
          html += '<div class="compare-route-item">';
          html += '<span class="compare-route-visible">[显示]</span> ';
          html +=
            '<span class="compare-route-path">' +
            utils.escapeHtml(visibleRoutes[v].path) +
            '</span>';
          if (visibleRoutes[v].name)
            html +=
              '<span class="compare-route-status">' +
              utils.escapeHtml(visibleRoutes[v].name) +
              '</span>';
          html += '</div>';
        }
      }
      if (captured.length === 0) {
        html +=
          '<div class="compare-section-title" style="background:#FFF3CD;color:#856404">提示</div>';
        html +=
          '<div class="compare-route-item" style="color:#856404">未捕获菜单数据。请先在「权限菜单」标签中开始拦截，然后刷新页面。</div>';
      }

      if (statusEl)
        statusEl.textContent =
          '路由 ' + routeList.length + ' 条，隐藏 ' + hiddenRoutes.length + ' 条';
      resultsEl.innerHTML = html;
    } catch (e) {
      if (statusEl) statusEl.textContent = '对比出错';
      utils.showToast('对比失败: ' + e.message, 'error');
    }
  }

  // ====== JS Control ======
  let currentJsCtrlTab = 'jstoggle';
  let jsBlocked = false;

  function switchJsCtrlTab(tab) {
    currentJsCtrlTab = tab;
    document
      .querySelectorAll('.jsctrl-tab')
      .forEach(b => b.classList.toggle('active', b.dataset.ctrl === tab));
    document.querySelectorAll('.jsctrl-panel').forEach(p => p.classList.remove('active'));
    const target = document.getElementById('jsctrl-' + tab);
    if (target) target.classList.add('active');
  }

  function updateJsToggleStatus() {
    const el = utils.get('js-toggle-status');
    if (!el) return;
    el.innerHTML = jsBlocked ? '<span class="spoof-status-active">JavaScript 已禁用</span>' : '';
  }

  async function disableJs() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: false,
      });
      if (response?.success) {
        jsBlocked = true;
        chrome.storage.local.set({ js_blocked_tabId: tab.id });
        updateJsToggleStatus();
        utils.showToast('JavaScript 已禁用，刷新页面生效', 'success');
      } else {
        utils.showToast('操作失败: ' + (response?.error || '未知错误'), 'error');
      }
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  async function enableJs() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: true,
      });
      if (response?.success) {
        jsBlocked = false;
        chrome.storage.local.remove('js_blocked_tabId');
        updateJsToggleStatus();
        utils.showToast('JavaScript 已启用，刷新页面生效', 'success');
      } else {
        utils.showToast('操作失败: ' + (response?.error || '未知错误'), 'error');
      }
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  async function scanAntiDebug() {
    const statusEl = utils.get('antidebug-status');
    const resultsEl = utils.get('antidebug-results');
    if (!statusEl || !resultsEl) return;

    statusEl.textContent = '扫描中...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          const detections = [];

          // Check for debugger statement in scripts
          const scripts = document.querySelectorAll('script');
          for (const s of scripts) {
            if (s.textContent && s.textContent.includes('debugger')) {
              detections.push({
                type: 'debugger语句',
                desc: '检测到 inline script 中的 debugger 语句',
              });
              break;
            }
          }

          // Check for Function constructor abuse
          const originalToString = Function.prototype.toString;
          const fnStr = originalToString.call(Function.prototype.constructor);
          if (fnStr === 'function () { [native code] }') {
            // Not overridden
          } else {
            detections.push({
              type: 'Function劫持',
              desc: 'Function.prototype.constructor 已被重写',
            });
          }

          // Check for setInterval/setTimeout debugger loops
          const origIntervalStr = originalToString.call(setInterval);
          if (origIntervalStr !== 'function setInterval() { [native code] }') {
            detections.push({ type: '定时器劫持', desc: 'setInterval 已被重写，可能用于反调试' });
          }

          // Check for console overrides
          const consoleStr = originalToString.call(console.log);
          if (
            consoleStr !== 'function log() { [native code] }' &&
            consoleStr !== 'function () { [native code] }'
          ) {
            detections.push({ type: 'Console劫持', desc: 'console.log 已被重写' });
          }

          // Check for devtools detection via window.outerWidth/innerWidth
          const scripts2 = document.querySelectorAll('script');
          for (const s of scripts2) {
            if (s.textContent && /outerWidth\s*-\s*innerWidth\s*>\s*\d+/.test(s.textContent)) {
              detections.push({ type: 'DevTools检测', desc: '通过窗口尺寸差检测开发者工具' });
              break;
            }
            if (s.textContent && /Firebug|firebug|chrome\.devtools/.test(s.textContent)) {
              detections.push({ type: 'DevTools检测', desc: '检测到 Firebug/DevTools 探测代码' });
              break;
            }
            if (s.textContent && /new\s+Image.*onerror.*devtools/i.test(s.textContent)) {
              detections.push({ type: 'DevTools检测', desc: '通过 Image.onerror 检测开发者工具' });
              break;
            }
          }

          return detections;
        },
      });

      const detections = results?.[0]?.result || [];
      if (detections.length === 0) {
        statusEl.textContent = '未检测到反调试';
        resultsEl.innerHTML = '<div class="empty-state">未发现常见的反调试手段</div>';
      } else {
        statusEl.textContent = '检测到 ' + detections.length + ' 项反调试';
        let html = '';
        detections.forEach(d => {
          html += '<div class="antidebug-item">';
          html += '<span class="antidebug-type">' + utils.escapeHtml(d.type) + '</span>';
          html += '<span class="antidebug-desc">' + utils.escapeHtml(d.desc) + '</span>';
          html += '</div>';
        });
        resultsEl.innerHTML = html;
      }
    } catch (e) {
      statusEl.textContent = '扫描失败';
      resultsEl.innerHTML = '<div class="empty-state">' + utils.escapeHtml(e.message) + '</div>';
    }
  }

  async function bypassAntiDebug() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          // Override Function constructor to strip debugger
          const OriginalFunction = Function.prototype.constructor;
          Function.prototype.constructor = function (...args) {
            if (args.length > 0 && typeof args[0] === 'string') {
              args[0] = args[0].replace(/debugger/g, '');
              if (/^\s*$/.test(args[0])) return function () {};
            }
            return new OriginalFunction(...args);
          };

          // Override eval to strip debugger
          const originalEval = window.eval;
          window.eval = function (code) {
            if (typeof code === 'string') {
              code = code.replace(/debugger/g, '');
            }
            return originalEval.call(window, code);
          };

          // Override setInterval/setTimeout to neutralize debugger callbacks
          const originalSetInterval = window.setInterval;
          const originalSetTimeout = window.setTimeout;

          function cleanCallback(fn) {
            if (typeof fn === 'string') {
              return fn.replace(/debugger/g, '');
            }
            if (typeof fn === 'function') {
              const fnStr = fn.toString();
              if (fnStr.includes('debugger')) {
                return function () {
                  try {
                    fn();
                  } catch (e) {
                    /* ignore debugger */
                  }
                };
              }
            }
            return fn;
          }

          window.setInterval = function (fn, delay, ...args) {
            return originalSetInterval.call(window, cleanCallback(fn), delay, ...args);
          };

          window.setTimeout = function (fn, delay, ...args) {
            return originalSetTimeout.call(window, cleanCallback(fn), delay, ...args);
          };

          // Restore console if overridden
          if (!console.log.restore) {
            const log = console.log;
            console.log = function (...args) {
              const stack = new Error().stack;
              const callerLine = stack ? stack.split('\n')[2] || '' : '';
              if (callerLine.includes('debugger')) return;
              return log.apply(console, args);
            };
            console.log.restore = true;
          }

          return true;
        },
      });

      utils.showToast('反调试绕过已注入，刷新页面后生效', 'success');
    } catch (e) {
      utils.showToast('注入失败: ' + e.message, 'error');
    }
  }

  async function clearScriptBlock() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      await chrome.runtime.sendMessage({
        type: 'TOGGLE_JS',
        tabId: tab.id,
        url: tab.url,
        enable: true,
      });
      jsBlocked = false;
      chrome.storage.local.remove('js_blocked_tabId');
      updateJsToggleStatus();
      utils.showToast('已清除所有脚本拦截规则', 'success');
    } catch (e) {
      utils.showToast('操作失败: ' + e.message, 'error');
    }
  }

  // ====== Init ======
  function initApp() {
    // Main panel tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const panel = btn.dataset.panel;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('panel-' + panel);
        if (target) target.classList.add('active');
        utils.get('status-text').textContent = btn.textContent;
      });
    });

    // Encoding sub-tabs
    document.querySelectorAll('.sub-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => switchEncodingTab(btn.dataset.type));
    });

    // Encoding buttons
    const encodingBindings = [
      { id: 'encode-btn', handler: handleEncode },
      { id: 'decode-btn', handler: handleDecode },
      { id: 'clear-encoding-btn', handler: clearEncodingFields },
      {
        id: 'copy-encoding-btn',
        handler: () => {
          const v = utils.get('encoding-output').value;
          if (!v) {
            utils.showToast('没有可复制的内容', 'warning');
            return;
          }
          utils.copyText(v);
          utils.showToast('已复制', 'success');
        },
      },
    ];
    encodingBindings.forEach(({ id, handler }) => {
      const el = utils.get(id);
      if (el) el.addEventListener('click', handler);
    });

    // Favicon buttons
    const faviconBtn = utils.get('extract-favicon-btn');
    if (faviconBtn) faviconBtn.addEventListener('click', extractFavicon);

    const copyHashBtn = utils.get('copy-favicon-hash-btn');
    if (copyHashBtn)
      copyHashBtn.addEventListener('click', () => {
        const hash = utils.get('favicon-hash').textContent;
        if (hash === '-') {
          utils.showToast('请先提取图标', 'warning');
          return;
        }
        utils.copyText(hash);
        utils.showToast('已复制 Hash', 'success');
      });

    // Asset mapping
    document.querySelectorAll('.source-btn').forEach(btn => {
      btn.addEventListener('click', () => switchAssetSource(btn.dataset.source));
    });

    const scanBtn = utils.get('asset-scan-btn');
    if (scanBtn) scanBtn.addEventListener('click', handleAssetScan);

    const saveKeysBtn = utils.get('save-keys-btn');
    if (saveKeysBtn) saveKeysBtn.addEventListener('click', saveApiKeys);

    const clearKeysBtn = utils.get('clear-keys-btn');
    if (clearKeysBtn) clearKeysBtn.addEventListener('click', clearApiKeys);

    loadApiKeys();

    // Info gather
    document.querySelectorAll('.gather-tab').forEach(btn => {
      btn.addEventListener('click', () => switchGatherTab(btn.dataset.gather));
    });
    const gatherBtn = utils.get('gather-btn');
    if (gatherBtn) gatherBtn.addEventListener('click', gatherInfo);
    const gatherCopyBtn = utils.get('gather-copy-btn');
    if (gatherCopyBtn) {
      gatherCopyBtn.addEventListener('click', () => {
        const list = gatherData[currentGatherTab] || [];
        if (list.length === 0) {
          utils.showToast('没有可复制的内容', 'warning');
          return;
        }
        const text = list.map(i => i.value).join('\n');
        utils.copyText(text);
        utils.showToast('已复制 ' + list.length + ' 条', 'success');
      });
    }

    // Link extract
    const linksExtractBtn = utils.get('links-extract-btn');
    if (linksExtractBtn) linksExtractBtn.addEventListener('click', extractLinks);
    const linksCopyBtn = utils.get('links-copy-btn');
    if (linksCopyBtn) {
      linksCopyBtn.addEventListener('click', () => {
        const filtered = getFilteredLinks();
        if (filtered.length === 0) {
          utils.showToast('没有链接', 'warning');
          return;
        }
        utils.copyText(filtered.map(l => l.href).join('\n'));
        utils.showToast('已复制 ' + filtered.length + ' 个链接', 'success');
      });
    }
    const linksSendBtn = utils.get('links-send-multiurl-btn');
    if (linksSendBtn) {
      linksSendBtn.addEventListener('click', () => {
        const filtered = getFilteredLinks().filter(l => !l.isMailto && !l.isJS);
        if (filtered.length === 0) {
          utils.showToast('没有可发送的链接', 'warning');
          return;
        }
        utils.get('multiurl-input').value = filtered.map(l => l.href).join('\n');
        updateMultiurlInfo(filtered.length);
        document
          .querySelectorAll('.tab-btn')
          .forEach(b => b.classList.toggle('active', b.dataset.panel === 'multiurl'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.getElementById('panel-multiurl').classList.add('active');
        utils.showToast('已发送 ' + filtered.length + ' 个链接', 'success');
      });
    }
    const linksFilter = utils.get('links-filter');
    if (linksFilter) linksFilter.addEventListener('input', renderLinks);
    const linksFilterType = utils.get('links-filter-type');
    if (linksFilterType) linksFilterType.addEventListener('change', renderLinks);

    // URL multi-open
    const multiurlInput = utils.get('multiurl-input');
    if (multiurlInput) {
      multiurlInput.addEventListener('input', () => updateMultiurlInfo(parseUrls().length));
    }
    const multiurlOpenBtn = utils.get('multiurl-open-btn');
    if (multiurlOpenBtn) multiurlOpenBtn.addEventListener('click', handleMultiurlOpen);
    const multiurlDedupBtn = utils.get('multiurl-dedup-btn');
    if (multiurlDedupBtn) multiurlDedupBtn.addEventListener('click', handleMultiurlDedup);
    const multiurlClearBtn = utils.get('multiurl-clear-btn');
    if (multiurlClearBtn)
      multiurlClearBtn.addEventListener('click', () => {
        utils.get('multiurl-input').value = '';
        updateMultiurlInfo(0);
      });

    // History
    const historyBtn = utils.get('history-query-btn');
    if (historyBtn) historyBtn.addEventListener('click', queryHistory);

    const historyCopyUrlBtn = utils.get('history-copy-url-btn');
    if (historyCopyUrlBtn) {
      historyCopyUrlBtn.addEventListener('click', async () => {
        let raw = utils.get('history-domain').value.trim();
        if (!raw) {
          const d = await getCurrentDomain();
          if (!d) {
            utils.showToast('请输入域名或打开一个网页', 'warning');
            return;
          }
          raw = d;
        }
        const domain = extractDomain(raw);
        utils.get('history-domain').value = domain;
        const cdxUrl = buildCdxUrl(domain);
        utils.copyText(cdxUrl);
        utils.showToast('查询URL已复制', 'success');
      });
    }

    const historyDomainInput = utils.get('history-domain');
    if (historyDomainInput) {
      historyDomainInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') queryHistory();
      });
      historyDomainInput.addEventListener('blur', () => {
        const val = historyDomainInput.value.trim();
        if (val) showHistoryQuickLinks(val);
      });

      // Auto-fill domain when switching to history panel
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          if (btn.dataset.panel === 'history') {
            if (!historyDomainInput.value.trim()) {
              getCurrentDomain().then(d => {
                if (d) historyDomainInput.value = d;
              });
            }
          }
        });
      });
    }

    const historyCopyResultBtn = utils.get('history-copy-result-btn');
    if (historyCopyResultBtn) {
      historyCopyResultBtn.addEventListener('click', () => {
        if (lastHistoryResults.length === 0) {
          utils.showToast('没有结果', 'warning');
          return;
        }
        const text = lastHistoryResults.map(i => i.raw || i.url).join('\n');
        utils.copyText(text);
        utils.showToast('已复制 ' + lastHistoryResults.length + ' 条', 'success');
      });
    }

    const historyTypeFilter = utils.get('history-type-filter');
    if (historyTypeFilter) {
      historyTypeFilter.addEventListener('input', () => {
        if (lastHistoryResults.length === 0) return;
        const filtered = filterByType(lastHistoryResults, historyTypeFilter.value);
        renderHistoryResults(filtered);
        utils.get('history-status').textContent =
          '筛选: ' + filtered.length + ' / ' + lastHistoryResults.length + ' 条';
      });
    }

    const historyCopyFilteredBtn = utils.get('history-copy-filtered-btn');
    if (historyCopyFilteredBtn) {
      historyCopyFilteredBtn.addEventListener('click', () => {
        if (lastHistoryResults.length === 0) {
          utils.showToast('没有结果', 'warning');
          return;
        }
        const typeFilter = historyTypeFilter ? historyTypeFilter.value : '';
        const filtered = filterByType(lastHistoryResults, typeFilter);
        if (filtered.length === 0) {
          utils.showToast('没有匹配的结果', 'warning');
          return;
        }
        const text = filtered.map(i => i.raw || i.url).join('\n');
        utils.copyText(text);
        utils.showToast('已复制 ' + filtered.length + ' 条', 'success');
      });
    }

    const historySendLinksBtn = utils.get('history-send-links-btn');
    if (historySendLinksBtn) {
      historySendLinksBtn.addEventListener('click', () => {
        if (lastHistoryResults.length === 0) {
          utils.showToast('没有结果', 'warning');
          return;
        }
        const urls = lastHistoryResults.map(i => i.url).filter(u => u && !u.startsWith('mailto:'));
        if (urls.length === 0) {
          utils.showToast('没有可用的URL', 'warning');
          return;
        }
        utils.get('multiurl-input').value = urls.join('\n');
        updateMultiurlInfo(urls.length);
        document
          .querySelectorAll('.tab-btn')
          .forEach(b => b.classList.toggle('active', b.dataset.panel === 'multiurl'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.getElementById('panel-multiurl').classList.add('active');
        utils.showToast('已发送 ' + urls.length + ' 个链接', 'success');
      });
    }

    // EXIF viewer
    initExifDragDrop();
    checkExifPending();

    document.querySelectorAll('.exif-mode-btn').forEach(btn => {
      btn.addEventListener('click', () => switchExifMode(btn.dataset.mode));
    });

    const exifFetchBtn = utils.get('exif-fetch-btn');
    if (exifFetchBtn) {
      const handler = () => {
        const url = utils.get('exif-url-input').value.trim();
        if (!url) {
          utils.showToast('请输入图片URL', 'warning');
          return;
        }
        fetchExifFromUrl(url);
      };
      exifFetchBtn.addEventListener('click', handler);
      utils.get('exif-url-input')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') handler();
      });
    }

    const exifScanBtn = utils.get('exif-scan-page-btn');
    if (exifScanBtn) exifScanBtn.addEventListener('click', scanPageImages);

    const exifCopyAllBtn = utils.get('exif-copy-all-btn');
    if (exifCopyAllBtn) {
      exifCopyAllBtn.addEventListener('click', () => {
        if (!lastExifData) {
          utils.showToast('没有元数据', 'warning');
          return;
        }
        const text = Object.entries(lastExifData)
          .map(([k, v]) => k + ': ' + v)
          .join('\n');
        utils.copyText(text);
        utils.showToast('已复制全部元数据', 'success');
      });
    }

    // Request Spoofing
    document.querySelectorAll('.spoof-tab').forEach(btn => {
      btn.addEventListener('click', () => switchSpoofTab(btn.dataset.spoof));
    });

    const uaCategoryEl = utils.get('ua-category');
    if (uaCategoryEl) {
      uaCategoryEl.addEventListener('change', () => renderUaList(uaCategoryEl.value));
      renderUaList('desktop');
    }

    const uaApplyBtn = utils.get('spoof-ua-apply');
    if (uaApplyBtn) uaApplyBtn.addEventListener('click', applyUserAgent);
    const uaResetBtn = utils.get('spoof-ua-reset');
    if (uaResetBtn) uaResetBtn.addEventListener('click', resetUserAgent);

    const cookieRefreshBtn = utils.get('cookie-refresh-btn');
    if (cookieRefreshBtn) cookieRefreshBtn.addEventListener('click', loadCookies);
    const cookieAddBtn = utils.get('cookie-add-btn');
    if (cookieAddBtn) cookieAddBtn.addEventListener('click', showCookieAddEditor);
    const cookieImportBtn = utils.get('cookie-import-btn');
    if (cookieImportBtn) cookieImportBtn.addEventListener('click', showCookieImportDialog);
    const cookieClearBtn = utils.get('cookie-clear-btn');
    if (cookieClearBtn) cookieClearBtn.addEventListener('click', clearAllCookies);

    const headerApplyBtn = utils.get('header-apply');
    if (headerApplyBtn) headerApplyBtn.addEventListener('click', applyHeaders);
    const headerResetBtn = utils.get('header-reset');
    if (headerResetBtn) headerResetBtn.addEventListener('click', resetHeaders);
    const customHeaderAddBtn = utils.get('custom-header-add');
    if (customHeaderAddBtn) customHeaderAddBtn.addEventListener('click', addCustomHeaderRow);

    const initialRemoveBtn = document.querySelector('.custom-header-remove');
    if (initialRemoveBtn)
      initialRemoveBtn.addEventListener('click', function () {
        this.closest('.custom-header-row').remove();
      });

    const refererPresetEl = utils.get('referer-preset');
    if (refererPresetEl) {
      refererPresetEl.addEventListener('change', () => {
        const v = refererPresetEl.value;
        const refererInput = utils.get('header-referer');
        if (!refererInput) return;
        if (v === 'none') refererInput.value = '';
        else if (v === 'google') refererInput.value = 'https://www.google.com/';
        else if (v === 'baidu') refererInput.value = 'https://www.baidu.com/';
        else if (v === 'same') refererInput.value = '';
      });
    }

    chrome.storage.local.get(['pentest_spoof'], result => {
      const saved = result.pentest_spoof;
      if (saved) {
        if (saved.ua) Object.assign(spoofState.ua, saved.ua);
        if (saved.headers) Object.assign(spoofState.headers, saved.headers);
        updateUaStatus();
      }
    });

    // Vue Analysis
    const vueDetectBtn = utils.get('vue-detect-btn');
    if (vueDetectBtn) vueDetectBtn.addEventListener('click', detectVue);
    const vueExportBtn = utils.get('vue-export-routes-btn');
    if (vueExportBtn) vueExportBtn.addEventListener('click', exportVueRoutes);
    const vueBypassBtn = utils.get('vue-bypass-guards-btn');
    if (vueBypassBtn) vueBypassBtn.addEventListener('click', bypassVueGuards);
    const vueCopyBtn = utils.get('vue-copy-btn');
    if (vueCopyBtn) {
      vueCopyBtn.addEventListener('click', () => {
        if (!lastVueResult) {
          utils.showToast('没有可复制的内容', 'warning');
          return;
        }
        utils.copyText(lastVueResult);
        utils.showToast('已复制', 'success');
      });
    }

    // Vue sub-tabs
    document.querySelectorAll('.vue-stab').forEach(btn => {
      btn.addEventListener('click', () => switchVueSubTab(btn.dataset.vstab));
    });

    // Permission menu interception
    const permStartBtn = utils.get('perm-start-btn');
    if (permStartBtn) permStartBtn.addEventListener('click', startPermInterception);
    const permStopBtn = utils.get('perm-stop-btn');
    if (permStopBtn) permStopBtn.addEventListener('click', stopPermInterception);
    const permRefreshBtn = utils.get('perm-refresh-btn');
    if (permRefreshBtn) permRefreshBtn.addEventListener('click', refreshPermCaptured);
    const permFilter = utils.get('perm-filter');
    if (permFilter) permFilter.addEventListener('input', renderPermList);
    const permTypeFilter = utils.get('perm-type-filter');
    if (permTypeFilter) permTypeFilter.addEventListener('change', renderPermList);
    const permDetailBack = utils.get('perm-detail-back');
    if (permDetailBack)
      permDetailBack.addEventListener('click', () => {
        permViewMode = 'list';
        utils.get('perm-captured-list').classList.remove('hidden');
        const filterRow = utils.get('perm-filter-row');
        if (filterRow) filterRow.classList.remove('hidden');
        utils.get('perm-detail').classList.add('hidden');
      });
    const permOpenAllBtn = utils.get('perm-open-all');
    if (permOpenAllBtn) permOpenAllBtn.addEventListener('click', permOpenAll);
    const permChangeAdminBtn = utils.get('perm-change-admin');
    if (permChangeAdminBtn) permChangeAdminBtn.addEventListener('click', permChangeAdmin);
    const permApplyBtn = utils.get('perm-apply-btn');
    if (permApplyBtn) permApplyBtn.addEventListener('click', applyPermOverride);
    const permCopyJsonBtn = utils.get('perm-copy-json');
    if (permCopyJsonBtn)
      permCopyJsonBtn.addEventListener('click', () => {
        const val = utils.get('perm-json-editor').value;
        if (!val) {
          utils.showToast('没有数据', 'warning');
          return;
        }
        utils.copyText(val);
        utils.showToast('已复制', 'success');
      });

    // JS keyword search
    const jssearchBtn = utils.get('jssearch-btn');
    if (jssearchBtn)
      jssearchBtn.addEventListener('click', () => {
        searchJsKeywords(utils.get('jssearch-keyword').value.trim());
      });
    const jssearchInput = utils.get('jssearch-keyword');
    if (jssearchInput)
      jssearchInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') searchJsKeywords(jssearchInput.value.trim());
      });
    document.querySelectorAll('.jssearch-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.get('jssearch-keyword').value = btn.dataset.kw;
        searchJsKeywords(btn.dataset.kw);
      });
    });

    // Route vs menu comparison
    const compareBtn = utils.get('compare-btn');
    if (compareBtn) compareBtn.addEventListener('click', compareRoutesAndMenu);
    const compareCopyHidden = utils.get('compare-copy-hidden');
    if (compareCopyHidden)
      compareCopyHidden.addEventListener('click', () => {
        const items = utils.get('compare-results').querySelectorAll('.compare-route-path');
        const hiddenPaths = [];
        items.forEach(el => {
          const parentItem = el.closest('.compare-route-item');
          if (parentItem && parentItem.querySelector('.compare-route-hidden')) {
            hiddenPaths.push(el.textContent);
          }
        });
        if (hiddenPaths.length === 0) {
          utils.showToast('没有隐藏路由', 'warning');
          return;
        }
        utils.copyText(hiddenPaths.join('\n'));
        utils.showToast('已复制 ' + hiddenPaths.length + ' 条隐藏路由', 'success');
      });

    // JS Control
    document.querySelectorAll('.jsctrl-tab').forEach(btn => {
      btn.addEventListener('click', () => switchJsCtrlTab(btn.dataset.ctrl));
    });
    const jsDisableBtn = utils.get('js-disable-btn');
    if (jsDisableBtn) jsDisableBtn.addEventListener('click', disableJs);
    const jsEnableBtn = utils.get('js-enable-btn');
    if (jsEnableBtn) jsEnableBtn.addEventListener('click', enableJs);
    const antidebugScanBtn = utils.get('antidebug-scan-btn');
    if (antidebugScanBtn) antidebugScanBtn.addEventListener('click', scanAntiDebug);
    const antidebugBypassBtn = utils.get('antidebug-bypass-btn');
    if (antidebugBypassBtn) antidebugBypassBtn.addEventListener('click', bypassAntiDebug);
    const antidebugClearBtn = utils.get('antidebug-clear-btn');
    if (antidebugClearBtn) antidebugClearBtn.addEventListener('click', clearScriptBlock);

    // Restore perm intercept state
    chrome.storage.local.get(['permInterceptTabId'], result => {
      if (result.permInterceptTabId) {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
          if (tabs[0] && tabs[0].id === result.permInterceptTabId) {
            permInterceptActive = true;
            const startBtn = utils.get('perm-start-btn');
            const stopBtn = utils.get('perm-stop-btn');
            if (startBtn) startBtn.disabled = true;
            if (stopBtn) stopBtn.disabled = false;
            const statusEl = utils.get('perm-status');
            if (statusEl) statusEl.textContent = '拦截中... 页面刷新后会自动重新注入';
          } else {
            chrome.storage.local.remove('permInterceptTabId');
          }
        });
      }
    });

    // Restore JS toggle state
    chrome.storage.local.get(['js_blocked_tabId'], result => {
      if (result.js_blocked_tabId) {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
          if (tabs[0] && tabs[0].id === result.js_blocked_tabId) {
            jsBlocked = true;
            updateJsToggleStatus();
          } else {
            chrome.storage.local.remove('js_blocked_tabId');
          }
        });
      }
    });

    // Restore gather data for current tab
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const currentUrl = tabs[0]?.url || '';
      chrome.storage.local.get(['gatherData', 'gatherDataUrl'], result => {
        if (result.gatherData && result.gatherDataUrl === currentUrl) {
          gatherData = result.gatherData;
          renderGatherTab();
          const total = Object.values(gatherData).reduce((s, a) => s + a.length, 0);
          const statusEl = utils.get('gather-status');
          if (statusEl) statusEl.textContent = '已恢复，共 ' + total + ' 条';
        }
      });
      chrome.storage.local.get(['allLinks', 'allLinksUrl'], result => {
        if (result.allLinks && result.allLinksUrl === currentUrl) {
          allLinks = result.allLinks;
          renderLinks();
          const statusEl = utils.get('links-count');
          if (statusEl) statusEl.textContent = '已恢复，共 ' + allLinks.length + ' 个链接';
        }
      });
    });

    // Theme toggle
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) {
      const themes = ['light', 'dark'];
      const saved = localStorage.getItem('pentest-theme');
      if (saved) document.documentElement.setAttribute('data-theme', saved);
      themeBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'light';
        const next = themes[(themes.indexOf(current) + 1) % themes.length];
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('pentest-theme', next);
      });
    }

    // Status bar clock
    const statusTime = utils.get('status-time');
    if (statusTime) {
      const update = () => {
        const now = new Date();
        statusTime.textContent =
          String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
      };
      update();
      setInterval(update, 30000);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
})();
