// VulnKit - Info Gather
window.VulnKitGather = (function () {
  'use strict';

  let gatherData = { api: [], domain: [], sensitive: [], ip: [] };
  let currentGatherTab = 'api';

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  function renderGatherTab() {
    const utils = getUtils();
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
    const utils = getUtils();
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

  return {
    renderGatherTab,
    switchGatherTab,
    gatherInfo,
    get gatherData() { return gatherData; },
    set gatherData(v) { gatherData = v; },
    get currentGatherTab() { return currentGatherTab; },
    set currentGatherTab(v) { currentGatherTab = v; },
  };
})();
