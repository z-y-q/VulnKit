// VulnKit - Asset Mapping
window.VulnKitAsset = (function () {
  'use strict';

  let currentAssetSource = 'fofa';
  let lastAssetResults = [];
  let customQueryMode = false;

  var utils = window.VulnKitUtils.utilsProxy;

  function bgFetch(url) {
    return new Promise(function (resolve) {
      chrome.runtime.sendMessage({ type: 'FETCH_URL', url: url }, function (resp) {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
          return;
        }
        if (resp && resp.error) {
          resolve({ success: false, error: resp.error });
        } else if (resp && resp.data) {
          try {
            resolve({ success: true, data: JSON.parse(resp.data) });
          } catch (e) {
            resolve({ success: true, data: resp.data });
          }
        } else {
          resolve({ success: false, error: '未知响应' });
        }
      });
    });
  }

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
    const tab = await utils.getActiveTab();
    return tab?.url || null;
  }

  function setAssetStatus(text) {
    const el = utils.get('asset-status');
    if (el) el.textContent = text;
  }

  function getAssetSize() {
    const el = utils.get('asset-size');
    return el ? parseInt(el.value, 10) || 10 : 10;
  }

  var currentSearchFilter = '';

  function renderAssetResults(data) {
    var filtered = data || lastAssetResults || [];
    if (currentSearchFilter && filtered.length > 0) {
      var lower = currentSearchFilter.toLowerCase();
      filtered = filtered.filter(function (item) {
        return (
          (item.host || '').toLowerCase().indexOf(lower) !== -1 ||
          String(item.port || '')
            .toLowerCase()
            .indexOf(lower) !== -1 ||
          (item.protocol || '').toLowerCase().indexOf(lower) !== -1 ||
          (item.title || '').toLowerCase().indexOf(lower) !== -1
        );
      });
    }

    const container = utils.get('asset-results');
    if (!container) return;
    var actionsRow = utils.get('asset-actions-row');
    if (data) lastAssetResults = data;
    var hasResults = lastAssetResults.length > 0;
    if (actionsRow) actionsRow.style.display = hasResults ? 'flex' : 'none';
    var searchInput = utils.get('asset-search');
    if (searchInput) searchInput.style.display = hasResults ? '' : 'none';
    if (filtered.length === 0 && !hasResults) {
      container.innerHTML = '<div class="empty-state">未找到结果</div>';
      return;
    }
    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">无匹配结果</div>';
      return;
    }
    var countLabel = currentSearchFilter
      ? '匹配 ' + filtered.length + ' / ' + lastAssetResults.length + ' 条结果'
      : '共 ' + filtered.length + ' 条结果';
    var html = '<div class="asset-count">' + countLabel + '</div>';
    html +=
      '<table class="asset-table"><thead><tr><th>IP/域名</th><th>端口</th><th>协议</th><th>标题</th></tr></thead><tbody>';
    filtered.forEach(function (item) {
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

  function applySearchFilter(text) {
    currentSearchFilter = text || '';
    renderAssetResults();
  }

  function exportData() {
    if (!lastAssetResults || lastAssetResults.length === 0) {
      utils.showToast('没有可导出的结果', 'warning');
      return;
    }
    var data = lastAssetResults;
    if (currentSearchFilter) {
      var lower = currentSearchFilter.toLowerCase();
      data = data.filter(function (item) {
        return (
          (item.host || '').toLowerCase().indexOf(lower) !== -1 ||
          String(item.port || '')
            .toLowerCase()
            .indexOf(lower) !== -1 ||
          (item.protocol || '').toLowerCase().indexOf(lower) !== -1 ||
          (item.title || '').toLowerCase().indexOf(lower) !== -1
        );
      });
    }
    var lines = ['IP/域名,端口,协议,标题'];
    data.forEach(function (item) {
      lines.push(
        '"' +
          (item.host || '').replace(/"/g, '""') +
          '",' +
          '"' +
          String(item.port || '').replace(/"/g, '""') +
          '",' +
          '"' +
          (item.protocol || '').replace(/"/g, '""') +
          '",' +
          '"' +
          (item.title || '').replace(/"/g, '""') +
          '"'
      );
    });
    var csv = lines.join('\n');
    utils.downloadCsv(csv, 'vulnkit-asset-' + currentAssetSource + '-' + Date.now() + '.csv');
  }

  async function scanFofa(query) {
    const keys = await getApiKey('fofa');
    if (!keys?.email || !keys?.key) {
      utils.showToast('请先配置 FOFA API Key', 'warning');
      return;
    }
    setAssetStatus('正在查询 FOFA...');
    const fofaQuery = customQueryMode ? query : 'domain="' + query + '"';
    const qbase64 = btoa(unescape(encodeURIComponent(fofaQuery)));
    const url =
      'https://fofa.info/api/v1/search/all?email=' +
      encodeURIComponent(keys.email) +
      '&key=' +
      encodeURIComponent(keys.key) +
      '&qbase64=' +
      qbase64 +
      '&fields=host,port,protocol,title&size=' +
      getAssetSize();

    chrome.runtime.sendMessage({ type: 'FETCH_URL', url }, response => {
      if (chrome.runtime.lastError) {
        setAssetStatus('查询失败: ' + chrome.runtime.lastError.message);
        return;
      }
      if (!response) {
        setAssetStatus('查询失败: 无响应');
        return;
      }
      if (response.error) {
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
        setAssetStatus('FOFA: 查询完成 (共 ' + (json.size || results.length) + ' 条)');
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
    var zoomQuery = customQueryMode ? query : 'hostname:' + query.replace(/^www\./, '');
    const url =
      'https://api.zoomeye.org/host/search?query=' +
      encodeURIComponent(zoomQuery) +
      '&page=1&size=' +
      getAssetSize();

    chrome.runtime.sendMessage(
      { type: 'FETCH_URL_AUTH', url, key, provider: 'zoomeye' },
      response => {
        if (chrome.runtime.lastError) {
          setAssetStatus('查询失败: ' + chrome.runtime.lastError.message);
          return;
        }
        if (!response) {
          setAssetStatus('查询失败: 无响应');
          return;
        }
        if (response.error) {
          setAssetStatus('查询失败: ' + response.error);
          return;
        }
        try {
          const json = JSON.parse(response.data);
          if (json.error) {
            setAssetStatus('API 错误: ' + (json.message || json.error));
            return;
          }
          const list = json.matches || json.data || [];
          const total = json.total || list.length;
          if (list.length === 0) {
            setAssetStatus('ZoomEye: 未找到资产 (total=0)');
            renderAssetResults([]);
            return;
          }
          const results = list.map(r => ({
            host: r.ip || '-',
            port: r.portinfo?.port || '-',
            protocol: r.portinfo?.service || r.portinfo?.type || '-',
            title: r.webinfo?.title || r.portinfo?.product || '-',
          }));
          setAssetStatus('ZoomEye: 查询完成 (共 ' + total + ' 条)');
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
    var searchQuery = customQueryMode
      ? query
      : /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(query)
        ? query
        : 'hostname:' + query;
    const url =
      'https://api.shodan.io/shodan/search?key=' +
      encodeURIComponent(key) +
      '&query=' +
      encodeURIComponent(searchQuery);

    chrome.runtime.sendMessage({ type: 'FETCH_URL', url }, response => {
      if (chrome.runtime.lastError) {
        setAssetStatus('查询失败: ' + chrome.runtime.lastError.message);
        return;
      }
      if (!response) {
        setAssetStatus('查询失败: 无响应');
        return;
      }
      if (response.error) {
        setAssetStatus('查询失败: ' + response.error);
        return;
      }
      try {
        const json = JSON.parse(response.data);
        if (json.error) {
          setAssetStatus('API 错误: ' + json.error);
          return;
        }
        const results = (json.matches || []).slice(0, getAssetSize()).map(m => ({
          host: m.ip_str || '-',
          port: m.port || '-',
          protocol: m._shodan?.module || '-',
          title: m.http?.title || '-',
        }));
        setAssetStatus('Shodan: 查询完成 (共 ' + (json.total || results.length) + ' 条)');
        renderAssetResults(results);
      } catch {
        setAssetStatus('解析结果失败');
      }
    });
  }

  function shodanHostLookup() {
    var inputEl = utils.get('shodan-host-input');
    var input = inputEl ? inputEl.value.trim() : '';
    var container = utils.get('shodan-host-info');
    if (!container) return;

    if (!input) {
      utils.getCurrentDomain().then(function (domain) {
        if (!domain) {
          utils.showToast('请输入 IP 或域名', 'warning');
          return;
        }
        if (inputEl) inputEl.value = domain;
        doShodanLookup(domain, container);
      });
      return;
    }
    doShodanLookup(input, container);
  }

  function doShodanLookup(input, container) {
    container.innerHTML =
      '<div style="text-align:center;padding:8px;color:#66B2FF;">正在查询...</div>';
    var resolvedIp = null;
    var isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(input);

    function step1() {
      if (isIp) {
        resolvedIp = input;
        step2();
        return;
      }
      bgFetch('https://geonet.shodan.io/api/dns/' + encodeURIComponent(input))
        .then(function (result) {
          if (result.success && result.data && result.data.answers) {
            resolvedIp = result.data.answers[0].value;
          }
        })
        .catch(function () {})
        .finally(function () {
          step2();
        });
    }

    function step2() {
      var targetIp = resolvedIp;
      if (!targetIp || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(targetIp)) {
        container.innerHTML =
          '<div style="color:#ff6b6b;padding:8px;">无法解析域名 ' +
          utils.escapeHtml(input) +
          ' 为 IP 地址，请直接输入 IP</div>';
        return;
      }
      bgFetch('https://internetdb.shodan.io/' + encodeURIComponent(targetIp))
        .then(function (result) {
          if (!result.success || !result.data || result.data.error) {
            container.innerHTML =
              '<div style="color:#ff6b6b;padding:8px;">未找到该主机的信息</div>';
            return;
          }
          step3(result.data, targetIp);
        })
        .catch(function (err) {
          container.innerHTML =
            '<div style="color:#ff6b6b;padding:8px;">查询失败: ' +
            utils.escapeHtml(String(err.message || err)) +
            '</div>';
        });
    }

    function step3(idbData, targetIp) {
      getApiKey('shodan').then(function (shodanKey) {
        if (!shodanKey || !resolvedIp) {
          renderShodanHostInfo(container, idbData, null, input, targetIp);
          return;
        }
        bgFetch(
          'https://api.shodan.io/shodan/host/' +
            encodeURIComponent(resolvedIp) +
            '?key=' +
            encodeURIComponent(shodanKey)
        )
          .then(function (result) {
            renderShodanHostInfo(
              container,
              idbData,
              result.success ? result.data : null,
              input,
              targetIp
            );
          })
          .catch(function () {
            renderShodanHostInfo(container, idbData, null, input, targetIp);
          });
      });
    }

    step1();
  }

  function renderShodanHostInfo(container, idbData, shodanData, queryInput, resolvedIp) {
    var esc =
      utils && utils.escapeHtml
        ? function (s) {
            return utils.escapeHtml(String(s == null ? '' : s));
          }
        : function (s) {
            return String(s == null ? '' : s);
          };
    var ip =
      (idbData && idbData.ip) || (shodanData && shodanData.ip_str) || resolvedIp || queryInput;
    var hostnames = (idbData && idbData.hostnames) || (shodanData && shodanData.hostnames) || [];
    var location = idbData && idbData.location ? idbData.location : null;
    var country = location
      ? location.country_name || location.country || '-'
      : (shodanData && shodanData.country_name) || '-';
    var city = location ? location.city || '-' : (shodanData && shodanData.city) || '-';
    var lat = location ? location.latitude : shodanData && shodanData.latitude;
    var lon = location ? location.longitude : shodanData && shodanData.longitude;
    var ports = (idbData && idbData.ports) || (shodanData && shodanData.ports) || [];
    var vulns = idbData ? idbData.vulns || {} : (shodanData && shodanData.vulns) || {};
    var cpes = (idbData && idbData.cpes) || [];
    var tags = (idbData && idbData.tags) || [];
    var lastUpdate =
      idbData && idbData.last_report_at
        ? idbData.last_report_at.replace('T', ' ').substring(0, 19)
        : (shodanData && shodanData.last_update) || '-';
    var isp = shodanData && shodanData.isp ? shodanData.isp : null;
    var org = shodanData && shodanData.org ? shodanData.org : null;
    var os = shodanData && shodanData.os ? shodanData.os : null;
    var serviceData = shodanData && shodanData.data ? shodanData.data : [];

    var h = '';
    h += '<div class="shodan-host-header">';
    h += '<div class="shodan-host-title">' + esc(hostnames[0] || queryInput) + '</div>';
    h += '<div class="shodan-host-ip">' + esc(ip) + '</div>';
    if (tags.length > 0) {
      h += '<div style="margin-top:4px;">';
      tags.forEach(function (tag) {
        h +=
          '<span style="display:inline-block;font-size:10px;background:#E8F4FD;color:#1976D2;padding:1px 6px;border-radius:3px;margin-right:4px;">' +
          esc(tag) +
          '</span>';
      });
      h += '</div>';
    }
    h += '</div>';

    h += '<div class="shodan-info-grid">';
    var infoItems = [];
    if (isp) infoItems.push({ label: 'ISP', value: isp });
    if (org) infoItems.push({ label: '组织', value: org });
    infoItems.push({ label: '国家/地区', value: country });
    infoItems.push({ label: '城市', value: city });
    if (lat != null && lon != null) infoItems.push({ label: '经纬度', value: lat + ', ' + lon });
    if (os) infoItems.push({ label: '操作系统', value: os });
    infoItems.push({ label: '最后更新', value: lastUpdate });
    infoItems.forEach(function (item) {
      h +=
        '<div class="shodan-info-item"><span class="shodan-info-label">' +
        item.label +
        '</span><span class="shodan-info-value">' +
        esc(item.value) +
        '</span></div>';
    });
    h += '</div>';

    if (ports.length > 0) {
      h += '<div class="shodan-section-title">开放端口 (' + ports.length + ')</div>';
      h += '<div class="shodan-ports">';
      ports.forEach(function (port) {
        var portInfo = serviceData.find(function (d) {
          return d.port === port;
        });
        var product = portInfo
          ? portInfo.product || (portInfo._shodan && portInfo._shodan.module) || ''
          : '';
        var version = portInfo && portInfo.version ? ' ' + portInfo.version : '';
        var portLabel = product ? product + version : '';
        h +=
          '<div class="shodan-port-item"><span class="shodan-port-num">' +
          esc(port) +
          '</span><span class="shodan-port-service">' +
          esc(portLabel) +
          '</span></div>';
      });
      h += '</div>';
    }

    if (cpes.length > 0) {
      h += '<div class="shodan-section-title">CPE 识别 (' + cpes.length + ')</div>';
      h += '<div class="shodan-ports">';
      cpes.slice(0, 15).forEach(function (cpe) {
        var short = cpe.replace('cpe:2.3:a:', '').replace(/:/g, ' ');
        h +=
          '<div class="shodan-port-item"><span class="shodan-port-service" style="font-family:monospace;font-size:11px;">' +
          esc(short) +
          '</span></div>';
      });
      if (cpes.length > 15)
        h +=
          '<div style="color:#888;font-size:11px;padding:4px 0;">...还有 ' +
          (cpes.length - 15) +
          ' 个</div>';
      h += '</div>';
    }

    var vulnKeys = Object.keys(vulns);
    if (vulnKeys.length > 0) {
      h += '<div class="shodan-section-title">已知漏洞 (' + vulnKeys.length + ')</div>';
      h += '<div class="shodan-vulns">';
      vulnKeys.slice(0, 30).forEach(function (cve) {
        var v = vulns[cve];
        var severity;
        if (v && typeof v === 'object' && v.cvss) {
          severity =
            v.cvss >= 9 ? 'critical' : v.cvss >= 7 ? 'high' : v.cvss >= 4 ? 'medium' : 'low';
        } else {
          severity = 'info';
        }
        var cvssStr =
          v && typeof v === 'object' && v.cvss
            ? '<span class="shodan-vuln-cvss">CVSS: ' + esc(v.cvss) + '</span>'
            : '';
        h += '<div class="shodan-vuln-item shodan-vuln-' + severity + '">';
        h += '<span class="shodan-vuln-cve">' + esc(cve) + '</span>';
        h += cvssStr;
        h += '</div>';
      });
      if (vulnKeys.length > 30)
        h +=
          '<div style="color:#888;font-size:11px;padding:4px 0;">...还有 ' +
          (vulnKeys.length - 30) +
          ' 个</div>';
      h += '</div>';
    }

    if (ports.length === 0 && vulnKeys.length === 0) {
      h += '<div style="color:#888;padding:8px;">该 IP 暂无开放端口或漏洞信息</div>';
    }

    h +=
      '<div style="text-align:center;padding:6px;font-size:10px;color:#aaa;">数据来源: Shodan InternetDB' +
      (shodanData ? ' + Shodan API' : '') +
      '</div>';

    container.innerHTML = h;
  }

  async function handleAssetScan() {
    const queryEl = utils.get('asset-query');
    let query = queryEl ? queryEl.value.trim() : '';
    if (!query) {
      query = await getCurrentUrl().then(url => {
        if (!url) return null;
        try {
          return new URL(url).hostname;
        } catch {
          return null;
        }
      });
      if (!query) {
        utils.showToast('请输入目标或打开一个网页', 'warning');
        return;
      }
      if (queryEl) queryEl.value = query;
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
    const results = utils.get('asset-results');
    if (results) results.innerHTML = '';
    setAssetStatus('');
  }

  function toggleCustomQueryMode(enabled) {
    customQueryMode = enabled;

    const queryInput = utils.get('asset-query');
    const hint = utils.get('asset-query-hint');
    if (queryInput) {
      queryInput.placeholder = enabled
        ? '输入自定义查询语法，如 domain="x.com" && title="login"'
        : '留空使用当前页面域名';
    }
    if (hint) hint.textContent = enabled ? '自定义模式：直接输入引擎查询语法' : '';
    var toggle = utils.get('asset-custom-toggle');
    if (toggle) toggle.classList.toggle('active', enabled);
  }

  function saveApiKeys() {
    var el = id => utils.get(id);
    const keys = {
      fofa_email: (el('key-fofa-email') || {}).value ? el('key-fofa-email').value.trim() : '',
      fofa_key: (el('key-fofa-key') || {}).value ? el('key-fofa-key').value.trim() : '',
      zoomeye: (el('key-zoomeye') || {}).value ? el('key-zoomeye').value.trim() : '',
      shodan: (el('key-shodan') || {}).value ? el('key-shodan').value.trim() : '',
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
      ['key-fofa-email', 'key-fofa-key', 'key-zoomeye', 'key-shodan'].forEach(id => {
        var el = utils.get(id);
        if (el) el.value = '';
      });
      utils.showToast('配置已清除', 'success');
    });
  }

  return {
    handleAssetScan,
    switchAssetSource,
    toggleCustomQueryMode,
    shodanHostLookup,
    saveApiKeys,
    loadApiKeys,
    clearApiKeys,
    exportData,
    applySearchFilter,
    get currentAssetSource() {
      return currentAssetSource;
    },
    get lastAssetResults() {
      return lastAssetResults;
    },
    set currentAssetSource(v) {
      currentAssetSource = v;
    },
  };
})();
