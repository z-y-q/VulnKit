// VulnKit - Info Gather (HaE Rules Engine)
window.VulnKitGather = (function () {
  'use strict';

  var DOM_GROUP = 'DOM Analysis';
  var STORAGE_KEY = 'gatherData';
  var URL_KEY = 'gatherDataUrl';
  var TABS_KEY = 'gatherDataTabs';

  var gatherData = {};
  var currentGatherTab = DOM_GROUP;
  var loadedRules = [];
  var searchFilter = '';

  var utils = window.VulnKitUtils.utilsProxy;

  function getHaeRules() {
    return window.VulnKitHaeRules || null;
  }

  function getFilteredList() {
    var list = gatherData[currentGatherTab] || [];
    if (!searchFilter) return list;
    var lower = searchFilter.toLowerCase();
    return list.filter(function (item) {
      return (
        (item.value && item.value.toLowerCase().indexOf(lower) !== -1) ||
        (item.name && item.name.toLowerCase().indexOf(lower) !== -1)
      );
    });
  }

  function updateSearchVisibility() {
    var searchInput = utils ? utils.get('gather-search') : null;
    if (!searchInput) return;
    var hasData = Object.keys(gatherData).some(function (k) {
      return Array.isArray(gatherData[k]) && gatherData[k].length > 0;
    });
    searchInput.style.display = hasData ? '' : 'none';
  }

  function renderGatherTab() {
    var list = getFilteredList();
    var container = utils.get('gather-results');
    if (!container || !utils.get('gather-status')) return;

    updateSearchVisibility();

    var fullList = gatherData[currentGatherTab] || [];
    if (fullList.length === 0) {
      utils.setEmpty('gather-results', '点击「收集当前页面」开始');
      utils.setStatus('gather-status', '');
      return;
    }

    var statusText = '共 ' + fullList.length + ' 条';
    if (searchFilter && list.length !== fullList.length) {
      statusText += '（筛选: ' + list.length + '）';
    }
    utils.setStatus('gather-status', statusText);

    if (list.length === 0) {
      utils.setEmpty('gather-results', '没有匹配的结果');
      return;
    }

    var html = '';
    list.forEach(function (item) {
      html += '<div class="gather-item">';
      html += '<span class="gather-item-type type-' + (item.color || item.type || 'gray') + '">';
      html += utils.escapeHtml(item.name || item.type || '');
      html += '</span>';
      html += '<span class="gather-item-value" title="' + utils.escapeHtml(item.value) + '">';
      html += utils.escapeHtml(item.value);
      html += '</span>';
      html +=
        '<button class="gather-item-copy" data-copy="' +
        utils.escapeHtml(item.value) +
        '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.gather-item-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        utils.copyAndToast(btn.dataset.copy);
      });
    });
  }

  function switchGatherTab(tab) {
    currentGatherTab = tab;
    searchFilter = '';
    var searchInput = utils ? utils.get('gather-search') : null;
    if (searchInput) searchInput.value = '';
    document.querySelectorAll('.gather-tab').forEach(function (b) {
      b.classList.toggle('active', b.dataset.gather === tab);
    });
    renderGatherTab();
  }

  function applySearchFilter(text) {
    searchFilter = text;
    renderGatherTab();
  }

  function renderSubTabs() {
    var container = utils ? utils.get('gather-sub-tabs') : null;
    if (!container) return;

    var groups = [DOM_GROUP];
    if (gatherData['JS API'] && gatherData['JS API'].length > 0) groups.push('JS API');
    groups = groups.concat(getHaeRules() ? getHaeRules().getGroups(loadedRules) : []);
    var html = '';
    groups.forEach(function (group, i) {
      var active = i === 0 ? ' active' : '';
      var label = group === DOM_GROUP ? 'DOM分析' : group;
      var count = (gatherData[group] || []).length;
      html +=
        '<button class="gather-tab' +
        active +
        '" data-gather="' +
        group +
        '">' +
        label +
        (count > 0 ? ' <span class="gather-tab-count">' + count + '</span>' : '') +
        '</button>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.gather-tab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        switchGatherTab(btn.dataset.gather);
      });
    });

    currentGatherTab = DOM_GROUP;
    updateSearchVisibility();
  }

  function init() {
    var haeRules = getHaeRules();
    if (!haeRules) return;

    haeRules.loadRules(function (rules) {
      loadedRules = rules;
      renderSubTabs();
    });
  }

  var API_PATTERNS = [
    {
      regex:
        /(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch|\.request)\s*\(\s*["']([^"']+)["']/gi,
      label: 'fetch',
    },
    {
      regex: /(?:url|endpoint|api|baseUrl|baseURL|apiUrl|apiURL)["']?\s*[:=]\s*["']([^"']+)["']/gi,
      label: 'config',
    },
    { regex: /["']\/api\/[a-zA-Z0-9_\-./{}:?&=]*["']/gi, label: 'api-path' },
    { regex: /["']\/v\d+(?:\/[a-zA-Z0-9_\-./{}:?&=]*)*["']/gi, label: 'versioned' },
    { regex: /path:\s*["']([^"']+)["']/gi, label: 'route-path' },
    { regex: /@(?:Get|Post|Put|Delete|Patch|Route)\s*\(\s*["']([^"']+)["']/gi, label: 'decorator' },
    {
      regex: /["']((?:\/[a-zA-Z0-9_-]+){2,}(?:\/[a-zA-Z0-9_-{}:?&=]*)*)["']/g,
      label: 'path',
    },
  ];

  function isValidApiPath(path) {
    if (!path || path.length < 3 || path.length > 200) return false;
    if (
      /^(https?:)?\/\/([^/]+\.)?google|facebook|github\.com|jquery|analytics|doubleclick|googletagmanager|fontawesome|bootstrapcdn|unpkg\.com|cdn\./i.test(
        path
      )
    )
      return false;
    if (/^\.\//.test(path) && !/api|route|endpoint|action/i.test(path)) return false;
    if (/^(\/\/)/.test(path) && /\.js(\?|$)/i.test(path)) return false;
    if (/\.(js|css|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico)(\?|$)/i.test(path)) return false;
    return true;
  }

  async function extractApiFromJsFiles(scriptSrcs, pageUrl) {
    var seen = {};
    var endpoints = [];
    var pageOrigin = '';
    try {
      pageOrigin = new URL(pageUrl).origin;
    } catch {}

    var filesToFetch = scriptSrcs.filter(function (src) {
      try {
        var u = new URL(src, pageUrl);
        return u.origin === pageOrigin;
      } catch {
        return false;
      }
    });
    filesToFetch = filesToFetch.slice(0, 15);

    var fetchPromises = filesToFetch.map(function (src) {
      return utils.fetchUrl({ url: src, tailOnly: false, timeout: 12000 });
    });
    var fetchResults = await Promise.all(fetchPromises);

    var jsContents = fetchResults.map(function (r) {
      return r && r.success ? r.data : null;
    });

    jsContents.forEach(function (content, idx) {
      if (!content) return;
      if (content.length > 500000) content = content.substring(0, 500000);

      API_PATTERNS.forEach(function (pattern) {
        var regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        var match;
        while ((match = regex.exec(content)) !== null) {
          var path = match[1];
          if (!path || !isValidApiPath(path)) continue;

          var cleanPath = path;
          if (cleanPath.startsWith('//')) {
            try {
              cleanPath = new URL('https:' + cleanPath).pathname;
            } catch {}
          } else if (cleanPath.startsWith('http')) {
            try {
              cleanPath = new URL(cleanPath).pathname;
            } catch {}
          }

          if (!cleanPath || cleanPath.length < 2) continue;

          var key = cleanPath.toLowerCase();
          if (seen[key]) continue;
          seen[key] = true;

          endpoints.push({
            name: pattern.label,
            value: cleanPath,
            color: 'api',
          });
        }
      });
    });

    return endpoints;
  }

  async function gatherInfo() {
    utils.setStatus('gather-status', '正在收集...');

    try {
      var tab = await utils.getActiveTab();
      if (!tab || !tab.url) {
        utils.setStatus('gather-status', '无法获取当前页面');
        return;
      }

      var rulesForInjection = loadedRules.filter(function (g) {
        return (
          g.rules &&
          g.rules.some(function (r) {
            return r.loaded;
          })
        );
      });

      var results = await utils.execInTab(
        tab.id,
        function (haeRules, domGroup) {
          var pageUrl = location.href;
          var rawHtml = document.documentElement.outerHTML;
          var truncated = rawHtml.length > 500000;
          var pageHtml = truncated ? rawHtml.substring(0, 500000) : rawHtml;
          var collected = {};
          collected._meta = { truncated: truncated, totalSize: rawHtml.length };

          var seenAll = {};
          function add(group, name, value, color) {
            if (!value) return;
            var key = group + '::' + value;
            if (seenAll[key]) return;
            seenAll[key] = true;
            if (!collected[group]) collected[group] = [];
            collected[group].push({ name: name || group, value: value, color: color || 'gray' });
          }

          // DOM Analysis
          var domSeen = {};
          var scriptSrcs = [];
          function addDom(type, value) {
            if (!value || domSeen[type + '::' + value]) return;
            domSeen[type + '::' + value] = true;
            add(domGroup, type, value, type);
          }

          document.querySelectorAll('form').forEach(function (form) {
            var action = form.getAttribute('action') || '';
            var method = (form.method || 'GET').toUpperCase();
            if (action) {
              try {
                addDom('form', new URL(action, pageUrl).href + ' [' + method + ']');
              } catch (e) {}
            }
          });

          document.querySelectorAll('script[src]').forEach(function (s) {
            if (s.src) {
              addDom('script', s.src);
              if (/^https?:\/\//i.test(s.src)) scriptSrcs.push(s.src);
            }
          });

          document.querySelectorAll('link[href]').forEach(function (l) {
            if (l.href && /\.(json|xml|yaml)$/i.test(l.href)) addDom('data', l.href);
          });

          document.querySelectorAll('[href]').forEach(function (el) {
            try {
              var url = new URL(el.href, pageUrl);
              if (url.hostname !== location.hostname) addDom('domain', url.hostname);
            } catch (e) {}
          });

          document.querySelectorAll('[src]').forEach(function (el) {
            try {
              var url = new URL(el.src, pageUrl);
              if (url.hostname !== location.hostname) addDom('domain', url.hostname);
            } catch (e) {}
          });

          document.querySelectorAll('iframe[src],frame[src]').forEach(function (el) {
            try {
              var url = new URL(el.src, pageUrl);
              addDom('frame', url.hostname);
            } catch (e) {}
          });

          document.querySelectorAll('meta[name="generator"]').forEach(function (m) {
            if (m.content) addDom('meta', m.content);
          });

          // Cookies
          try {
            document.cookie.split(';').forEach(function (c) {
              var name = c.split('=')[0].trim();
              if (name) addDom('cookie', name);
            });
          } catch (e) {}

          // localStorage
          try {
            for (var i = 0; i < localStorage.length; i++) {
              var key = localStorage.key(i);
              if (/token|key|secret|session|auth|user|admin/i.test(key)) {
                addDom('storage', key);
              }
            }
          } catch (e) {}

          // Cloud hints
          var cloudPatterns = [
            { p: /aws\.amazon/i, l: 'AWS' },
            { p: /azure\.microsoft/i, l: 'Azure' },
            { p: /googleapis\.com/i, l: 'GCP' },
            { p: /aliyuncs\.com/i, l: 'Aliyun' },
            { p: /tencentcloud/i, l: 'Tencent' },
            { p: /cloudflare/i, l: 'Cloudflare' },
            { p: /fastly/i, l: 'Fastly' },
            { p: /cdn\.|c\.cloudfront\.net/i, l: 'CDN' },
          ];
          cloudPatterns.forEach(function (c) {
            if (c.p.test(pageHtml)) addDom('cloud', c.l);
          });

          // HTTP Security Headers (from meta http-equiv)
          document.querySelectorAll('meta[http-equiv]').forEach(function (m) {
            var header = m.getAttribute('http-equiv');
            var content = m.getAttribute('content');
            if (header && content) {
              addDom('header', header + ': ' + content);
            }
          });

          // HaE rules matching
          var pageScopes = ['response body', 'response', 'request', 'header', 'any'];
          haeRules.forEach(function (group) {
            var groupResults = [];
            (group.rules || []).forEach(function (rule) {
              if (!rule.loaded || !rule.f_regex) return;
              if (pageScopes.indexOf(rule.scope) === -1) return;

              try {
                var flags = rule.sensitive ? 'g' : 'gi';
                var regex = new RegExp(rule.f_regex, flags);
                var match;
                var ruleSeen = {};

                while ((match = regex.exec(pageHtml)) !== null) {
                  var captures = [];
                  for (var ci = 1; ci < match.length; ci++) captures.push(match[ci] || '');

                  var value = rule.format || '{0}';
                  for (var fi = 0; fi < captures.length; fi++) {
                    while (value.indexOf('{' + fi + '}') !== -1) {
                      value = value.replace('{' + fi + '}', captures[fi] || '');
                    }
                  }
                  if (!value || value.trim() === '') continue;

                  if (rule.s_regex && rule.s_regex.trim() !== '') {
                    try {
                      var sFlags = rule.sensitive ? '' : 'i';
                      if (!new RegExp(rule.s_regex, sFlags).test(match[0])) continue;
                    } catch (e) {}
                  }

                  var rKey = rule.name + '::' + value;
                  if (ruleSeen[rKey]) continue;
                  ruleSeen[rKey] = true;

                  groupResults.push({
                    name: rule.name,
                    value: value,
                    color: rule.color || 'gray',
                  });
                }
              } catch (e) {}
            });

            if (groupResults.length > 0) {
              collected[group.group] = groupResults;
            }
          });

          collected._scriptSrcs = scriptSrcs;
          return collected;
        },
        { args: [rulesForInjection, DOM_GROUP], world: 'ISOLATED' }
      );

      var extracted = utils.execResult(results);
      if (extracted) {
        gatherData = extracted;
        var meta = gatherData._meta;
        delete gatherData._meta;
        var scriptSrcs = gatherData._scriptSrcs || [];
        delete gatherData._scriptSrcs;

        // Fetch external JS files and extract API endpoints
        if (scriptSrcs.length > 0) {
          utils.setStatus('gather-status', '正在分析 JS 文件（' + scriptSrcs.length + ' 个）...');
          var apiEndpoints = await extractApiFromJsFiles(scriptSrcs, tab.url);
          if (apiEndpoints.length > 0) {
            gatherData['JS API'] = apiEndpoints;
          }
        }

        renderSubTabs();
        renderGatherTab();

        var total = Object.values(gatherData).reduce(function (s, a) {
          return s + (Array.isArray(a) ? a.length : 0);
        }, 0);
        var statusText = '收集完成，共 ' + total + ' 条';
        if (meta && meta.truncated) {
          statusText += '（HTML 已截断至 500KB/' + (meta.totalSize / 1024).toFixed(0) + 'KB）';
        }
        utils.setStatus('gather-status', statusText);
        utils.showToast(
          meta && meta.truncated ? '收集完成（页面过大，部分内容被截断）' : '收集完成',
          meta && meta.truncated ? 'warning' : 'success'
        );

        var groups = [DOM_GROUP].concat(
          gatherData['JS API'] ? ['JS API'] : [],
          getHaeRules() ? getHaeRules().getGroups(loadedRules) : []
        );
        chrome.storage.local.set({
          gatherData: gatherData,
          gatherDataUrl: tab.url,
          gatherDataTabs: groups,
        });
      } else {
        utils.setStatus('gather-status', '收集失败');
      }
    } catch (e) {
      utils.setStatus('gather-status', '收集失败: ' + e.message);
      utils.showToast('收集失败', 'error');
    }
  }

  function restoreData(url) {
    chrome.storage.local.get([STORAGE_KEY, URL_KEY, TABS_KEY], function (result) {
      if (result[STORAGE_KEY] && result[URL_KEY] === url) {
        gatherData = result[STORAGE_KEY];
        if (result[TABS_KEY]) {
          loadedRules =
            loadedRules.length > 0
              ? loadedRules
              : getHaeRules()
                ? getHaeRules().getDefaultRules()
                : [];
          var allGroups = [DOM_GROUP].concat(
            getHaeRules() ? getHaeRules().getGroups(loadedRules) : []
          );
          renderSubTabs();
        }
        var firstGroup = Object.keys(gatherData)[0] || DOM_GROUP;
        currentGatherTab = firstGroup;
        renderGatherTab();

        var total = Object.values(gatherData).reduce(function (s, a) {
          return s + (Array.isArray(a) ? a.length : 0);
        }, 0);
        utils.setStatus('gather-status', '已恢复，共 ' + total + ' 条');
      }
    });
  }

  function exportAllData() {
    var rows = [];
    Object.keys(gatherData).forEach(function (group) {
      var items = gatherData[group];
      if (!Array.isArray(items)) return;
      items.forEach(function (item) {
        rows.push([group, item.name, item.value]);
      });
    });
    if (rows.length === 0) {
      utils.showToast('没有数据可导出', 'warning');
      return;
    }
    utils.buildCsv(['Group', 'Type', 'Value'], rows, 'vulnkit-gather-' + Date.now() + '.csv');
  }

  function copyAllData() {
    var list = gatherData[currentGatherTab] || [];
    if (list.length === 0) {
      utils.showToast('当前分组没有数据', 'warning');
      return;
    }
    var text = list
      .map(function (item) {
        return item.value;
      })
      .join('\n');
    utils.copyAndToast(text, '已复制 ' + list.length + ' 条数据');
  }

  function getActiveRules() {
    return loadedRules;
  }

  function updateRules(rules) {
    loadedRules = rules;
    if (getHaeRules()) getHaeRules().saveRules(rules);
    renderSubTabs();
  }

  return {
    init: init,
    gatherInfo: gatherInfo,
    restoreData: restoreData,
    applySearchFilter: applySearchFilter,
    exportAllData: exportAllData,
    copyAllData: copyAllData,
    getActiveRules: getActiveRules,
    updateRules: updateRules,
    get gatherData() {
      return gatherData;
    },
    set gatherData(v) {
      gatherData = v;
    },
    get currentGatherTab() {
      return currentGatherTab;
    },
    set currentGatherTab(v) {
      currentGatherTab = v;
    },
  };
})();
