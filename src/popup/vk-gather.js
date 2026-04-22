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

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  function getHaeRules() {
    return window.VulnKitHaeRules || null;
  }

  function renderGatherTab() {
    var utils = getUtils();
    var list = gatherData[currentGatherTab] || [];
    var container = utils.get('gather-results');
    var statusEl = utils.get('gather-status');

    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state">点击「收集当前页面」开始</div>';
      statusEl.textContent = '';
      return;
    }

    statusEl.textContent = '共 ' + list.length + ' 条';
    var html = '';
    list.forEach(function (item) {
      html += '<div class="gather-item">';
      html += '<span class="gather-item-type type-' + (item.color || item.type || 'gray') + '">';
      html += utils.escapeHtml(item.name || item.type || '');
      html += '</span>';
      html += '<span class="gather-item-value" title="' + utils.escapeHtml(item.value) + '">';
      html += utils.escapeHtml(item.value);
      html += '</span>';
      html += '<button class="gather-item-copy" data-copy="' + utils.escapeHtml(item.value) + '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.gather-item-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        utils.copyText(btn.dataset.copy);
        utils.showToast('已复制', 'success');
      });
    });
  }

  function switchGatherTab(tab) {
    currentGatherTab = tab;
    document.querySelectorAll('.gather-tab').forEach(function (b) {
      b.classList.toggle('active', b.dataset.gather === tab);
    });
    renderGatherTab();
  }

  function renderSubTabs() {
    var container = document.getElementById('gather-sub-tabs');
    if (!container) return;

    var groups = [DOM_GROUP].concat(getHaeRules().getGroups(loadedRules));
    var html = '';
    groups.forEach(function (group, i) {
      var active = i === 0 ? ' active' : '';
      var label = group === DOM_GROUP ? 'DOM分析' : group;
      html += '<button class="gather-tab' + active + '" data-gather="' + group + '">' + label + '</button>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.gather-tab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        switchGatherTab(btn.dataset.gather);
      });
    });

    currentGatherTab = DOM_GROUP;
  }

  function init() {
    var haeRules = getHaeRules();
    if (!haeRules) return;

    haeRules.loadRules(function (rules) {
      loadedRules = rules;
      renderSubTabs();
    });
  }

  async function gatherInfo() {
    var utils = getUtils();
    var statusEl = utils.get('gather-status');
    statusEl.textContent = '正在收集...';

    try {
      var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      var tab = tabs[0];
      if (!tab || !tab.url) {
        statusEl.textContent = '无法获取当前页面';
        return;
      }

      var rulesForInjection = loadedRules.filter(function (g) {
        return g.rules && g.rules.some(function (r) { return r.loaded; });
      });

      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: function (haeRules, domGroup) {
          var pageUrl = location.href;
          var pageHtml = document.documentElement.outerHTML;
          var collected = {};

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
            if (s.src) addDom('script', s.src);
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
            { p: /cdn\.|c\.cloudfront\.net/i, l: 'CDN' }
          ];
          cloudPatterns.forEach(function (c) {
            if (c.p.test(pageHtml)) addDom('cloud', c.l);
          });

          // HaE rules matching
          var pageScopes = ['response body', 'response', 'any'];
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

                  var value = (rule.format || '{0}');
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
                    color: rule.color || 'gray'
                  });
                }
              } catch (e) {}
            });

            if (groupResults.length > 0) {
              collected[group.group] = groupResults;
            }
          });

          return collected;
        },
        args: [rulesForInjection, DOM_GROUP]
      });

      if (results && results[0] && results[0].result) {
        gatherData = results[0].result;
        renderGatherTab();

        var total = Object.values(gatherData).reduce(function (s, a) { return s + a.length; }, 0);
        statusEl.textContent = '收集完成，共 ' + total + ' 条';
        utils.showToast('收集完成', 'success');

        var groups = [DOM_GROUP].concat(getHaeRules().getGroups(loadedRules));
        chrome.storage.local.set({
          gatherData: gatherData,
          gatherDataUrl: tab.url,
          gatherDataTabs: groups
        });
      } else {
        statusEl.textContent = '收集失败';
      }
    } catch (e) {
      statusEl.textContent = '收集失败: ' + e.message;
      utils.showToast('收集失败', 'error');
    }
  }

  function restoreData(url) {
    chrome.storage.local.get([STORAGE_KEY, URL_KEY, TABS_KEY], function (result) {
      if (result[STORAGE_KEY] && result[URL_KEY] === url) {
        gatherData = result[STORAGE_KEY];
        if (result[TABS_KEY]) {
          loadedRules = loadedRules.length > 0 ? loadedRules : (getHaeRules() ? getHaeRules().getDefaultRules() : []);
          var allGroups = [DOM_GROUP].concat(getHaeRules().getGroups(loadedRules));
          renderSubTabs();
        }
        var firstGroup = Object.keys(gatherData)[0] || DOM_GROUP;
        currentGatherTab = firstGroup;
        renderGatherTab();

        var utils = getUtils();
        var statusEl = utils.get('gather-status');
        var total = Object.values(gatherData).reduce(function (s, a) { return s + a.length; }, 0);
        statusEl.textContent = '已恢复，共 ' + total + ' 条';
      }
    });
  }

  function getActiveRules() {
    return loadedRules;
  }

  function updateRules(rules) {
    loadedRules = rules;
    getHaeRules().saveRules(rules);
    renderSubTabs();
  }

  return {
    init: init,
    renderGatherTab: renderGatherTab,
    switchGatherTab: switchGatherTab,
    renderSubTabs: renderSubTabs,
    gatherInfo: gatherInfo,
    restoreData: restoreData,
    getActiveRules: getActiveRules,
    updateRules: updateRules,
    get gatherData() { return gatherData; },
    set gatherData(v) { gatherData = v; },
    get currentGatherTab() { return currentGatherTab; },
    set currentGatherTab(v) { currentGatherTab = v; },
    DOM_GROUP: DOM_GROUP
  };
})();
