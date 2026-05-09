// 灵眸 - Info Gather (HaE Rules Engine)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import * as haeRules from './vk-hae-rules.js';
import { LEAK_SCAN_GROUP, runDeepLeakScan } from './vk-leakscan-scanner.js';

const DOM_GROUP = 'DOM Analysis';
const STORAGE_KEY = 'gatherData';
const URL_KEY = 'gatherDataUrl';
const TABS_KEY = 'gatherDataTabs';

let gatherData = {};
let currentGatherTab = DOM_GROUP;
let loadedRules = [];
let searchFilter = '';
let gatherAbortFlag = false;
let gatherTimerInterval = null;
let gatherStartTime = 0;

function getHaeRules() {
  return haeRules || null;
}

function getFilteredList() {
  let list = gatherData[currentGatherTab] || [];
  if (!searchFilter) return list;
  const lower = searchFilter.toLowerCase();
  var crossGroup = [];
  Object.keys(gatherData).forEach(function (group) {
    var items = gatherData[group];
    if (!Array.isArray(items)) return;
    items.forEach(function (item) {
      if (
        (item.value && item.value.toLowerCase().indexOf(lower) !== -1) ||
        (item.name && item.name.toLowerCase().indexOf(lower) !== -1)
      ) {
        crossGroup.push(Object.assign({}, item, { _matchedGroup: group }));
      }
    });
  });
  return crossGroup;
}

function updateSearchVisibility() {
  const searchInput = utils ? utils.get('gather-search') : null;
  if (!searchInput) return;
  const hasData = Object.keys(gatherData).some(function (k) {
    return Array.isArray(gatherData[k]) && gatherData[k].length > 0;
  });
  searchInput.style.display = hasData ? '' : 'none';
}

function renderGatherTab() {
  let list = getFilteredList();
  const container = utils.get('gather-results');
  if (!container || !utils.get('gather-status')) return;

  updateSearchVisibility();

  const fullList = gatherData[currentGatherTab] || [];
  if (fullList.length === 0) {
    if (currentGatherTab === LEAK_SCAN_GROUP && gatherData[LEAK_SCAN_GROUP]) {
      utils.get('gather-results').innerHTML =
        '<div class="gather-empty-state"><div class="gather-empty-icon">&#9989;</div><div class="gather-empty-text">未发现敏感信息泄漏</div></div>';
      utils.setStatus('gather-status', '深度扫描完成');
      return;
    }
    utils.get('gather-results').innerHTML =
      '<div class="gather-empty-state"><div class="gather-empty-icon">&#128269;</div><div class="gather-empty-text">点击「收集当前页面」开始</div></div>';
    utils.setStatus('gather-status', '');
    return;
  }

  let statusText = searchFilter ? `全局搜索: ${list.length} 条匹配` : `共 ${fullList.length} 条`;
  if (searchFilter && list.length !== fullList.length) {
    statusText += `（筛选: ${list.length}）`;
  }
  utils.setStatus('gather-status', statusText);

  if (list.length === 0) {
    utils.get('gather-results').innerHTML =
      '<div class="gather-empty-state"><div class="gather-empty-icon">&#128270;</div><div class="gather-empty-text">没有匹配的结果</div></div>';
    return;
  }

  let html = '';
  var lastGroup = '';
  list.forEach(function (item) {
    if (searchFilter && item._matchedGroup && item._matchedGroup !== lastGroup) {
      lastGroup = item._matchedGroup;
      html += `<div class="gather-cross-group-label">${utils.escapeHtml(lastGroup)}</div>`;
    }
    html += `<div class="gather-item">
        <span class="gather-item-type type-${item.color || item.type || 'gray'}">${utils.escapeHtml(item.name || item.type || '')}</span>
        <span class="gather-item-value" title="${utils.escapeHtml(item.value)}">${utils.escapeHtml(item.value)}</span>
        <button class="gather-item-copy" data-copy="${utils.escapeHtml(item.value)}">复制</button>
      </div>`;
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
  const searchInput = utils ? utils.get('gather-search') : null;
  if (searchInput) searchInput.value = '';
  document.querySelectorAll('.gather-tab').forEach(function (b) {
    b.classList.toggle('active', b.dataset.gather === tab);
  });
  renderGatherTab();
}

function countAll() {
  return Object.values(gatherData).reduce(function (s, a) {
    return s + (Array.isArray(a) ? a.length : 0);
  }, 0);
}

function buildGroups() {
  return [DOM_GROUP].concat(
    gatherData['JS API'] ? ['JS API'] : [],
    gatherData['JS Sensitive Info'] ? ['JS Sensitive Info'] : [],
    gatherData[LEAK_SCAN_GROUP] ? [LEAK_SCAN_GROUP] : [],
    getHaeRules() ? getHaeRules().getGroups(loadedRules) : []
  );
}

function applySearchFilter(text) {
  searchFilter = text;
  renderGatherTab();
}

function renderSubTabs() {
  const container = utils ? utils.get('gather-sub-tabs') : null;
  if (!container) return;

  const groups = buildGroups();
  let html = '';
  groups.forEach(function (group, i) {
    const active = i === 0 ? ' active' : '';
    const label = group === DOM_GROUP ? 'DOM分析' : group;
    const count = (gatherData[group] || []).length;
    html += `<button class="gather-tab${active}" data-gather="${group}">${label}${count > 0 ? ` <span class="gather-tab-count">${count}</span>` : ''}</button>`;
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
  const haeRulesMod = getHaeRules();
  if (!haeRulesMod) return;

  haeRulesMod.loadRules(function (rules) {
    loadedRules = rules;
    renderSubTabs();
  });
}

function gatherStartTimer() {
  gatherStopTimer();
  gatherStartTime = Date.now();
  gatherTimerInterval = setInterval(function () {
    let el = utils.get('gather-status');
    if (el) {
      const base = el.textContent.replace(/\s*\(\d+s\)$/, '');
      el.textContent = `${base} (${Math.floor((Date.now() - gatherStartTime) / 1000)}s)`;
    }
  }, 1000);
}

function gatherStopTimer() {
  if (gatherTimerInterval) {
    clearInterval(gatherTimerInterval);
    gatherTimerInterval = null;
  }
}

function gatherElapsed() {
  return Math.floor((Date.now() - gatherStartTime) / 1000);
}

const SENSITIVE_PATTERNS = [
  { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key', color: 'red' },
  {
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    label: 'Private Key',
    color: 'red',
  },
  {
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}/g,
    label: 'JWT Token',
    color: 'yellow',
  },
  {
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    label: 'IP Address',
    color: 'cyan',
  },
  {
    regex: /(?:mongodb|mysql|postgres|redis):\/\/[^\s'"]+/gi,
    label: 'DB Connection',
    color: 'red',
  },
  {
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi,
    label: 'Hardcoded Password',
    color: 'red',
  },
  { regex: /AIza[0-9A-Za-z_-]{35}/g, label: 'Google API Key', color: 'yellow' },
  { regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, label: 'Slack Token', color: 'red' },
  { regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, label: 'GitHub Token', color: 'red' },
  {
    regex: /["'](api[_-]?key|apikey|api[_-]?secret)["']\s*[:=]\s*["']([^"']{8,})["']/gi,
    label: 'API Key',
    color: 'yellow',
    captureIdx: 2,
  },
];

const API_PATTERNS = [
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
    /^(https?:)?\/\/([^/]+\.)?(?:google|facebook|github\.com|jquery|analytics|doubleclick|googletagmanager|fontawesome|bootstrapcdn|unpkg\.com|cdn\.)/i.test(
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
  const seen = {};
  const endpoints = [];
  const sensitiveItems = [];
  const sensitiveSeen = {};
  let pageOrigin = '';
  try {
    pageOrigin = new URL(pageUrl).origin;
  } catch (e) {
    console.debug('URL parse failed in gather', e);
  }

  let filesToFetch = scriptSrcs.filter(function (src) {
    try {
      const u = new URL(src, pageUrl);
      return u.origin === pageOrigin;
    } catch {
      return false;
    }
  });
  filesToFetch = filesToFetch.slice(0, 50);

  if (gatherAbortFlag) return { endpoints: endpoints, sensitiveItems: sensitiveItems };

  const fetchPromises = filesToFetch.map(function (src) {
    return utils.fetchUrl({ url: src, tailOnly: false, timeout: 12000 });
  });
  const fetchResults = await Promise.all(fetchPromises);

  const jsContents = fetchResults.map(function (r) {
    return r && r.success ? r.data : null;
  });

  jsContents.forEach(function (content) {
    if (!content) return;
    if (content.length > 500000) content = content.substring(0, 500000);

    API_PATTERNS.forEach(function (pattern) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const path = match[1];
        if (!path || !isValidApiPath(path)) continue;

        let cleanPath = path;
        if (cleanPath.startsWith('//')) {
          try {
            cleanPath = new URL(`https:${cleanPath}`).pathname;
          } catch (e) {
            console.debug('URL parse failed for double-slash path', e);
          }
        } else if (cleanPath.startsWith('http')) {
          try {
            cleanPath = new URL(cleanPath).pathname;
          } catch (e) {
            console.debug('URL parse failed for http path', e);
          }
        }

        if (!cleanPath || cleanPath.length < 2) continue;

        const key = cleanPath.toLowerCase();
        if (seen[key]) continue;
        seen[key] = true;

        endpoints.push({
          name: pattern.label,
          value: cleanPath,
          color: 'api',
        });
      }
    });

    SENSITIVE_PATTERNS.forEach(function (pattern) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        let value = pattern.captureIdx ? match[pattern.captureIdx] : match[0];
        if (!value) continue;
        const sKey = `${pattern.label}::${value}`;
        if (sensitiveSeen[sKey]) continue;
        sensitiveSeen[sKey] = true;
        sensitiveItems.push({
          name: pattern.label,
          value: value,
          color: pattern.color || 'gray',
        });
      }
    });
  });

  return { endpoints: endpoints, sensitiveItems: sensitiveItems };
}

async function gatherInfo() {
  if (gatherAbortFlag === false) {
    const btn = utils.get('gather-btn');
    if (btn && btn.classList.contains('btn-danger')) {
      gatherAbortFlag = true;
      return;
    }
  }

  utils.setStatus('gather-status', '正在收集...');
  gatherAbortFlag = false;
  gatherStartTimer();
  const gatherBtn = utils.get('gather-btn');
  if (gatherBtn) {
    gatherBtn.textContent = '停止收集';
    gatherBtn.classList.remove('btn-primary');
    gatherBtn.classList.add('btn-danger');
  }

  try {
    const tab = await utils.getActiveTab();
    if (!tab || !tab.url) {
      utils.setStatus('gather-status', '无法获取当前页面');
      return;
    }

    if (gatherAbortFlag) {
      utils.setStatus('gather-status', '已取消');
      return;
    }

    const rulesForInjection = loadedRules.filter(function (g) {
      return (
        g.rules &&
        g.rules.some(function (r) {
          return r.loaded;
        })
      );
    });

    const extracted = await utils.execInTabData(
      tab.id,
      function (haeRules, domGroup) {
        const pageUrl = location.href;
        const rawHtml = document.documentElement.outerHTML;
        const truncated = rawHtml.length > 500000;
        const pageHtml = truncated ? rawHtml.substring(0, 500000) : rawHtml;
        const collected = {};
        collected._meta = { truncated: truncated, totalSize: rawHtml.length };

        const seenAll = {};
        function add(group, name, value, color) {
          if (!value) return;
          const key = `${group}::${value}`;
          if (seenAll[key]) return;
          seenAll[key] = true;
          if (!collected[group]) collected[group] = [];
          collected[group].push({ name: name || group, value: value, color: color || 'gray' });
        }

        // DOM Analysis
        let scriptSrcs = [];
        function addDom(type, value) {
          add(domGroup, type, value, type);
        }

        document.querySelectorAll('form').forEach(function (form) {
          const action = form.getAttribute('action') || '';
          const method = (form.method || 'GET').toUpperCase();
          if (action) {
            try {
              addDom('form', `${new URL(action, pageUrl).href} [${method}]`);
            } catch (e) {
              /* ignore */
            }
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
            const url = new URL(el.href, pageUrl);
            if (url.hostname !== location.hostname) addDom('domain', url.hostname);
          } catch (e) {
            /* ignore */
          }
        });

        document.querySelectorAll('[src]').forEach(function (el) {
          try {
            const url = new URL(el.src, pageUrl);
            if (url.hostname !== location.hostname) addDom('domain', url.hostname);
          } catch (e) {
            /* ignore */
          }
        });

        document.querySelectorAll('iframe[src],frame[src]').forEach(function (el) {
          try {
            const url = new URL(el.src, pageUrl);
            addDom('frame', url.hostname);
          } catch (e) {
            /* ignore */
          }
        });

        document.querySelectorAll('meta[name="generator"]').forEach(function (m) {
          if (m.content) addDom('meta', m.content);
        });

        // Cookies
        try {
          document.cookie.split(';').forEach(function (c) {
            let name = c.split('=')[0].trim();
            if (name) addDom('cookie', name);
          });
        } catch (e) {
          /* ignore */
        }

        // localStorage
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (/token|key|secret|session|auth|user|admin/i.test(key)) {
              addDom('storage', key);
            }
          }
        } catch (e) {
          /* ignore */
        }

        // Cloud hints
        const cloudPatterns = [
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
          const header = m.getAttribute('http-equiv');
          let content = m.getAttribute('content');
          if (header && content) {
            addDom('header', `${header}: ${content}`);
          }
        });

        // HaE rules matching
        const pageScopes = ['response body', 'response', 'request', 'header', 'any'];
        haeRules.forEach(function (group) {
          const groupResults = [];
          (group.rules || []).forEach(function (rule) {
            if (!rule.loaded || !rule.f_regex) return;
            if (pageScopes.indexOf(rule.scope) === -1) return;

            try {
              const flags = rule.sensitive ? 'g' : 'gi';
              const regex = new RegExp(rule.f_regex, flags);
              let match;
              const ruleSeen = {};

              while ((match = regex.exec(pageHtml)) !== null) {
                const captures = [];
                for (let ci = 1; ci < match.length; ci++) captures.push(match[ci] || '');

                let value = rule.format || '{0}';
                for (let fi = 0; fi < captures.length; fi++) {
                  while (value.indexOf(`{${fi}}`) !== -1) {
                    value = value.replace(`{${fi}}`, captures[fi] || '');
                  }
                }
                if (!value || value.trim() === '') continue;

                if (rule.s_regex && rule.s_regex.trim() !== '') {
                  try {
                    const sFlags = rule.sensitive ? '' : 'i';
                    if (!new RegExp(rule.s_regex, sFlags).test(match[0])) continue;
                  } catch (e) {
                    /* ignore */
                  }
                }

                const rKey = `${rule.name}::${value}`;
                if (ruleSeen[rKey]) continue;
                ruleSeen[rKey] = true;

                groupResults.push({
                  name: rule.name,
                  value: value,
                  color: rule.color || 'gray',
                });
              }
            } catch (e) {
              /* ignore */
            }
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

    if (extracted) {
      gatherData = extracted;
      let meta = gatherData._meta;
      delete gatherData._meta;
      let scriptSrcs = gatherData._scriptSrcs || [];
      delete gatherData._scriptSrcs;

      // Fetch external JS files and extract API endpoints + sensitive info
      if (scriptSrcs.length > 0 && !gatherAbortFlag) {
        utils.setStatus('gather-status', `正在分析 JS 文件（${scriptSrcs.length} 个）...`);
        const jsResult = await extractApiFromJsFiles(scriptSrcs, tab.url);
        if (jsResult.endpoints.length > 0) {
          gatherData['JS API'] = jsResult.endpoints;
        }
        if (jsResult.sensitiveItems.length > 0) {
          gatherData['JS Sensitive Info'] = jsResult.sensitiveItems;
        }
      }

      if (!gatherAbortFlag) {
        utils.setStatus('gather-status', '深度泄漏扫描中...');
        var leakItems = await runDeepLeakScan(gatherData, tab.id);
        gatherData[LEAK_SCAN_GROUP] = leakItems;
      }

      renderSubTabs();
      renderGatherTab();

      let statusText = `收集完成，共 ${countAll()} 条（${gatherElapsed()}s）`;
      if (meta && meta.truncated) {
        const truncatedKb = (500).toFixed(0);
        const totalKb = (meta.totalSize / 1024).toFixed(0);
        const warningEl = utils.get('gather-status');
        if (warningEl) {
          warningEl.innerHTML =
            '<span class="gather-truncation-warn" title="HTML 体积过大，仅分析了前 500KB，可能导致部分规则匹配遗漏">' +
            '⚠ 页面过大，HTML 已截断至 ' +
            truncatedKb +
            'KB/' +
            totalKb +
            'KB，部分内容可能未被分析</span>' +
            ' — 共 ' +
            countAll() +
            ' 条（' +
            gatherElapsed() +
            's）';
          warningEl.style.display = '';
        }
      } else {
        utils.setStatus('gather-status', statusText);
      }
      utils.showToast(
        meta && meta.truncated ? '收集完成（页面过大，部分内容被截断）' : '收集完成',
        meta && meta.truncated ? 'warning' : 'success'
      );

      const groups = buildGroups();
      if (utils.getSetting('storeHistory', true)) {
        chrome.storage.local.set({
          gatherData: gatherData,
          gatherDataUrl: tab.url,
          gatherDataTabs: groups,
          gatherDataTime: Date.now(),
        });
      }
    } else {
      utils.setStatus('gather-status', '收集失败');
    }
  } catch (e) {
    utils.setStatus('gather-status', `收集失败: ${e.message}`);
    utils.showToast('收集失败', 'error');
  } finally {
    gatherStopTimer();
    const gatherBtn = utils.get('gather-btn');
    if (gatherBtn) {
      gatherBtn.textContent = '收集当前页面';
      gatherBtn.disabled = false;
      gatherBtn.classList.remove('btn-danger');
      gatherBtn.classList.add('btn-primary');
    }
  }
}

function restoreData(url) {
  chrome.storage.local.get([STORAGE_KEY, URL_KEY, TABS_KEY, 'gatherDataTime'], function (result) {
    if (result[STORAGE_KEY] && result[URL_KEY] === url) {
      gatherData = result[STORAGE_KEY];
      if (result[TABS_KEY]) {
        loadedRules =
          loadedRules.length > 0
            ? loadedRules
            : getHaeRules()
              ? getHaeRules().getDefaultRules()
              : [];
        renderSubTabs();
      }
      const firstGroup = Object.keys(gatherData)[0] || DOM_GROUP;
      currentGatherTab = firstGroup;
      renderGatherTab();

      const total = Object.values(gatherData).reduce(function (s, a) {
        return s + (Array.isArray(a) ? a.length : 0);
      }, 0);
      let statusMsg = `已恢复，共 ${countAll()} 条`;
      const savedTime = result.gatherDataTime;
      if (savedTime) {
        const ageMinutes = Math.floor((Date.now() - savedTime) / 60000);
        if (ageMinutes > 60) {
          statusMsg += `（上次收集: ${Math.floor(ageMinutes / 60)}小时前，建议重新收集）`;
        } else if (ageMinutes > 5) {
          statusMsg += `（上次收集: ${ageMinutes}分钟前）`;
        }
      }
      utils.setStatus('gather-status', statusMsg);
    }
  });
}

function exportAllData() {
  const rows = [];
  Object.keys(gatherData).forEach(function (group) {
    const items = gatherData[group];
    if (!Array.isArray(items)) return;
    items.forEach(function (item) {
      rows.push([group, item.name, item.value]);
    });
  });
  if (rows.length === 0) {
    utils.showToast('没有数据可导出', 'warning');
    return;
  }
  utils.buildCsv(['Group', 'Type', 'Value'], rows, `lingmou-gather-${Date.now()}.csv`);
}

function exportAllDataJson() {
  const output = {};
  Object.keys(gatherData).forEach(function (group) {
    const items = gatherData[group];
    if (!Array.isArray(items) || items.length === 0) return;
    output[group] = items.map(function (item) {
      return { name: item.name, value: item.value };
    });
  });
  if (Object.keys(output).length === 0) {
    utils.showToast('没有数据可导出', 'warning');
    return;
  }
  const json = JSON.stringify(output, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  chrome.downloads.download(
    { url: url, filename: `lingmou-gather-${Date.now()}.json`, saveAs: true },
    function () {
      URL.revokeObjectURL(url);
    }
  );
  utils.showToast('JSON 导出中...', 'info');
}

function copyAllData() {
  let list = gatherData[currentGatherTab] || [];
  if (list.length === 0) {
    utils.showToast('当前分组没有数据', 'warning');
    return;
  }
  const text = list
    .map(function (item) {
      return item.value;
    })
    .join('\n');
  utils.copyAndToast(text, `已复制 ${list.length} 条数据`);
}

function copyAllGroupsData() {
  const rows = [];
  Object.keys(gatherData).forEach(function (group) {
    const items = gatherData[group];
    if (!Array.isArray(items) || items.length === 0) return;
    rows.push(`=== ${group} ===`);
    items.forEach(function (item) {
      rows.push(item.value);
    });
  });
  if (rows.length === 0) {
    utils.showToast('没有数据可复制', 'warning');
    return;
  }
  utils.copyAndToast(rows.join('\n'), `已复制全部 ${countAll()} 条数据`);
}

function getActiveRules() {
  return loadedRules;
}

function updateRules(rules) {
  loadedRules = rules;
  if (getHaeRules()) getHaeRules().saveRules(rules);
  renderSubTabs();
}

export {
  init,
  gatherInfo,
  restoreData,
  applySearchFilter,
  exportAllData,
  exportAllDataJson,
  copyAllData,
  copyAllGroupsData,
  getScriptUrls,
  getActiveRules,
  updateRules,
  gatherData,
  currentGatherTab,
};

function getScriptUrls() {
  var urls = [];
  var domGroup = gatherData[DOM_GROUP] || [];
  domGroup.forEach(function (item) {
    if (item.name === 'script' && item.value && item.value.startsWith('http')) {
      urls.push(item.value);
    }
  });
  return urls;
}
