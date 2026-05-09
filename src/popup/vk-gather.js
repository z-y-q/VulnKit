// 灵眸 - Info Gather (HaE Rules Engine)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import * as haeRules from './vk-hae-rules.js';
import {
  initTrafficDeps,
  API_TRAFFIC_GROUP,
  applyApiTrafficFilter,
  startApiTraffic,
  stopApiTraffic,
  setApiFilter,
} from './vk-gather-traffic.js';

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
  const isApiTraffic = currentGatherTab === API_TRAFFIC_GROUP;
  if (isApiTraffic) {
    list = applyApiTrafficFilter(list);
  }
  if (!searchFilter) return list;
  const lower = searchFilter.toLowerCase();
  return list.filter(function (item) {
    return (
      (item.value && item.value.toLowerCase().indexOf(lower) !== -1) ||
      (item.name && item.name.toLowerCase().indexOf(lower) !== -1)
    );
  });
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

  const isApiTraffic = currentGatherTab === API_TRAFFIC_GROUP;
  const fullList = gatherData[currentGatherTab] || [];
  if (fullList.length === 0) {
    utils.setEmpty('gather-results', '点击「收集当前页面」开始');
    utils.setStatus('gather-status', '');
    return;
  }

  let statusText = `共 ${fullList.length} 条`;
  if (searchFilter && list.length !== fullList.length) {
    statusText += `（筛选: ${list.length}）`;
  }
  if (isApiTraffic && list.length !== fullList.length && !searchFilter) {
    statusText += `（筛选: ${list.length}）`;
  }
  utils.setStatus('gather-status', statusText);

  if (list.length === 0) {
    utils.setEmpty('gather-results', '没有匹配的结果');
    return;
  }

  let html = '';
  list.forEach(function (item, idx) {
    let meta = item._meta || {};
    if (isApiTraffic && meta.method) {
      html += `<div class="gather-item gather-api-item" data-api-idx="${idx}">
        <span class="gather-item-type type-${item.color || 'gray'}">${utils.escapeHtml(meta.method)}</span>
        <span class="gather-item-value" title="${utils.escapeHtml(item.value)}">${utils.escapeHtml(item.value)}</span>
        <span class="api-duration">${meta.duration || 0}ms</span>
        <button class="gather-item-copy" data-copy="${utils.escapeHtml(item.value)}">复制</button>
      </div>`;
      html += `<div class="gather-api-detail" id="api-detail-${idx}" style="display:none;">`;
      if (meta.contentType) {
        html += `<div class="api-detail-row"><span class="api-detail-label">Content-Type</span><span class="api-detail-value">${utils.escapeHtml(meta.contentType)}</span></div>`;
      }
      if (meta.status) {
        html += `<div class="api-detail-row"><span class="api-detail-label">Status</span><span class="api-detail-value"><span class="api-status-badge ${
          meta.status >= 200 && meta.status < 300
            ? 'api-st-2xx'
            : meta.status >= 400
              ? 'api-st-err'
              : 'api-st-warn'
        }">${meta.status}</span></span></div>`;
      }
      const headers = meta.reqHeaders || {};
      const headerKeys = Object.keys(headers);
      if (headerKeys.length > 0) {
        html +=
          '<div class="api-detail-row"><span class="api-detail-label">Headers</span><span class="api-detail-value">';
        headerKeys.forEach(function (k) {
          html += `<div class="api-header-entry"><span class="api-header-key">${utils.escapeHtml(k)}:</span> ${utils.escapeHtml(headers[k])}</div>`;
        });
        html += '</span></div>';
      }
      if (meta.reqBody) {
        html += `<div class="api-detail-row"><span class="api-detail-label">Request Body</span><span class="api-detail-value api-body-preview">${utils.escapeHtml(meta.reqBody)}</span></div>`;
      }
      if (meta.resBody) {
        html += `<div class="api-detail-row"><span class="api-detail-label">Response Body</span><span class="api-detail-value api-body-preview">${utils.escapeHtml(meta.resBody)}</span></div>`;
      }
      html += '</div>';
    } else {
      html += `<div class="gather-item">
        <span class="gather-item-type type-${item.color || item.type || 'gray'}">${utils.escapeHtml(item.name || item.type || '')}</span>
        <span class="gather-item-value" title="${utils.escapeHtml(item.value)}">${utils.escapeHtml(item.value)}</span>
        <button class="gather-item-copy" data-copy="${utils.escapeHtml(item.value)}">复制</button>
      </div>`;
    }
  });
  container.innerHTML = html;

  container.querySelectorAll('.gather-item-copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      utils.copyAndToast(btn.dataset.copy);
    });
  });

  container.querySelectorAll('.gather-api-item').forEach(function (el) {
    el.addEventListener('click', function (ev) {
      if (ev.target.classList.contains('gather-item-copy')) return;
      let idx = el.dataset.apiIdx;
      const detail = document.getElementById(`api-detail-${idx}`);
      if (detail) {
        const shown = detail.style.display !== 'none';
        detail.style.display = shown ? 'none' : '';
        el.classList.toggle('gather-api-expanded', !shown);
      }
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
    gatherData['API Traffic'] ? [API_TRAFFIC_GROUP] : [],
    gatherData['JS API'] ? ['JS API'] : [],
    gatherData['JS Sensitive Info'] ? ['JS Sensitive Info'] : [],
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
  filesToFetch = filesToFetch.slice(0, 15);

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

      renderSubTabs();
      renderGatherTab();

      let statusText = `收集完成，共 ${countAll()} 条`;
      if (meta && meta.truncated) {
        statusText += `（HTML 已截断至 500KB/${(meta.totalSize / 1024).toFixed(0)}KB）`;
      }
      statusText += `（${gatherElapsed()}s）`;
      utils.setStatus('gather-status', statusText);
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

function getActiveRules() {
  return loadedRules;
}

function updateRules(rules) {
  loadedRules = rules;
  if (getHaeRules()) getHaeRules().saveRules(rules);
  renderSubTabs();
}

initTrafficDeps(gatherData, () => currentGatherTab, renderSubTabs, renderGatherTab);

export {
  init,
  gatherInfo,
  restoreData,
  applySearchFilter,
  exportAllData,
  copyAllData,
  getActiveRules,
  updateRules,
  startApiTraffic,
  stopApiTraffic,
  setApiFilter,
  gatherData,
  currentGatherTab,
};
