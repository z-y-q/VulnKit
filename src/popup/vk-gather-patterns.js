// vk-gather-patterns.js - Pattern matching + API extraction for Info Gather
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

var SENSITIVE_PATTERNS = [
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
  { regex: /["'](\/api\/[a-zA-Z0-9_\-./{}:?&=]*)["']/gi, label: 'api-path' },
  { regex: /["'](\/v\d+(?:\/[a-zA-Z0-9_\-./{}:?&=]*)*)["']/gi, label: 'versioned' },
  { regex: /path:\s*["']([^"']+)["']/gi, label: 'route-path' },
  { regex: /@(?:Get|Post|Put|Delete|Patch|Route)\s*\(\s*["']([^"']+)["']/gi, label: 'decorator' },
  {
    regex: /["']((?:\/[a-zA-Z0-9_-]+){2,}(?:\/[a-zA-Z0-9_-{}:?&=]*)*)["']/g,
    label: 'path',
  },
];

var DEFAULT_EXCLUDE_REGEX =
  /^(https?:)?\/\/([^/]+\.)?(?:google|facebook|github\.com|jquery|analytics|doubleclick|googletagmanager|fontawesome|bootstrapcdn|unpkg\.com|cdn\.)/i;
var _customExcludeRegex = null;

function refreshExcludeRegex() {
  chrome.storage.local.get(['pentestSettings'], function (result) {
    var list = (result.pentestSettings || {}).domainExcludeList || '';
    var domains = list
      .split('\n')
      .map(function (d) {
        return d.trim();
      })
      .filter(Boolean);
    if (domains.length === 0) {
      _customExcludeRegex = null;
    } else {
      _customExcludeRegex = new RegExp(
        '^(https?:)?\\/\\/([^\\/]+\\.)?(?:' +
          domains
            .map(function (d) {
              return d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            })
            .join('|') +
          ')',
        'i'
      );
    }
  });
}
refreshExcludeRegex();
chrome.storage.onChanged.addListener(function (changes, area) {
  if (area === 'local' && changes.pentestSettings) refreshExcludeRegex();
});

function isValidApiPath(path) {
  if (!path || path.length < 3 || path.length > 200) return false;
  if (_customExcludeRegex && _customExcludeRegex.test(path)) return false;
  if (DEFAULT_EXCLUDE_REGEX.test(path)) return false;
  if (/^\.\//.test(path) && !/api|route|endpoint|action/i.test(path)) return false;
  if (/^(\/\/)/.test(path) && /\.js(\?|$)/i.test(path)) return false;
  if (/\.(js|css|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico)(\?|$)/i.test(path)) return false;
  return true;
}

async function extractApiFromJsFiles(scriptSrcs, pageUrl, abortFlag) {
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

  if (abortFlag) return { endpoints: endpoints, sensitiveItems: sensitiveItems };

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

export {
  SENSITIVE_PATTERNS,
  API_PATTERNS,
  isValidApiPath,
  extractApiFromJsFiles,
  refreshExcludeRegex,
};
