// vk-gather-patterns.js - Pattern matching + API extraction for Info Gather
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { loadJsonData } from './vk-data-loader.js';

var _data = null;

async function ensureLoaded() {
  if (_data) return _data;
  _data = await loadJsonData('data/gather-patterns.json') || { SENSITIVE_PATTERNS: [], API_PATTERNS: [] };
  return _data;
}

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
  var data = await ensureLoaded();
  var SENSITIVE_PATTERNS = data.SENSITIVE_PATTERNS;
  var API_PATTERNS = data.API_PATTERNS;

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
  isValidApiPath,
  extractApiFromJsFiles,
  refreshExcludeRegex,
};
