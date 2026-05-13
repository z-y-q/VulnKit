// vk-data-loader.js -- 灵眸 Chrome Extension
// Shared JSON data loader for externalized rule/signature files
'use strict';

var _cache = {};

function hydrateRegexFields(obj) {
  if (obj === null || obj === undefined) return obj;
  if (obj.__regexp__) {
    return new RegExp(obj.source, obj.flags || '');
  }
  if (Array.isArray(obj)) {
    for (var i = 0; i < obj.length; i++) {
      obj[i] = hydrateRegexFields(obj[i]);
    }
    return obj;
  }
  if (typeof obj === 'object') {
    var keys = Object.keys(obj);
    for (var k = 0; k < keys.length; k++) {
      var val = obj[keys[k]];
      if (val !== null && val !== undefined && typeof val === 'object') {
        obj[keys[k]] = hydrateRegexFields(val);
      }
    }
  }
  return obj;
}

async function loadJsonData(relativePath) {
  if (_cache[relativePath]) return _cache[relativePath];
  if (_cache[relativePath] === null) return null;

  var url = chrome.runtime.getURL('src/popup/' + relativePath);
  try {
    var response = await fetch(url);
    if (!response.ok) throw new Error('HTTP ' + response.status);
    var data = await response.json();
    hydrateRegexFields(data);
    _cache[relativePath] = data;
    return data;
  } catch (e) {
    console.error('[灵眸] Failed to load data:', relativePath, e);
    _cache[relativePath] = null;
    return null;
  }
}

function attachValidateFns(rules, fnMap) {
  if (!rules || !fnMap) return;
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (rule.id && fnMap[rule.id]) {
      rule.validate = fnMap[rule.id];
    }
  }
}

export { loadJsonData, attachValidateFns };
