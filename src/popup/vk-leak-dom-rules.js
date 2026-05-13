// vk-leak-dom-rules.js -- 灵眸 Chrome Extension
// DOM-specific leak detection rules (applied to DOM HTML)
'use strict';

import { loadJsonData } from './vk-data-loader.js';

var _rules = null;

async function ensureLoaded() {
  if (_rules) return _rules;
  _rules = await loadJsonData('data/leak-dom-rules.json') || [];
  return _rules;
}

async function getDomLeakRules() {
  return ensureLoaded();
}

export { getDomLeakRules, ensureLoaded };
