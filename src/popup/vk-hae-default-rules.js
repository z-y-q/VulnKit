// 灵眸 - HaE Default Rules Data
'use strict';

import { loadJsonData } from './vk-data-loader.js';

var _rules = null;

async function ensureLoaded() {
  if (_rules) return _rules;
  _rules = await loadJsonData('data/hae-default-rules.json') || [];
  return _rules;
}

async function getDefaultRules() {
  return ensureLoaded();
}

export { ensureLoaded, getDefaultRules };
