// vk-sniff-state.js -- 灵眸 Chrome Extension
// Technology fingerprint rules database and confidence scoring

import { loadJsonData } from './vk-data-loader.js';

var _signatures = null;

async function ensureLoaded() {
  if (_signatures) return _signatures;
  _signatures = await loadJsonData('data/sniff-tech-signatures.json') || [];
  return _signatures;
}

async function getTechSignatures() {
  return ensureLoaded();
}

const CONFIDENCE_BASE_SCORES = {
  headers: 30,
  globals: 30,
  meta: 20,
  body: 20,
  cookies: 25,
  classNames: 15,
  ids: 15,
  scriptSrc: 18,
};

const CONFIDENCE_LEVELS = {
  strong: { min: 90, label: '强', color: '#10b981' },
  moderate: { min: 75, label: '稳', color: '#f59e0b' },
  weak: { min: 0, label: '弱', color: '#9ca3af' },
};

function scoreConfidence(matchedMatchers) {
  if (matchedMatchers.length === 0) return null;

  var baseScore = 0;
  var matchedSources = {};

  for (var i = 0; i < matchedMatchers.length; i++) {
    var m = matchedMatchers[i];
    var sourceScore = CONFIDENCE_BASE_SCORES[m.source] || 20;
    if (sourceScore > baseScore) baseScore = sourceScore;
    matchedSources[m.source] = true;
  }

  var sourceCount = Object.keys(matchedSources).length;
  var bonusMultiplier = 1 + (matchedMatchers.length - 1) * 0.2;
  var sourceBonus = (sourceCount - 1) * 4;
  var totalScore = Math.min(100, Math.round(baseScore * bonusMultiplier + sourceBonus));

  if (totalScore >= CONFIDENCE_LEVELS.strong.min) {
    return {
      score: totalScore,
      label: CONFIDENCE_LEVELS.strong.label,
      color: CONFIDENCE_LEVELS.strong.color,
    };
  }
  if (totalScore >= CONFIDENCE_LEVELS.moderate.min) {
    return {
      score: totalScore,
      label: CONFIDENCE_LEVELS.moderate.label,
      color: CONFIDENCE_LEVELS.moderate.color,
    };
  }
  return {
    score: totalScore,
    label: CONFIDENCE_LEVELS.weak.label,
    color: CONFIDENCE_LEVELS.weak.color,
  };
}

function extractVersion(techName, versions) {
  if (!versions || typeof versions !== 'object') return null;
  return versions[techName] || null;
}

export {
  getTechSignatures,
  CONFIDENCE_BASE_SCORES,
  CONFIDENCE_LEVELS,
  scoreConfidence,
  extractVersion,
};
