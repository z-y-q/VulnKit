// vk-xss-state.js -- Shared mutable state + setters for XSS scanner
'use strict';

let xssPoints = [];
let xssFilterType = 'all';
let xssSearchText = '';
let xssInterceptTimer = null;
let xssInterceptActive = false;
let xssInterceptCountdown = 0;
let _xssDefaultTimeout = 10000;
let lastVerifyResults = [];

chrome.storage.local.get(['pentestSettings'], function (result) {
  var t = (result.pentestSettings || {}).xssDefaultTimeout;
  if (t && typeof t === 'number' && t >= 3000) _xssDefaultTimeout = t;
});

chrome.storage.onChanged.addListener(function (changes, area) {
  if (area === 'local' && changes.pentestSettings) {
    var t = (changes.pentestSettings.newValue || {}).xssDefaultTimeout;
    if (t && typeof t === 'number' && t >= 3000) _xssDefaultTimeout = t;
  }
});

function setXssPointsVal(v) { xssPoints = v; }
function appendXssPoints(newPoints) { xssPoints = [...xssPoints, ...newPoints]; }
function setXssFilterType(v) { xssFilterType = v; }
function setXssSearchText(v) { xssSearchText = v; }
function setXssInterceptTimer(v) { xssInterceptTimer = v; }
function setXssInterceptActive(v) { xssInterceptActive = v; }
function setXssInterceptCountdown(v) { xssInterceptCountdown = v; }
function setLastVerifyResults(v) { lastVerifyResults = v; }

export {
  xssPoints,
  xssFilterType,
  xssSearchText,
  xssInterceptTimer,
  xssInterceptActive,
  xssInterceptCountdown,
  _xssDefaultTimeout,
  lastVerifyResults,
  setXssPointsVal,
  appendXssPoints,
  setXssFilterType,
  setXssSearchText,
  setXssInterceptTimer,
  setXssInterceptActive,
  setXssInterceptCountdown,
  setLastVerifyResults,
};
