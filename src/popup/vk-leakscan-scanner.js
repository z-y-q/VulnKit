// vk-leakscan-scanner.js -- 灵眸 Chrome Extension
// Deep leak scan: multi-source sensitive information detection

import { LEAK_RULES, DOM_LEAK_RULES, SEVERITY_ORDER, SEVERITY_COLOR } from './vk-leak-rules.js';

const LEAK_SCAN_GROUP = 'Deep Leak Scan';
const MAX_FINDINGS = 200;

async function collectPageData(tabId) {
  try {
    var result = await chrome.tabs.sendMessage(tabId, {
      type: 'VK_PAGE_INSPECT',
      action: 'leak-scan',
      timeout: 5000,
    });
    console.debug(
      '[Deep Leak Scan] inspect result:',
      result
        ? { storage: (result.storage || []).length, globals: (result.globals || []).length }
        : 'null'
    );
    return result;
  } catch (e) {
    console.debug('[Deep Leak Scan] VK_PAGE_INSPECT failed:', e.message);
    return null;
  }
}

function buildTextSources(inspectResult, apiEntries) {
  var sources = [];

  if (inspectResult && !inspectResult.error) {
    var storageEntries = inspectResult.storage || [];
    for (var i = 0; i < storageEntries.length; i++) {
      var entry = storageEntries[i];
      if (entry.value && entry.value !== '[access denied]' && typeof entry.value === 'string') {
        sources.push({ label: entry.store + '.' + entry.key, text: entry.value });
      }
    }

    var globalEntries = inspectResult.globals || [];
    for (var j = 0; j < globalEntries.length; j++) {
      var g = globalEntries[j];
      if (g.value && g.value.indexOf('[Function') === -1 && g.value.indexOf('[Object') === -1) {
        sources.push({ label: 'window.' + g.name, text: g.value });
      }
    }
  }

  for (var k = 0; k < apiEntries.length; k++) {
    var item = apiEntries[k];
    var meta = item._meta || {};
    if (meta.reqBody) {
      sources.push({ label: 'REQ ' + item.value, text: meta.reqBody });
    }
    if (meta.resBody) {
      sources.push({ label: 'RES ' + item.value, text: meta.resBody });
    }
  }

  return sources;
}

function matchRules(sources) {
  var findings = [];
  var seen = {};
  var allRules = LEAK_RULES.concat(DOM_LEAK_RULES);

  for (var s = 0; s < sources.length; s++) {
    var source = sources[s];
    if (findings.length >= MAX_FINDINGS) break;

    for (var r = 0; r < allRules.length; r++) {
      if (findings.length >= MAX_FINDINGS) break;

      var ruleName = allRules[r][0];
      var regex = allRules[r][1];
      var severity = allRules[r][2];
      var re = new RegExp(regex.source, regex.flags);
      var match;

      while ((match = re.exec(source.text)) !== null) {
        var value = match[1] || match[0];
        if (!value || value.length > 500) continue;

        var dedupKey = ruleName + '::' + value;
        if (seen[dedupKey]) continue;
        seen[dedupKey] = true;

        findings.push({
          name: ruleName + ' (' + source.label + ')',
          value: value,
          color: SEVERITY_COLOR[severity] || 'gray',
          severity: severity,
        });
      }
    }
  }

  findings.sort(function (a, b) {
    return (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
  });

  return findings;
}

async function runDeepLeakScan(existingGatherData, tabId) {
  var inspectResult = await collectPageData(tabId);
  var apiEntries = existingGatherData['API Traffic'] || [];
  var sources = buildTextSources(inspectResult, apiEntries);
  console.debug(
    '[Deep Leak Scan] text sources:',
    sources.length,
    '(api entries:',
    apiEntries.length,
    ')'
  );

  if (sources.length === 0) return [];

  var findings = matchRules(sources);
  console.debug('[Deep Leak Scan] findings:', findings.length);
  return findings;
}

export { LEAK_SCAN_GROUP, runDeepLeakScan };
