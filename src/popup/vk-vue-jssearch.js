// vk-vue-jssearch.js -- 灵眸 Chrome Extension
// JS keyword search, path extraction, auto-fill

import { utilsProxy as utils } from './vk-namespace.js';
import { vueState, switchVueSubTab } from './vk-vue-state.js';

const S = vueState;

async function searchJsKeywords(keyword) {
  const statusEl = utils.get('jssearch-status');
  const resultsEl = utils.get('jssearch-results');
  if (!keyword || keyword.length < 2) {
    utils.showToast('请输入至少2个字符', 'warning');
    return;
  }
  if (statusEl) statusEl.textContent = '搜索中...';
  S.lastJsMatchContexts = [];

  try {
    const tab = await utils.requireTabId();
    if (!tab) return;

    const inlineData =
      (await utils.execInTabData(
        tab.id,
        function (kw) {
          const matches = [];
          const seen = {};
          const scripts = document.querySelectorAll('script:not([src])');
          for (let i = 0; i < scripts.length; i++) {
            let text = scripts[i].textContent || '';
            if (text.indexOf(kw) === -1) continue;
            let lines = text.split('\n');
            for (let j = 0; j < lines.length; j++) {
              let idx = lines[j].indexOf(kw);
              while (idx !== -1) {
                let start = Math.max(0, idx - 40);
                let end = Math.min(lines[j].length, idx + kw.length + 60);
                let context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
                const key = `${i}:${idx}`;
                if (!seen[key]) {
                  seen[key] = true;
                  matches.push({
                    source: `(inline script #${i + 1})`,
                    line: j + 1,
                    context: context,
                  });
                }
                if (matches.length >= 50) break;
                idx = lines[j].indexOf(kw, idx + 1);
              }
              if (matches.length >= 50) break;
            }
            if (matches.length >= 50) break;
          }
          let extUrls = [];
          document.querySelectorAll('script[src]').forEach(function (s) {
            extUrls.push(s.src);
          });
          return { matches: matches, extUrls: extUrls };
        },
        { args: [keyword], world: 'ISOLATED' }
      )) || {};
    const matchList = inlineData.matches || [];
    const extUrls = inlineData.extUrls || [];

    const allContent = await utils.batchFetch(extUrls, { concurrency: 5 });
    for (let b = 0; b < allContent.length && matchList.length < 50; b++) {
      let text = allContent[b];
      if (!text) continue;
      if (text.indexOf(keyword) !== -1) {
        let shortUrl = extUrls[b];
        if (shortUrl.length > 60) shortUrl = `...${shortUrl.substring(shortUrl.length - 57)}`;
        const lines = text.split('\n');
        for (let j = 0; j < lines.length && matchList.length < 50; j++) {
          let idx = lines[j].indexOf(keyword);
          while (idx !== -1 && matchList.length < 50) {
            let start = Math.max(0, idx - 40);
            let end = Math.min(lines[j].length, idx + keyword.length + 60);
            const context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
            matchList.push({ source: shortUrl, line: j + 1, context: context });
            idx = lines[j].indexOf(keyword, idx + 1);
          }
        }
      }
    }

    if (matchList.length === 0) {
      if (statusEl) statusEl.textContent = '未找到匹配';
      if (resultsEl) resultsEl.innerHTML = utils.emptyHtml(`在页面JS中未找到「${keyword}」`);
      return;
    }

    if (statusEl) statusEl.textContent = `找到 ${matchList.length} 处匹配`;
    let html = '';
    for (let i = 0; i < matchList.length; i++) {
      let m = matchList[i];
      S.lastJsMatchContexts.push(m.context);
      const escapedKeyword = utils.escapeHtml(keyword).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const escaped = utils.escapeHtml(m.context);
      const highlighted = escaped.replace(
        new RegExp(`(${escapedKeyword})`, 'gi'),
        '<mark>$1</mark>'
      );
      html +=
        `<div class="jssearch-match">` +
        `<div class="jssearch-match-source">${utils.escapeHtml(m.source)} : line ${m.line}</div>` +
        `<div class="jssearch-match-code">${highlighted}</div>` +
        `</div>`;
    }
    resultsEl.innerHTML = html;
  } catch (e) {
    if (statusEl) statusEl.textContent = '搜索出错';
    utils.showToast(`搜索失败: ${e.message}`, 'error');
  }
}

function extractPathsFromJsResults() {
  const found = new Set();
  const pathRegex = /(?:path|url|href|route|component)\s*[:=]\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/gi;
  const genericRegex = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+)['"`]/g;
  const contexts = S.lastJsMatchContexts;
  for (let i = 0; i < contexts.length; i++) {
    const ctx = contexts[i];
    let m;
    pathRegex.lastIndex = 0;
    while ((m = pathRegex.exec(ctx)) !== null) {
      let p = m[1];
      if (p.indexOf('/api/') === -1 && p.length > 2) found.add(p);
    }
    genericRegex.lastIndex = 0;
    while ((m = genericRegex.exec(ctx)) !== null) {
      const p2 = m[1];
      if (
        p2.indexOf('/api/') === -1 &&
        p2.length > 3 &&
        !/^\.(js|css|png|jpg|svg|ico|woff)/.test(p2)
      )
        found.add(p2);
    }
  }
  S.jsSearchFoundPaths = Array.from(found);
  return S.jsSearchFoundPaths;
}

function autoFillFromJsPaths() {
  if (S.jsSearchFoundPaths.length === 0) {
    extractPathsFromJsResults();
  }
  if (S.jsSearchFoundPaths.length === 0) {
    utils.showToast('未找到JS路径，请先搜索关键词', 'warning');
    return;
  }
  let editor = utils.get('perm-json-editor');
  if (!editor) return;
  const text = editor.value;
  if (!text) {
    utils.showToast('请先选择一条捕获数据', 'warning');
    return;
  }
  try {
    const parsed = JSON.parse(text);
  } catch (e) {
    utils.showToast('JSON 格式错误', 'error');
    return;
  }
  const template = S.Compare.getTemplateFromMenuData(parsed);
  const targetArray = Array.isArray(parsed) ? parsed : S.Compare.findMenuArray(parsed);
  if (!targetArray) {
    utils.showToast('无法定位菜单数组，请检查 JSON 结构', 'warning');
    return;
  }
  const menuPaths = new Set();
  S.Compare.extractMenuPaths(parsed, menuPaths);
  let injected = 0;
  for (let p = 0; p < S.jsSearchFoundPaths.length; p++) {
    const routePath = S.jsSearchFoundPaths[p];
    if (!menuPaths.has(routePath)) {
      const newItem = S.Compare.constructMenuItemFromRoute(
        { path: routePath, name: routePath },
        template
      );
      targetArray.push(newItem);
      menuPaths.add(routePath);
      injected++;
    }
  }
  editor.value = JSON.stringify(parsed, null, 2);
  utils.showToast(`已注入 ${injected} 条JS路径到菜单数据`, 'success');
}

function extractKeywordsFromCapturedUrls() {
  const keywords = [];
  const seen = {};
  const permCapturedData = S.permCapturedData;
  if (!permCapturedData || permCapturedData.length === 0) return keywords;

  for (let i = 0; i < permCapturedData.length; i++) {
    const item = permCapturedData[i];
    if (!item || !item.url) continue;
    const url = item.url;
    const segments = url.split(/[\/?#]/);
    let processed = 0;
    for (let s = segments.length - 1; s >= 0 && processed < 2; s--) {
      const seg = segments[s].trim();
      if (!seg || seg.length < 3) continue;
      if (
        /^(api|v1|v2|v3|v4|index|list|detail|page|id|json|html|js|css|get|post|put|delete)$/i.test(
          seg
        )
      )
        continue;
      if (/^\d+$/.test(seg)) continue;

      const words = seg.replace(/([a-z])([A-Z])/g, '$1 $2').split(/[\s_\-]+/);
      for (let w = 0; w < words.length; w++) {
        const word = words[w];
        if (word.length < 4) continue;
        if (!seen[word.toLowerCase()]) {
          seen[word.toLowerCase()] = true;
          keywords.push(word);
        }
      }
      if (!seen[seg.toLowerCase()]) {
        seen[seg.toLowerCase()] = true;
        keywords.push(seg);
      }
      processed++;
    }
  }
  return keywords.slice(0, 8);
}

async function autoSearchForZeroOpen() {
  S.lastJsMatchContexts = [];
  let allContexts = [];
  const classifyEl = utils.get('perm-classify');

  if (classifyEl) classifyEl.textContent = '正在搜索: menu...';
  await searchJsKeywords('menu');
  allContexts = allContexts.concat(S.lastJsMatchContexts);

  if (classifyEl) classifyEl.textContent = `正在搜索: routes... (${allContexts.length} 条)`;
  await searchJsKeywords('routes');
  allContexts = allContexts.concat(S.lastJsMatchContexts);

  const urlKeywords = extractKeywordsFromCapturedUrls();
  for (let uk = 0; uk < urlKeywords.length; uk++) {
    if (allContexts.length >= 50) break;
    const kw = urlKeywords[uk];
    if (/^(menu|routes|route|permission)$/i.test(kw)) continue;
    if (classifyEl) classifyEl.textContent = `正在搜索: ${kw}... (${allContexts.length} 条)`;
    S.lastJsMatchContexts = [];
    await searchJsKeywords(kw);
    allContexts = allContexts.concat(S.lastJsMatchContexts);
  }

  if (classifyEl) classifyEl.textContent = `搜索完成，共 ${allContexts.length} 条结果`;

  S.lastJsMatchContexts = allContexts;
  extractPathsFromJsResults();
  if (S.jsSearchFoundPaths.length > 0) {
    utils.showToast(
      `找到 ${S.jsSearchFoundPaths.length} 条路径，可点击「应用修改」注入`,
      'success'
    );
    switchVueSubTab('perm');
    const editor = utils.get('perm-json-editor');
    if (editor && editor.value) {
      autoFillFromJsPaths();
    }
  } else {
    utils.showToast('未从JS中提取到路径，请手动搜索关键词', 'warning');
  }
}

S.JsSearch = {
  searchJsKeywords: searchJsKeywords,
  extractPathsFromJsResults: extractPathsFromJsResults,
  autoFillFromJsPaths: autoFillFromJsPaths,
  extractKeywordsFromCapturedUrls: extractKeywordsFromCapturedUrls,
  autoSearchForZeroOpen: autoSearchForZeroOpen,
};

export {
  searchJsKeywords,
  extractPathsFromJsResults,
  autoFillFromJsPaths,
  extractKeywordsFromCapturedUrls,
  autoSearchForZeroOpen,
};
