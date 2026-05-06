// vk-vue-jssearch.js -- 灵眸 Chrome Extension
// JS keyword search, path extraction, auto-fill
(function () {
  'use strict';

  var S = window.VulnKitVueState;
  var utils = S.utils;

  async function searchJsKeywords(keyword) {
    var statusEl = utils.get('jssearch-status');
    var resultsEl = utils.get('jssearch-results');
    if (!keyword || keyword.length < 2) {
      utils.showToast('请输入至少2个字符', 'warning');
      return;
    }
    if (statusEl) statusEl.textContent = '搜索中...';
    S.lastJsMatchContexts = [];

    try {
      var tab = await utils.requireTabId();
      if (!tab) return;

      var inlineData =
        (await utils.execInTabData(
          tab.id,
          function (kw) {
            var matches = [];
            var seen = {};
            var scripts = document.querySelectorAll('script:not([src])');
            for (var i = 0; i < scripts.length; i++) {
              var text = scripts[i].textContent || '';
              if (text.indexOf(kw) === -1) continue;
              var lines = text.split('\n');
              for (var j = 0; j < lines.length; j++) {
                var idx = lines[j].indexOf(kw);
                while (idx !== -1) {
                  var start = Math.max(0, idx - 40);
                  var end = Math.min(lines[j].length, idx + kw.length + 60);
                  var context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
                  var key = i + ':' + idx;
                  if (!seen[key]) {
                    seen[key] = true;
                    matches.push({ source: '(inline script #' + (i + 1) + ')', line: j + 1, context: context });
                  }
                  if (matches.length >= 50) break;
                  idx = lines[j].indexOf(kw, idx + 1);
                }
                if (matches.length >= 50) break;
              }
              if (matches.length >= 50) break;
            }
            var extUrls = [];
            document.querySelectorAll('script[src]').forEach(function (s) { extUrls.push(s.src); });
            return { matches: matches, extUrls: extUrls };
          },
          { args: [keyword], world: 'ISOLATED' }
        )) || {};
      var matchList = inlineData.matches || [];
      var extUrls = inlineData.extUrls || [];

      var allContent = await utils.batchFetch(extUrls, { concurrency: 5 });
      for (var b = 0; b < allContent.length && matchList.length < 50; b++) {
        var text = allContent[b];
        if (!text) continue;
        if (text.indexOf(keyword) !== -1) {
          var shortUrl = extUrls[b];
          if (shortUrl.length > 60) shortUrl = '...' + shortUrl.substring(shortUrl.length - 57);
          var lines = text.split('\n');
          for (var j = 0; j < lines.length && matchList.length < 50; j++) {
            var idx = lines[j].indexOf(keyword);
            while (idx !== -1 && matchList.length < 50) {
              var start = Math.max(0, idx - 40);
              var end = Math.min(lines[j].length, idx + keyword.length + 60);
              var context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
              matchList.push({ source: shortUrl, line: j + 1, context: context });
              idx = lines[j].indexOf(keyword, idx + 1);
            }
          }
        }
      }

      if (matchList.length === 0) {
        if (statusEl) statusEl.textContent = '未找到匹配';
        if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('在页面JS中未找到「' + keyword + '」');
        return;
      }

      if (statusEl) statusEl.textContent = '找到 ' + matchList.length + ' 处匹配';
      var html = '';
      for (var i = 0; i < matchList.length; i++) {
        var m = matchList[i];
        S.lastJsMatchContexts.push(m.context);
        var escapedKeyword = utils.escapeHtml(keyword).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var escaped = utils.escapeHtml(m.context);
        var highlighted = escaped.replace(new RegExp('(' + escapedKeyword + ')', 'gi'), '<mark>$1</mark>');
        html += '<div class="jssearch-match">';
        html += '<div class="jssearch-match-source">' + utils.escapeHtml(m.source) + ' : line ' + m.line + '</div>';
        html += '<div class="jssearch-match-code">' + highlighted + '</div>';
        html += '</div>';
      }
      resultsEl.innerHTML = html;
    } catch (e) {
      if (statusEl) statusEl.textContent = '搜索出错';
      utils.showToast('搜索失败: ' + e.message, 'error');
    }
  }

  function extractPathsFromJsResults() {
    var found = new Set();
    var pathRegex = /(?:path|url|href|route|component)\s*[:=]\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/gi;
    var genericRegex = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+)['"`]/g;
    var contexts = S.lastJsMatchContexts;
    for (var i = 0; i < contexts.length; i++) {
      var ctx = contexts[i];
      var m;
      pathRegex.lastIndex = 0;
      while ((m = pathRegex.exec(ctx)) !== null) {
        var p = m[1];
        if (p.indexOf('/api/') === -1 && p.length > 2) found.add(p);
      }
      genericRegex.lastIndex = 0;
      while ((m = genericRegex.exec(ctx)) !== null) {
        var p2 = m[1];
        if (
          p2.indexOf('/api/') === -1 && p2.length > 3 &&
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
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    var text = editor.value;
    if (!text) {
      utils.showToast('请先选择一条捕获数据', 'warning');
      return;
    }
    try {
      var parsed = JSON.parse(text);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }
    var template = S.Compare.getTemplateFromMenuData(parsed);
    var targetArray = Array.isArray(parsed) ? parsed : S.Compare.findMenuArray(parsed);
    if (!targetArray) {
      utils.showToast('无法定位菜单数组，请检查 JSON 结构', 'warning');
      return;
    }
    var menuPaths = new Set();
    S.Compare.extractMenuPaths(parsed, menuPaths);
    var injected = 0;
    for (var p = 0; p < S.jsSearchFoundPaths.length; p++) {
      var routePath = S.jsSearchFoundPaths[p];
      if (!menuPaths.has(routePath)) {
        var newItem = S.Compare.constructMenuItemFromRoute({ path: routePath, name: routePath }, template);
        targetArray.push(newItem);
        menuPaths.add(routePath);
        injected++;
      }
    }
    editor.value = JSON.stringify(parsed, null, 2);
    utils.showToast('已注入 ' + injected + ' 条JS路径到菜单数据', 'success');
  }

  function extractKeywordsFromCapturedUrls() {
    var keywords = [];
    var seen = {};
    var permCapturedData = S.permCapturedData;
    if (!permCapturedData || permCapturedData.length === 0) return keywords;

    for (var i = 0; i < permCapturedData.length; i++) {
      var item = permCapturedData[i];
      if (!item || !item.url) continue;
      var url = item.url;
      var segments = url.split(/[\/?#]/);
      var processed = 0;
      for (var s = segments.length - 1; s >= 0 && processed < 2; s--) {
        var seg = segments[s].trim();
        if (!seg || seg.length < 3) continue;
        if (
          /^(api|v1|v2|v3|v4|index|list|detail|page|id|json|html|js|css|get|post|put|delete)$/i.test(seg)
        )
          continue;
        if (/^\d+$/.test(seg)) continue;

        var words = seg.replace(/([a-z])([A-Z])/g, '$1 $2').split(/[\s_\-]+/);
        for (var w = 0; w < words.length; w++) {
          var word = words[w];
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
    var allContexts = [];
    var classifyEl = utils.get('perm-classify');

    if (classifyEl) classifyEl.textContent = '正在搜索: menu...';
    await searchJsKeywords('menu');
    allContexts = allContexts.concat(S.lastJsMatchContexts);

    if (classifyEl) classifyEl.textContent = '正在搜索: routes... (' + allContexts.length + ' 条)';
    await searchJsKeywords('routes');
    allContexts = allContexts.concat(S.lastJsMatchContexts);

    var urlKeywords = extractKeywordsFromCapturedUrls();
    for (var uk = 0; uk < urlKeywords.length; uk++) {
      if (allContexts.length >= 50) break;
      var kw = urlKeywords[uk];
      if (/^(menu|routes|route|permission)$/i.test(kw)) continue;
      if (classifyEl)
        classifyEl.textContent = '正在搜索: ' + kw + '... (' + allContexts.length + ' 条)';
      S.lastJsMatchContexts = [];
      await searchJsKeywords(kw);
      allContexts = allContexts.concat(S.lastJsMatchContexts);
    }

    if (classifyEl) classifyEl.textContent = '搜索完成，共 ' + allContexts.length + ' 条结果';

    S.lastJsMatchContexts = allContexts;
    extractPathsFromJsResults();
    if (S.jsSearchFoundPaths.length > 0) {
      utils.showToast(
        '找到 ' + S.jsSearchFoundPaths.length + ' 条路径，可点击「应用修改」注入',
        'success'
      );
      S.switchVueSubTab('perm');
      var editor = utils.get('perm-json-editor');
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
})();
