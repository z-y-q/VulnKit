// 灵眸 - Link Extract
window.VulnKitLinks = (function () {
  'use strict';

  let allLinks = [];
  var utils = window.VulnKitUtils.utilsProxy;
  var TAG_LABELS = {
    a: '链接',
    img: '图片',
    script: '脚本',
    link: '资源',
    iframe: '框架',
    form: '表单',
  };
  var TAG_COLORS = {
    a: '#4A90E2',
    img: '#27ae60',
    script: '#e67e22',
    link: '#9b59b6',
    iframe: '#e74c3c',
    form: '#f39c12',
  };

  async function extractLinks() {
    utils.setStatus('links-count', '正在提取...');

    try {
      const tab = await utils.getActiveTab();
      if (!tab || !tab.url) {
        utils.setStatus('links-count', '无法获取当前页面');
        return;
      }

      var extractedLinks = await utils.execInTabData(tab.id, () => {
        const pageUrl = location.href;
        const pageDomain = location.hostname;
        const links = [];

        function makeLink(href, text, tag) {
          var domain = '';
          try {
            domain = new URL(href, pageUrl).hostname;
          } catch {}
          return {
            href: href,
            text: text,
            tag: tag,
            domain: domain,
            isExternal: domain !== pageDomain,
            isJS: false,
            isMailto: false,
          };
        }

        document.querySelectorAll('a[href]').forEach(el => {
          const href = el.href;
          if (!href || href === '#' || href.startsWith('javascript:')) return;
          let domain = '';
          try {
            domain = new URL(href, pageUrl).hostname;
          } catch {}
          links.push({
            href,
            text: (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
            tag: 'a',
            domain,
            isExternal: domain !== pageDomain,
            isJS: false,
            isMailto: href.startsWith('mailto:'),
          });
        });

        document.querySelectorAll('img[src]').forEach(el => {
          links.push(makeLink(el.src, el.alt || '', 'img'));
        });

        document.querySelectorAll('script[src]').forEach(el => {
          links.push(makeLink(el.src, '', 'script'));
        });

        document.querySelectorAll('link[href]').forEach(el => {
          links.push(makeLink(el.href, el.rel || '', 'link'));
        });

        document.querySelectorAll('iframe[src],frame[src]').forEach(el => {
          links.push(makeLink(el.src, '', 'iframe'));
        });

        // Extract forms
        document.querySelectorAll('form').forEach(el => {
          var action = el.getAttribute('action') || pageUrl;
          var method = (el.getAttribute('method') || 'GET').toUpperCase();
          try {
            action = new URL(action, pageUrl).href;
          } catch {}
          var inputs = [];
          el.querySelectorAll('input[name],select[name],textarea[name]').forEach(function (inp) {
            inputs.push(inp.getAttribute('name'));
          });
          links.push({
            href:
              action + ' [' + method + ']' + (inputs.length ? ' {' + inputs.join(', ') + '}' : ''),
            text: inputs.length ? inputs.join(', ') : '',
            tag: 'form',
            domain: '',
            isExternal: false,
            isJS: false,
            isMailto: false,
            formMethod: method,
            formInputs: inputs,
          });
        });

        const seen = new Set();
        return links.filter(l => {
          if (seen.has(l.href)) return false;
          seen.add(l.href);
          return true;
        });
      });

      if (extractedLinks) {
        allLinks = extractedLinks;
        renderLinks();
        renderStats();
        utils.setStatus('links-count', '提取完成，共 ' + allLinks.length + ' 个链接');
        utils.showToast('提取完成', 'success');
        if (utils.getSetting('storeHistory', true)) {
          chrome.storage.local.set({ allLinks: allLinks, allLinksUrl: tab.url });
        }
      }
    } catch (e) {
      utils.setStatus('links-count', '提取失败: ' + e.message);
      utils.showToast('提取失败', 'error');
    }
  }

  function getFilteredLinks() {
    var filterEl = utils.get('links-filter');
    var filterTypeEl = utils.get('links-filter-type');
    var filterText = filterEl ? filterEl.value.trim().toLowerCase() : '';
    var filterType = filterTypeEl ? filterTypeEl.value : 'all';

    return allLinks.filter(function (link) {
      if (filterType === 'external' && !link.isExternal) return false;
      if (filterType === 'internal' && link.isExternal) return false;
      if (filterType !== 'all' && filterType !== 'external' && filterType !== 'internal') {
        if (link.tag !== filterType) return false;
      }
      if (
        filterText &&
        !link.href.toLowerCase().includes(filterText) &&
        (!link.text || !link.text.toLowerCase().includes(filterText)) &&
        (!link.domain || !link.domain.toLowerCase().includes(filterText))
      )
        return false;
      return true;
    });
  }

  function renderStats() {
    var statsEl = utils.get('links-stats');
    if (!statsEl || allLinks.length === 0) return;

    var counts = {};
    var domains = {};
    allLinks.forEach(function (link) {
      counts[link.tag] = (counts[link.tag] || 0) + 1;
      if (link.domain) {
        domains[link.domain] = (domains[link.domain] || 0) + 1;
      }
    });

    var externalCount = allLinks.filter(function (l) {
      return l.isExternal;
    }).length;

    var html = '<div class="links-stats-bar">';
    html += '<span class="links-stat">总计: ' + allLinks.length + '</span>';

    Object.keys(counts).forEach(function (tag) {
      html += '<span class="links-stat" style="color:' + (TAG_COLORS[tag] || '#888') + '">';
      html += (TAG_LABELS[tag] || tag) + ': ' + counts[tag];
      html += '</span>';
    });

    if (externalCount > 0) {
      html += '<span class="links-stat" style="color:#e74c3c">外部: ' + externalCount + '</span>';
    }

    var uniqueDomains = Object.keys(domains).length;
    if (uniqueDomains > 1) {
      html += '<span class="links-stat">域名: ' + uniqueDomains + '</span>';
    }

    html += '</div>';
    statsEl.innerHTML = html;
  }

  function renderLinks() {
    var filtered = getFilteredLinks();
    var container = utils.get('links-results');
    var countEl = utils.get('links-count');
    if (!container) return;

    var existingText = countEl ? countEl.textContent : '';
    if (countEl && !existingText.includes('正在')) {
      countEl.textContent = '显示 ' + filtered.length + ' / ' + allLinks.length + ' 个链接';
    }

    if (filtered.length === 0) {
      utils.setEmpty('links-results', '没有匹配的链接');
      return;
    }

    var html = '';
    filtered.forEach(function (link) {
      var tagClass = 'tag-' + link.tag;
      var extClass = link.isExternal ? ' link-item-external' : '';
      html += '<div class="link-item' + extClass + '">';
      html +=
        '<span class="link-item-tag ' +
        tagClass +
        '" style="background:' +
        (TAG_COLORS[link.tag] || '#888') +
        '">' +
        link.tag +
        '</span>';
      html += '<span class="link-item-text">';
      html +=
        '<span class="link-item-href" title="' +
        utils.escapeHtml(link.href) +
        '">' +
        utils.escapeHtml(link.href) +
        '</span>';
      if (link.domain) {
        html += '<span class="link-item-domain">' + utils.escapeHtml(link.domain);
        if (link.text) html += ' - ' + utils.escapeHtml(link.text);
        html += '</span>';
      } else if (link.text) {
        html += '<span class="link-item-domain">' + utils.escapeHtml(link.text) + '</span>';
      }
      html += '</span>';
      html +=
        '<button class="link-item-copy" data-href="' +
        utils.escapeHtml(link.href) +
        '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.link-item-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        utils.copyAndToast(btn.dataset.href);
      });
    });
  }

  function copyFilteredUrls() {
    var filtered = getFilteredLinks();
    if (filtered.length === 0) {
      utils.showToast('没有可复制的链接', 'warning');
      return;
    }
    var urls = filtered
      .map(function (l) {
        return l.href;
      })
      .join('\n');
    utils.copyAndToast(urls, '已复制 ' + filtered.length + ' 个 URL');
  }

  function exportLinks() {
    var filtered = getFilteredLinks();
    if (filtered.length === 0) {
      utils.showToast('没有可导出的链接', 'warning');
      return;
    }
    var rows = filtered.map(function (l) {
      return [l.href, l.tag, l.domain, l.text, l.isExternal ? 'Yes' : 'No'];
    });
    utils.buildCsv(
      ['URL', 'Tag', 'Domain', 'Text', 'External'],
      rows,
      'lingmou-links-' + Date.now() + '.csv'
    );
  }

  function sendToMultiUrl() {
    var filtered = getFilteredLinks();
    if (filtered.length === 0) {
      utils.showToast('没有可发送的链接', 'warning');
      return;
    }
    var urls = filtered
      .filter(function (l) {
        return l.tag === 'a' || l.tag === 'iframe';
      })
      .map(function (l) {
        return l.href;
      });
    if (urls.length === 0) {
      utils.showToast('没有可发送的 URL 类型的链接', 'warning');
      return;
    }
    var inputEl = utils.get('multiurl-input');
    if (inputEl) {
      inputEl.value = urls.join('\n');
      if (window.VulnKitMultiUrl && window.VulnKitMultiUrl.updateMultiurlInfo) {
        window.VulnKitMultiUrl.updateMultiurlInfo(urls.length);
      }
      // Switch to multiurl panel
      var multiurlBtn = document.querySelector('[data-panel="multiurl"]');
      if (multiurlBtn) multiurlBtn.click();
      utils.showToast('已发送 ' + urls.length + ' 个 URL 到多开面板', 'success');
    }
  }

  return {
    extractLinks,
    getFilteredLinks,
    renderLinks,
    copyFilteredUrls,
    exportLinks,
    sendToMultiUrl,
    get allLinks() {
      return allLinks;
    },
    set allLinks(v) {
      allLinks = v;
    },
  };
})();
