// VulnKit - Link Extract
window.VulnKitLinks = (function () {
  'use strict';

  let allLinks = [];

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  async function extractLinks() {
    const utils = getUtils();
    const statusEl = utils.get('links-count');
    if (statusEl) statusEl.textContent = '正在提取...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        if (statusEl) statusEl.textContent = '无法获取当前页面';
        return;
      }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const pageUrl = location.href;
          const pageDomain = location.hostname;
          const links = [];

          document.querySelectorAll('a[href]').forEach(el => {
            const href = el.href;
            if (!href || href === '#' || href.startsWith('javascript:')) return;
            let domain = '';
            try {
              domain = new URL(href, pageUrl).hostname;
            } catch {}
            links.push({
              href,
              text:
                (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
              tag: 'a',
              domain,
              isExternal: domain !== pageDomain,
              isJS: href.startsWith('javascript:'),
              isMailto: href.startsWith('mailto:'),
            });
          });

          document.querySelectorAll('img[src]').forEach(el => {
            links.push({
              href: el.src,
              text: el.alt || '',
              tag: 'img',
              domain: '',
              isExternal: false,
              isJS: false,
              isMailto: false,
            });
            try {
              links[links.length - 1].domain = new URL(el.src, pageUrl).hostname;
              links[links.length - 1].isExternal = links[links.length - 1].domain !== pageDomain;
            } catch {}
          });

          document.querySelectorAll('script[src]').forEach(el => {
            const src = el.src;
            let domain = '';
            try {
              domain = new URL(src, pageUrl).hostname;
            } catch {}
            links.push({
              href: src,
              text: '',
              tag: 'script',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          document.querySelectorAll('link[href]').forEach(el => {
            const href = el.href;
            let domain = '';
            try {
              domain = new URL(href, pageUrl).hostname;
            } catch {}
            links.push({
              href,
              text: el.rel || '',
              tag: 'link',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          document.querySelectorAll('iframe[src],frame[src]').forEach(el => {
            const src = el.src;
            let domain = '';
            try {
              domain = new URL(src, pageUrl).hostname;
            } catch {}
            links.push({
              href: src,
              text: '',
              tag: 'iframe',
              domain,
              isExternal: domain !== pageDomain,
              isJS: false,
              isMailto: false,
            });
          });

          const seen = new Set();
          return links.filter(l => {
            if (seen.has(l.href)) return false;
            seen.add(l.href);
            return true;
          });
        },
      });

      if (results?.[0]?.result) {
        allLinks = results[0].result;
        renderLinks();
        if (statusEl) statusEl.textContent = '提取完成，共 ' + allLinks.length + ' 个链接';
        utils.showToast('提取完成', 'success');
        chrome.storage.local.set({ allLinks: allLinks, allLinksUrl: tab.url });
      }
    } catch (e) {
      var errEl = utils.get('links-count');
      if (errEl) errEl.textContent = '提取失败: ' + e.message;
      utils.showToast('提取失败', 'error');
    }
  }

  function getFilteredLinks() {
    const utils = getUtils();
    const filterEl = utils.get('links-filter');
    const filterTypeEl = utils.get('links-filter-type');
    const filterText = filterEl ? filterEl.value.trim().toLowerCase() : '';
    const filterType = filterTypeEl ? filterTypeEl.value : 'all';

    return allLinks.filter(link => {
      if (filterType !== 'all' && link.tag !== filterType && filterType !== 'script') return false;
      if (filterType === 'script' && !link.isJS && link.tag !== 'script') return false;
      if (filterType === 'external' && !link.isExternal) return false;
      if (filterType === 'internal' && link.isExternal) return false;
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

  function renderLinks() {
    const utils = getUtils();
    const filtered = getFilteredLinks();
    const container = utils.get('links-results');
    const countEl = utils.get('links-count');
    if (!container) return;

    const existingText = countEl ? countEl.textContent : '';
    if (countEl && !existingText.includes('正在')) {
      countEl.textContent = '显示 ' + filtered.length + ' / ' + allLinks.length + ' 个链接';
    }

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">没有匹配的链接</div>';
      return;
    }

    let html = '';
    filtered.forEach(link => {
      const tagClass = 'tag-' + link.tag;
      html += '<div class="link-item">';
      html += '<span class="link-item-tag ' + tagClass + '">' + link.tag + '</span>';
      html += '<span class="link-item-text">';
      html +=
        '<span class="link-item-href" title="' +
        utils.escapeHtml(link.href) +
        '">' +
        utils.escapeHtml(link.href) +
        '</span>';
      if (link.domain)
        html +=
          '<span class="link-item-domain">' +
          utils.escapeHtml(link.domain) +
          (link.text ? ' - ' + utils.escapeHtml(link.text) : '') +
          '</span>';
      html += '</span>';
      html +=
        '<button class="link-item-copy" data-href="' +
        utils.escapeHtml(link.href) +
        '">复制</button>';
      html += '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.link-item-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.copyText(btn.dataset.href);
        utils.showToast('已复制', 'success');
      });
    });
  }

  return {
    extractLinks,
    getFilteredLinks,
    renderLinks,
    get allLinks() {
      return allLinks;
    },
    set allLinks(v) {
      allLinks = v;
    },
  };
})();
