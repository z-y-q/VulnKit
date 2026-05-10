import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { utils } from '../src/popup/vk-namespace.js';
import {
  renderXssPoints,
  xssPoints,
  xssFilterType,
  xssSearchText,
  setXssFilterType,
  setXssSearchText,
} from '../src/popup/vk-xss.js';

function createEl(id) {
  const el = document.createElement('div');
  el.id = id;
  document.body.appendChild(el);
  return el;
}

describe('renderXssPoints', () => {
  let resultsEl, countEl;

  beforeEach(() => {
    utils.cache.clear();
    resultsEl = createEl('xssscan-results');
    countEl = createEl('xssscan-count');
    xssPoints.length = 0;
    setXssFilterType('all');
    setXssSearchText('');
  });

  afterEach(() => {
    resultsEl.remove();
    countEl.remove();
  });

  it('renders empty state when no points', () => {
    renderXssPoints();
    expect(resultsEl.innerHTML).toContain('暂无注入点');
  });

  it('renders stat-badge with total count', () => {
    xssPoints.push(
      { source: 'link', url: 'https://example.com/?q=1', param: 'q', method: 'GET' },
      { source: 'form', url: 'https://example.com/login', param: 'user', method: 'POST' }
    );
    renderXssPoints();
    expect(countEl.innerHTML).toContain('stat-badge stat-total');
    expect(countEl.innerHTML).toContain('共 2 个注入点');
  });

  it('renders xssscan-card for each filtered point', () => {
    xssPoints.push(
      { source: 'link', url: 'https://example.com/?q=1', param: 'q', method: 'GET' },
      { source: 'form', url: 'https://example.com/login', param: 'user', method: 'POST' }
    );
    renderXssPoints();
    const cards = resultsEl.querySelectorAll('.xssscan-card');
    expect(cards.length).toBe(2);
  });

  it('renders source tag with correct label and color', () => {
    xssPoints.push({ source: 'link', url: 'https://example.com/?q=1', param: 'q', method: 'GET' });
    renderXssPoints();
    const tag = resultsEl.querySelector('.xssscan-source-tag');
    expect(tag.textContent).toBe('链接');
    expect(tag.style.background).toBe('rgb(74, 144, 226)');
  });

  it('renders copy button with COPY_SVG inside', () => {
    xssPoints.push({ source: 'link', url: 'https://example.com/?q=1', param: 'q', method: 'GET' });
    renderXssPoints();
    const btn = resultsEl.querySelector('.xssscan-copy-btn');
    expect(btn).not.toBeNull();
    expect(btn.getAttribute('data-copy')).toBe('https://example.com/?q=1');
    expect(btn.innerHTML).toContain('<svg');
  });

  it('renders param and URL in card body', () => {
    xssPoints.push({
      source: 'url',
      url: 'https://example.com/search?q=test',
      param: 'q',
      method: 'GET',
    });
    renderXssPoints();
    expect(resultsEl.innerHTML).toContain('q');
    expect(resultsEl.innerHTML).toContain('https://example.com/search?q=test');
  });

  it('renders check-all checkbox', () => {
    xssPoints.push({ source: 'link', url: 'https://example.com/?q=1', param: 'q', method: 'GET' });
    renderXssPoints();
    const checkAll = resultsEl.querySelector('#xssscan-check-all');
    expect(checkAll).not.toBeNull();
    expect(checkAll.checked).toBe(true);
  });

  it('check-all toggles all point checkboxes', () => {
    xssPoints.push(
      { source: 'link', url: 'https://example.com/?q=1', param: 'q', method: 'GET' },
      { source: 'form', url: 'https://example.com/login', param: 'user', method: 'POST' }
    );
    renderXssPoints();
    const checkAll = resultsEl.querySelector('#xssscan-check-all');
    const pointChecks = resultsEl.querySelectorAll('.xssscan-point-check');
    expect(pointChecks.length).toBe(2);

    checkAll.checked = false;
    checkAll.dispatchEvent(new Event('change'));
    expect(pointChecks[0].checked).toBe(false);
    expect(pointChecks[1].checked).toBe(false);

    checkAll.checked = true;
    checkAll.dispatchEvent(new Event('change'));
    expect(pointChecks[0].checked).toBe(true);
  });

  it('filters by source type', () => {
    xssPoints.push(
      { source: 'link', url: 'https://example.com/?q=1', param: 'q', method: 'GET' },
      { source: 'form', url: 'https://example.com/login', param: 'user', method: 'POST' }
    );
    setXssFilterType('link');
    renderXssPoints();
    const cards = resultsEl.querySelectorAll('.xssscan-card');
    expect(cards.length).toBe(1);
    expect(countEl.innerHTML).toContain('显示 1');
  });

  it('escapes HTML in param and URL text nodes', () => {
    xssPoints.push({
      source: 'link',
      url: 'https://example.com/?q=<script>alert(1)</script>',
      param: 'q"><img>',
      method: 'GET',
    });
    renderXssPoints();
    const paramEl = resultsEl.querySelector('.xssscan-card-param');
    const urlEl = resultsEl.querySelector('.xssscan-card-url');
    expect(paramEl.textContent).toContain('q"><img>');
    expect(urlEl.textContent).toContain('<script>alert(...');
    expect(resultsEl.querySelectorAll('script').length).toBe(0);
    expect(resultsEl.querySelectorAll('img').length).toBe(0);
  });

  it('truncates long URLs in display', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(100) + '?q=1';
    xssPoints.push({ source: 'url', url: longUrl, param: 'q', method: 'GET' });
    renderXssPoints();
    const cardUrl = resultsEl.querySelector('.xssscan-card-url');
    expect(cardUrl.textContent.length).toBeLessThan(longUrl.length);
    expect(cardUrl.getAttribute('title')).toBe(longUrl);
  });

  it('returns early when container is missing', () => {
    resultsEl.remove();
    expect(() => renderXssPoints()).not.toThrow();
  });
});
