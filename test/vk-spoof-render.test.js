import { describe, it, expect, beforeEach, afterEach, vi } from '@jest/globals';
import { utils } from '../src/popup/vk-namespace.js';
import {
  renderUaList,
  updateUaStatus,
  renderCookieList,
  spoofState,
} from '../src/popup/vk-spoof.js';

function createEl(id) {
  const el = document.createElement('div');
  el.id = id;
  document.body.appendChild(el);
  return el;
}

describe('renderUaList', () => {
  let container, customGroup, customInput;

  beforeEach(() => {
    utils.cache.clear();
    container = createEl('ua-list');
    customGroup = createEl('ua-custom-group');
    customInput = createEl('ua-custom-input');
    spoofState.ua.current = '';
  });

  afterEach(() => {
    container.remove();
    customGroup.remove();
    customInput.remove();
  });

  it('renders ua-card for each preset in category', () => {
    renderUaList('mobile');
    const cards = container.querySelectorAll('.ua-card');
    expect(cards.length).toBeGreaterThan(0);
  });

  it('marks matching preset as ua-selected', () => {
    const presets = require('../src/popup/vk-spoof.js').UA_PRESETS;
    if (presets.desktop && presets.desktop.length > 0) {
      spoofState.ua.current = presets.desktop[0].value;
      renderUaList('desktop');
      const firstCard = container.querySelector('.ua-card');
      expect(firstCard.classList.contains('ua-selected')).toBe(true);
    }
  });

  it('renders copy button with COPY_SVG in each card', () => {
    renderUaList('mobile');
    const copyBtns = container.querySelectorAll('.ua-copy-btn');
    expect(copyBtns.length).toBeGreaterThan(0);
    expect(copyBtns[0].innerHTML).toContain('<svg');
  });

  it('copy button has data-copy attribute with UA value', () => {
    const presets = require('../src/popup/vk-spoof.js').UA_PRESETS;
    if (presets.mobile && presets.mobile.length > 0) {
      renderUaList('mobile');
      const firstBtn = container.querySelector('.ua-copy-btn');
      expect(firstBtn.getAttribute('data-copy')).toBe(presets.mobile[0].value);
    }
  });

  it('hides custom group for non-custom categories', () => {
    renderUaList('mobile');
    expect(customGroup.classList.contains('hidden')).toBe(true);
  });

  it('shows custom group and clears container for custom category', () => {
    renderUaList('custom');
    expect(customGroup.classList.contains('hidden')).toBe(false);
    expect(container.innerHTML).toBe('');
  });

  it('clicking a card sets ua-custom-input value and marks selected', () => {
    renderUaList('desktop');
    const cards = container.querySelectorAll('.ua-card');
    if (cards.length > 0) {
      const firstCard = cards[0];
      const idx = parseInt(firstCard.dataset.idx, 10);
      firstCard.click();
      const presets = require('../src/popup/vk-spoof.js').UA_PRESETS.desktop;
      expect(customInput.value).toBe(presets[idx].value);
      expect(firstCard.classList.contains('ua-selected')).toBe(true);
    }
  });

  it('clicking a card deselects other cards', () => {
    renderUaList('desktop');
    const cards = container.querySelectorAll('.ua-card');
    if (cards.length >= 2) {
      cards[0].click();
      cards[1].click();
      expect(cards[0].classList.contains('ua-selected')).toBe(false);
      expect(cards[1].classList.contains('ua-selected')).toBe(true);
    }
  });

  it('returns early when container is missing', () => {
    container.remove();
    expect(() => renderUaList('mobile')).not.toThrow();
  });

  it('renders empty state for category with no presets', () => {
    renderUaList('nonexistent');
    expect(container.innerHTML).toContain('无预设项');
  });
});

describe('updateUaStatus', () => {
  let statusEl;

  beforeEach(() => {
    utils.cache.clear();
    statusEl = createEl('spoof-ua-status');
  });

  afterEach(() => {
    statusEl.remove();
  });

  it('shows active status when UA spoofing is enabled', () => {
    spoofState.ua.enabled = true;
    updateUaStatus();
    expect(statusEl.innerHTML).toContain('UA 伪造已启用');
    expect(statusEl.innerHTML).toContain('spoof-status-active');
  });

  it('shows empty when UA spoofing is disabled', () => {
    spoofState.ua.enabled = false;
    updateUaStatus();
    expect(statusEl.innerHTML).toBe('');
  });

  it('returns early when element is missing', () => {
    statusEl.remove();
    expect(() => updateUaStatus()).not.toThrow();
  });
});

describe('renderCookieList', () => {
  let listEl;

  beforeEach(() => {
    utils.cache.clear();
    listEl = createEl('cookie-list');
  });

  afterEach(() => {
    listEl.remove();
  });

  it('renders empty state when no cookies', () => {
    renderCookieList([], 'example.com');
    expect(listEl.innerHTML).toContain('当前域名无 Cookie');
  });

  it('renders stat-badge with cookie count', () => {
    renderCookieList(
      [{ name: 'sid', value: 'abc123', domain: '.example.com', path: '/' }],
      'example.com'
    );
    expect(listEl.innerHTML).toContain('stat-badge stat-total');
    expect(listEl.innerHTML).toContain('共 1 个 Cookie');
  });

  it('renders cookie-card for each cookie', () => {
    renderCookieList(
      [
        { name: 'sid', value: 'abc123', domain: '.example.com', path: '/' },
        { name: 'token', value: 'xyz', domain: '.example.com', path: '/' },
      ],
      'example.com'
    );
    const cards = listEl.querySelectorAll('.cookie-card');
    expect(cards.length).toBe(2);
  });

  it('renders cookie name and value', () => {
    renderCookieList(
      [{ name: 'session', value: 'secret-value', domain: '.example.com', path: '/' }],
      'example.com'
    );
    expect(listEl.innerHTML).toContain('session');
    expect(listEl.innerHTML).toContain('secret-value');
  });

  it('renders HttpOnly and Secure badges when applicable', () => {
    renderCookieList(
      [
        {
          name: 'sid',
          value: 'v',
          domain: '.example.com',
          path: '/',
          httpOnly: true,
          secure: true,
        },
      ],
      'example.com'
    );
    expect(listEl.innerHTML).toContain('HttpOnly');
    expect(listEl.innerHTML).toContain('Secure');
  });

  it('renders sameSite badge', () => {
    renderCookieList(
      [{ name: 'sid', value: 'v', domain: '.example.com', path: '/', sameSite: 'Strict' }],
      'example.com'
    );
    expect(listEl.innerHTML).toContain('Strict');
  });

  it('renders copy button with COPY_SVG', () => {
    renderCookieList(
      [{ name: 'sid', value: 'abc', domain: '.example.com', path: '/' }],
      'example.com'
    );
    const copyBtn = listEl.querySelector('.cookie-copy-btn');
    expect(copyBtn).not.toBeNull();
    expect(copyBtn.innerHTML).toContain('<svg');
    expect(copyBtn.getAttribute('data-copy')).toBe('sid=abc');
  });

  it('renders edit and delete action buttons', () => {
    renderCookieList(
      [{ name: 'sid', value: 'v', domain: '.example.com', path: '/' }],
      'example.com'
    );
    const editBtn = listEl.querySelector('.cookie-edit-btn');
    const deleteBtn = listEl.querySelector('.cookie-delete-btn');
    expect(editBtn).not.toBeNull();
    expect(deleteBtn).not.toBeNull();
    expect(editBtn.textContent).toBe('编辑');
    expect(deleteBtn.textContent).toBe('删除');
  });

  it('escapes HTML in cookie values', () => {
    renderCookieList(
      [{ name: 'xss', value: '<script>alert(1)</script>', domain: '.example.com', path: '/' }],
      'example.com'
    );
    const valueEl = listEl.querySelector('.cookie-card-value');
    expect(valueEl.textContent).toContain('<script>alert(1)</script>');
    expect(listEl.querySelectorAll('script').length).toBe(0);
  });

  it('truncates long cookie values in display', () => {
    const longVal = 'a'.repeat(100);
    renderCookieList(
      [{ name: 'data', value: longVal, domain: '.example.com', path: '/' }],
      'example.com'
    );
    const valueEl = listEl.querySelector('.cookie-card-value');
    expect(valueEl.textContent.length).toBeLessThan(longVal.length);
    expect(valueEl.getAttribute('title')).toBe(longVal);
  });

  it('returns early when container is missing', () => {
    listEl.remove();
    expect(() => renderCookieList([{ name: 'x', value: 'y' }], 'example.com')).not.toThrow();
  });
});
