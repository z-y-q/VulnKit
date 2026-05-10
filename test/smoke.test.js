import { describe, it, expect } from '@jest/globals';

describe('smoke test', () => {
  it('jsdom works', () => {
    expect(document).toBeDefined();
    expect(document.createElement).toBeDefined();
  });

  it('chrome mock works', () => {
    expect(global.chrome).toBeDefined();
    expect(global.chrome.tabs.query).toBeDefined();
    expect(global.chrome.storage.local.get).toBeDefined();
  });
});
