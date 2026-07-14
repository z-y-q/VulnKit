// Test setup — Chrome API mocks
import { vi } from 'vitest';

// Mock browser namespace (Chrome 148+ cross-browser alias)
(globalThis as any).browser = {
  runtime: {
    sendMessage: vi.fn(),
    onMessage: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
    openOptionsPage: vi.fn(),
    getURL: vi.fn((path: string) => `chrome-extension://test-id/${path}`),
    getPlatformInfo: vi.fn(() => Promise.resolve({ os: 'mac', arch: 'arm' })),
  },
  tabs: {
    query: vi.fn(() => Promise.resolve([{ id: 1, url: 'https://example.com' }])),
    sendMessage: vi.fn(),
  },
  storage: {
    local: {
      get: vi.fn(() => Promise.resolve({})),
      set: vi.fn(() => Promise.resolve()),
      remove: vi.fn(() => Promise.resolve()),
    },
    session: {
      get: vi.fn(() => Promise.resolve({})),
      set: vi.fn(() => Promise.resolve()),
    },
    onChanged: {
      addListener: vi.fn(),
    },
  },
  sidePanel: {
    open: vi.fn(() => Promise.resolve()),
  },
} as any;

// jsdom 未实现 matchMedia（stores/ui.ts themeStore 初始化用到）
if (typeof window !== 'undefined' && !window.matchMedia) {
  (window as any).matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}

// Mock TextEncoder/TextDecoder
if (typeof TextEncoder === 'undefined') {
  (globalThis as any).TextEncoder = class {
    encode(str: string) {
      return new Uint8Array(Buffer.from(str, 'utf-8'));
    }
  };
}
if (typeof TextDecoder === 'undefined') {
  (globalThis as any).TextDecoder = class {
    decode(buf: Uint8Array) {
      return Buffer.from(buf).toString('utf-8');
    }
  };
}
