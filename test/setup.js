// test/setup.js -- Chrome API stubs for Jest jsdom environment

const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

const noop = () => {};
const noopResolver = () => Promise.resolve([]);

global.chrome = {
  runtime: {
    sendMessage: noop,
    onMessage: { addListener: noop, removeListener: noop },
    id: 'test-extension-id',
    openOptionsPage: noop,
    getURL: path => `chrome-extension://test-extension-id/${path}`,
  },
  tabs: {
    query: () => Promise.resolve([{ id: 1, url: 'https://example.com' }]),
    get: () => Promise.resolve({ id: 1, url: 'https://example.com' }),
    create: noop,
    sendMessage: noop,
    onUpdated: { addListener: noop, removeListener: noop },
  },
  storage: {
    local: {
      get: () => Promise.resolve({}),
      set: noop,
      remove: noop,
    },
    onChanged: { addListener: noop, removeListener: noop },
  },
  scripting: {
    executeScript: noopResolver,
  },
  cookies: {
    getAll: () => Promise.resolve([]),
    set: noop,
    remove: noop,
  },
  downloads: {
    download: noop,
  },
  action: {
    setBadgeText: noop,
    setBadgeBackgroundColor: noop,
  },
  declarativeNetRequest: {},
  contextMenus: { create: noop, onClicked: { addListener: noop } },
};
