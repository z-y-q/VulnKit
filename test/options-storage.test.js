import { describe, it, expect } from '@jest/globals';

// We test the pure logic by importing the constants/functions directly.
// options-storage.js uses globals (escapeHtml, showStatus, etc.) so we test
// extractable logic here rather than importing the module directly.

// ====== formatBytes (same logic as options-storage.js) ======
const KB = 1024;
const MB = KB * KB;

function formatBytes(bytes) {
  if (bytes < KB) return bytes + ' B';
  if (bytes < MB) return (bytes / KB).toFixed(1) + ' KB';
  return (bytes / MB).toFixed(2) + ' MB';
}

// ====== FULL_BACKUP_SCHEMA validation logic ======
const FULL_BACKUP_SCHEMA = {
  pentestSettings: 'object',
  pentest_keys: 'object',
  haeRules: 'object',
  gatherData: 'object',
  gatherDataUrl: 'string',
  gatherDataTabs: 'string',
  gatherDataTime: 'string',
  allLinks: 'object',
  allLinksUrl: 'string',
  pentest_spoof: 'object',
  pentest_ui_state: 'object',
  remotePayloads: 'object',
  payloadRemoteUrl: 'string',
  payloadVersion: 'string',
};

const TRANSIENT_KEYS = [
  'contextExtractedLinks',
  'contextExtractedUrl',
  'contextSelection',
  'contextAction',
  'contextExtractUrl',
  'exif_pending_url',
  'ruoyiHookTabId',
  'ruoyiHookEnabled',
  'ruoyiHookOrigin',
  'js_blocked_tabId',
  'permInterceptTabId',
];

function validateImportData(data) {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return { error: '需要 JSON 对象' };
  }
  const cleaned = {};
  let imported = 0;
  let skipped = 0;
  for (const key in data) {
    if (!data.hasOwnProperty(key)) continue;
    if (!FULL_BACKUP_SCHEMA[key]) {
      skipped++;
      continue;
    }
    if (data[key] === null || typeof data[key] !== FULL_BACKUP_SCHEMA[key]) {
      skipped++;
      continue;
    }
    cleaned[key] = data[key];
    imported++;
  }
  return { cleaned, imported, skipped };
}

function filterTransientKeys(allData) {
  const result = {};
  for (const key in allData) {
    if (!allData.hasOwnProperty(key)) continue;
    if (TRANSIENT_KEYS.indexOf(key) !== -1) continue;
    result[key] = allData[key];
  }
  return result;
}

// ---------------------------------------------------------------------------
// formatBytes
// ---------------------------------------------------------------------------
describe('formatBytes', () => {
  it('returns bytes for values under 1 KB', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1023)).toBe('1023 B');
  });

  it('returns KB for values between 1 KB and 1 MB', () => {
    expect(formatBytes(1024)).toBe('1.0 KB');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(1048575)).toBe('1024.0 KB');
  });

  it('returns MB for values >= 1 MB', () => {
    expect(formatBytes(1048576)).toBe('1.00 MB');
    expect(formatBytes(2097152)).toBe('2.00 MB');
    expect(formatBytes(5242880)).toBe('5.00 MB');
  });
});

// ---------------------------------------------------------------------------
// validateImportData
// ---------------------------------------------------------------------------
describe('validateImportData', () => {
  it('rejects non-object input', () => {
    expect(validateImportData(null).error).toBeDefined();
    expect(validateImportData('string').error).toBeDefined();
    expect(validateImportData([1, 2]).error).toBeDefined();
    expect(validateImportData(42).error).toBeDefined();
  });

  it('accepts valid backup data', () => {
    const data = {
      pentestSettings: { theme: 'dark' },
      gatherDataUrl: 'https://example.com',
    };
    const result = validateImportData(data);
    expect(result.imported).toBe(2);
    expect(result.skipped).toBe(0);
    expect(result.cleaned.pentestSettings).toEqual({ theme: 'dark' });
  });

  it('skips unknown keys', () => {
    const data = {
      pentestSettings: {},
      unknownKey: 'value',
      __proto__: {},
    };
    const result = validateImportData(data);
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(1);
  });

  it('skips keys with wrong type', () => {
    const data = {
      pentestSettings: 'not-an-object',
      gatherDataUrl: 123,
    };
    const result = validateImportData(data);
    expect(result.imported).toBe(0);
    expect(result.skipped).toBe(2);
  });

  it('skips null values', () => {
    const data = {
      pentestSettings: null,
    };
    const result = validateImportData(data);
    expect(result.imported).toBe(0);
    expect(result.skipped).toBe(1);
  });

  it('imports all valid keys with correct types', () => {
    const data = {
      pentestSettings: {},
      pentest_keys: {},
      haeRules: {},
      gatherData: {},
      gatherDataUrl: 'url',
      gatherDataTabs: 'tabs',
      gatherDataTime: 'time',
      allLinks: {},
      allLinksUrl: 'url',
      pentest_spoof: {},
      pentest_ui_state: {},
      remotePayloads: {},
      payloadRemoteUrl: 'url',
      payloadVersion: '1.0',
    };
    const result = validateImportData(data);
    expect(result.imported).toBe(14);
    expect(result.skipped).toBe(0);
  });

  it('returns empty result for empty object', () => {
    const result = validateImportData({});
    expect(result.imported).toBe(0);
    expect(result.skipped).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// filterTransientKeys
// ---------------------------------------------------------------------------
describe('filterTransientKeys', () => {
  it('removes all transient keys', () => {
    const data = {
      pentestSettings: { theme: 'dark' },
      contextExtractedLinks: ['link1'],
      contextExtractedUrl: 'https://example.com',
      contextSelection: 'text',
      contextAction: 'copy',
      ruoyiHookTabId: 42,
      js_blocked_tabId: 99,
    };
    const result = filterTransientKeys(data);
    expect(Object.keys(result)).toEqual(['pentestSettings']);
  });

  it('returns all keys when none are transient', () => {
    const data = {
      pentestSettings: {},
      gatherData: {},
      allLinks: {},
    };
    const result = filterTransientKeys(data);
    expect(Object.keys(result)).toEqual(['pentestSettings', 'gatherData', 'allLinks']);
  });

  it('returns empty object for empty input', () => {
    expect(Object.keys(filterTransientKeys({}))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// FULL_BACKUP_SCHEMA completeness
// ---------------------------------------------------------------------------
describe('FULL_BACKUP_SCHEMA', () => {
  it('has all expected keys', () => {
    const expectedKeys = [
      'pentestSettings', 'pentest_keys', 'haeRules',
      'gatherData', 'gatherDataUrl', 'gatherDataTabs', 'gatherDataTime',
      'allLinks', 'allLinksUrl', 'pentest_spoof', 'pentest_ui_state',
      'remotePayloads', 'payloadRemoteUrl', 'payloadVersion',
    ];
    expect(Object.keys(FULL_BACKUP_SCHEMA).sort()).toEqual(expectedKeys.sort());
  });

  it('all values are valid typeof strings', () => {
    const validTypes = ['string', 'number', 'boolean', 'object', 'function', 'undefined'];
    for (const key in FULL_BACKUP_SCHEMA) {
      expect(validTypes).toContain(FULL_BACKUP_SCHEMA[key]);
    }
  });
});
