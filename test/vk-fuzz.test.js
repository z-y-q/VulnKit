import { describe, it, expect } from '@jest/globals';
import {
  extractHeader,
  extractContentLength,
  analyzeContent,
  formatSize,
} from '../src/popup/vk-fuzz.js';

// ---------------------------------------------------------------------------
// extractHeader
// ---------------------------------------------------------------------------
describe('extractHeader', () => {
  it('returns empty string for null headers', () => {
    expect(extractHeader(null, 'content-type')).toBe('');
  });

  it('returns empty string for undefined headers', () => {
    expect(extractHeader(undefined, 'content-type')).toBe('');
  });

  it('extracts from array format [{name, value}]', () => {
    var headers = [
      { name: 'Content-Type', value: 'text/html' },
      { name: 'Content-Length', value: '1234' },
    ];
    expect(extractHeader(headers, 'content-type')).toBe('text/html');
    expect(extractHeader(headers, 'content-length')).toBe('1234');
  });

  it('returns empty when header not found in array', () => {
    var headers = [{ name: 'Content-Type', value: 'text/html' }];
    expect(extractHeader(headers, 'x-missing')).toBe('');
  });

  it('extracts from object format (tries exact key, then lowercase fallback)', () => {
    var headers = { 'content-type': 'application/json', 'X-Custom': 'val' };
    expect(extractHeader(headers, 'content-type')).toBe('application/json');
    expect(extractHeader(headers, 'X-Custom')).toBe('val');
    // lowercase fallback: tries headers['x-custom'] which doesn't exist
    expect(extractHeader(headers, 'x-custom')).toBe('');
  });

  it('returns empty when header not found in object', () => {
    expect(extractHeader({}, 'x-missing')).toBe('');
  });

  it('is case-insensitive when name param is lowercase', () => {
    var headers = [{ name: 'Server', value: 'nginx' }];
    expect(extractHeader(headers, 'server')).toBe('nginx');
  });

  it('does not match uppercase name param against lowercase header name in array', () => {
    var headers = [{ name: 'server', value: 'nginx' }];
    expect(extractHeader(headers, 'SERVER')).toBe('');
  });

  it('returns empty string for empty value', () => {
    var headers = [{ name: 'X-Empty', value: '' }];
    expect(extractHeader(headers, 'x-empty')).toBe('');
  });
});

// ---------------------------------------------------------------------------
// extractContentLength
// ---------------------------------------------------------------------------
describe('extractContentLength', () => {
  it('parses Content-Length from array headers', () => {
    var headers = [{ name: 'Content-Length', value: '2048' }];
    expect(extractContentLength(headers)).toBe(2048);
  });

  it('returns 0 when Content-Length is missing', () => {
    expect(extractContentLength([])).toBe(0);
  });

  it('returns 0 for null headers', () => {
    expect(extractContentLength(null)).toBe(0);
  });

  it('parses from object headers (lowercase key)', () => {
    expect(extractContentLength({ 'content-length': '4096' })).toBe(4096);
  });
});

// ---------------------------------------------------------------------------
// analyzeContent
// ---------------------------------------------------------------------------
describe('analyzeContent', () => {
  it('returns null for null body', () => {
    expect(analyzeContent(null)).toBeNull();
  });

  it('returns null for undefined body', () => {
    expect(analyzeContent(undefined)).toBeNull();
  });

  it('returns null for short strings (< 10 chars)', () => {
    expect(analyzeContent('short')).toBeNull();
  });

  it('extracts title from HTML', () => {
    var body = '<html><head><title>Login Page</title></head><body>content here</body></html>';
    var result = analyzeContent(body);
    expect(result).not.toBeNull();
    expect(result.title).toBe('Login Page');
  });

  it('detects login page tag', () => {
    var body = '<html><body><h1>Please sign in to continue</h1></body></html>';
    var result = analyzeContent(body);
    expect(result).not.toBeNull();
    expect(result.tags).toContain('登录页面');
  });

  it('detects admin/dashboard tag', () => {
    var body = '<html><body>Welcome to the admin dashboard panel</body></html>';
    var result = analyzeContent(body);
    expect(result).not.toBeNull();
    expect(result.tags).toContain('管理界面');
  });

  it('detects Spring framework', () => {
    var body = '<html><body><p>Powered by Spring Framework</p></body></html>';
    var result = analyzeContent(body);
    expect(result.tags).toContain('Spring');
  });

  it('detects WAF/blocking', () => {
    var body = '<html><body><p>Request blocked by WAF firewall</p></body></html>';
    var result = analyzeContent(body);
    expect(result.tags).toContain('WAF');
  });

  it('deduplicates tags', () => {
    var body = '<html><body>swagger API endpoint and openapi docs</body></html>';
    var result = analyzeContent(body);
    var apiDocCount = result.tags.filter(function (t) {
      return t === 'API文档';
    }).length;
    expect(apiDocCount).toBe(1);
  });

  it('returns empty tags for body with no pattern matches', () => {
    var body = 'AAAAAAAAAAAAAAAAA'; // 17 chars, no pattern matches
    var result = analyzeContent(body);
    expect(result).not.toBeNull();
    expect(result.title).toBe('');
    expect(result.tags).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// formatSize
// ---------------------------------------------------------------------------
describe('formatSize', () => {
  it('formats bytes below 1024', () => {
    expect(formatSize(512)).toBe('512B');
  });

  it('formats 0 bytes', () => {
    expect(formatSize(0)).toBe('0B');
  });

  it('formats exactly 1024 as B (strict greater-than)', () => {
    expect(formatSize(1024)).toBe('1024B');
  });

  it('formats 2048 as KB', () => {
    expect(formatSize(2048)).toBe('2.0K');
  });

  it('formats 1536 as KB with decimal', () => {
    expect(formatSize(1536)).toBe('1.5K');
  });

  it('formats large values', () => {
    expect(formatSize(1048576)).toBe('1024.0K');
  });
});
