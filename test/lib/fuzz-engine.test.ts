import { describe, it, expect } from 'vitest';
import {
  analyzeContent,
  extractHeader,
  extractContentLength,
  isFoundStatus,
  getWordlist,
  getWordlistKeys,
  CONTENT_PATTERNS,
  FUZZ_SORT_FNS,
} from '@/lib/scanners/fuzz-engine';

describe('fuzz-engine: 字典', () => {
  it('getWordlist 返回指定字典', () => {
    const common = getWordlist('common');
    expect(common.length).toBeGreaterThan(10);
    expect(common).toContain('/admin/');
  });

  it('getWordlistKeys 返回所有字典键', () => {
    const keys = getWordlistKeys();
    expect(keys).toContain('common');
    expect(keys).toContain('backup');
    expect(keys).toContain('sensitive');
    expect(keys.length).toBeGreaterThanOrEqual(3);
  });
});

describe('fuzz-engine: analyzeContent', () => {
  it('识别登录页面', () => {
    const result = analyzeContent('<html><body><form>用户登录 Login</form></body></html>');
    expect(result).not.toBeNull();
    expect(result!.tags).toContain('登录页面');
  });

  it('识别管理界面', () => {
    const result = analyzeContent('<html>admin dashboard 后台管理</html>');
    expect(result!.tags).toContain('管理界面');
  });

  it('提取 title', () => {
    const result = analyzeContent('<html><head><title>Test Page</title></head></html>');
    expect(result!.title).toBe('Test Page');
  });

  it('识别 Spring 框架', () => {
    const result = analyzeContent('Whitelabel Error Page springboot');
    expect(result!.tags).toContain('Spring');
  });

  it('识别 PHPInfo 泄露', () => {
    const result = analyzeContent('<title>phpinfo()</title> PHP Version 8.1');
    expect(result!.tags).toContain('PHPInfo');
  });

  it('识别 swagger API 文档', () => {
    const result = analyzeContent('<div>Swagger UI api-docs openapi</div>');
    expect(result!.tags).toContain('API文档');
  });

  it('识别 403', () => {
    const result = analyzeContent('403 Forbidden');
    expect(result!.tags).toContain('403禁止');
  });

  it('识别敏感信息', () => {
    const result = analyzeContent('password=secret123 token=abc');
    expect(result!.tags).toContain('敏感信息');
  });

  it('过短内容返回 null', () => {
    expect(analyzeContent('short')).toBeNull();
    expect(analyzeContent('')).toBeNull();
  });
});

describe('fuzz-engine: 头提取', () => {
  it('extractHeader 对象格式', () => {
    expect(extractHeader({ 'content-type': 'text/html' }, 'content-type')).toBe('text/html');
  });

  it('extractHeader 数组格式', () => {
    const headers = [{ name: 'Content-Length', value: '1024' }];
    expect(extractHeader(headers, 'content-length')).toBe('1024');
  });

  it('extractContentLength 解析数字', () => {
    expect(extractContentLength({ 'content-length': '2048' })).toBe(2048);
  });

  it('extractContentLength 无值返回 0', () => {
    expect(extractContentLength({})).toBe(0);
  });
});

describe('fuzz-engine: isFoundStatus', () => {
  it('2xx 视为发现', () => {
    expect(isFoundStatus(200)).toBe(true);
    expect(isFoundStatus(204)).toBe(true);
  });

  it('3xx 视为发现', () => {
    expect(isFoundStatus(301)).toBe(true);
    expect(isFoundStatus(302)).toBe(true);
  });

  it('401/403/405 视为发现（路径存在但需认证/禁止）', () => {
    expect(isFoundStatus(401)).toBe(true);
    expect(isFoundStatus(403)).toBe(true);
    expect(isFoundStatus(405)).toBe(true);
  });

  it('404 视为未发现', () => {
    expect(isFoundStatus(404)).toBe(false);
  });

  it('500 视为未发现', () => {
    expect(isFoundStatus(500)).toBe(false);
  });
});

describe('fuzz-engine: 排序', () => {
  const results = [
    { status: 200, size: 100, time: 50 },
    { status: 404, size: 500, time: 20 },
    { status: 301, size: 300, time: 80 },
  ] as any;

  it('按状态码排序', () => {
    const sorted = [...results].sort(FUZZ_SORT_FNS.status);
    expect(sorted[0].status).toBe(200);
    expect(sorted[2].status).toBe(404);
  });

  it('按大小降序排序', () => {
    const sorted = [...results].sort(FUZZ_SORT_FNS.size);
    expect(sorted[0].size).toBe(500);
  });

  it('按时间升序排序', () => {
    const sorted = [...results].sort(FUZZ_SORT_FNS.time);
    expect(sorted[0].time).toBe(20);
  });
});

describe('fuzz-engine: CONTENT_PATTERNS 完整性', () => {
  it('包含所有 group 类型', () => {
    const groups = new Set(CONTENT_PATTERNS.map(p => p.group));
    expect(groups.has('title')).toBe(true);
    expect(groups.has('feature')).toBe(true);
    expect(groups.has('security')).toBe(true);
    expect(groups.has('framework')).toBe(true);
    expect(groups.has('infoleak')).toBe(true);
  });
});
