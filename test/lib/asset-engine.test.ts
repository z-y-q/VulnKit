import { describe, it, expect } from 'vitest';
import {
  buildZoomEyeUrl,
  normalizeResults,
  buildCsv,
  type ZoomEyeResult,
} from '@/lib/scanners/asset-engine';

describe('asset-engine: buildZoomEyeUrl', () => {
  it('host 模式构建正确 URL', () => {
    const url = buildZoomEyeUrl('hostname:example.com', 1, 'host');
    expect(url).toContain('api.zoomeye.org/host/search');
    expect(url).toContain('query=hostname%3Aexample.com');
    expect(url).toContain('page=1');
  });

  it('web 模式构建正确 URL', () => {
    const url = buildZoomEyeUrl('site:example.com', 2, 'web');
    expect(url).toContain('api.zoomeye.org/web/search');
    expect(url).toContain('query=site%3Aexample.com');
    expect(url).toContain('page=2');
  });

  it('query 包含空格正确编码', () => {
    const url = buildZoomEyeUrl('title:"test page"', 1, 'web');
    expect(url).toContain('title%3A%22test');
  });
});

describe('asset-engine: normalizeResults (host)', () => {
  it('解析 host 模式 matches', () => {
    const raw = {
      matches: [
        {
          ip: '1.2.3.4',
          portinfo: { port: 443, service: 'https', banner: 'HTTP/1.1 200 OK' },
          geoinfo: { country: { names: { zh: '中国', en: 'China' } }, city: { names: { zh: '北京', en: 'Beijing' } } },
          webinfo: { title: 'Example' },
          hostname: ['www.example.com'],
        },
      ],
    };
    const results = normalizeResults(raw, 'host');
    expect(results).toHaveLength(1);
    expect(results[0].ip).toBe('1.2.3.4');
    expect(results[0].port).toBe(443);
    expect(results[0].service).toBe('https');
    expect(results[0].hostname).toBe('www.example.com');
    expect(results[0].country).toBe('中国');
    expect(results[0].region).toBe('北京');
    expect(results[0].banner).toBe('HTTP/1.1 200 OK');
    expect(results[0].title).toBe('Example');
  });

  it('缺失字段使用默认值', () => {
    const raw = { matches: [{ ip: '10.0.0.1' }] };
    const results = normalizeResults(raw, 'host');
    expect(results[0].port).toBe(0);
    expect(results[0].service).toBe('-');
    expect(results[0].hostname).toBe('-');
    expect(results[0].country).toBe('-');
  });

  it('支持 data 字段（兼容格式）', () => {
    const raw = {
      data: [
        {
          ip: '5.6.7.8',
          portinfo: { port: 8080, service: 'http' },
          geoinfo: { country: { names: { en: 'US' } }, city: { names: { en: 'New York' } } },
        },
      ],
    };
    const results = normalizeResults(raw, 'host');
    expect(results).toHaveLength(1);
    expect(results[0].ip).toBe('5.6.7.8');
    expect(results[0].port).toBe(8080);
  });
});

describe('asset-engine: normalizeResults (web)', () => {
  it('解析 web 模式 matches', () => {
    const raw = {
      matches: [
        {
          site: 'example.com',
          title: 'Welcome',
          domain: 'example.com',
          ip: ['1.2.3.4', '5.6.7.8'],
          country: '中国',
          city: '上海',
          updated: '2024-01-01',
        },
      ],
    };
    const results = normalizeResults(raw, 'web');
    expect(results).toHaveLength(1);
    expect(results[0].ip).toBe('1.2.3.4');
    expect(results[0].port).toBe(80);
    expect(results[0].hostname).toBe('example.com');
    expect(results[0].title).toBe('Welcome');
    expect(results[0].country).toBe('中国');
    expect(results[0].region).toBe('上海');
  });

  it('web 模式缺失字段使用默认值', () => {
    const raw = { matches: [{}] };
    const results = normalizeResults(raw, 'web');
    expect(results[0].ip).toBe('-');
    expect(results[0].hostname).toBe('-');
    expect(results[0].title).toBe('-');
  });
});

describe('asset-engine: normalizeResults 边界', () => {
  it('null 返回空数组', () => {
    expect(normalizeResults(null, 'host')).toEqual([]);
  });

  it('非对象返回空数组', () => {
    expect(normalizeResults('string', 'web')).toEqual([]);
  });

  it('无 matches/data 返回空数组', () => {
    expect(normalizeResults({}, 'host')).toEqual([]);
  });

  it('matches 非数组返回空数组', () => {
    expect(normalizeResults({ matches: 'bad' }, 'host')).toEqual([]);
  });
});

describe('asset-engine: buildCsv', () => {
  it('生成包含 BOM 的 CSV', () => {
    const results: ZoomEyeResult[] = [
      { ip: '1.2.3.4', port: 443, service: 'https', hostname: 'example.com', country: '中国', region: '北京', banner: 'OK', title: 'Example' },
    ];
    const csv = buildCsv(results);
    expect(csv.startsWith('﻿')).toBe(true);
    expect(csv).toContain('IP');
    expect(csv).toContain('1.2.3.4');
    expect(csv).toContain('Example');
  });

  it('包含列标题（无 Banner 列）', () => {
    const csv = buildCsv([]);
    expect(csv).toContain('IP');
    expect(csv).toContain('端口');
    expect(csv).toContain('服务');
    expect(csv).toContain('主机名');
    expect(csv).toContain('国家');
    expect(csv).toContain('地区');
    expect(csv).toContain('标题');
    // banner 不在 CSV_HEADERS 中，不应出现
    expect(csv).not.toContain('Banner');
  });

  it('转义逗号和引号', () => {
    const results: ZoomEyeResult[] = [
      { ip: '1.2.3.4', port: 443, service: 'https', hostname: 'example, "com"', country: '中国', region: '北京', banner: 'x', title: 'Test, "Case"' },
    ];
    const csv = buildCsv(results);
    // hostname 和 title 含逗号/引号，应被双引号包裹并转义
    expect(csv).toContain('"example, ""com"""');
    expect(csv).toContain('"Test, ""Case"""');
  });
});
