import { describe, it, expect } from 'vitest';
import {
  extractRootDomain,
  buildSubdomainCandidates,
  analyzeDnsResult,
  dedupAliveResults,
  buildStats,
  DNS_RECORD_TYPES,
  SUBDOMAIN_WORDLIST,
  type SubdomainResult,
} from '@/lib/scanners/subdomain-engine';

describe('subdomain-engine: 常量完整性', () => {
  it('DNS_RECORD_TYPES 为非空数组', () => {
    expect(Array.isArray(DNS_RECORD_TYPES)).toBe(true);
    expect(DNS_RECORD_TYPES.length).toBeGreaterThan(0);
  });

  it('DNS_RECORD_TYPES 包含常见类型', () => {
    expect(DNS_RECORD_TYPES).toContain('A');
    expect(DNS_RECORD_TYPES).toContain('AAAA');
    expect(DNS_RECORD_TYPES).toContain('CNAME');
    expect(DNS_RECORD_TYPES).toContain('MX');
    expect(DNS_RECORD_TYPES).toContain('TXT');
    expect(DNS_RECORD_TYPES).toContain('NS');
  });

  it('SUBDOMAIN_WORDLIST 为非空数组', () => {
    expect(Array.isArray(SUBDOMAIN_WORDLIST)).toBe(true);
    expect(SUBDOMAIN_WORDLIST.length).toBeGreaterThan(50);
  });

  it('SUBDOMAIN_WORDLIST 包含基础设施前缀', () => {
    expect(SUBDOMAIN_WORDLIST).toContain('www');
    expect(SUBDOMAIN_WORDLIST).toContain('api');
    expect(SUBDOMAIN_WORDLIST).toContain('dev');
    expect(SUBDOMAIN_WORDLIST).toContain('admin');
    expect(SUBDOMAIN_WORDLIST).toContain('staging');
  });
});

describe('subdomain-engine: extractRootDomain', () => {
  it('普通域名 example.com → example.com', () => {
    expect(extractRootDomain('example.com')).toBe('example.com');
  });

  it('单级子域名 www.example.com → example.com', () => {
    expect(extractRootDomain('www.example.com')).toBe('example.com');
  });

  it('多级子域名 a.b.example.com → example.com', () => {
    expect(extractRootDomain('a.b.example.com')).toBe('example.com');
  });

  it('大小写不敏感', () => {
    expect(extractRootDomain('WWW.Example.COM')).toBe('example.com');
  });

  it('多部分 TLD: example.co.uk → example.co.uk', () => {
    expect(extractRootDomain('example.co.uk')).toBe('example.co.uk');
  });

  it('多部分 TLD 子域名: dev.example.co.uk → example.co.uk', () => {
    expect(extractRootDomain('dev.example.co.uk')).toBe('example.co.uk');
  });

  it('多部分 TLD 深层子域名: a.b.example.co.uk → example.co.uk', () => {
    expect(extractRootDomain('a.b.example.co.uk')).toBe('example.co.uk');
  });

  it('多部分 TLD: example.com.cn → example.com.cn', () => {
    expect(extractRootDomain('example.com.cn')).toBe('example.com.cn');
  });

  it('多部分 TLD 子域名: test.example.com.cn → example.com.cn', () => {
    expect(extractRootDomain('test.example.com.cn')).toBe('example.com.cn');
  });

  it('多部分 TLD: example.com.au → example.com.au', () => {
    expect(extractRootDomain('example.com.au')).toBe('example.com.au');
  });

  it('多部分 TLD: example.ac.uk → example.ac.uk', () => {
    expect(extractRootDomain('example.ac.uk')).toBe('example.ac.uk');
  });

  it('多部分 TLD: example.gov.uk → example.gov.uk', () => {
    expect(extractRootDomain('example.gov.uk')).toBe('example.gov.uk');
  });

  it('纯域名 localhost → localhost', () => {
    expect(extractRootDomain('localhost')).toBe('localhost');
  });
});

describe('subdomain-engine: buildSubdomainCandidates', () => {
  it('生成去重的候选列表', () => {
    const candidates = buildSubdomainCandidates('example.com');
    const fulls = candidates.map(c => c.full);
    const uniqueFulls = new Set(fulls);
    expect(fulls.length).toBe(uniqueFulls.size);
  });

  it('候选数量等于词表大小', () => {
    const candidates = buildSubdomainCandidates('example.com');
    expect(candidates.length).toBe(SUBDOMAIN_WORDLIST.length);
  });

  it('包含 dev.example.com', () => {
    const candidates = buildSubdomainCandidates('example.com');
    expect(candidates.some(c => c.full === 'dev.example.com')).toBe(true);
    expect(candidates.some(c => c.subdomain === 'dev')).toBe(true);
  });

  it('包含 api.example.com', () => {
    const candidates = buildSubdomainCandidates('example.com');
    expect(candidates.some(c => c.full === 'api.example.com')).toBe(true);
  });

  it('包含 admin.example.com', () => {
    const candidates = buildSubdomainCandidates('example.com');
    expect(candidates.some(c => c.full === 'admin.example.com')).toBe(true);
  });

  it('多部分 TLD 也能正确拼接', () => {
    const candidates = buildSubdomainCandidates('dev.example.co.uk');
    // extractRootDomain 先提取根域，再拼接
    expect(candidates.some(c => c.full === 'dev.example.co.uk')).toBe(true);
  });

  it('每个候选都有 subdomain 和 full 字段', () => {
    const candidates = buildSubdomainCandidates('example.com');
    for (const c of candidates) {
      expect(c).toHaveProperty('subdomain');
      expect(c).toHaveProperty('full');
      expect(typeof c.subdomain).toBe('string');
      expect(typeof c.full).toBe('string');
      expect(c.full).toContain('.');
    }
  });
});

describe('subdomain-engine: analyzeDnsResult', () => {
  it('有 addresses 时标记为 alive', () => {
    const result = analyzeDnsResult('dev.example.com', {
      addresses: ['1.2.3.4'],
    });
    expect(result.status).toBe('alive');
    expect(result.ips).toEqual(['1.2.3.4']);
    expect(result.subdomain).toBe('dev.example.com');
  });

  it('有 answers 时标记为 alive', () => {
    const result = analyzeDnsResult('api.example.com', {
      answers: [{ type: 1, data: '5.6.7.8', name: 'api.example.com' }],
    });
    expect(result.status).toBe('alive');
    expect(result.ips).toContain('5.6.7.8');
    expect(result.records).toHaveLength(1);
    expect(result.records[0].type).toBe('A');
  });

  it('空结果标记为 dead', () => {
    const result = analyzeDnsResult('test.example.com', {});
    expect(result.status).toBe('dead');
    expect(result.ips).toEqual([]);
    expect(result.records).toEqual([]);
  });

  it('无 addresses 也无 answers 标记为 dead', () => {
    const result = analyzeDnsResult('ghost.example.com', {
      addresses: [],
      answers: [],
    });
    expect(result.status).toBe('dead');
  });

  it('提取 CNAME 记录', () => {
    const result = analyzeDnsResult('cdn.example.com', {
      answers: [
        { type: 5, data: 'cdn.cloudflare.com', name: 'cdn.example.com' },
      ],
    });
    expect(result.status).toBe('alive');
    expect(result.cname).toBe('cdn.cloudflare.com');
    expect(result.records[0].type).toBe('CNAME');
  });

  it('提取 AAAA 记录的 IP', () => {
    const result = analyzeDnsResult('v6.example.com', {
      answers: [
        { type: 28, data: '2001:db8::1', name: 'v6.example.com' },
      ],
    });
    expect(result.status).toBe('alive');
    expect(result.ips).toContain('2001:db8::1');
    expect(result.records[0].type).toBe('AAAA');
  });

  it('addresses 和 answers 同时存在时 IP 去重', () => {
    const result = analyzeDnsResult('dual.example.com', {
      addresses: ['1.2.3.4'],
      answers: [
        { type: 1, data: '1.2.3.4', name: 'dual.example.com' },
        { type: 1, data: '5.6.7.8', name: 'dual.example.com' },
      ],
    });
    expect(result.ips).toEqual(['1.2.3.4', '5.6.7.8']);
  });

  it('多类型 DNS 记录全部提取', () => {
    const result = analyzeDnsResult('mx.example.com', {
      answers: [
        { type: 15, data: 'mail.example.com', name: 'mx.example.com' },
        { type: 16, data: 'v=spf1 include:_spf.example.com ~all', name: 'mx.example.com' },
      ],
    });
    expect(result.records).toHaveLength(2);
    expect(result.records[0].type).toBe('MX');
    expect(result.records[1].type).toBe('TXT');
  });
});

describe('subdomain-engine: dedupAliveResults', () => {
  it('过滤 dead 结果', () => {
    const results: SubdomainResult[] = [
      { subdomain: 'alive.example.com', ips: ['1.2.3.4'], records: [], status: 'alive' },
      { subdomain: 'dead.example.com', ips: [], records: [], status: 'dead' },
    ];
    const deduped = dedupAliveResults(results);
    expect(deduped).toHaveLength(1);
    expect(deduped[0].subdomain).toBe('alive.example.com');
  });

  it('按 subdomain 去重', () => {
    const results: SubdomainResult[] = [
      { subdomain: 'api.example.com', ips: ['1.1.1.1'], records: [], status: 'alive' },
      { subdomain: 'api.example.com', ips: ['2.2.2.2'], records: [], status: 'alive' },
    ];
    const deduped = dedupAliveResults(results);
    expect(deduped).toHaveLength(1);
    // 保留第一个出现的
    expect(deduped[0].ips).toEqual(['1.1.1.1']);
  });

  it('按 subdomain 字母排序', () => {
    const results: SubdomainResult[] = [
      { subdomain: 'charlie.example.com', ips: ['1.1.1.1'], records: [], status: 'alive' },
      { subdomain: 'alpha.example.com', ips: ['2.2.2.2'], records: [], status: 'alive' },
      { subdomain: 'bravo.example.com', ips: ['3.3.3.3'], records: [], status: 'alive' },
    ];
    const deduped = dedupAliveResults(results);
    expect(deduped[0].subdomain).toBe('alpha.example.com');
    expect(deduped[1].subdomain).toBe('bravo.example.com');
    expect(deduped[2].subdomain).toBe('charlie.example.com');
  });

  it('空数组返回空', () => {
    expect(dedupAliveResults([])).toEqual([]);
  });

  it('全部 dead 返回空', () => {
    const results: SubdomainResult[] = [
      { subdomain: 'dead1.example.com', ips: [], records: [], status: 'dead' },
      { subdomain: 'dead2.example.com', ips: [], records: [], status: 'dead' },
    ];
    expect(dedupAliveResults(results)).toEqual([]);
  });
});

describe('subdomain-engine: buildStats', () => {
  it('统计总数、存活、死亡', () => {
    const results: SubdomainResult[] = [
      { subdomain: 'a', ips: ['1.1.1.1'], records: [], status: 'alive' },
      { subdomain: 'b', ips: [], records: [], status: 'dead' },
      { subdomain: 'c', ips: ['2.2.2.2'], records: [], status: 'alive' },
    ];
    const stats = buildStats(results, 1234);
    expect(stats.total).toBe(3);
    expect(stats.alive).toBe(2);
    expect(stats.dead).toBe(1);
    expect(stats.elapsed).toBe(1234);
  });

  it('空结果 total=0, alive=0, dead=0', () => {
    const stats = buildStats([], 0);
    expect(stats.total).toBe(0);
    expect(stats.alive).toBe(0);
    expect(stats.dead).toBe(0);
  });

  it('全部存活 dead=0', () => {
    const results: SubdomainResult[] = [
      { subdomain: 'a', ips: ['1.1.1.1'], records: [], status: 'alive' },
      { subdomain: 'b', ips: ['2.2.2.2'], records: [], status: 'alive' },
    ];
    const stats = buildStats(results, 500);
    expect(stats.dead).toBe(0);
    expect(stats.alive).toBe(2);
  });

  it('elapsed 保留原始值', () => {
    const stats = buildStats([], 99);
    expect(stats.elapsed).toBe(99);
  });
});
