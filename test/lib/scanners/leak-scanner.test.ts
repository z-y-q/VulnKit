import { describe, it, expect } from 'vitest';
import {
  scanLeaks,
  getLeakRuleCount,
  severityRank,
  toSimpleSeverity,
  type LeakSeverity,
} from '@/lib/scanners/leak-scanner';

describe('leak-scanner: 规则编译', () => {
  it('共 90 条规则预编译（cloud 38 + crypto 22 + exposure 30）', () => {
    expect(getLeakRuleCount()).toBe(90);
  });
});

describe('leak-scanner: 真阳性', () => {
  it('AWS Access Key ID', () => {
    const findings = scanLeaks('accessKeyId: "AKIAIOSFODNN7EXAMPLE"');
    const f = findings.find((x) => x.ruleId === 'aws-access-key-id');
    expect(f).toBeTruthy();
    expect(f!.value).toBe('AKIAIOSFODNN7EXAMPLE');
  });
  it('GitHub Token', () => {
    const findings = scanLeaks('token = "ghp_0123456789012345678901234567890123456"');
    expect(findings.some((x) => x.ruleId === 'github-token')).toBe(true);
  });
  it('内部 IP', () => {
    const findings = scanLeaks('server at 192.168.1.100 reachable');
    expect(findings.some((x) => x.ruleId === 'internal-ip')).toBe(true);
  });
  it('PEM 私钥头', () => {
    const findings = scanLeaks('-----BEGIN RSA PRIVATE KEY-----\nMIIE...');
    expect(findings.some((x) => x.ruleId === 'pem-private-key')).toBe(true);
  });
  it('JWT', () => {
    const findings = scanLeaks('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMiJ9.SflKxwRJSMeKKF2QT4f');
    expect(findings.some((x) => x.ruleId === 'jwt-token')).toBe(true);
  });
  it('Source Mapping URL', () => {
    const findings = scanLeaks('//# sourceMappingURL=app.js.map');
    expect(findings.some((x) => x.ruleId === 'source-map-reference')).toBe(true);
  });
});

describe('leak-scanner: placeholder 过滤', () => {
  it('AWS secret 全相同字符（占位符）被过滤', () => {
    // 40 个 a：匹配 aws-secret-access-key 正则，但 isPlaceholder(全相同) → 丢弃
    const findings = scanLeaks('aws_secret_access_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"');
    expect(findings.some((x) => x.ruleId === 'aws-secret-access-key')).toBe(false);
  });
  it('AWS secret 真实高熵值保留', () => {
    const findings = scanLeaks('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"');
    expect(findings.some((x) => x.ruleId === 'aws-secret-access-key')).toBe(true);
  });
});

describe('leak-scanner: 低熵字符串过滤（api-key-header minEntropy≥3.0）', () => {
  it('低熵 API key 被过滤', () => {
    // abcd 循环 4 次 = 16 字符，仅 4 种字符 → 熵 ≈ 2.0 < 3.0
    const findings = scanLeaks("'api-key': 'abcdabcdabcdabcd'");
    expect(findings.some((x) => x.ruleId === 'api-key-header')).toBe(false);
  });
  it('高熵 API key 保留', () => {
    // 16 个不同字符 → 熵 = 4.0 ≥ 3.0
    const findings = scanLeaks("'api-key': 'x9k2m7p4q1r8s3t6'");
    const f = findings.find((x) => x.ruleId === 'api-key-header');
    expect(f).toBeTruthy();
    expect(f!.value).toBe('x9k2m7p4q1r8s3t6');
  });
});

describe('leak-scanner: 信用卡 Luhn 校验', () => {
  it('合法 Visa 测试卡保留', () => {
    const findings = scanLeaks('card: 4111111111111111');
    expect(findings.some((x) => x.ruleId === 'bank-card-number')).toBe(true);
  });
  it('Luhn 不通过的卡号被过滤', () => {
    const findings = scanLeaks('card: 4111111111111112');
    expect(findings.some((x) => x.ruleId === 'bank-card-number')).toBe(false);
  });
});

describe('leak-scanner: 边界长度', () => {
  it('空串 → []', () => {
    expect(scanLeaks('')).toEqual([]);
  });
  it('2 字符 → []（< 4）', () => {
    expect(scanLeaks('ab')).toEqual([]);
  });
  it('3 字符 → []（< 4）', () => {
    expect(scanLeaks('abc')).toEqual([]);
  });
  it('4 字符无匹配 → []', () => {
    expect(scanLeaks('abcd')).toEqual([]);
  });
});

describe('leak-scanner: 重复结果去重', () => {
  it('同一值多次出现只报告一次', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE ... AKIAIOSFODNN7EXAMPLE again';
    const findings = scanLeaks(text).filter((x) => x.ruleId === 'aws-access-key-id');
    expect(findings.length).toBe(1);
  });
  it('不同值各自报告', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE and AKIAABCDEFGHIJKLMNOP';
    const findings = scanLeaks(text).filter((x) => x.ruleId === 'aws-access-key-id');
    expect(findings.length).toBe(2);
  });
});

describe('leak-scanner: 单规则命中上限 cap', () => {
  it('cap=1 时单规则最多 1 条', () => {
    const text = ['AKIAIOSFODNN7EXAMPLE', 'AKIAIABCDEFGHJKLM', 'AKIAIJKLMNOPQRSTUV'].join('\n');
    const findings = scanLeaks(text, 1).filter((x) => x.ruleId === 'aws-access-key-id');
    expect(findings.length).toBe(1);
  });
});

describe('leak-scanner: 严重级别排序', () => {
  it('findings 按 severity 降序', () => {
    // high(AWS key) + info/low(console.log) 同时出现
    const findings = scanLeaks('AKIAIOSFODNN7EXAMPLE\nconsole.log("x")');
    const ranks = findings.map((f) => severityRank(f.severity));
    for (let i = 1; i < ranks.length; i++) {
      expect(ranks[i]).toBeLessThanOrEqual(ranks[i - 1]);
    }
  });
});

describe('leak-scanner: severityRank / toSimpleSeverity', () => {
  it('severityRank 数值正确', () => {
    expect(severityRank('critical')).toBe(5);
    expect(severityRank('high')).toBe(4);
    expect(severityRank('medium')).toBe(3);
    expect(severityRank('low')).toBe(2);
    expect(severityRank('info')).toBe(1);
  });
  const cases: Array<[LeakSeverity, 'high' | 'medium' | 'low']> = [
    ['critical', 'high'],
    ['high', 'high'],
    ['medium', 'medium'],
    ['low', 'low'],
    ['info', 'low'],
  ];
  for (const [s, expected] of cases) {
    it(`toSimpleSeverity(${s}) → ${expected}`, () => {
      expect(toSimpleSeverity(s)).toBe(expected);
    });
  }
});

describe('leak-scanner: 大输入执行时间', () => {
  it('120KB 文本扫描 < 1500ms', () => {
    const big = 'console.log("test");\n'.repeat(5000); // ~120KB
    expect(big.length).toBeGreaterThan(100_000);
    const t0 = performance.now();
    scanLeaks(big);
    const dt = performance.now() - t0;
    expect(dt).toBeLessThan(1500);
  });
  it('无匹配大文本快速返回空', () => {
    const big = 'no secrets here just plain text\n'.repeat(5000);
    const t0 = performance.now();
    const findings = scanLeaks(big);
    const dt = performance.now() - t0;
    expect(findings.length).toBe(0);
    expect(dt).toBeLessThan(1500);
  });
});
