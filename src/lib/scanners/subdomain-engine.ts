/**
 * 子域名枚举引擎
 * 从 vk-subdomain.js 提取的纯分析逻辑（不含网络请求与 UI）
 * 网络解析由调用方通过 sendMessage 完成，引擎只负责词表生成、根域提取与结果处理
 */

// ====== 常量 ======

/** DNS 记录类型 */
export const DNS_RECORD_TYPES: string[] = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'TXT',
  'NS',
];

/** 常见子域名前缀词表 (~150 条，覆盖基础设施/业务/DevOps/安全 等) */
export const SUBDOMAIN_WORDLIST: string[] = [
  // Web 服务
  'www',
  'mail',
  'ftp',
  'localhost',
  'admin',
  'portal',
  'api',
  'app',
  'm',
  'mobile',
  'static',
  'assets',
  'img',
  'images',
  'media',
  'upload',
  'download',
  'file',
  'files',
  'res',
  'resource',
  'image',
  'pic',
  'photo',
  'video',
  // 内容
  'blog',
  'forum',
  'wiki',
  'docs',
  'doc',
  'help',
  'support',
  // 业务
  'shop',
  'store',
  'pay',
  'payment',
  'order',
  'cart',
  'billing',
  'shipping',
  'user',
  'member',
  'crm',
  'erp',
  'oa',
  'hr',
  // 基础设施 / DevOps
  'dev',
  'staging',
  'stg',
  'test',
  'uat',
  'prod',
  'pre',
  'release',
  'master',
  'alpha',
  'beta',
  'gamma',
  'v2',
  'v3',
  'api2',
  'old',
  'new',
  'demo',
  'sandbox',
  'preview',
  'internal',
  'intranet',
  'cdn',
  'proxy',
  'gateway',
  'vpn',
  // CI/CD 与代码托管
  'git',
  'svn',
  'jenkins',
  'ci',
  'cd',
  'gitea',
  'drone',
  'harbor',
  'argo',
  'argocd',
  'tekton',
  'flux',
  'spinnaker',
  // 认证
  'auth',
  'sso',
  'login',
  'oauth',
  'ldap',
  // 数据库 & 缓存
  'db',
  'database',
  'redis',
  'mongo',
  'mysql',
  // 监控 & 可观测
  'monitor',
  'grafana',
  'prometheus',
  'kibana',
  'elasticsearch',
  'log',
  'logs',
  'syslog',
  'audit',
  'trace',
  'jaeger',
  'zipkin',
  'tempo',
  'otel',
  'metrics',
  'traces',
  'health',
  'statuspage',
  // 消息队列
  'mq',
  'rabbitmq',
  'kafka',
  'zookeeper',
  // 服务发现 / 配置
  'consul',
  'etcd',
  'nacos',
  'consul-template',
  'nomad',
  // 存储
  'nas',
  'backup',
  'bak',
  'minio',
  'ceph',
  's3',
  'blob',
  'vault',
  'secrets',
  'credentials',
  'keys',
  // 网络 / 安全
  'waf',
  'firewall',
  'pomerium',
  'tailscale',
  'cloudflare',
  // 协议服务
  'smtp',
  'webmail',
  'sip',
  'mqtt',
  'amqp',
  'ws',
  'wss',
  'socket',
  'push',
  'websocket',
  // 搜索 & 通知
  'search',
  'notify',
  'msg',
  // 服务网格
  'istio',
];

// ====== 类型 ======

export interface SubdomainCandidate {
  /** 子域名前缀，如 'api' */
  subdomain: string;
  /** 完整域名，如 'api.example.com' */
  full: string;
}

export interface SubdomainResult {
  subdomain: string;
  ips: string[];
  cname?: string;
  records: { type: string; data: string }[];
  status: 'alive' | 'dead';
  /** 来源：brute=DNS暴力, ct=crt.sh证书透明, wayback=Wayback Machine, page=页面链接 */
  source?: 'brute' | 'ct' | 'wayback' | 'page';
}

// ====== 工具函数 ======

/** 多部分 TLD 列表（用于根域提取） */
const MULTI_PART_TLDS: string[] = [
  'co.uk',
  'com.cn',
  'com.au',
  'com.br',
  'com.mx',
  'co.jp',
  'co.kr',
  'co.in',
  'co.nz',
  'org.cn',
  'net.cn',
  'gov.cn',
  'ac.uk',
  'gov.uk',
  'edu.uk',
  'me.uk',
  'com.tw',
  'org.tw',
  'net.tw',
  'com.hk',
  'org.hk',
  'com.sg',
  'com.my',
  'co.za',
  'co.id',
  'co.th',
  'co.il',
  'com.ph',
  'com.eg',
  'co.ke',
  'com.ar',
  'com.ve',
  'com.co',
  'com.pe',
  'com.cl',
  'com.ec',
  'ne.jp',
  'or.jp',
  'ac.jp',
  'go.jp',
  'org.za',
  'edu.cn',
  'mil.cn',
  'nom.br',
  'adm.br',
  'gov.br',
];

/**
 * 从任意 hostname 提取根域（注册域）。
 * 处理多部分 TLD（如 .co.uk、.com.cn）和普通二部分域名。
 *
 * @example
 * extractRootDomain('api.dev.example.co.uk') // 'example.co.uk'
 * extractRootDomain('www.example.com')       // 'example.com'
 * extractRootDomain('example.com')            // 'example.com'
 */
export function extractRootDomain(hostname: string): string {
  const d = hostname.toLowerCase();
  // 检查多部分 TLD
  for (const suffix of MULTI_PART_TLDS) {
    if (d.endsWith(`.${suffix}`)) {
      const prefix = d.slice(0, -(suffix.length + 1));
      const parts = prefix.split('.');
      return `${parts[parts.length - 1]}.${suffix}`;
    }
  }
  // 普通域名：取最后两部分
  const parts = d.split('.');
  if (parts.length <= 2) return d;
  return parts.slice(-2).join('.');
}

/**
 * 根据词表 + 根域生成子域名候选列表。
 * 去重、过滤根域本身。
 */
export function buildSubdomainCandidates(rootDomain: string): SubdomainCandidate[] {
  const root = extractRootDomain(rootDomain).toLowerCase();
  const candidates: SubdomainCandidate[] = [];
  const seen = new Set<string>();

  for (const prefix of SUBDOMAIN_WORDLIST) {
    const full = `${prefix}.${root}`;
    if (!seen.has(full)) {
      seen.add(full);
      candidates.push({ subdomain: prefix, full });
    }
  }

  return candidates;
}

/**
 * 分析 DNS 解析结果，提取 IP / CNAME / 记录摘要。
 * 纯函数：输入原始 DnsResolveResult，输出 SubdomainResult。
 */
export function analyzeDnsResult(
  hostname: string,
  result: { addresses?: string[]; answers?: { type: number; data: string; name: string }[]; resultCode?: number; error?: string },
): SubdomainResult {
  const ips: string[] = [];
  const records: { type: string; data: string }[] = [];
  let cname: string | undefined;

  // 从 addresses 字段提取 IP
  if (result.addresses && result.addresses.length > 0) {
    ips.push(...result.addresses);
  }

  // 从 answers 字段提取详细信息
  if (result.answers && result.answers.length > 0) {
    for (const ans of result.answers) {
      const typeName = dnsRecordTypeName(ans.type);
      records.push({ type: typeName, data: ans.data });

      if (ans.type === 1 || ans.type === 28) {
        // A=1, AAAA=28
        if (!ips.includes(ans.data)) ips.push(ans.data);
      }
      if (ans.type === 5) {
        // CNAME=5
        cname = ans.data;
      }
    }
  }

  const alive = ips.length > 0 || records.length > 0;

  return {
    subdomain: hostname,
    ips,
    cname,
    records,
    status: alive ? 'alive' : 'dead',
  };
}

/**
 * DNS 记录类型编号 → 名称。
 * 常用: 1=A, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 2=NS
 */
function dnsRecordTypeName(type: number): string {
  const map: Record<number, string> = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
  };
  return map[type] || String(type);
}

/**
 * 对存活子域名结果排序、去重。
 * 返回去重后的 alive 列表（按子域名字母排序）。
 */
export function dedupAliveResults(results: SubdomainResult[]): SubdomainResult[] {
  const seen = new Set<string>();
  const alive = results.filter(r => r.status === 'alive');
  const unique: SubdomainResult[] = [];
  for (const r of alive) {
    if (!seen.has(r.subdomain)) {
      seen.add(r.subdomain);
      unique.push(r);
    }
  }
  return unique.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
}

/**
 * 统计结果汇总（供 UI 展示）。
 */
export interface SubdomainStats {
  total: number;
  alive: number;
  dead: number;
  elapsed: number; // ms
}

export function buildStats(results: SubdomainResult[], elapsedMs: number): SubdomainStats {
  let alive = 0;
  for (const r of results) {
    if (r.status === 'alive') alive++;
  }
  return {
    total: results.length,
    alive,
    dead: results.length - alive,
    elapsed: elapsedMs,
  };
}

// ====== 被动枚举（证书透明 / Wayback）======

/** 生成随机子域名（用于 Wildcard 检测） */
function randomLabel(len = 12): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

/**
 * Wildcard DNS 检测：解析 3 个随机子域名，若全部解析成功则存在泛解析。
 * resolver: hostname -> 是否解析到 IP
 */
export async function detectWildcard(
  rootDomain: string,
  resolver: (host: string) => Promise<boolean>,
): Promise<boolean> {
  const probes = [randomLabel(), randomLabel(), randomLabel()].map(l => `${l}.${rootDomain}`);
  try {
    const results = await Promise.all(probes.map(resolver));
    return results.every(Boolean);
  } catch {
    return false;
  }
}

/** 从 crt.sh JSON 响应提取子域名（去重、限定根域）。 */
export function parseCrtshResponse(jsonText: string, rootDomain: string): string[] {
  try {
    const arr = JSON.parse(jsonText);
    if (!Array.isArray(arr)) return [];
    const root = rootDomain.toLowerCase();
    const found = new Set<string>();
    for (const entry of arr) {
      const name = (entry?.name_value || entry?.common_name || '') as string;
      if (!name) continue;
      // name_value 可能含多行（SAN）
      for (let n of name.split('\n')) {
        n = n.trim().toLowerCase().replace(/^\*\./, '');
        if (n && n.endsWith(root) && n !== root) found.add(n);
      }
    }
    return [...found];
  } catch {
    return [];
  }
}

/** 从 Wayback CDX 响应提取子域名（去重、限定根域）。 */
export function parseWaybackResponse(text: string, rootDomain: string): string[] {
  const root = rootDomain.toLowerCase();
  const found = new Set<string>();
  const lines = text.split('\n');
  for (const line of lines) {
    // CDX 格式: key(timestamp) url ...
    try {
      const parts = line.split(/\s+/);
      const urlStr = parts.find(p => p.startsWith('http')) || parts[2];
      if (!urlStr) continue;
      const host = (() => { try { return new URL(urlStr).hostname.toLowerCase(); } catch { return ''; } })();
      if (host && host.endsWith(root) && host !== root) found.add(host);
    } catch { /* ignore */ }
  }
  return [...found];
}

/**
 * 从 CertSpotter API 响应提取子域名（去重、限定根域）。
 * CertSpotter 返回 JSON 数组，每项含 dns_names[] / dns_name。
 */
export function parseCertspotterResponse(jsonText: string, rootDomain: string): string[] {
  try {
    const arr = JSON.parse(jsonText);
    if (!Array.isArray(arr)) return [];
    const root = rootDomain.toLowerCase();
    const found = new Set<string>();
    for (const entry of arr) {
      const names: string[] = Array.isArray(entry?.dns_names)
        ? entry.dns_names
        : (entry?.dns_name ? [entry.dns_name] : []);
      for (let n of names) {
        if (typeof n !== 'string') continue;
        n = n.trim().toLowerCase().replace(/^\*\./, '');
        if (n && n.endsWith(root) && n !== root) found.add(n);
      }
    }
    return [...found];
  } catch {
    return [];
  }
}

/**
 * 从 DNS NS / MX 记录文本中提取子域名（去重、限定根域）。
 * 这些记录常暴露邮件服务器、DNS 服务器等内部主机名。
 * 输入：每行一条记录（如 "10 mail.example.com." 或 "ns1.example.com."）。
 */
export function parseDnsRecords(text: string, rootDomain: string): string[] {
  const root = rootDomain.toLowerCase();
  const found = new Set<string>();
  // 提取所有看起来像主机名的 token
  const hostRe = /[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+/gi;
  let m: RegExpExecArray | null;
  while ((m = hostRe.exec(text.toLowerCase())) !== null) {
    let host = m[0].replace(/\.$/, ''); // 去尾点
    if (host.endsWith(root) && host !== root) found.add(host);
  }
  return [...found];
}


/** 从页面链接文本（纯文本，每行一个 URL 或 hostname）提取属于根域的子域名。 */
export function parsePageLinks(hrefs: string[], rootDomain: string): string[] {
  const root = rootDomain.toLowerCase();
  const found = new Set<string>();
  for (const raw of hrefs) {
    const host = (() => {
      try { return new URL(raw, 'http://x.invalid').hostname.toLowerCase(); } catch { return ''; }
    })();
    if (host && host.endsWith(root) && host !== root) found.add(host);
  }
  return [...found];
}
