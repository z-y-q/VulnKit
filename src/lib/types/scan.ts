// 通用扫描结果类型
export interface ScanResult {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence?: string;
  url?: string;
  category?: string;
}

// XSS 扫描结果
export interface XssPoint {
  url: string;
  parameter: string;
  method: string;
  context: 'html' | 'attribute' | 'script' | 'url' | 'style' | 'comment';
  payload: string;
  reflected: boolean;
  verified: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

// CORS 检测结果
export interface CorsResult {
  origin: string;
  targetUrl: string;
  allowOrigin: string | null;
  allowCredentials: boolean;
  allowMethods: string[];
  allowHeaders: string[];
  exposedHeaders: string[];
  preflight: boolean;
  vulnerable: boolean;
  severity: 'high' | 'medium' | 'low' | 'info';
}

// 安全头分析结果
export interface HeaderResult {
  name: string;
  value: string | null;
  status: 'present' | 'missing' | 'misconfigured';
  severity: 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
}

// 技术指纹
export interface TechFingerprint {
  name: string;
  category: string;
  version?: string;
  confidence: {
    score: number;
    label: string;
    color: string;
  };
  evidences: TechEvidence[];
}

export interface TechEvidence {
  source: string;
  evidence: string;
}

// 子域名结果
export interface SubdomainResult {
  domain: string;
  source: 'page' | 'crt' | 'dns';
  alive: boolean;
  ips?: string[];
}

// 统一报告
export interface ReportFinding {
  module: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence?: string;
  url?: string;
  timestamp: number;
}
