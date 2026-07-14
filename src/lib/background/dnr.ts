// declarativeNetRequest 规则管理
// JS 阻断、UA 伪造、请求头伪造。状态持久化到 browser.storage.local。

import type { SpoofHeaders } from '@/lib/types/messaging';
import type { Browser } from 'wxt/browser';

const JS_BLOCK_RULE_ID = 9001;
const UA_RULE_ID = 9002;
const HEADER_RULES_START = 9010;
const MAX_HEADER_RULES = 20;

const ALL_RESOURCE_TYPES = [
  'main_frame',
  'sub_frame',
  'stylesheet',
  'script',
  'image',
  'xmlhttprequest',
  'font',
  'other',
] as const;

interface UaSpoofState {
  enabled: boolean;
  current: string;
  url: string;
}
interface HeaderSpoofState {
  xff?: string;
  referer?: string;
  clientIp?: string;
  custom?: { name: string; value: string }[];
  url: string;
}
export interface SpoofState {
  ua: UaSpoofState;
  headers: HeaderSpoofState;
}

const DEFAULT_STATE: SpoofState = {
  ua: { enabled: false, current: '', url: '' },
  headers: { xff: '', referer: '', clientIp: '', custom: [], url: '' },
};

let spoofState: SpoofState = JSON.parse(JSON.stringify(DEFAULT_STATE));

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v));
}

async function persist() {
  await browser.storage.local.set({ pentest_spoof: spoofState }).catch(() => {});
}

function hostUrlFilter(url: string): string {
  const parsed = new URL(url);
  return parsed.hostname + '/*';
}

// ====== JS 阻断 ======
async function addJsBlockRule() {
  await browser.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [JS_BLOCK_RULE_ID],
    addRules: [
      {
        id: JS_BLOCK_RULE_ID,
        priority: 1,
        action: { type: 'block' },
        condition: { urlFilter: '.js', resourceTypes: ['script'] },
      },
    ],
  });
}

async function removeJsBlockRule() {
  await browser.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [JS_BLOCK_RULE_ID],
  });
}

export async function queryJsBlocked(): Promise<boolean> {
  try {
    const rules = await browser.declarativeNetRequest.getDynamicRules();
    return rules.some(r => r.id === JS_BLOCK_RULE_ID);
  } catch {
    return false;
  }
}

export async function toggleJs(enable: boolean): Promise<void> {
  if (enable) await removeJsBlockRule();
  else await addJsBlockRule();
}

// ====== UA 伪造 ======
async function addUaRule(url: string, ua: string) {
  const urlFilter = hostUrlFilter(url);
  await browser.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [UA_RULE_ID],
    addRules: [
      {
        id: UA_RULE_ID,
        priority: 2,
        action: {
          type: 'modifyHeaders',
          requestHeaders: [{ header: 'User-Agent', operation: 'set', value: ua }],
        },
        condition: { urlFilter, resourceTypes: [...ALL_RESOURCE_TYPES] },
      },
    ],
  });
}

async function removeUaRule() {
  await browser.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [UA_RULE_ID] });
}

export async function spoofUa(url: string, userAgent: string): Promise<void> {
  if (!url || !userAgent) throw new Error('Missing url or userAgent');
  spoofState.ua = { enabled: true, current: userAgent, url };
  await persist();
  await addUaRule(url, userAgent);
}

export async function resetSpoofUa(): Promise<void> {
  spoofState.ua = { enabled: false, current: '', url: '' };
  await persist();
  await removeUaRule();
}

// ====== 请求头伪造 ======
function buildHeaderModifications(headers: SpoofHeaders) {
  const mods: Browser.declarativeNetRequest.ModifyHeaderInfo[] = [];
  if (headers.xff) mods.push({ header: 'X-Forwarded-For', operation: 'set', value: headers.xff });
  if (headers.referer) mods.push({ header: 'Referer', operation: 'set', value: headers.referer });
  if (headers.clientIp) {
    mods.push({ header: 'Client-IP', operation: 'set', value: headers.clientIp });
    mods.push({ header: 'X-Real-IP', operation: 'set', value: headers.clientIp });
  }
  for (const h of headers.custom || []) {
    if (h.name && h.value) mods.push({ header: h.name, operation: 'set', value: h.value });
  }
  return mods;
}

function headerRuleIds(): number[] {
  return Array.from({ length: MAX_HEADER_RULES }, (_, i) => HEADER_RULES_START + i);
}

async function addHeaderRules(url: string, headers: SpoofHeaders) {
  const mods = buildHeaderModifications(headers);
  if (mods.length === 0) return;
  const urlFilter = hostUrlFilter(url);
  const headerResourceTypes = ['main_frame', 'sub_frame', 'xmlhttprequest', 'other'];
  const rules = mods.map((h, i) => ({
    id: HEADER_RULES_START + i,
    priority: 3,
    action: { type: 'modifyHeaders' as const, requestHeaders: [h] },
    condition: {
      urlFilter,
      resourceTypes: headerResourceTypes,
    },
  })) as any[];
  await browser.declarativeNetRequest.updateDynamicRules({
    addRules: rules,
    removeRuleIds: headerRuleIds(),
  });
}

async function removeAllHeaderRules() {
  await browser.declarativeNetRequest.updateDynamicRules({ removeRuleIds: headerRuleIds() });
}

export async function spoofHeaders(url: string, headers: SpoofHeaders): Promise<void> {
  if (!headers) throw new Error('Missing headers');
  spoofState.headers = { ...clone(headers), url };
  await persist();
  await addHeaderRules(url, headers);
}

export async function resetSpoofHeaders(): Promise<void> {
  spoofState.headers = { xff: '', referer: '', clientIp: '', custom: [], url: '' };
  await persist();
  await removeAllHeaderRules();
}

// ====== 启动时恢复 ======
export async function restoreSpoofState(): Promise<void> {
  const result = await browser.storage.local.get(['pentest_spoof']);
  const stored = result.pentest_spoof as SpoofState | undefined;
  if (!stored) return;
  spoofState = stored;
  try {
    if (spoofState.ua.enabled && spoofState.ua.current) {
      await addUaRule(spoofState.ua.url || '', spoofState.ua.current);
    }
    if (
      spoofState.headers &&
      (spoofState.headers.xff ||
        spoofState.headers.referer ||
        spoofState.headers.clientIp ||
        (spoofState.headers.custom && spoofState.headers.custom.length > 0))
    ) {
      await addHeaderRules(spoofState.headers.url || '', spoofState.headers);
    }
  } catch {
    /* 恢复失败忽略，规则可由用户重新设置 */
  }
}
