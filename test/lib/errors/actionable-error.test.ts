import { describe, it, expect } from 'vitest';
import { toActionableError, COMMON_ERRORS } from '@/lib/errors/actionable-error';

describe('actionable-error（§5.4）', () => {
  it('toActionableError 原样返回 ActionableError', () => {
    const e = { code: 'X', title: 'T', message: 'M', recovery: [{ label: 'r', action: 'retry' as const }] };
    expect(toActionableError(e)).toBe(e);
  });

  it('Error 含 timeout 关键字 → REQUEST_TIMEOUT + cause', () => {
    const r = toActionableError(new Error('Request timeout'));
    expect(r.code).toBe('REQUEST_TIMEOUT');
    expect(r.cause).toBeTruthy();
  });

  it('Error 含 clipboard 关键字 → CLIPBOARD_FAILED', () => {
    const r = toActionableError(new Error('clipboard write denied'));
    expect(r.code).toBe('CLIPBOARD_FAILED');
  });

  it('普通 Error → UNKNOWN + message + 至少一个 recovery', () => {
    const r = toActionableError(new Error('boom'));
    expect(r.code).toBe('UNKNOWN');
    expect(r.message).toBe('boom');
    expect(r.recovery.length).toBeGreaterThan(0);
  });

  it('字符串 → message；空字符串/其他 → UNKNOWN 默认', () => {
    expect(toActionableError('oops').message).toBe('oops');
    expect(toActionableError(null).code).toBe('UNKNOWN');
    expect(toActionableError(undefined).code).toBe('UNKNOWN');
    expect(toActionableError(42).code).toBe('UNKNOWN');
    expect(toActionableError('').code).toBe('UNKNOWN');
  });

  it('COMMON_ERRORS 覆盖 §5.4 全部常见错误且每个有 recovery', () => {
    const codes = [
      'NO_ACTIVE_TAB',
      'CONTENT_SCRIPT_DISCONNECTED',
      'API_KEY_MISSING',
      'API_QUOTA_EXCEEDED',
      'REQUEST_TIMEOUT',
      'PERMISSION_DENIED',
      'CLIPBOARD_FAILED',
    ];
    for (const code of codes) {
      expect(COMMON_ERRORS[code]).toBeDefined();
      expect(COMMON_ERRORS[code].recovery.length).toBeGreaterThan(0);
    }
  });
});
