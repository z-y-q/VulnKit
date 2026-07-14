import { describe, it, expect } from 'vitest';
import { severityTone } from '@/components/results/detail-drawer-utils';

describe('severityTone', () => {
  it('critical/danger/high → danger', () => {
    expect(severityTone('critical')).toBe('danger');
    expect(severityTone('danger')).toBe('danger');
    expect(severityTone('high')).toBe('danger');
  });

  it('warning/medium → warn', () => {
    expect(severityTone('warning')).toBe('warn');
    expect(severityTone('medium')).toBe('warn');
  });

  it('low → low', () => {
    expect(severityTone('low')).toBe('low');
  });

  it('safe/pass → ok', () => {
    expect(severityTone('safe')).toBe('ok');
    expect(severityTone('pass')).toBe('ok');
  });

  it('info → info', () => {
    expect(severityTone('info')).toBe('info');
  });

  it('大小写无关', () => {
    expect(severityTone('CRITICAL')).toBe('danger');
    expect(severityTone('Warning')).toBe('warn');
    expect(severityTone('SAFE')).toBe('ok');
  });

  it('未知 / 空 / null / undefined → muted（容错）', () => {
    expect(severityTone('unknown')).toBe('muted');
    expect(severityTone('')).toBe('muted');
    expect(severityTone(undefined)).toBe('muted');
    expect(severityTone(null)).toBe('muted');
  });
});
