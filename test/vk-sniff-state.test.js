import { describe, it, expect } from '@jest/globals';
import { scoreConfidence, extractVersion, CONFIDENCE_LEVELS } from '../src/popup/vk-sniff-state.js';

// ---------------------------------------------------------------------------
// scoreConfidence
// ---------------------------------------------------------------------------
describe('scoreConfidence', () => {
  it('returns null for empty matchers array', () => {
    expect(scoreConfidence([])).toBeNull();
  });

  it('returns object with score, label, and color for a single matcher', () => {
    const result = scoreConfidence([{ source: 'headers' }]);
    expect(result).not.toBeNull();
    expect(typeof result.score).toBe('number');
    expect(result.label).toBeDefined();
    expect(result.color).toBeDefined();
    expect(['强', '稳', '弱']).toContain(result.label);
  });

  it('two matchers from different sources score higher than single matcher', () => {
    const single = scoreConfidence([{ source: 'headers' }]);
    const multi = scoreConfidence([{ source: 'headers' }, { source: 'body' }]);
    expect(multi.score).toBeGreaterThan(single.score);
  });

  it('multiple matchers from same source score higher than single matcher', () => {
    const single = scoreConfidence([{ source: 'headers' }]);
    const multi = scoreConfidence([{ source: 'headers' }, { source: 'headers' }]);
    expect(multi.score).toBeGreaterThan(single.score);
  });

  it('many matchers from different sources produce "强" label', () => {
    // baseScore=30 (headers), bonusMultiplier=1+(9)*0.2=2.8, sourceBonus=(4-1)*4=12
    // total = 30*2.8 + 12 = 96 >= 90 -> "强"
    const result = scoreConfidence([
      { source: 'headers' },
      { source: 'headers' },
      { source: 'headers' },
      { source: 'globals' },
      { source: 'globals' },
      { source: 'cookies' },
      { source: 'body' },
      { source: 'meta' },
      { source: 'scriptSrc' },
    ]);
    expect(result).not.toBeNull();
    expect(result.label).toBe('强');
  });
});

// ---------------------------------------------------------------------------
// extractVersion
// ---------------------------------------------------------------------------
describe('extractVersion', () => {
  it('returns the version string when techName matches', () => {
    expect(extractVersion('WordPress', { WordPress: '5.8.1' })).toBe('5.8.1');
  });

  it('returns null when techName is not in versions object', () => {
    expect(extractVersion('WordPress', { Drupal: '9.2' })).toBeNull();
  });

  it('returns null when versions is null', () => {
    expect(extractVersion('WordPress', null)).toBeNull();
  });

  it('returns null when versions is undefined', () => {
    expect(extractVersion('WordPress', undefined)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CONFIDENCE_LEVELS
// ---------------------------------------------------------------------------
describe('CONFIDENCE_LEVELS', () => {
  it('strong.min is 90', () => {
    expect(CONFIDENCE_LEVELS.strong.min).toBe(90);
  });

  it('moderate.min is 75', () => {
    expect(CONFIDENCE_LEVELS.moderate.min).toBe(75);
  });

  it('weak.min is 0', () => {
    expect(CONFIDENCE_LEVELS.weak.min).toBe(0);
  });

  it('all levels have label and color properties', () => {
    const levels = ['strong', 'moderate', 'weak'];
    levels.forEach(level => {
      expect(CONFIDENCE_LEVELS[level]).toHaveProperty('label');
      expect(CONFIDENCE_LEVELS[level]).toHaveProperty('color');
      expect(typeof CONFIDENCE_LEVELS[level].label).toBe('string');
      expect(typeof CONFIDENCE_LEVELS[level].color).toBe('string');
    });
  });
});
