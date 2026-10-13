/* eslint-env jest */
import {
  formatBytes,
  formatCount,
  formatDate,
  formatDateTime,
  formatDuration,
  formatRelativeTime,
  truncateMiddle,
} from '../src/utils/format';

describe('formatRelativeTime', () => {
  const now = Date.parse('2026-01-15T12:00:00.000Z');
  const at = (msAgo: number) => new Date(now - msAgo).toISOString();

  it('says "just now" under a minute', () => {
    expect(formatRelativeTime(at(30_000), now)).toBe('just now');
  });

  it('reports minutes', () => {
    expect(formatRelativeTime(at(5 * 60_000), now)).toBe('5 min ago');
  });

  it('reports hours', () => {
    expect(formatRelativeTime(at(3 * 3_600_000), now)).toBe('3 h ago');
  });

  it('reports days within the week', () => {
    expect(formatRelativeTime(at(3 * 86_400_000), now)).toBe('3 d ago');
  });

  it('falls back to a date beyond a week', () => {
    expect(formatRelativeTime(at(10 * 86_400_000), now)).not.toMatch(/ago/);
  });

  it('handles an unparseable timestamp', () => {
    expect(formatRelativeTime('not-a-date', now)).toBe('unknown time');
  });
});

describe('formatDuration', () => {
  it('renders an em dash for a missing value', () => {
    expect(formatDuration(undefined)).toBe('—');
  });

  it('uses milliseconds below a second', () => {
    expect(formatDuration(500)).toBe('500 ms');
  });

  it('uses one decimal for short seconds', () => {
    expect(formatDuration(1_500)).toBe('1.5 s');
  });

  it('drops the decimal for longer seconds', () => {
    expect(formatDuration(15_000)).toBe('15 s');
  });

  it('uses minutes and seconds past a minute', () => {
    expect(formatDuration(65_000)).toBe('1 m 5 s');
  });
});

describe('formatBytes', () => {
  it('renders an em dash for a missing value', () => {
    expect(formatBytes(undefined)).toBe('—');
  });

  it('shows whole bytes without a decimal', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
  });

  it('steps up through binary units', () => {
    expect(formatBytes(1024)).toBe('1.0 KB');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(1024 * 1024)).toBe('1.0 MB');
  });
});

describe('truncateMiddle', () => {
  it('leaves short values untouched', () => {
    expect(truncateMiddle('abc')).toBe('abc');
  });

  it('keeps the head and tail of a long value', () => {
    const hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    const short = truncateMiddle(hash);
    expect(short.startsWith('275a021b')).toBe(true);
    expect(short.endsWith('51fd0f')).toBe(true);
    expect(short).toContain('…');
    expect(short.length).toBeLessThan(hash.length);
  });
});

describe('date formatters', () => {
  it('returns a placeholder for invalid input', () => {
    expect(formatDateTime('nope')).toBe('unknown date');
    expect(formatDate('nope')).toBe('unknown date');
  });

  it('formats a real date without the invalid placeholder', () => {
    expect(formatDateTime('2026-01-15T12:00:00.000Z')).not.toBe('unknown date');
  });
});

describe('formatCount', () => {
  it('matches the platform number formatting', () => {
    expect(formatCount(1234)).toBe((1234).toLocaleString());
  });
});
