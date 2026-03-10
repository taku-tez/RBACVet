import { describe, it, expect } from 'vitest';
import { parseInterval } from '../../src/schedule/runner';

describe('parseInterval', () => {
  it("'30s' -> 30000", () => {
    expect(parseInterval('30s')).toBe(30000);
  });

  it("'5m' -> 300000", () => {
    expect(parseInterval('5m')).toBe(300000);
  });

  it("'1h' -> 3600000", () => {
    expect(parseInterval('1h')).toBe(3600000);
  });

  it("'2h' -> 7200000", () => {
    expect(parseInterval('2h')).toBe(7200000);
  });

  it("'invalid' -> null", () => {
    expect(parseInterval('invalid')).toBeNull();
  });

  it("'0s' -> 0", () => {
    expect(parseInterval('0s')).toBe(0);
  });

  it("'' -> null", () => {
    expect(parseInterval('')).toBeNull();
  });
});
