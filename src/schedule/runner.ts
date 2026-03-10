export interface ScheduleOptions {
  intervalMs: number;
  runOnce: () => Promise<void>;
}

export function parseInterval(s: string): number | null {
  // parse e.g. "30s" -> 30000, "5m" -> 300000, "1h" -> 3600000
  const m = /^(\d+)(s|m|h)$/.exec(s);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2];
  if (unit === 's') return n * 1000;
  if (unit === 'm') return n * 60 * 1000;
  return n * 3600 * 1000;
}

export async function runScheduled(opts: ScheduleOptions): Promise<never> {
  // Run immediately, then repeat
  await opts.runOnce();
  return new Promise<never>(() => {
    setInterval(async () => {
      try {
        await opts.runOnce();
      } catch (e) {
        console.error(`Schedule run failed: ${(e as Error).message}`);
      }
    }, opts.intervalMs);
  });
}
