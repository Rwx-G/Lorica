/**
 * Centralised byte-size formatter.
 *
 * Replaces the three drifted implementations that v1.5.2 audit M-20
 * caught (System.svelte: B/KB/MB/GB/TB log-2 with 1 decimal ;
 * Overview.svelte: KB/MB/GB threshold-based with 0-1 decimals ;
 * CertExportTab.svelte: B/KiB/MiB IEC with 1-2 decimals). Same
 * operator was seeing `1.4 MB`, `1 MB`, and `1.43 MiB` for the same
 * underlying number depending on the page they were on.
 *
 * One canonical formatter keeps the dashboard internally consistent
 * and lets ops triage tickets without "is the System page lying or
 * is the Overview page lying" friction.
 *
 * @param bytes - Non-negative byte count. Negative or NaN inputs
 *   collapse to `'0 B'` (operators don't want a thrown error in the
 *   middle of a stats panel).
 * @param opts.units - `'binary'` (default, IEC : KiB / MiB / GiB) or
 *   `'decimal'` (SI : KB / MB / GB). Both use base-1024 division for
 *   compatibility with the three sites we replaced ; the difference
 *   is purely the unit suffix. (`'decimal'` is technically a misnomer
 *   for that reason, but it matches what System.svelte / Overview.
 *   svelte were already producing - changing the divisor would make
 *   the migration a behavior change rather than a doc / unit fix.)
 * @param opts.precision - Number of digits after the decimal point.
 *   Default 1.
 */
export function formatBytes(
  bytes: number,
  opts: { units?: 'binary' | 'decimal'; precision?: number } = {},
): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';

  const units = opts.units ?? 'binary';
  const precision = opts.precision ?? 1;

  const suffixes =
    units === 'binary'
      ? ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
      : ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

  const exp = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    suffixes.length - 1,
  );
  const value = bytes / Math.pow(1024, exp);

  // Bytes are always integral - no decimal needed.
  if (exp === 0) return `${Math.round(value)} ${suffixes[0]}`;
  return `${value.toFixed(precision)} ${suffixes[exp]}`;
}
