/*
 * Pure-logic helpers for the CountryPicker component. Extracted
 * to a standalone module so vitest can exercise parse / serialize
 * / matching without standing up the SVG map in jsdom.
 */

/// Parse a user-supplied CSV (commas OR whitespace-separated) of
/// ISO 3166-1 alpha-2 codes into a Set of normalised upper-case
/// codes. Whitespace-trimmed, case-folded, filtered to length-2
/// entries — anything else drops silently.
export function parseCountryValue(v: string): Set<string> {
  return new Set(
    v
      .split(/[,\s]+/)
      .map((s) => s.trim().toUpperCase())
      .filter((s) => s.length === 2)
  );
}

/// Serialize a Set back to the CSV wire shape with deterministic
/// sort so a round-trip through parse+serialize converges. The
/// backend API side also uppercases + dedupes, so this just makes
/// the form value stable under re-renders.
export function serializeCountryValue(s: Set<string>): string {
  return Array.from(s).sort().join(', ');
}

/// Walk up a DOM subtree looking for the first ancestor whose
/// `id` attribute is exactly two characters — the ISO code
/// convention used by the Wikimedia SVG map. Returns the code
/// upper-cased, or `null` when no match (click hit a group that
/// does not represent a country, e.g. the background).
///
/// Stops at `stopAt` (exclusive) so the walk does not escape
/// into document-level elements above the SVG container.
export function findIsoCodeInAncestry(
  target: Element | null,
  stopAt: Element | null,
): string | null {
  let cur: Element | null = target;
  while (cur && cur !== stopAt) {
    const id = cur.getAttribute?.('id') ?? '';
    if (id.length === 2) {
      return id.toUpperCase();
    }
    cur = cur.parentElement;
  }
  return null;
}

/// Toggle a country in the selection set and return the new set
/// AND the serialised CSV in one call. Keeps the picker's click
/// handler branch-free.
export function toggleCountry(
  current: Set<string>,
  iso: string,
): { next: Set<string>; csv: string } {
  const next = new Set(current);
  if (next.has(iso)) {
    next.delete(iso);
  } else {
    next.add(iso);
  }
  return { next, csv: serializeCountryValue(next) };
}
