// Stale-chunk detection for Vite-emitted lazy route chunks.
//
// When the operator upgrades Lorica while a dashboard tab is open, the
// in-memory bundle still references the old chunk hashes baked at build
// time. Routes the user has not visited yet in this session will 404 on
// the next navigation because the new binary embeds different hashes.
// The browser surfaces this as a TypeError whose message varies by
// engine; the substrings below cover Chrome / Firefox / Safari / WebKit.
export function isDynamicImportError(message: string): boolean {
  return (
    message.includes('dynamically imported module') ||
    message.includes('Importing a module script failed') ||
    message.includes('Failed to fetch dynamically imported module')
  );
}
