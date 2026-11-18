/**
 * The backend address rule the form applies before a save, read the way
 * the server reads it (`backend_address_port` in
 * `lorica-config/src/models/backend.rs`, Story 12.1 D-6): `host:port`,
 * `[v6]:port`, and the portless forms a port-range stream links (a host
 * name, an IPv4 literal, a bracketed IPv6 literal). The server stays the
 * authority on where a portless backend may be attached.
 */

export type BackendAddressCheck = { error: string } | { portless: boolean };

/** A host name or IPv4 literal: what the server takes as a portless address. */
const HOST = /^[A-Za-z0-9._-]{1,253}$/;

/** Whether `literal` is an IPv6 address, as the browser's own parser reads it. */
function isIpv6(literal: string): boolean {
  try {
    return new URL(`http://[${literal}]/`).hostname !== '';
  } catch {
    return false;
  }
}

export function validateBackendAddress(raw: string): BackendAddressCheck {
  const address = raw.trim();
  if (address === '') return { error: 'Address is required (e.g. 10.0.0.1:8080)' };
  if (address.startsWith('[') && address.endsWith(']')) {
    return isIpv6(address.slice(1, -1))
      ? { portless: true }
      : { error: `Invalid bracketed IPv6 literal (got '${address}')` };
  }
  if (!address.includes(':')) {
    return HOST.test(address)
      ? { portless: true }
      : { error: `Address must be host:port, or a host without a port for a port-range stream (got '${address}')` };
  }
  if (address.endsWith(':')) return { error: `Address must be in host:port format (got '${address}')` };
  // An unbracketed IPv6 literal keeps its historical reading, as on the
  // server: the text after the last colon is the port.
  const port = address.slice(address.lastIndexOf(':') + 1);
  if (!/^\d+$/.test(port) || Number(port) > 65535) return { error: `Invalid port (got '${address}')` };
  return { portless: false };
}
