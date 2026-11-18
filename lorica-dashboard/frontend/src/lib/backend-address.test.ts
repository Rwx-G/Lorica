import { describe, it, expect } from 'vitest';

import { validateBackendAddress } from './backend-address';

// The cases of `address_tests` in `lorica-config/src/models/backend.rs`,
// which pin the server's reading.
describe('validateBackendAddress', () => {
  it.each(['backend.example.com', 'backend', '192.0.2.10', '[2001:db8::1]', '[::1]'])(
    'accepts the portless form %s',
    (address) => {
      expect(validateBackendAddress(address)).toEqual({ portless: true });
    },
  );

  it.each(['192.0.2.10:8080', '[2001:db8::1]:53', 'backend.example.com:443'])('accepts %s with its port', (address) => {
    expect(validateBackendAddress(address)).toEqual({ portless: false });
  });

  it('reads an unbracketed IPv6 literal as the server does: the last group is the port', () => {
    expect(validateBackendAddress('2001:db8::1')).toEqual({ portless: false });
  });

  it.each(['', '192.0.2.10:', '192.0.2.10:http', '192.0.2.10:70000', '[2001:db8::zz]', '[192.0.2.10]', 'two words', 'host/path'])(
    'refuses %j',
    (address) => {
      expect(validateBackendAddress(address)).toHaveProperty('error');
    },
  );
});
