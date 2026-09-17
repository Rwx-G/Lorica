/**
 * A `$state` proxy for tests that mount a component with a `$bindable`
 * prop.
 *
 * A plain object passed to `bind:` is not reactive, and Svelte 5 says
 * so at runtime (`binding_property_non_reactive`). The warning is not
 * cosmetic: the component's writes through the binding go nowhere the
 * test can observe, so a test built on a plain object asserts against a
 * form that silently stopped updating.
 *
 * Runes only compile inside `.svelte` files and `.svelte.js` / `.svelte.ts`
 * modules, which is why this helper lives in a `.svelte.ts` file rather
 * than beside the tests that call it.
 */
export function reactive<T extends object>(value: T): T {
  const proxied = $state(value);
  return proxied;
}
