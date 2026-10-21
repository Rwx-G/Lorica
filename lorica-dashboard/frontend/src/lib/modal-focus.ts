/**
 * Keyboard focus for a modal dialog, as a Svelte attachment on its
 * overlay: `<div role="dialog" {@attach modalFocus}>`.
 *
 * On mount it moves focus into the dialog, to the element marked
 * `data-autofocus` when there is one (a Cancel button on an
 * irreversible confirmation), else the first focusable element, else
 * the overlay itself, which carries `tabindex="-1"`. Without this,
 * focus stays on the page behind the dialog, so an Escape handled on
 * the overlay does nothing until the user has tabbed in. Tab and
 * Shift+Tab then cycle inside the dialog, and on unmount focus goes
 * back to the element that opened it.
 */

import type { Attachment } from 'svelte/attachments';

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'summary',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function focusableIn(node: HTMLElement): HTMLElement[] {
  return Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE));
}

export const modalFocus: Attachment<HTMLElement> = (node) => {
  const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const initial = node.querySelector<HTMLElement>('[data-autofocus]') ?? focusableIn(node)[0] ?? node;
  initial.focus();

  function keepFocusInside(e: KeyboardEvent): void {
    if (e.key !== 'Tab') return;
    const items = focusableIn(node);
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === node)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  }

  node.addEventListener('keydown', keepFocusInside);
  return () => {
    node.removeEventListener('keydown', keepFocusInside);
    if (opener?.isConnected) opener.focus();
  };
};
