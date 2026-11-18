import { writable } from 'svelte/store';

/**
 * `warning` is for a write that succeeded with something to read: the
 * `warnings` an answer carries. It is not a softer `error`.
 */
export type ToastType = 'success' | 'warning' | 'error';

export interface Toast {
  id: number;
  message: string;
  type: ToastType;
}

let nextId = 0;

export const toasts = writable<Toast[]>([]);

export function showToast(message: string, type: ToastType = 'success', duration = 4000): void {
  const id = nextId++;
  toasts.update((all) => [...all, { id, message, type }]);
  setTimeout(() => {
    toasts.update((all) => all.filter((t) => t.id !== id));
  }, duration);
}

export function dismissToast(id: number): void {
  toasts.update((all) => all.filter((t) => t.id !== id));
}
