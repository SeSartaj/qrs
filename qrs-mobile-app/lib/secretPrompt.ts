/**
 * Tiny external store for prompting the user for a verification secret (e.g. a
 * stripped passcode). The qrs-core context provider calls `requestSecret`, which
 * shows a dialog and resolves when the user answers (or cancels).
 */
export interface PendingSecret {
  field: { label: string; name: string };
}

let pending: PendingSecret | null = null;
let resolver: ((value: string | null) => void) | null = null;
let listeners: Array<() => void> = [];

function emit(): void {
  for (const l of listeners) l();
}

/** Called by the runtime's context provider. */
export function requestSecret(field: PendingSecret['field']): Promise<string | null> {
  pending = { field };
  emit();
  return new Promise<string | null>((resolve) => {
    resolver = resolve;
  });
}

/** Called by the dialog when the user submits or cancels. */
export function settleSecret(value: string | null): void {
  const r = resolver;
  resolver = null;
  pending = null;
  emit();
  r?.(value);
}

export function subscribe(listener: () => void): () => void {
  listeners.push(listener);
  return () => {
    listeners = listeners.filter((l) => l !== listener);
  };
}

export function getPendingSecret(): PendingSecret | null {
  return pending;
}
