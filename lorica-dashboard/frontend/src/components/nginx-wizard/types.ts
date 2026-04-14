// Shared types for the Nginx import wizard sub-components.

export interface BackendCheck {
  address: string;
  exists: boolean;
  willCreate: boolean;
  existingId?: string;
}

export interface IncludeEntry {
  line: number;
  path: string;
  content: string;
}

export interface CertEntry {
  hostname: string;
  aliases: string[];
  certPath: string;
  keyPath: string;
  mode: 'acme' | 'import' | 'skip';
  certContent: string;
  keyContent: string;
}

export interface ApplyResult {
  type: 'backend' | 'route';
  label: string;
  success: boolean;
  error?: string;
  routeId?: string;
}

export type ConfigLine = {
  text: string;
  annotation: string;
  annotationType: 'mapped' | 'handled' | 'none';
  kind: 'normal' | 'replaced';
};
