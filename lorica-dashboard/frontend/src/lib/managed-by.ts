// Copyright 2026 Rwx-G (Lorica)
//
// Wording for rows the automation API owns (Story 10.4 AC #8). One
// place, so the Routes page, the Backends page and the route drawer
// tell the operator the same thing.

import type { ManagedBy } from './api';

/** Why Edit is refused on a managed row: the tooltip and the drawer banner. */
export function managedEditHint(managedBy: ManagedBy): string {
  return `Managed by the automation API for environment "${managedBy.environment}". Update it through the pipeline: the next PUT would overwrite a manual change.`;
}

/** Why Delete is refused on a managed backend: the set of backends belongs to the pipeline. */
export function managedDeleteHint(managedBy: ManagedBy): string {
  return `Managed by the automation API for environment "${managedBy.environment}". Delete the environment, or update it through the pipeline: a backend removed by hand would be recreated by the next PUT.`;
}

/** The badge tooltip, shorter than the edit hint. */
export function managedBadgeTitle(managedBy: ManagedBy): string {
  return `Managed by the automation API for environment "${managedBy.environment}"`;
}
