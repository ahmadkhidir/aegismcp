/**
 * Specification Anchors: FEAT-008, FEAT-009, NFR-029, C-002, C-003, C-005,
 * C-013, C-015, C-017, C-018, C-019
 *
 * Role-scoped console access. Every rule here mirrors the RBAC clause on the
 * frozen contract the screen reads, so a navigation entry is offered only when
 * the gateway will answer that operator's request.
 *
 * Where a contract lists several roles for a read and fewer for a write, the
 * read set governs navigation and the write set governs the action control.
 */

import { UserRole } from '../types/auth';

/** Screens declared in screens.md Navigation Map. */
export type ScreenId = 'dashboard' | 'inspector' | 'approvals' | 'policies' | 'audit';

/** Ordered so the first entry is the landing destination for every role. */
export const SCREEN_IDS: readonly ScreenId[] = [
  'dashboard',
  'inspector',
  'approvals',
  'policies',
  'audit',
];

const ALL_ROLES: readonly UserRole[] = ['admin', 'operator', 'auditor', 'viewer'];

/**
 * Roles that can open each screen.
 *
 * - Dashboard: C-009, C-010, C-016, C-020 admit any console role.
 * - Inspector: C-002 admits any console role.
 * - Approvals: C-003, C-004, and C-014 admit admin and operator for the
 *   pending queue; C-019 additionally admits auditors for resolved history.
 *   The screen opens on the pending queue unless the role is limited to history.
 * - Policies: C-005 and C-017 admit admin, operator, and auditor.
 * - Audit: C-013 and C-015 admit admin and auditor.
 */
export const SCREEN_ROLES: Record<ScreenId, readonly UserRole[]> = {
  dashboard: ALL_ROLES,
  inspector: ALL_ROLES,
  approvals: ['admin', 'operator', 'auditor'],
  policies: ['admin', 'operator', 'auditor'],
  audit: ['admin', 'auditor'],
};

/** True when the operator holds at least one role the screen admits. */
export function canAccessScreen(roles: readonly UserRole[], screen: ScreenId): boolean {
  return roles.some((role) => SCREEN_ROLES[screen].includes(role));
}

/** C-003: the pending approval queue requires the admin or operator role. */
export function canReadApprovals(roles: readonly UserRole[]): boolean {
  return roles.some((role) => role === 'admin' || role === 'operator');
}

/** C-008 and C-021: emergency kill and release require admin or operator. */
export function canOperateEmergency(roles: readonly UserRole[]): boolean {
  return roles.some((role) => role === 'admin' || role === 'operator');
}

/** C-006 and C-018: publishing and activating a policy require the admin role. */
export function canManagePolicy(roles: readonly UserRole[]): boolean {
  return roles.includes('admin');
}

/** C-012: policy simulation requires the admin or operator role. */
export function canSimulatePolicy(roles: readonly UserRole[]): boolean {
  return roles.some((role) => role === 'admin' || role === 'operator');
}
