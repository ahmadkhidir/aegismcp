/**
 * Specification Anchors: FEAT-008, FEAT-009, NFR-029, C-002, C-003, C-005,
 * C-013, C-015, C-017
 * Navigation gating mirrors the RBAC clause on each screen's frozen contract.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Sidebar } from '../components/Sidebar';
import { UserRole } from '../types/auth';

const ITEM_IDS = ['dashboard', 'inspector', 'approvals', 'policies', 'audit'];

function visibleItems(): string[] {
  return ITEM_IDS.filter((id) => screen.queryByTestId(`nav-item-${id}`) !== null);
}

function renderSidebar(roles: UserRole[], pendingApprovalsCount = 0) {
  const onNavigate = vi.fn();
  render(
    <Sidebar
      currentScreen="dashboard"
      onNavigate={onNavigate}
      roles={roles}
      pendingApprovalsCount={pendingApprovalsCount}
    />
  );
  return onNavigate;
}

describe('Sidebar role-based navigation', () => {
  it('offers every declared screen to an admin', () => {
    renderSidebar(['admin']);
    expect(visibleItems()).toEqual(ITEM_IDS);
  });

  it('omits the audit ledger from an operator', () => {
    renderSidebar(['operator']);
    expect(visibleItems()).toEqual([
      'dashboard',
      'inspector',
      'approvals',
      'policies',
    ]);
  });

  it('offers an auditor the resolved history without letting it decide pending tickets', () => {
    renderSidebar(['auditor']);
    expect(visibleItems()).toEqual(['dashboard', 'inspector', 'approvals', 'policies', 'audit']);
    expect(screen.queryByTestId('nav-badge-approvals')).not.toBeInTheDocument();
  });

  it('offers only the read-only telemetry screens to a viewer', () => {
    renderSidebar(['viewer']);
    expect(visibleItems()).toEqual(['dashboard', 'inspector']);
  });

  it('shows the pending approval badge only where the queue is readable', () => {
    renderSidebar(['operator'], 4);
    expect(screen.getByTestId('nav-badge-approvals')).toHaveTextContent('4');
  });

  it('navigates to an offered screen', () => {
    const onNavigate = renderSidebar(['admin']);
    fireEvent.click(screen.getByTestId('nav-item-audit'));
    expect(onNavigate).toHaveBeenCalledWith('audit');
  });
});
