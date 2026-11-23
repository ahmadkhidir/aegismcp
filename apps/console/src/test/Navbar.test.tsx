/**
 * Specification Anchors: FEAT-010, C-008, C-021
 * The kill-switch entry is offered to admin and operator only. The gateway
 * independently refuses a viewer or auditor with HTTP 403.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Navbar } from '../components/Navbar';

const authState = vi.hoisted(() => ({ roles: [] as string[] }));

vi.mock('../context/AuthContext', () => ({
  useAuth: () => ({
    hasRole: (role: string | string[]) => {
      const required = Array.isArray(role) ? role : [role];
      return authState.roles.some((held) => required.includes(held));
    },
    user: null,
    logout: vi.fn(),
    renewSession: vi.fn(),
    idleRemainingSeconds: 900,
  }),
}));

describe('Navbar emergency controls', () => {
  beforeEach(() => {
    authState.roles = [];
  });

  it.each(['admin', 'operator'])('enables the kill-switch for %s', (role) => {
    authState.roles = [role];
    const onOpenKillSwitch = vi.fn();
    render(<Navbar threatLevel="NORMAL" onOpenKillSwitch={onOpenKillSwitch} />);

    const button = screen.getByTestId('nav-killswitch-button');
    expect(button).not.toBeDisabled();
    fireEvent.click(button);
    expect(onOpenKillSwitch).toHaveBeenCalledTimes(1);
  });

  it.each(['auditor', 'viewer'])('disables the kill-switch for %s', (role) => {
    authState.roles = [role];
    const onOpenKillSwitch = vi.fn();
    render(<Navbar threatLevel="NORMAL" onOpenKillSwitch={onOpenKillSwitch} />);

    const button = screen.getByTestId('nav-killswitch-button');
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('title', expect.stringContaining('operator or admin'));
    fireEvent.click(button);
    expect(onOpenKillSwitch).not.toHaveBeenCalled();
  });
});
