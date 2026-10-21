/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-personas.md
 * Unit & Integration Tests for Real OIDC / SSO Authentication & Inactivity Guard
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from '../context/AuthContext';
import { UserProfileMenu } from '../components/UserProfileMenu';
import { SessionTimeoutModal } from '../components/SessionTimeoutModal';
import { LoginScreen } from '../components/LoginScreen';
import { oidcService } from '../services/oidc';

// Test consumer component
const AuthConsumerTestComponent: React.FC = () => {
  const { user, isAuthenticated, isSessionExpired, idleRemainingSeconds, hasRole, switchPersona, logout, renewSession } = useAuth();
  return (
    <div>
      <div data-testid="auth-status">{isAuthenticated ? 'AUTHENTICATED' : 'ANONYMOUS'}</div>
      <div data-testid="auth-user-name">{user?.name}</div>
      <div data-testid="auth-user-email">{user?.email}</div>
      <div data-testid="auth-user-title">{user?.title}</div>
      <div data-testid="auth-is-admin">{hasRole('admin') ? 'YES_ADMIN' : 'NO_ADMIN'}</div>
      <div data-testid="auth-is-auditor">{hasRole('auditor') ? 'YES_AUDITOR' : 'NO_AUDITOR'}</div>
      <div data-testid="auth-session-expired">{isSessionExpired ? 'EXPIRED' : 'ACTIVE'}</div>
      <div data-testid="auth-idle-seconds">{idleRemainingSeconds}</div>
      <button data-testid="btn-switch-priya" onClick={() => switchPersona('priya')}>Switch to Priya</button>
      <button data-testid="btn-switch-marcus" onClick={() => switchPersona('marcus')}>Switch to Marcus</button>
      <button data-testid="btn-renew" onClick={() => renewSession()}>Renew</button>
      <button data-testid="btn-logout" onClick={() => logout()}>Logout</button>
    </div>
  );
};

describe('OIDC / SSO Authentication & Session Management', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('initializes with default mock persona (Elena Rostova / Admin) in dev mode', () => {
    render(
      <AuthProvider>
        <AuthConsumerTestComponent />
      </AuthProvider>
    );

    expect(screen.getByTestId('auth-status')).toHaveTextContent('AUTHENTICATED');
    expect(screen.getByTestId('auth-user-name')).toHaveTextContent('Elena Rostova');
    expect(screen.getByTestId('auth-user-email')).toHaveTextContent('elena.rostova@aegis.internal');
    expect(screen.getByTestId('auth-user-title')).toHaveTextContent('SecOps Admin');
    expect(screen.getByTestId('auth-is-admin')).toHaveTextContent('YES_ADMIN');
    expect(screen.getByTestId('auth-is-auditor')).toHaveTextContent('YES_AUDITOR');
    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('ACTIVE');
  });

  it('switches enterprise personas dynamically with updated RBAC roles', () => {
    render(
      <AuthProvider>
        <AuthConsumerTestComponent />
      </AuthProvider>
    );

    // Switch to Priya Sharma (CISO / Auditor)
    fireEvent.click(screen.getByTestId('btn-switch-priya'));
    expect(screen.getByTestId('auth-user-name')).toHaveTextContent('Priya Sharma');
    expect(screen.getByTestId('auth-user-title')).toHaveTextContent('CISO / Auditor');
    expect(screen.getByTestId('auth-is-admin')).toHaveTextContent('NO_ADMIN');
    expect(screen.getByTestId('auth-is-auditor')).toHaveTextContent('YES_AUDITOR');

    // Switch to Marcus Vance (Platform Infrastructure)
    fireEvent.click(screen.getByTestId('btn-switch-marcus'));
    expect(screen.getByTestId('auth-user-name')).toHaveTextContent('Marcus Vance');
    expect(screen.getByTestId('auth-user-title')).toHaveTextContent('Platform Engineer');
    expect(screen.getByTestId('auth-is-admin')).toHaveTextContent('NO_ADMIN');
    expect(screen.getByTestId('auth-is-auditor')).toHaveTextContent('NO_AUDITOR');
  });

  it('enforces NFR-029 15-minute inactivity idle expiration', () => {
    vi.useFakeTimers();

    render(
      <AuthProvider>
        <AuthConsumerTestComponent />
      </AuthProvider>
    );

    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('ACTIVE');

    // Fast-forward 14 minutes (840 seconds)
    act(() => {
      vi.advanceTimersByTime(840 * 1000);
    });

    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('ACTIVE');

    // Fast-forward past 15 minutes (another 61 seconds)
    act(() => {
      vi.advanceTimersByTime(61 * 1000);
    });

    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('EXPIRED');

    // User renews session
    fireEvent.click(screen.getByTestId('btn-renew'));
    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('ACTIVE');
  });

  it('clears session on logout', () => {
    render(
      <AuthProvider>
        <AuthConsumerTestComponent />
      </AuthProvider>
    );

    expect(screen.getByTestId('auth-status')).toHaveTextContent('AUTHENTICATED');

    fireEvent.click(screen.getByTestId('btn-logout'));

    expect(screen.getByTestId('auth-status')).toHaveTextContent('ANONYMOUS');
    expect(screen.getByTestId('auth-user-name')).toHaveTextContent('');
  });
});

describe('UserProfileMenu Component', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it('renders active user badge, toggles popover menu, and shows RBAC roles', () => {
    render(
      <AuthProvider>
        <UserProfileMenu />
      </AuthProvider>
    );

    const menuBtn = screen.getByTestId('user-profile-menu-button');
    expect(menuBtn).toBeInTheDocument();
    expect(screen.getByText('Elena Rostova')).toBeInTheDocument();

    // Open popover
    fireEvent.click(menuBtn);

    expect(screen.getByTestId('user-profile-dropdown')).toBeInTheDocument();
    expect(screen.getByText('RBAC Roles')).toBeInTheDocument();
    expect(screen.getByText('admin')).toBeInTheDocument();
    expect(screen.getByTestId('idle-timer-display')).toBeInTheDocument();

    // Switch persona through dropdown
    const switchPriyaBtn = screen.getByTestId('switch-persona-priya');
    fireEvent.click(switchPriyaBtn);

    // Popover closed and new persona active
    expect(screen.queryByTestId('user-profile-dropdown')).not.toBeInTheDocument();
    expect(screen.getByText('Priya Sharma')).toBeInTheDocument();
  });
});

describe('LoginScreen & SessionTimeoutModal Components', () => {
  it('renders enterprise SSO login options and authenticates persona', async () => {
    render(
      <AuthProvider>
        <LoginScreen />
      </AuthProvider>
    );

    expect(screen.getByText('Zero-Trust Reverse Proxy & Security Firewall for Model Context Protocol')).toBeInTheDocument();
    expect(screen.getByTestId('sso-primary-login-button')).toBeInTheDocument();
    expect(screen.getByTestId('login-as-marcus')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('login-as-marcus'));

    await waitFor(() => {
      const session = oidcService.getSavedSession();
      expect(session?.user.name).toBe('Marcus Vance');
    });
  });

  it('renders SessionTimeoutModal and handles renew / logout', () => {
    const onRenew = vi.fn();
    const onLogout = vi.fn();

    const { rerender } = render(
      <SessionTimeoutModal
        isOpen={false}
        userName="Elena Rostova"
        onRenew={onRenew}
        onLogout={onLogout}
      />
    );

    expect(screen.queryByText(/Session Locked/i)).not.toBeInTheDocument();

    rerender(
      <SessionTimeoutModal
        isOpen={true}
        userName="Elena Rostova"
        onRenew={onRenew}
        onLogout={onLogout}
      />
    );

    expect(screen.getByText(/Session Locked \(NFR-029\)/i)).toBeInTheDocument();
    expect(screen.getByText('Elena Rostova')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('timeout-renew-button'));
    expect(onRenew).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByTestId('timeout-logout-button'));
    expect(onLogout).toHaveBeenCalledTimes(1);
  });
});
