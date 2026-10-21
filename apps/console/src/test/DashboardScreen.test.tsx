/**
 * Specification Anchors: FEAT-008, FEAT-010, C-008, C-009, C-010
 * Dashboard Screen Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DashboardScreen } from '../screens/DashboardScreen';
import { AegisApi } from '../services/api';

describe('DashboardScreen Component', () => {
  const onNavigateTo = vi.fn();
  const onOpenKillSwitch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders threat posture banner and metric counter grid', async () => {
    render(
      <DashboardScreen
        onNavigateTo={onNavigateTo}
        onOpenKillSwitch={onOpenKillSwitch}
        threatLevel="NORMAL"
      />
    );

    // Threat level badge
    expect(await screen.findByTestId('threat-level-badge')).toHaveTextContent('NORMAL');

    // Metric counter grid (C-010)
    expect(await screen.findByTestId('metric-active-agents')).toBeInTheDocument();
    expect(await screen.findByTestId('metric-tool-calls')).toBeInTheDocument();
    expect(await screen.findByTestId('metric-blocked-violations')).toBeInTheDocument();
    expect(await screen.findByTestId('metric-pending-approvals')).toBeInTheDocument();

    // Recent incidents
    expect(screen.getByText('Recent Security Incidents')).toBeInTheDocument();
  });

  it('triggers emergency kill-switch modal on button click', async () => {
    render(
      <DashboardScreen
        onNavigateTo={onNavigateTo}
        onOpenKillSwitch={onOpenKillSwitch}
        threatLevel="NORMAL"
      />
    );

    const killBtn = await screen.findByTestId('emergency-killswitch-trigger');
    fireEvent.click(killBtn);
    expect(onOpenKillSwitch).toHaveBeenCalledTimes(1);
  });

  it('navigates to approvals queue when clicking pending approvals metric card', async () => {
    render(
      <DashboardScreen
        onNavigateTo={onNavigateTo}
        onOpenKillSwitch={onOpenKillSwitch}
        threatLevel="NORMAL"
      />
    );

    const pendingCard = await screen.findByTestId('metric-pending-approvals');
    fireEvent.click(pendingCard);
    expect(onNavigateTo).toHaveBeenCalledWith('approvals');
  });

  it('renders elevated threat level and lockdown banner properly', async () => {
    const { rerender } = render(
      <DashboardScreen
        onNavigateTo={onNavigateTo}
        onOpenKillSwitch={onOpenKillSwitch}
        threatLevel="ELEVATED"
      />
    );

    expect(await screen.findByTestId('threat-level-badge')).toHaveTextContent('ELEVATED');

    rerender(
      <DashboardScreen
        onNavigateTo={onNavigateTo}
        onOpenKillSwitch={onOpenKillSwitch}
        threatLevel="LOCKDOWN"
      />
    );

    expect(await screen.findByTestId('threat-level-badge')).toHaveTextContent('LOCKDOWN');
  });

  it('renders error state and retries fetching', async () => {
    vi.spyOn(AegisApi, 'getSystemStatus').mockRejectedValueOnce(new Error('Gateway timeout'));

    render(
      <DashboardScreen
        onNavigateTo={onNavigateTo}
        onOpenKillSwitch={onOpenKillSwitch}
        threatLevel="NORMAL"
      />
    );

    expect(await screen.findByTestId('error-state')).toBeInTheDocument();
    expect(screen.getByText('Gateway timeout')).toBeInTheDocument();

    // Click retry
    const retryBtn = screen.getByTestId('retry-button');
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.queryByTestId('error-state')).not.toBeInTheDocument();
    });
  });
});
