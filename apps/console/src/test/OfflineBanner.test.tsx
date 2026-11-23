/**
 * Specification Anchors: FEAT-008, screens/01-dashboard
 * Connectivity loss is a first-class shell state: the banner stays visible
 * until the browser reports it is online again.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { OfflineBanner } from '../components/OfflineBanner';

describe('OfflineBanner', () => {
  it('renders nothing while the browser is online', () => {
    render(<OfflineBanner isOffline={false} />);
    expect(screen.queryByTestId('offline-banner')).not.toBeInTheDocument();
  });

  it('states that the connection is lost and telemetry is paused', () => {
    render(<OfflineBanner isOffline />);
    expect(screen.getByTestId('offline-banner')).toHaveTextContent(
      /Offline . browser connection lost\. Telemetry paused\./
    );
  });
});
