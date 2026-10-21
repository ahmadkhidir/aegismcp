/**
 * Specification Anchors: FEAT-002, FEAT-008, FEAT-012, C-005, C-006
 * Policy Manager Screen Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { PolicyManagerScreen } from '../screens/PolicyManagerScreen';
import { AegisApi } from '../services/api';

describe('PolicyManagerScreen Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders declarative policy editor and lists policy files (C-005)', async () => {
    render(<PolicyManagerScreen />);

    expect(await screen.findByText('Declarative Policy Manager')).toBeInTheDocument();
    expect(await screen.findByTestId('policy-yaml-editor')).toBeInTheDocument();
    expect(screen.getByText('Zero-Trust Production Gateway Guardrails')).toBeInTheDocument();
  });

  it('runs policy simulator with high-risk payload and displays BLOCKED outcome', async () => {
    render(<PolicyManagerScreen />);

    const runBtn = await screen.findByTestId('simulate-test-button');
    fireEvent.click(runBtn);

    // Default simulation payload is bash curl|sh, which should block
    expect(await screen.findByTestId('simulation-outcome')).toBeInTheDocument();
    expect(screen.getByText('BLOCKED')).toBeInTheDocument();
  });

  it('edits YAML and deploys policy update invoking C-006', async () => {
    const deploySpy = vi.spyOn(AegisApi, 'createPolicy');
    vi.spyOn(window, 'alert').mockImplementation(() => {});

    render(<PolicyManagerScreen />);

    const editor = await screen.findByTestId('policy-yaml-editor');
    fireEvent.change(editor, {
      target: { value: 'apiVersion: security.aegis.io/v1alpha1\nkind: SecurityPolicy\n# updated' },
    });

    const deployBtn = screen.getByTestId('deploy-policy-button');
    expect(deployBtn).not.toBeDisabled();

    fireEvent.click(deployBtn);

    await waitFor(() => {
      expect(deploySpy).toHaveBeenCalledWith(
        expect.objectContaining({
          rawYaml: expect.stringContaining('# updated'),
        })
      );
    });
  });
});
