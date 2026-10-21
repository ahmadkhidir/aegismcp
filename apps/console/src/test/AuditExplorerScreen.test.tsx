/**
 * Specification Anchors: FEAT-007, FEAT-008, FEAT-011, C-007
 * Audit Explorer Screen Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AuditExplorerScreen } from '../screens/AuditExplorerScreen';
import { AegisApi } from '../services/api';

describe('AuditExplorerScreen Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders cryptographic integrity banner and audit record table', async () => {
    render(<AuditExplorerScreen />);

    expect(await screen.findByTestId('audit-integrity-banner')).toBeInTheDocument();
    expect(screen.getByText('Cryptographic Chain Verified')).toBeInTheDocument();

    // Audit records
    expect(await screen.findByTestId('audit-row-1048590')).toBeInTheDocument();
    expect(screen.getByText('stripe_charge_create')).toBeInTheDocument();
    expect(screen.getByText('database_execute_query')).toBeInTheDocument();
  });

  it('verifies Merkle root on "Verify Now" button click (C-007)', async () => {
    const verifySpy = vi.spyOn(AegisApi, 'verifyAuditLedger');

    render(<AuditExplorerScreen />);

    const verifyBtn = await screen.findByTestId('verify-now-button');
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(verifySpy).toHaveBeenCalled();
    });
  });

  it('filters audit records by tool or agent name', async () => {
    render(<AuditExplorerScreen />);

    const searchInput = await screen.findByPlaceholderText(/Search by agent, tool, or SHA-256 hash/i);
    fireEvent.change(searchInput, { target: { value: 'database_execute_query' } });

    expect(screen.getByText('database_execute_query')).toBeInTheDocument();
    expect(screen.queryByText('fs_read_file')).not.toBeInTheDocument();
  });

  it('opens cryptographic proof drawer for a specific block', async () => {
    render(<AuditExplorerScreen />);

    const proofBtn = await screen.findByTestId('view-proof-1048590');
    fireEvent.click(proofBtn);

    expect(await screen.findByText('Cryptographic Ledger Proof #1048590')).toBeInTheDocument();
    expect(screen.getByText(/Block SHA-256 Hash/i)).toBeInTheDocument();
    expect(screen.getByText(/ECDSA Digital Signature/i)).toBeInTheDocument();
  });

  it('opens compliance report export modal and triggers download', async () => {
    render(<AuditExplorerScreen />);

    const exportBtn = await screen.findByTestId('export-report-button');
    fireEvent.click(exportBtn);

    expect(await screen.findByText('Export Tamper-Evident Audit Report')).toBeInTheDocument();

    // Trigger download
    const downloadBtn = screen.getByTestId('confirm-download-report');
    fireEvent.click(downloadBtn);

    await waitFor(() => {
      expect(screen.queryByText('Export Tamper-Evident Audit Report')).not.toBeInTheDocument();
    });
  });
});
