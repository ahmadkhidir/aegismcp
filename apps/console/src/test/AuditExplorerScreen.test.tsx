/**
 * Specification Anchors: FEAT-007, FEAT-008, FEAT-011, FEAT-012, C-007, C-011, C-013
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

  it('renders cryptographic integrity banner and audit record table (C-013)', async () => {
    render(<AuditExplorerScreen />);

    expect(await screen.findByTestId('audit-integrity-banner')).toBeInTheDocument();
    expect(screen.getByText('Cryptographic Chain Verified')).toBeInTheDocument();

    // Audit records
    expect(await screen.findByTestId('audit-row-1048590')).toBeInTheDocument();
    expect(screen.getByText('stripe_charge_create')).toBeInTheDocument();
    expect(screen.getByText('database_execute_query')).toBeInTheDocument();

    // Pagination info
    expect(screen.getByTestId('pagination-info')).toBeInTheDocument();
    expect(screen.getByTestId('pagination-prev')).toBeDisabled();
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

  it('filters audit records by decision and re-fetches records (C-013)', async () => {
    const recordsSpy = vi.spyOn(AegisApi, 'getAuditRecords');

    render(<AuditExplorerScreen />);

    await screen.findByTestId('audit-row-1048590');

    const select = screen.getByDisplayValue('All Decisions');
    fireEvent.change(select, { target: { value: 'BLOCKED' } });

    await waitFor(() => {
      expect(recordsSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          decision: 'BLOCKED',
        })
      );
    });
  });

  it('opens cryptographic proof drawer for a specific block', async () => {
    render(<AuditExplorerScreen />);

    const proofBtn = await screen.findByTestId('view-proof-1048590');
    fireEvent.click(proofBtn);

    expect(await screen.findByText('Cryptographic Ledger Proof #1048590')).toBeInTheDocument();
    expect(screen.getByText(/Block SHA-256 Hash/i)).toBeInTheDocument();
    expect(screen.getByText(/Parent Previous Hash/i)).toBeInTheDocument();
    expect(screen.getByText(/ECDSA Digital Signature/i)).toBeInTheDocument();
  });

  it('opens compliance report export modal and triggers download via C-011', async () => {
    const exportSpy = vi.spyOn(AegisApi, 'exportComplianceReport');

    render(<AuditExplorerScreen />);

    const exportBtn = await screen.findByTestId('export-report-button');
    fireEvent.click(exportBtn);

    expect(await screen.findByText('Export Tamper-Evident Audit Report')).toBeInTheDocument();

    // Select SOC2_TYPE2 and CSV format
    const frameworkSelect = screen.getByDisplayValue(/EU AI Act/i);
    fireEvent.change(frameworkSelect, { target: { value: 'SOC2_TYPE2' } });

    const csvRadio = screen.getByLabelText(/Auditor CSV Ledger/i);
    fireEvent.click(csvRadio);

    // Trigger download
    const downloadBtn = screen.getByTestId('confirm-download-report');
    fireEvent.click(downloadBtn);

    await waitFor(() => {
      expect(exportSpy).toHaveBeenCalledWith({
        framework: 'SOC2_TYPE2',
        format: 'CSV',
      });
      expect(screen.queryByText('Export Tamper-Evident Audit Report')).not.toBeInTheDocument();
    });
  });

  it('handles 409 Conflict integrity errors with an alert banner', async () => {
    const conflictError = new Error('Cryptographic hash chain broken or integrity compromised');
    (conflictError as unknown as { status: number }).status = 409;
    vi.spyOn(AegisApi, 'exportComplianceReport').mockRejectedValueOnce(conflictError);

    render(<AuditExplorerScreen />);

    const exportBtn = await screen.findByTestId('export-report-button');
    fireEvent.click(exportBtn);

    const downloadBtn = screen.getByTestId('confirm-download-report');
    fireEvent.click(downloadBtn);

    expect(await screen.findByTestId('audit-integrity-error-banner')).toBeInTheDocument();
    expect(screen.getByText(/Cryptographic Integrity Alert \(409 Conflict\)/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Cryptographic hash chain is broken or compromised/i)
    ).toBeInTheDocument();
  });
});
