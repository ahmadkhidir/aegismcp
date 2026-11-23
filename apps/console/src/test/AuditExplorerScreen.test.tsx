/**
 * Specification Anchors: FEAT-007, FEAT-008, FEAT-011, FEAT-012, C-011, C-013, C-015
 * Audit explorer behaviour with contract fixtures held in this test module.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AuditExplorerScreen } from '../screens/AuditExplorerScreen';
import { AegisApi, ApiError } from '../services/api';
import { AuditIntegrityResponse, AuditRecordItem } from '../types/contracts';

const INTEGRITY: AuditIntegrityResponse = {
  valid: true,
  totalVerifiedBlocks: 1048590,
  lastVerifiedAt: '2026-11-23T09:00:00Z',
};

const RECORDS: AuditRecordItem[] = [
  {
    blockIndex: 1048590,
    blockHash: '3f4a9b8c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a',
    parentHash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    agentId: 'spiffe://example.org/ns/finance/sa/settlement-worker',
    toolName: 'payments_transfer',
    argumentsHash: '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e',
    decision: 'allow',
    redactionCount: 2,
    latencyMs: 4.2,
    timestamp: '2026-11-23T09:59:55Z',
    reviewedBy: 'operator@example.com',
  },
  {
    blockIndex: 1048589,
    blockHash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    parentHash: '8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e',
    agentId: 'spiffe://example.org/ns/ops/sa/triage-bot',
    toolName: 'bash_run_command',
    argumentsHash: '8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e',
    decision: 'block',
    redactionCount: 0,
    latencyMs: 1.8,
    timestamp: '2026-11-23T09:58:12Z',
    reviewedBy: null,
  },
];

const EXPORT_RESPONSE = {
  reportId: 'rep-comp-1',
  framework: 'SOC2_TYPE2',
  format: 'CSV',
  status: 'COMPLETED' as const,
  generatedAt: '2026-11-23T10:00:00Z',
  recordCount: 2,
  violationsCount: 1,
  approvalsCount: 0,
  merkleRoot: 'root-hash',
  signature: 'signature-bytes',
  content: 'index,blockHash,timestamp\n1048590,abc,2026-11-23T09:59:55Z\n',
};

describe('AuditExplorerScreen', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(AegisApi, 'getAuditRecords').mockResolvedValue({ records: RECORDS, total: 24 });
    vi.spyOn(AegisApi, 'getLedgerIntegrity').mockResolvedValue(INTEGRITY);
    vi.spyOn(AegisApi, 'exportComplianceReport').mockResolvedValue(EXPORT_RESPONSE);
  });

  it('renders the integrity summary and the audit record table', async () => {
    render(<AuditExplorerScreen />);

    expect(await screen.findByTestId('audit-integrity-banner')).toHaveTextContent(
      'Cryptographic chain verified'
    );
    expect(screen.getByText(/1,048,590 sealed blocks/)).toBeInTheDocument();

    expect(await screen.findByTestId('audit-row-1048590')).toBeInTheDocument();
    expect(screen.getByText('payments_transfer')).toBeInTheDocument();
    expect(screen.getByText('bash_run_command')).toBeInTheDocument();
    expect(screen.getByText('Showing 1 - 10 of 24 records')).toBeInTheDocument();
    expect(screen.getByTestId('pagination-prev')).toBeDisabled();
  });

  it('re-reads the last completed verification when the operator refreshes status', async () => {
    const integrity = vi.mocked(AegisApi.getLedgerIntegrity);
    render(<AuditExplorerScreen />);

    await screen.findByText(/1,048,590 sealed blocks/);
    fireEvent.click(screen.getByTestId('verify-now-button'));

    await waitFor(() => {
      expect(integrity).toHaveBeenCalledTimes(2);
    });
  });

  it('searches by exact tool identity and re-fetches records', async () => {
    const records = vi.mocked(AegisApi.getAuditRecords);
    render(<AuditExplorerScreen />);

    const search = await screen.findByPlaceholderText(/Search by agent, tool, or SHA-256 hash/i);
    fireEvent.change(search, { target: { value: 'bash_run_command' } });
    fireEvent.click(screen.getByTestId('audit-search-button'));

    await waitFor(() => {
      expect(records).toHaveBeenCalledWith(
        expect.objectContaining({ toolName: 'bash_run_command', limit: 10, offset: 0 })
      );
    });
  });

  it('filters by contract decision values', async () => {
    const records = vi.mocked(AegisApi.getAuditRecords);
    render(<AuditExplorerScreen />);

    await screen.findByTestId('audit-row-1048590');
    fireEvent.change(screen.getByDisplayValue('All Decisions'), {
      target: { value: 'block' },
    });

    await waitFor(() => {
      expect(records).toHaveBeenCalledWith(expect.objectContaining({ decision: 'block' }));
    });
  });

  it('opens the proof drawer with the sealed hash links and reviewer', async () => {
    render(<AuditExplorerScreen />);

    fireEvent.click(await screen.findByTestId('view-proof-1048590'));

    expect(await screen.findByText('Cryptographic Ledger Proof #1048590')).toBeInTheDocument();
    expect(screen.getByText('Block SHA-256 hash:')).toBeInTheDocument();
    expect(screen.getByText('Parent hash:')).toBeInTheDocument();
    expect(screen.getByText('Arguments hash:')).toBeInTheDocument();
    expect(screen.getAllByText('operator@example.com').length).toBeGreaterThan(0);
    expect(screen.queryByText(/ECDSA Digital Signature/i)).not.toBeInTheDocument();
  });

  it('exports a signed report for the selected framework, format, and period', async () => {
    const exportReport = vi.mocked(AegisApi.exportComplianceReport);
    render(<AuditExplorerScreen />);

    fireEvent.click(await screen.findByTestId('export-report-button'));
    expect(await screen.findByText('Export Tamper-Evident Audit Report')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Compliance Framework'), {
      target: { value: 'SOC2_TYPE2' },
    });
    fireEvent.click(screen.getByLabelText(/Auditor CSV Ledger/i));
    fireEvent.click(screen.getByTestId('confirm-download-report'));

    await waitFor(() => {
      expect(exportReport).toHaveBeenCalledWith(
        expect.objectContaining({
          framework: 'SOC2_TYPE2',
          format: 'CSV',
          from: expect.any(String),
          to: expect.any(String),
        })
      );
    });
    await waitFor(() => {
      expect(screen.queryByText('Export Tamper-Evident Audit Report')).not.toBeInTheDocument();
    });
  });

  it('reports an accepted background export instead of waiting on it', async () => {
    vi.mocked(AegisApi.exportComplianceReport).mockResolvedValue({
      reportId: 'rep-comp-2',
      status: 'GENERATING',
    });

    render(<AuditExplorerScreen />);
    fireEvent.click(await screen.findByTestId('export-report-button'));
    fireEvent.click(await screen.findByTestId('confirm-download-report'));

    expect(await screen.findByTestId('export-accepted-banner')).toHaveTextContent(
      'rep-comp-2 was accepted for background generation'
    );
  });

  it('surfaces a 409 chain failure as an integrity alert with the damaged block', async () => {
    vi.mocked(AegisApi.exportComplianceReport).mockRejectedValue(
      new ApiError(409, 'Hash chain broken.', { brokenBlockIndex: 1048589 })
    );

    render(<AuditExplorerScreen />);
    fireEvent.click(await screen.findByTestId('export-report-button'));
    fireEvent.click(await screen.findByTestId('confirm-download-report'));

    expect(await screen.findByTestId('audit-integrity-error-banner')).toHaveTextContent(
      'broken at block #1048589'
    );
  });

  it('keeps records visible when the integrity state cannot be read', async () => {
    vi.mocked(AegisApi.getLedgerIntegrity).mockRejectedValue(
      new ApiError(503, 'Ledger store unreachable.')
    );

    render(<AuditExplorerScreen />);

    expect(await screen.findByTestId('audit-integrity-error-banner')).toHaveTextContent(
      'Ledger store unreachable.'
    );
    expect(await screen.findByTestId('audit-row-1048590')).toBeInTheDocument();
  });

  it('shows a true empty state when no record matches', async () => {
    vi.mocked(AegisApi.getAuditRecords).mockResolvedValue({ records: [], total: 0 });

    render(<AuditExplorerScreen />);

    expect(await screen.findByText('No audit records found')).toBeInTheDocument();
  });
});
