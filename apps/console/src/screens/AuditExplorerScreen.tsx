/**
 * Specification Anchors: FEAT-007, FEAT-008, FEAT-011, FEAT-012, C-011, C-013, C-015
 * Screen 5: Audit Explorer. The integrity banner reports the gateway's most
 * recent completed verification; records and exports come from C-013/C-011.
 */

import React, { useCallback, useEffect, useState } from 'react';
import {
  ShieldCheck,
  Search,
  Filter,
  Download,
  Copy,
  Check,
  RotateCw,
  X,
  FileCheck2,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Loader2,
} from 'lucide-react';
import { AegisApi, ApiError } from '../services/api';
import {
  AuditDecision,
  AuditIntegrityResponse,
  AuditRecordItem,
  ComplianceExportRequest,
  ComplianceFramework,
  ComplianceFormat,
} from '../types/contracts';
import { Skeleton } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

const PAGE_SIZE = 10;

function localDateTimeInput(offsetMs: number): string {
  const date = new Date(Date.now() + offsetMs);
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

function toIso(localValue: string): string | null {
  if (!localValue) return null;
  const parsed = new Date(localValue);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

export const AuditExplorerScreen: React.FC = () => {
  const [records, setRecords] = useState<AuditRecordItem[]>([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [page, setPage] = useState(0);
  const [integrity, setIntegrity] = useState<AuditIntegrityResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [integrityLoading, setIntegrityLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [integrityError, setIntegrityError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<AuditRecordItem | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [appliedQuery, setAppliedQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<'ALL' | AuditDecision>('ALL');

  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [exportFramework, setExportFramework] = useState<ComplianceFramework>('EU_AI_ACT');
  const [exportFormat, setExportFormat] = useState<ComplianceFormat>('JSON');
  const [exportFrom, setExportFrom] = useState(() => localDateTimeInput(-24 * 60 * 60 * 1000));
  const [exportTo, setExportTo] = useState(() => localDateTimeInput(0));
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  const loadRecords = useCallback(
    async (targetPage: number, decision: 'ALL' | AuditDecision, queryText: string) => {
      setLoading(true);
      setError(null);
      try {
        const trimmed = queryText.trim();
        const filters: Parameters<typeof AegisApi.getAuditRecords>[0] = {
          limit: PAGE_SIZE,
          offset: targetPage * PAGE_SIZE,
        };
        if (decision !== 'ALL') filters.decision = decision;
        if (trimmed) {
          if (trimmed.startsWith('spiffe://')) filters.agentId = trimmed;
          else if (/^(0x)?[0-9a-f]{8,}$/i.test(trimmed)) filters.blockHash = trimmed;
          else filters.toolName = trimmed;
        }

        const response = await AegisApi.getAuditRecords(filters);
        setRecords(response.records);
        setTotalRecords(response.total);
        setLoading(false);
      } catch (err: unknown) {
        setLoading(false);
        setError(err instanceof Error ? err.message : 'Failed to retrieve audit records');
      }
    },
    []
  );

  const loadIntegrity = useCallback(async () => {
    setIntegrityLoading(true);
    setIntegrityError(null);
    try {
      const response = await AegisApi.getLedgerIntegrity();
      setIntegrity(response);
      if (!response.valid) {
        setIntegrityError('The last completed ledger verification found a hash-chain mismatch.');
      }
    } catch (err: unknown) {
      setIntegrityError(
        err instanceof Error
          ? err.message
          : 'The ledger integrity state could not be read from the gateway.'
      );
    } finally {
      setIntegrityLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRecords(page, decisionFilter, appliedQuery);
  }, [page, decisionFilter, appliedQuery, loadRecords]);

  useEffect(() => {
    loadIntegrity();
  }, [loadIntegrity]);

  const handleDecisionFilterChange = (value: string) => {
    setDecisionFilter(value as 'ALL' | AuditDecision);
    setPage(0);
  };

  const handleSearch = (event: React.FormEvent) => {
    event.preventDefault();
    setPage(0);
    setAppliedQuery(searchQuery);
  };

  const handleVerifyNow = async () => {
    setVerifying(true);
    await loadIntegrity();
    setVerifying(false);
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedHash(text);
      setTimeout(() => setCopiedHash(null), 2000);
    } catch {
      // Clipboard access can be denied; the hash remains visible.
    }
  };

  const handleDownloadExport = async () => {
    const from = toIso(exportFrom);
    const to = toIso(exportTo);
    if (!from || !to) {
      setExportError('Select a valid reporting period.');
      return;
    }
    if (new Date(from) > new Date(to)) {
      setExportError('The start of the reporting period must be before its end.');
      return;
    }

    const request: ComplianceExportRequest = {
      framework: exportFramework,
      format: exportFormat,
      from,
      to,
    };

    setIsExporting(true);
    setExportError(null);
    setExportNotice(null);
    try {
      const response = await AegisApi.exportComplianceReport(request);

      if (response.status === 'GENERATING') {
        setExportNotice(
          `Report ${response.reportId} was accepted for background generation. The signed archive will be delivered through the deployment's configured notification channels.`
        );
        setIsExportModalOpen(false);
        return;
      }

      let downloadContent = response.content;
      if (exportFormat === 'JSON') {
        try {
          const parsed = JSON.parse(response.content);
          if (!parsed.signature) parsed.signature = response.signature;
          if (!parsed.merkleRoot) parsed.merkleRoot = response.merkleRoot;
          downloadContent = JSON.stringify(parsed, null, 2);
        } catch {
          downloadContent = JSON.stringify(response, null, 2);
        }
      } else {
        if (!downloadContent.includes('Merkle Root') && !downloadContent.includes('Signature')) {
          downloadContent =
            `# Merkle Root: ${response.merkleRoot}\n# Digital Signature: ${response.signature}\n` +
            downloadContent;
        }
      }

      if (typeof window !== 'undefined' && typeof window.URL?.createObjectURL === 'function') {
        const blob = new Blob([downloadContent], {
          type: exportFormat === 'JSON' ? 'application/json' : 'text/csv',
        });
        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `aegis-compliance-${exportFramework.toLowerCase()}.${exportFormat.toLowerCase()}`;
        anchor.click();
        window.URL.revokeObjectURL(url);
      }
      setIsExportModalOpen(false);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 409) {
        setIntegrityError(
          err.brokenBlockIndex !== undefined
            ? `Compliance export aborted: the hash chain is broken at block #${err.brokenBlockIndex}.`
            : err.message
        );
        setIsExportModalOpen(false);
      } else {
        setExportError(err instanceof Error ? err.message : 'The compliance export failed.');
      }
    } finally {
      setIsExporting(false);
    }
  };

  const pageCount = Math.max(1, Math.ceil(totalRecords / PAGE_SIZE));
  const integrityUnavailable = !!integrityError && !integrity?.valid;

  return (
    <div className="p-space-lg max-w-7xl mx-auto space-y-space-md animate-in fade-in duration-150">
      <div
        data-testid="audit-integrity-banner"
        className={`p-space-md rounded-radius-lg border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-md shadow-sm ${
          integrityUnavailable
            ? 'bg-warning-100 border-warning-300'
            : 'bg-grey-100 border-grey-300'
        }`}
      >
        <div className="flex items-center gap-space-md">
          <div
            className={`p-2.5 rounded-radius-md border ${
              integrityUnavailable
                ? 'bg-warning-100 text-warning-900 border-warning-300'
                : 'bg-success-100 text-success-900 border-success-300'
            }`}
          >
            {integrityUnavailable ? (
              <AlertTriangle className="w-6 h-6 text-warning-500" />
            ) : (
              <ShieldCheck className="w-6 h-6 text-success-500" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className={`text-xs font-mono font-bold uppercase ${
                  integrityUnavailable ? 'text-warning-700' : 'text-success-500'
                }`}
              >
                {integrityLoading
                  ? 'Reading ledger integrity'
                  : integrityUnavailable
                  ? 'Ledger integrity unavailable'
                  : integrity?.valid
                  ? 'Cryptographic chain verified'
                  : 'Ledger integrity alert'}
              </span>
              <span className="text-xs font-mono text-grey-500">(SHA-256 hash chain)</span>
            </div>
            <p className="text-sm font-semibold text-grey-900 mt-0.5">
              {integrity
                ? `${integrity.totalVerifiedBlocks.toLocaleString()} sealed blocks covered by the last completed verification`
                : integrityLoading
                ? 'Loading the last completed verification…'
                : 'No verification result is available.'}
            </p>
            <p className="text-[11px] font-mono text-grey-500 mt-0.5">
              {integrity
                ? `Last verified ${new Date(integrity.lastVerifiedAt).toLocaleString()}`
                : '—'}
            </p>
          </div>
        </div>

        <button
          onClick={handleVerifyNow}
          disabled={verifying || integrityLoading}
          data-testid="verify-now-button"
          className="inline-flex items-center gap-1.5 px-space-md py-space-sm bg-grey-200 hover:bg-grey-300 text-grey-900 font-semibold text-xs rounded-radius-md transition-colors disabled:opacity-50 border border-grey-300"
        >
          <RotateCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
          <span>{verifying ? 'Reading verification status...' : 'Refresh Status'}</span>
        </button>
      </div>

      {exportNotice && (
        <div
          data-testid="export-accepted-banner"
          role="status"
          className="p-space-sm rounded-radius-md bg-info-100 border border-info-300 text-info-900 text-xs"
        >
          {exportNotice}
        </div>
      )}

      {integrityError && (
        <div
          data-testid="audit-integrity-error-banner"
          role="alert"
          className="p-space-md rounded-radius-lg bg-error-100 border border-error-300 text-error-900 flex items-start justify-between gap-space-md shadow-sm"
        >
          <div className="flex items-center gap-space-md">
            <div className="p-2.5 rounded-radius-md bg-error-500/10 text-error-900 border border-error-300">
              <AlertTriangle className="w-6 h-6 text-error-700" />
            </div>
            <div>
              <span className="text-xs font-mono font-bold text-error-700 uppercase">
                {integrity?.valid === false
                  ? 'Cryptographic integrity alert'
                  : 'Ledger integrity unavailable'}
              </span>
              <p className="text-sm font-semibold text-error-900 mt-0.5">{integrityError}</p>
            </div>
          </div>
          <button
            onClick={() => setIntegrityError(null)}
            className="p-1 text-error-700 hover:text-error-900"
            aria-label="Dismiss alert"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {error && <ErrorState message={error} onRetry={() => loadRecords(page, decisionFilter, appliedQuery)} />}

      <form
        onSubmit={handleSearch}
        className="flex flex-wrap items-center justify-between gap-space-md p-space-sm bg-grey-100 border border-grey-300 rounded-radius-md"
      >
        <div className="flex items-center gap-space-sm flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-grey-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search by agent, tool, or SHA-256 hash..."
              className="pl-8 pr-space-md py-1.5 bg-grey-200 border border-grey-300 rounded-radius-md text-xs text-grey-900 placeholder:text-grey-500 focus:border-primary-500 outline-none w-full sm:w-72 font-mono"
            />
          </div>

          <button
            type="submit"
            data-testid="audit-search-button"
            className="px-space-md py-1.5 bg-grey-200 hover:bg-grey-300 border border-grey-300 rounded-radius-md text-xs font-semibold text-grey-800"
          >
            Search
          </button>

          <div className="flex items-center gap-1.5 bg-grey-200 border border-grey-300 rounded-radius-md px-2 py-1 text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-grey-500" />
            <select
              value={decisionFilter}
              onChange={(event) => handleDecisionFilterChange(event.target.value)}
              className="bg-transparent text-grey-800 outline-none cursor-pointer"
            >
              <option value="ALL">All Decisions</option>
              <option value="allow">Allowed</option>
              <option value="block">Blocked</option>
              <option value="require_approval">Requires Approval</option>
            </select>
          </div>
        </div>

        <button
          type="button"
          onClick={() => {
            setExportError(null);
            setIsExportModalOpen(true);
          }}
          data-testid="export-report-button"
          className="inline-flex items-center gap-1.5 px-space-md py-1.5 bg-primary-500 hover:bg-primary-600 text-grey-900 font-bold text-xs rounded-radius-md transition-colors shadow-sm"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Compliance Report</span>
        </button>
      </form>

      {loading ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      ) : records.length === 0 ? (
        <EmptyState
          icon={Search}
          title="No audit records found"
          description="No ledger blocks match the current query. Check the block hash or reset the filters."
          actionLabel="Reset Search"
          onAction={() => {
            setSearchQuery('');
            setAppliedQuery('');
            setDecisionFilter('ALL');
            setPage(0);
          }}
        />
      ) : (
        <div className="bg-grey-100 border border-grey-300 rounded-radius-md overflow-x-auto shadow-sm">
          <table className="w-full min-w-[900px] text-left text-xs font-mono">
            <thead className="bg-grey-200 border-b border-grey-300 text-grey-500">
              <tr>
                <th className="py-2.5 px-space-md font-medium">Block #</th>
                <th className="py-2.5 px-space-md font-medium">Timestamp (UTC)</th>
                <th className="py-2.5 px-space-md font-medium">SHA-256 Hash</th>
                <th className="py-2.5 px-space-md font-medium">Agent Workload</th>
                <th className="py-2.5 px-space-md font-medium">Target Tool</th>
                <th className="py-2.5 px-space-md font-medium">Arguments Hash</th>
                <th className="py-2.5 px-space-md font-medium">Decision</th>
                <th className="py-2.5 px-space-md font-medium">Approver</th>
                <th className="py-2.5 px-space-md font-medium text-right">Proof</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-grey-300/40">
              {records.map((record) => (
                <tr
                  key={record.blockIndex}
                  data-testid={`audit-row-${record.blockIndex}`}
                  className="hover:bg-grey-200/50 transition-colors"
                >
                  <td className="py-2.5 px-space-md text-primary-500 font-bold">#{record.blockIndex}</td>
                  <td className="py-2.5 px-space-md text-grey-500 whitespace-nowrap">
                    {new Date(record.timestamp).toISOString()}
                  </td>
                  <td className="py-2.5 px-space-md text-grey-600">
                    <span className="inline-flex items-center gap-1">
                      <span>{record.blockHash.slice(0, 10)}...</span>
                      <button
                        onClick={() => copyToClipboard(record.blockHash)}
                        className="p-1 hover:text-grey-900"
                        title="Copy hash"
                        aria-label="Copy block hash"
                      >
                        {copiedHash === record.blockHash ? (
                          <Check className="w-3 h-3 text-success-500" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </span>
                  </td>
                  <td
                    className="py-2.5 px-space-md text-grey-800 max-w-[140px] truncate"
                    title={record.agentId}
                  >
                    {record.agentId.split('/').pop()}
                  </td>
                  <td className="py-2.5 px-space-md text-primary-700 font-semibold">
                    {record.toolName}
                  </td>
                  <td
                    className="py-2.5 px-space-md text-grey-500 max-w-[120px] truncate"
                    title={record.argumentsHash}
                  >
                    {record.argumentsHash.slice(0, 10)}...
                  </td>
                  <td className="py-2.5 px-space-md">
                    <StatusPill verdict={record.decision} />
                  </td>
                  <td className="py-2.5 px-space-md text-grey-500 truncate max-w-[140px]" title={record.reviewedBy ?? undefined}>
                    {record.reviewedBy ?? 'Not applicable'}
                  </td>
                  <td className="py-2.5 px-space-md text-right">
                    <button
                      onClick={() => setSelectedRecord(record)}
                      data-testid={`view-proof-${record.blockIndex}`}
                      className="text-primary-500 hover:text-primary-400 font-semibold underline"
                    >
                      View Proof
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="p-space-sm bg-grey-200 border-t border-grey-300 flex items-center justify-between text-xs font-mono text-grey-700">
            <span data-testid="pagination-info">
              Showing {records.length > 0 ? page * PAGE_SIZE + 1 : 0} -{' '}
              {Math.min((page + 1) * PAGE_SIZE, totalRecords)} of {totalRecords} records
            </span>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage((current) => Math.max(0, current - 1))}
                disabled={page === 0}
                data-testid="pagination-prev"
                className="inline-flex items-center gap-1 px-2.5 py-1 bg-grey-100 border border-grey-300 hover:bg-grey-300 disabled:opacity-40 rounded-radius-sm"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Prev</span>
              </button>
              <span className="px-2 font-bold">
                Page {page + 1} of {pageCount}
              </span>
              <button
                onClick={() => setPage((current) => current + 1)}
                disabled={(page + 1) * PAGE_SIZE >= totalRecords}
                data-testid="pagination-next"
                className="inline-flex items-center gap-1 px-2.5 py-1 bg-grey-100 border border-grey-300 hover:bg-grey-300 disabled:opacity-40 rounded-radius-sm"
              >
                <span>Next</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedRecord && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="proof-dialog-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm"
        >
          <div className="w-full max-w-xl bg-grey-100 border border-grey-300 rounded-radius-lg p-space-lg shadow-xl space-y-space-md">
            <div className="flex items-center justify-between pb-space-xs border-b border-grey-300">
              <div className="flex items-center gap-2">
                <FileCheck2 className="w-5 h-5 text-success-500" />
                <h3 id="proof-dialog-title" className="font-bold text-sm text-grey-900">
                  Cryptographic Ledger Proof #{selectedRecord.blockIndex}
                </h3>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="p-1 text-grey-500 hover:text-grey-900"
                aria-label="Close proof"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-space-sm text-xs font-mono">
              <div className="p-space-sm bg-grey-200 rounded-radius-md space-y-1">
                <span className="text-grey-500 block">Block SHA-256 hash:</span>
                <span className="text-primary-700 break-all">{selectedRecord.blockHash}</span>
              </div>

              <div className="p-space-sm bg-grey-200 rounded-radius-md space-y-1">
                <span className="text-grey-500 block">Parent hash:</span>
                <span className="text-grey-700 break-all">{selectedRecord.parentHash}</span>
              </div>

              <div className="p-space-sm bg-grey-200 rounded-radius-md space-y-1">
                <span className="text-grey-500 block">Arguments hash:</span>
                <span className="text-grey-700 break-all">{selectedRecord.argumentsHash}</span>
              </div>

              <div className="grid grid-cols-2 gap-space-sm">
                <div className="p-space-sm bg-grey-200 rounded-radius-md">
                  <span className="text-grey-500 block">Decision</span>
                  <StatusPill verdict={selectedRecord.decision} />
                </div>
                <div className="p-space-sm bg-grey-200 rounded-radius-md">
                  <span className="text-grey-500 block">Reviewed by</span>
                  <span className="text-grey-700">{selectedRecord.reviewedBy ?? 'Not applicable'}</span>
                </div>
                <div className="p-space-sm bg-grey-200 rounded-radius-md">
                  <span className="text-grey-500 block">Redactions</span>
                  <span className="text-grey-700">{selectedRecord.redactionCount}</span>
                </div>
                <div className="p-space-sm bg-grey-200 rounded-radius-md">
                  <span className="text-grey-500 block">Processing latency</span>
                  <span className="text-grey-700">{selectedRecord.latencyMs} ms</span>
                </div>
              </div>

              <div className="p-space-sm bg-grey-200 rounded-radius-md">
                <span className="text-grey-500 block">Sealed at</span>
                <span className="text-grey-700">
                  {new Date(selectedRecord.timestamp).toISOString()}
                </span>
              </div>
            </div>

            <div className="flex justify-end pt-space-xs">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-space-md py-space-sm bg-grey-200 hover:bg-grey-300 rounded-radius-md text-xs font-medium text-grey-800"
              >
                Close Proof
              </button>
            </div>
          </div>
        </div>
      )}

      {isExportModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="export-dialog-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm"
        >
          <div className="w-full max-w-md bg-grey-100 border border-grey-300 rounded-radius-lg p-space-lg shadow-xl space-y-space-md">
            <div className="flex items-center justify-between pb-space-xs border-b border-grey-300">
              <h3 id="export-dialog-title" className="font-bold text-sm text-grey-900">
                Export Tamper-Evident Audit Report
              </h3>
              <button
                onClick={() => setIsExportModalOpen(false)}
                className="p-1 text-grey-500 hover:text-grey-900"
                aria-label="Close export dialog"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {exportError && (
              <div
                role="alert"
                data-testid="export-error"
                className="p-space-sm bg-error-100 border border-error-300 text-error-900 rounded-radius-md text-xs"
              >
                {exportError}
              </div>
            )}

            <div className="space-y-space-sm text-xs">
              <div>
                <label className="block text-grey-600 font-semibold mb-1" htmlFor="export-framework">
                  Compliance Framework
                </label>
                <select
                  id="export-framework"
                  value={exportFramework}
                  onChange={(event) =>
                    setExportFramework(event.target.value as ComplianceFramework)
                  }
                  className="w-full bg-grey-200 border border-grey-300 rounded-radius-md p-2 text-grey-900 outline-none"
                >
                  <option value="EU_AI_ACT">EU AI Act (Article 12/14 Human Oversight Record)</option>
                  <option value="SOC2_TYPE2">SOC 2 Type II (Continuous Access Control Log)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-space-sm">
                <div>
                  <label className="block text-grey-600 font-semibold mb-1" htmlFor="export-from">
                    Period start
                  </label>
                  <input
                    id="export-from"
                    type="datetime-local"
                    value={exportFrom}
                    onChange={(event) => setExportFrom(event.target.value)}
                    className="w-full bg-grey-200 border border-grey-300 rounded-radius-md p-2 text-grey-900 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-grey-600 font-semibold mb-1" htmlFor="export-to">
                    Period end
                  </label>
                  <input
                    id="export-to"
                    type="datetime-local"
                    value={exportTo}
                    onChange={(event) => setExportTo(event.target.value)}
                    className="w-full bg-grey-200 border border-grey-300 rounded-radius-md p-2 text-grey-900 outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-grey-600 font-semibold mb-1">Export Format</label>
                <div className="flex items-center gap-space-md">
                  <label className="inline-flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="format"
                      checked={exportFormat === 'JSON'}
                      onChange={() => setExportFormat('JSON')}
                    />
                    <span>Cryptographic JSON Archive</span>
                  </label>
                  <label className="inline-flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="format"
                      checked={exportFormat === 'CSV'}
                      onChange={() => setExportFormat('CSV')}
                    />
                    <span>Auditor CSV Ledger</span>
                  </label>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-space-sm pt-space-xs border-t border-grey-300">
              <button
                onClick={() => setIsExportModalOpen(false)}
                className="px-space-md py-space-sm rounded-radius-md text-xs text-grey-600 hover:text-grey-900"
              >
                Cancel
              </button>
              <button
                onClick={handleDownloadExport}
                disabled={isExporting}
                data-testid="confirm-download-report"
                className="inline-flex items-center gap-1.5 px-space-md py-space-sm bg-primary-500 hover:bg-primary-600 disabled:opacity-50 text-grey-900 font-bold text-xs rounded-radius-md transition-colors"
              >
                {isExporting ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
                <span>{isExporting ? 'Generating Report...' : 'Download Report'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
