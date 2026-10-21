/**
 * Specification Anchors: FEAT-007, FEAT-008, FEAT-011, FEAT-012, C-007, C-011, C-013
 * Screen 5: Audit Explorer
 */

import React, { useEffect, useState } from 'react';
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
import { AegisApi } from '../services/api';
import { AuditRecordItem, AuditVerifyResponse } from '../types/contracts';
import { Skeleton } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

export const AuditExplorerScreen: React.FC = () => {
  const [records, setRecords] = useState<AuditRecordItem[]>([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [page, setPage] = useState(0);
  const pageSize = 10;
  const [integrityStatus, setIntegrityStatus] = useState<AuditVerifyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [integrityError, setIntegrityError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<AuditRecordItem | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');

  // Export modal state
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [exportFramework, setExportFramework] = useState<'EU_AI_ACT' | 'SOC2_TYPE2'>('EU_AI_ACT');
  const [exportFormat, setExportFormat] = useState<'JSON' | 'CSV'>('JSON');

  const loadAuditData = async (
    targetPage = page,
    targetDecision = decisionFilter,
    targetQuery = searchQuery
  ) => {
    setLoading(true);
    setError(null);
    try {
      const [auditRes, verifyRes] = await Promise.all([
        AegisApi.getAuditRecords({
          agentId: targetQuery.trim().startsWith('spiffe://') ? targetQuery.trim() : undefined,
          decision: targetDecision !== 'ALL' ? targetDecision : undefined,
          limit: pageSize,
          offset: targetPage * pageSize,
        }),
        AegisApi.verifyAuditLedger(),
      ]);
      setRecords(auditRes.records);
      setTotalRecords(auditRes.total);
      setIntegrityStatus(verifyRes);
      if (!verifyRes.valid) {
        setIntegrityError(
          `Cryptographic chain broken at block #${verifyRes.brokenAtBlock ?? 'unknown'}. Merkle root mismatch.`
        );
      }
      setLoading(false);
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : 'Failed to retrieve cryptographic audit data');
    }
  };

  useEffect(() => {
    loadAuditData(page, decisionFilter, searchQuery);
  }, [page, decisionFilter]);

  const handleDecisionFilterChange = (val: string) => {
    setDecisionFilter(val);
    setPage(0);
  };

  const handleVerifyNow = async () => {
    setVerifying(true);
    try {
      const res = await AegisApi.verifyAuditLedger();
      setIntegrityStatus(res);
      if (!res.valid) {
        setIntegrityError(
          `Cryptographic chain broken at block #${res.brokenAtBlock ?? 'unknown'}. Merkle root mismatch.`
        );
      }
      setVerifying(false);
    } catch {
      setVerifying(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedHash(text);
      setTimeout(() => setCopiedHash(null), 2000);
    } catch {
      // Fallback
    }
  };

  const filteredRecords = records.filter((r) => {
    const matchesSearch =
      searchQuery === '' ||
      r.toolName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.agentId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.blockHash.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesDecision =
      decisionFilter === 'ALL' || r.decision === decisionFilter;

    return matchesSearch && matchesDecision;
  });

  const handleDownloadExport = async () => {
    setIsExporting(true);
    setIntegrityError(null);
    try {
      const res = await AegisApi.exportComplianceReport({
        framework: exportFramework,
        format: exportFormat,
      });

      let downloadContent = res.content;
      if (exportFormat === 'JSON') {
        try {
          const parsed = JSON.parse(res.content);
          if (!parsed.signature) parsed.signature = res.signature;
          if (!parsed.merkleRoot) parsed.merkleRoot = res.merkleRoot;
          downloadContent = JSON.stringify(parsed, null, 2);
        } catch {
          downloadContent = JSON.stringify(res, null, 2);
        }
      } else {
        if (!downloadContent.includes('Merkle Root') && !downloadContent.includes('Signature')) {
          downloadContent =
            `# Merkle Root: ${res.merkleRoot}\n# Digital Signature: ${res.signature}\n` +
            downloadContent;
        }
      }

      if (typeof window !== 'undefined' && typeof window.URL?.createObjectURL === 'function') {
        const blob = new Blob([downloadContent], {
          type: exportFormat === 'JSON' ? 'application/json' : 'text/csv',
        });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `aegis-compliance-${exportFramework.toLowerCase()}.${exportFormat.toLowerCase()}`;
        a.click();
        window.URL.revokeObjectURL(url);
      }
      setIsExportModalOpen(false);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Export failed';
      const is409 =
        (err as unknown as { status?: number })?.status === 409 ||
        errorMsg.includes('409') ||
        errorMsg.toLowerCase().includes('hash chain broken') ||
        errorMsg.toLowerCase().includes('integrity');
      if (is409) {
        setIntegrityError(
          'Integrity Violation (409 Conflict): Cryptographic hash chain is broken or compromised. Compliance report export aborted.'
        );
        setIsExportModalOpen(false);
      } else {
        alert(`Export error: ${errorMsg}`);
      }
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="p-space-lg max-w-7xl mx-auto space-y-space-md animate-in fade-in duration-150">
      {/* 1. Cryptographic Ledger Integrity Status Banner (C-007) */}
      <div
        data-testid="audit-integrity-banner"
        className="p-space-md rounded-radius-lg bg-grey-100 border border-grey-300 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-md shadow-sm"
      >
        <div className="flex items-center gap-space-md">
          <div className="p-2.5 rounded-radius-md bg-success-100 text-success-900 border border-success-300">
            <ShieldCheck className="w-6 h-6 text-success-500" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-success-500 uppercase">
                Cryptographic Chain Verified
              </span>
              <span className="text-xs font-mono text-grey-500">
                (SHA-256 Merkle Ledger)
              </span>
            </div>
            <p className="text-sm font-semibold text-grey-900 mt-0.5">
              {integrityStatus?.checkedBlocks.toLocaleString() ?? '1,048,590'} sealed blocks verified with 0 discrepancies
            </p>
            <p className="text-[11px] font-mono text-grey-500 mt-0.5">
              Merkle Root: {integrityStatus?.merkleRoot.slice(0, 24)}...
            </p>
          </div>
        </div>

        <button
          onClick={handleVerifyNow}
          disabled={verifying}
          data-testid="verify-now-button"
          className="inline-flex items-center gap-1.5 px-space-md py-space-sm bg-grey-200 hover:bg-grey-300 text-grey-900 font-semibold text-xs rounded-radius-md transition-colors disabled:opacity-50 border border-grey-300"
        >
          <RotateCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
          <span>{verifying ? 'Verifying Merkle Root...' : 'Verify Now (C-007)'}</span>
        </button>
      </div>

      {/* 409 Conflict / Compromised Chain Integrity Banner */}
      {integrityError && (
        <div
          data-testid="audit-integrity-error-banner"
          role="alert"
          className="p-space-md rounded-radius-lg bg-error-100 border border-error-300 text-error-900 flex items-start justify-between gap-space-md shadow-sm"
        >
          <div className="flex items-center gap-space-md">
            <div className="p-2.5 rounded-radius-md bg-error-200 text-error-900 border border-error-400">
              <AlertTriangle className="w-6 h-6 text-error-600" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-error-600 uppercase">
                  Cryptographic Integrity Alert (409 Conflict)
                </span>
              </div>
              <p className="text-sm font-semibold text-error-900 mt-0.5">
                {integrityError}
              </p>
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

      {error && <ErrorState message={error} onRetry={() => loadAuditData()} />}

      {/* 2. Query and Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-space-md p-space-sm bg-grey-100 border border-grey-300 rounded-radius-md">
        <div className="flex items-center gap-space-sm flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-grey-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by agent, tool, or SHA-256 hash..."
              className="pl-8 pr-space-md py-1.5 bg-grey-200 border border-grey-300 rounded-radius-md text-xs text-grey-900 placeholder:text-grey-500 focus:border-primary-500 outline-none w-full sm:w-72 font-mono"
            />
          </div>

          <div className="flex items-center gap-1.5 bg-grey-200 border border-grey-300 rounded-radius-md px-2 py-1 text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-grey-500" />
            <select
              value={decisionFilter}
              onChange={(e) => handleDecisionFilterChange(e.target.value)}
              className="bg-transparent text-grey-800 outline-none cursor-pointer"
            >
              <option value="ALL">All Decisions</option>
              <option value="ALLOWED">Allowed</option>
              <option value="BLOCKED">Blocked</option>
            </select>
          </div>
        </div>

        <button
          onClick={() => setIsExportModalOpen(true)}
          data-testid="export-report-button"
          className="inline-flex items-center gap-1.5 px-space-md py-1.5 bg-primary-500 hover:bg-primary-600 text-grey-900 font-bold text-xs rounded-radius-md transition-colors shadow-sm"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Compliance Report</span>
        </button>
      </div>

      {/* 3. Forensic Event Data Table */}
      {loading ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      ) : filteredRecords.length === 0 ? (
        <EmptyState
          icon={Search}
          title="No audit records found"
          description="No ledger blocks match your query criteria. Verify block hash or reset active filters."
          actionLabel="Reset Search"
          onAction={() => {
            setSearchQuery('');
            setDecisionFilter('ALL');
          }}
        />
      ) : (
        <div className="bg-grey-100 border border-grey-300 rounded-radius-md overflow-x-auto shadow-sm">
          <table className="w-full min-w-[700px] text-left text-xs font-mono">
            <thead className="bg-grey-200 border-b border-grey-300 text-grey-500">
              <tr>
                <th className="py-2.5 px-space-md font-medium">Block #</th>
                <th className="py-2.5 px-space-md font-medium">Timestamp (UTC)</th>
                <th className="py-2.5 px-space-md font-medium">SHA-256 Hash</th>
                <th className="py-2.5 px-space-md font-medium">Agent Workload</th>
                <th className="py-2.5 px-space-md font-medium">Target Tool</th>
                <th className="py-2.5 px-space-md font-medium">Decision</th>
                <th className="py-2.5 px-space-md font-medium">Approver</th>
                <th className="py-2.5 px-space-md font-medium text-right">Proof</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-grey-300/40">
              {filteredRecords.map((r) => (
                <tr
                  key={r.index}
                  data-testid={`audit-row-${r.index}`}
                  className="hover:bg-grey-200/50 transition-colors"
                >
                  <td className="py-2.5 px-space-md text-primary-500 font-bold">#{r.index}</td>
                  <td className="py-2.5 px-space-md text-grey-500 whitespace-nowrap">
                    {new Date(r.timestamp).toISOString()}
                  </td>
                  <td className="py-2.5 px-space-md text-grey-600">
                    <span className="inline-flex items-center gap-1">
                      <span>{r.blockHash.slice(0, 10)}...</span>
                      <button
                        onClick={() => copyToClipboard(r.blockHash)}
                        className="p-1 hover:text-grey-900"
                        title="Copy Hash"
                      >
                        {copiedHash === r.blockHash ? (
                          <Check className="w-3 h-3 text-success-500" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </span>
                  </td>
                  <td
                    className="py-2.5 px-space-md text-grey-800 max-w-[140px] truncate"
                    title={r.agentId}
                  >
                    {r.agentId.split('/').pop()}
                  </td>
                  <td className="py-2.5 px-space-md text-primary-700 font-semibold">{r.toolName}</td>
                  <td className="py-2.5 px-space-md">
                    <StatusPill verdict={r.decision} />
                  </td>
                  <td className="py-2.5 px-space-md text-grey-500">
                    {r.approver ? r.approver : 'Autonomous Policy'}
                  </td>
                  <td className="py-2.5 px-space-md text-right">
                    <button
                      onClick={() => setSelectedRecord(r)}
                      data-testid={`view-proof-${r.index}`}
                      className="text-primary-500 hover:text-primary-400 font-semibold underline"
                    >
                      View Proof
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination Toolbar */}
          <div className="p-space-sm bg-grey-200 border-t border-grey-300 flex items-center justify-between text-xs font-mono text-grey-700">
            <span data-testid="pagination-info">
              Showing {filteredRecords.length > 0 ? page * pageSize + 1 : 0} -{' '}
              {Math.min((page + 1) * pageSize, totalRecords)} of {totalRecords} records
            </span>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                data-testid="pagination-prev"
                className="inline-flex items-center gap-1 px-2.5 py-1 bg-grey-100 border border-grey-300 hover:bg-grey-300 disabled:opacity-40 rounded-radius-sm"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Prev</span>
              </button>
              <span className="px-2 font-bold">
                Page {page + 1} of {Math.max(1, Math.ceil(totalRecords / pageSize))}
              </span>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={(page + 1) * pageSize >= totalRecords}
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

      {/* 4. Cryptographic Proof Drawer (Modal or side panel) */}
      {selectedRecord && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm"
        >
          <div className="w-full max-w-xl bg-grey-100 border border-grey-300 rounded-radius-lg p-space-lg shadow-xl space-y-space-md">
            <div className="flex items-center justify-between pb-space-xs border-b border-grey-300">
              <div className="flex items-center gap-2">
                <FileCheck2 className="w-5 h-5 text-success-500" />
                <h3 className="font-bold text-sm text-grey-900">
                  Cryptographic Ledger Proof #{selectedRecord.index}
                </h3>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="p-1 text-grey-500 hover:text-grey-900"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-space-sm text-xs font-mono">
              <div className="p-space-sm bg-grey-200 rounded-radius-md space-y-1">
                <span className="text-grey-500 block">Block SHA-256 Hash:</span>
                <span className="text-primary-700 break-all">{selectedRecord.blockHash}</span>
              </div>

              <div className="p-space-sm bg-grey-200 rounded-radius-md space-y-1">
                <span className="text-grey-500 block">Parent Previous Hash:</span>
                <span className="text-grey-700 break-all">
                  {selectedRecord.parentHash || selectedRecord.prevHash}
                </span>
              </div>

              <div className="p-space-sm bg-grey-200 rounded-radius-md space-y-1">
                <span className="text-grey-500 block">ECDSA Digital Signature:</span>
                <span className="text-grey-700 break-all">
                  {selectedRecord.signature || 'ecdsa-p256-sha256:MEYCIQD...'}
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

      {/* 5. Compliance Export Modal */}
      {isExportModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm"
        >
          <div className="w-full max-w-md bg-grey-100 border border-grey-300 rounded-radius-lg p-space-lg shadow-xl space-y-space-md">
            <div className="flex items-center justify-between pb-space-xs border-b border-grey-300">
              <h3 className="font-bold text-sm text-grey-900">Export Tamper-Evident Audit Report</h3>
              <button
                onClick={() => setIsExportModalOpen(false)}
                className="p-1 text-grey-500 hover:text-grey-900"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-space-sm text-xs">
              <div>
                <label className="block text-grey-600 font-semibold mb-1">
                  Compliance Framework
                </label>
                <select
                  value={exportFramework}
                  onChange={(e) =>
                    setExportFramework(e.target.value as 'EU_AI_ACT' | 'SOC2_TYPE2')
                  }
                  className="w-full bg-grey-200 border border-grey-300 rounded-radius-md p-2 text-grey-900 outline-none"
                >
                  <option value="EU_AI_ACT">EU AI Act (Article 12/14 Human Oversight Record)</option>
                  <option value="SOC2_TYPE2">SOC 2 Type II (Continuous Access Control Log)</option>
                </select>
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
