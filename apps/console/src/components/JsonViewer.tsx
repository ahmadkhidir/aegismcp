import React, { useState } from 'react';
import { Copy, Check, ShieldAlert } from 'lucide-react';

interface JsonViewerProps {
  data: unknown;
  redactions?: Array<{
    field: string;
    type: string;
    maskedPreview: string;
  }>;
  title?: string;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({
  data,
  redactions,
  title = 'JSON Payload',
}) => {
  const [copied, setCopied] = useState(false);

  const formattedJson = typeof data === 'string'
    ? data
    : JSON.stringify(data, null, 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(formattedJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="rounded-radius-md border border-grey-300 bg-grey-50 overflow-hidden font-mono text-xs">
      <div className="flex items-center justify-between px-space-md py-space-xs bg-grey-100 border-b border-grey-300 text-grey-500">
        <div className="flex items-center gap-space-sm">
          <span className="font-semibold text-grey-700">{title}</span>
          {redactions && redactions.length > 0 && (
            <span
              data-testid="redaction-badge"
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-radius-sm bg-accent-100 text-accent-900 border border-accent-300 text-[11px]"
            >
              <ShieldAlert className="w-3 h-3 text-accent-500" />
              <span>{redactions.length} DLP Redacted</span>
            </span>
          )}
        </div>
        <button
          onClick={handleCopy}
          aria-label="Copy JSON"
          className="inline-flex items-center gap-1 px-2 py-1 rounded-radius-sm bg-grey-200 hover:bg-grey-300 text-grey-800 transition-colors"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-success-500" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied' : 'Copy JSON'}</span>
        </button>
      </div>

      {redactions && redactions.length > 0 && (
        <div className="px-space-md py-space-xs bg-accent-100/30 border-b border-accent-300/30 text-[11px] text-accent-900 flex flex-wrap gap-2">
          {redactions.map((r, idx) => (
            <span key={idx} className="inline-flex items-center gap-1 font-mono">
              <span className="text-accent-500 font-semibold">{r.field}:</span>
              <span className="bg-grey-200 px-1 py-0.5 rounded-radius-sm text-grey-600">{r.maskedPreview} ({r.type})</span>
            </span>
          ))}
        </div>
      )}

      <pre
        data-testid="json-content"
        className="p-space-md text-grey-800 overflow-x-auto leading-relaxed max-h-96 selection:bg-primary-300"
      >
        <code>{formattedJson}</code>
      </pre>
    </div>
  );
};
