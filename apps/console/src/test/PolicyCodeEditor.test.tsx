/**
 * Specification Anchors: FEAT-008, screens/04-policy-manager.md
 * The policy code editor marks a lint finding inline on its line and column.
 */

import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/react';
import { EditorState } from '@codemirror/state';
import PolicyCodeEditor, { toDiagnostics } from '../components/PolicyCodeEditor';

const YAML = 'metadata:\n  name: production-guardrails\n  action: BLOCK\n';

describe('PolicyCodeEditor', () => {
  it('maps a finding to the reported line and column with a positioned message', () => {
    const state = EditorState.create({ doc: YAML });
    const [diagnostic] = toDiagnostics(state, [
      { line: 2, column: 9, message: 'Unknown tool keyword' },
    ]);

    const line = state.doc.line(2);
    expect(diagnostic.from).toBe(line.from + 8);
    expect(diagnostic.to).toBe(line.to);
    expect(diagnostic.message).toBe('Line 2, column 9: Unknown tool keyword');
  });

  it('ignores a finding without a document position', () => {
    const state = EditorState.create({ doc: YAML });
    expect(toDiagnostics(state, [{ line: null, column: null, message: 'Rejected' }])).toEqual([]);
  });

  it('renders the inline marker on the failing line at the failing column', () => {
    const { container } = render(
      <PolicyCodeEditor
        value={YAML}
        onChange={() => {}}
        issues={[{ line: 2, column: 9, message: 'Unknown tool keyword' }]}
        ariaLabel="Policy YAML editor"
        describedBy="policy-lint-error"
        invalid
      />
    );

    const failingLine = container.querySelectorAll('.cm-line')[1];
    expect(failingLine).not.toBeUndefined();
    expect(container.querySelector('.cm-gutter-lint .cm-lint-marker-error')).not.toBeNull();
    const range = failingLine.querySelector('.cm-lintRange-error');
    expect(range).not.toBeNull();
    // The marker starts at column 9, so the underline begins at "production".
    expect(range?.textContent).toBe('production-guardrails');

    const content = container.querySelector('.cm-content');
    expect(content?.getAttribute('aria-invalid')).toBe('true');
    expect(content?.getAttribute('aria-describedby')).toBe('policy-lint-error');
  });

  it('keeps a positionless gateway finding out of the document', () => {
    const { container } = render(
      <PolicyCodeEditor
        value={YAML}
        onChange={() => {}}
        issues={[{ line: null, column: null, message: 'Schema rejection' }]}
        invalid
      />
    );

    expect(container.querySelector('.cm-lintRange-error')).toBeNull();
    expect(container.querySelector('.cm-lint-marker-error')).toBeNull();
    expect(container.querySelector('.cm-content')?.getAttribute('aria-invalid')).toBe('true');
  });

  it('makes the document read-only for a viewer', () => {
    const { container } = render(<PolicyCodeEditor value={YAML} onChange={() => {}} readOnly />);
    expect(container.querySelector('.cm-content')?.getAttribute('contenteditable')).toBe('false');
  });

  it('adopts a document loaded by the screen without reporting a user edit', () => {
    const onChange = vi.fn();
    const { container, rerender } = render(<PolicyCodeEditor value={YAML} onChange={onChange} />);

    rerender(<PolicyCodeEditor value={'kind: SecurityPolicy\n'} onChange={onChange} />);

    const content = container.querySelector('.cm-content');
    expect(content?.textContent).toContain('kind: SecurityPolicy');
    expect(content?.textContent).not.toContain('production-guardrails');
    expect(onChange).not.toHaveBeenCalled();
  });
});
