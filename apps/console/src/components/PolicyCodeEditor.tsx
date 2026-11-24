/**
 * Specification Anchors: FEAT-008, screens/04-policy-manager.md
 * Screen 4: Policy Manager. Code editor pane for the declarative YAML policy.
 *
 * The component is imported lazily by the policy screen so the editor engine
 * and the YAML grammar stay out of the console's initial chunk. It renders a
 * CodeMirror 6 editor: line numbers, YAML syntax highlighting, local lint
 * markers on the failing line, and a focus ring that follows the theme tokens.
 */

import React, { useEffect, useRef } from 'react';
import { Annotation, Compartment, EditorState } from '@codemirror/state';
import {
  EditorView,
  crosshairCursor,
  drawSelection,
  dropCursor,
  highlightActiveLine,
  highlightActiveLineGutter,
  keymap,
  lineNumbers,
  rectangularSelection,
} from '@codemirror/view';
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
import {
  bracketMatching,
  HighlightStyle,
  indentOnInput,
  syntaxHighlighting,
} from '@codemirror/language';
import { yaml } from '@codemirror/lang-yaml';
import { lintGutter, setDiagnostics, type Diagnostic } from '@codemirror/lint';
import { tags } from '@lezer/highlight';

/**
 * One finding the screen wants marked inside the document. `line` and
 * `column` are 1-based; a null line means the gateway rejected the document
 * without naming a position, so only the banner below the editor reports it.
 */
export interface PolicyEditorIssue {
  line: number | null;
  column: number | null;
  message: string;
}

/**
 * Marks a transaction the component issued to adopt a document loaded by the
 * screen. Those are not user edits, so they must not mark the policy dirty.
 */
const documentReplacement = Annotation.define<boolean>();

/** Stable empty list so the marker effect does not re-run every render. */
const NO_ISSUES: PolicyEditorIssue[] = [];

interface PolicyCodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  issues?: PolicyEditorIssue[];
  readOnly?: boolean;
  /** VoiceOver and keyboard assistive technology announce this editor name. */
  ariaLabel?: string;
  /** Id of the Lint Error banner that describes the current finding. */
  describedBy?: string;
  invalid?: boolean;
}

/**
 * Editor chrome in terms of the console design tokens. CodeMirror resolves
 * these CSS custom properties in the browser, so no colour, radius, spacing or
 * type value is duplicated here.
 */
const editorTheme = EditorView.theme({
  '&': {
    height: '100%',
    backgroundColor: 'rgb(var(--color-grey-50))',
    color: 'rgb(var(--color-grey-800))',
    fontFamily: 'var(--font-family-mono)',
    fontSize: 'var(--font-size-caption)',
  },
  '&.cm-focused': {
    outline: '2px solid rgb(var(--color-primary-500))',
    outlineOffset: '-2px',
  },
  '.cm-scroller': {
    overflow: 'auto',
    fontFamily: 'var(--font-family-mono)',
    lineHeight: 'var(--line-height-caption)',
  },
  '.cm-content': {
    padding: 'var(--space-md) 0',
    caretColor: 'rgb(var(--color-primary-500))',
  },
  '.cm-line': {
    padding: '0 var(--space-md)',
  },
  '.cm-gutters': {
    backgroundColor: 'rgb(var(--color-grey-100))',
    color: 'rgb(var(--color-grey-400))',
    borderRight: '1px solid rgb(var(--color-grey-300))',
  },
  '.cm-lineNumbers .cm-gutterElement': {
    padding: '0 var(--space-xs) 0 var(--space-sm)',
  },
  '.cm-activeLine': {
    backgroundColor: 'rgb(var(--color-primary-500) / 0.06)',
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'rgb(var(--color-primary-500) / 0.1)',
    color: 'rgb(var(--color-grey-700))',
  },
  '.cm-cursor, .cm-dropCursor': {
    borderLeftColor: 'rgb(var(--color-primary-500))',
  },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': {
    backgroundColor: 'rgb(var(--color-primary-300) / 0.5)',
  },
  '.cm-placeholder': {
    color: 'rgb(var(--color-grey-400))',
  },
  // The editor's default lint underline carries a fixed red; the Lint Error
  // state uses the error-500 token instead.
  '.cm-lintRange-error': {
    backgroundImage: 'none',
    textDecorationLine: 'underline',
    textDecorationStyle: 'wavy',
    textDecorationColor: 'rgb(var(--color-error-500))',
    textDecorationSkipInk: 'none',
    textUnderlineOffset: 'var(--space-xs)',
  },
});

/** YAML token colours from the brand palette declared in `src/index.css`. */
const policyHighlight = HighlightStyle.define([
  { tag: tags.keyword, color: 'rgb(var(--color-primary-700))', fontWeight: '600' },
  { tag: [tags.propertyName, tags.attributeName], color: 'rgb(var(--color-info-700))' },
  { tag: [tags.string, tags.special(tags.string)], color: 'rgb(var(--color-success-700))' },
  { tag: [tags.number, tags.bool, tags.null], color: 'rgb(var(--color-accent-700))' },
  { tag: [tags.comment, tags.lineComment], color: 'rgb(var(--color-grey-500))', fontStyle: 'italic' },
  { tag: [tags.punctuation, tags.separator], color: 'rgb(var(--color-grey-600))' },
  { tag: tags.invalid, color: 'rgb(var(--color-error-700))' },
]);

/**
 * Translates the screen's findings into CodeMirror diagnostics so each one is
 * underlined in place and repeated in the lint gutter. The message includes
 * the 1-based line and column, which is what the Lint Error state promises on
 * hover for a keyboard or pointer user.
 */
export function toDiagnostics(state: EditorState, issues: PolicyEditorIssue[]): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  for (const issue of issues) {
    if (issue.line === null || issue.line < 1 || issue.line > state.doc.lines) continue;
    const line = state.doc.line(issue.line);
    const column = Math.min(Math.max(issue.column ?? 1, 1), line.length + 1);
    const from = line.from + column - 1;
    diagnostics.push({
      from,
      to: Math.max(from + 1, line.to),
      severity: 'error',
      source: 'policy',
      message: `Line ${issue.line}, column ${column}: ${issue.message}`,
    });
  }
  return diagnostics;
}

/** Content attributes shared by the mount and reconfiguration paths. */
function contentAttributes(
  ariaLabel: string,
  describedBy?: string,
  invalid?: boolean
): Record<string, string> {
  const attributes: Record<string, string> = {
    'aria-label': ariaLabel,
    spellcheck: 'false',
    autocapitalize: 'off',
    autocorrect: 'off',
  };
  if (describedBy) attributes['aria-describedby'] = describedBy;
  if (invalid) attributes['aria-invalid'] = 'true';
  return attributes;
}

const PolicyCodeEditor: React.FC<PolicyCodeEditorProps> = ({
  value,
  onChange,
  issues = NO_ISSUES,
  readOnly = false,
  ariaLabel = 'Policy YAML editor',
  describedBy,
  invalid = false,
}) => {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  const readOnlyCompartment = useRef(new Compartment());
  const attributesCompartment = useRef(new Compartment());

  useEffect(() => {
    onChangeRef.current = onChange;
  });

  // Create the view once; later prop changes are applied as transactions so
  // the user's selection, scroll position, and undo history survive re-renders.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return undefined;

    const view = new EditorView({
      parent: host,
      state: EditorState.create({
        doc: value,
        extensions: [
          lineNumbers(),
          highlightActiveLineGutter(),
          highlightActiveLine(),
          history(),
          drawSelection(),
          dropCursor(),
          indentOnInput(),
          bracketMatching(),
          rectangularSelection(),
          crosshairCursor(),
          yaml(),
          syntaxHighlighting(policyHighlight),
          lintGutter(),
          EditorView.lineWrapping,
          keymap.of([
            ...defaultKeymap,
            ...historyKeymap,
            indentWithTab,
            // Tab indents YAML; Escape is the documented way out of the
            // contenteditable region without a pointer.
            {
              key: 'Escape',
              run: (target) => {
                target.contentDOM.blur();
                return true;
              },
            },
          ]),
          readOnlyCompartment.current.of([
            EditorState.readOnly.of(readOnly),
            EditorView.editable.of(!readOnly),
          ]),
          attributesCompartment.current.of(
            EditorView.contentAttributes.of(contentAttributes(ariaLabel, describedBy, invalid))
          ),
          editorTheme,
          EditorView.updateListener.of((update) => {
            if (!update.docChanged) return;
            if (update.transactions.some((tr) => tr.annotation(documentReplacement))) return;
            onChangeRef.current(update.state.doc.toString());
          }),
        ],
      }),
    });
    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // The view is created once; prop-driven updates use the effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Adopt a document loaded or replaced by the screen.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    if (value !== view.state.doc.toString()) {
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: value },
        annotations: documentReplacement.of(true),
      });
    }
  }, [value]);

  // Keep the inline markers aligned with the current lint finding.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    view.dispatch(setDiagnostics(view.state, toDiagnostics(view.state, issues)));
  }, [issues]);

  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    view.dispatch({
      effects: readOnlyCompartment.current.reconfigure([
        EditorState.readOnly.of(readOnly),
        EditorView.editable.of(!readOnly),
      ]),
    });
  }, [readOnly]);

  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    view.dispatch({
      effects: attributesCompartment.current.reconfigure(
        EditorView.contentAttributes.of(contentAttributes(ariaLabel, describedBy, invalid))
      ),
    });
  }, [ariaLabel, describedBy, invalid]);

  return (
    <div
      ref={hostRef}
      data-testid="policy-yaml-editor"
      className="flex-1 min-w-0 min-h-0 overflow-hidden bg-grey-50"
    />
  );
};

export default PolicyCodeEditor;
