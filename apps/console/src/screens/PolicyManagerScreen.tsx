/**
 * Specification Anchors: FEAT-002, FEAT-008, FEAT-012, C-005, C-006, C-012, C-017, C-018
 * Screen 4: Policy Manager. Loads real policy versions and the active
 * document, publishes drafts through C-006, activates through C-018, and
 * evaluates sample payloads through C-012.
 */

import React, { useCallback, useEffect, useState } from 'react';
import {
  FileCode,
  Play,
  Save,
  GitCommit,
  Loader2,
  AlertCircle,
  Rocket,
  Layers,
} from 'lucide-react';
import { AegisApi, ApiError } from '../services/api';
import { PolicyRecord, PolicySimulateResponse } from '../types/contracts';
import { Skeleton } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { StatusPill } from '../components/StatusPill';

interface PolicyManagerScreenProps {
  /** C-006 and C-018 admit the admin role only. */
  canManagePolicy?: boolean;
  /** C-012 admits admin and operator. */
  canSimulatePolicy?: boolean;
}

export const PolicyManagerScreen: React.FC<PolicyManagerScreenProps> = ({
  canManagePolicy = true,
  canSimulatePolicy = true,
}) => {
  const [policies, setPolicies] = useState<PolicyRecord[]>([]);
  const [activePolicy, setActivePolicy] = useState<PolicyRecord | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyRecord | null>(null);
  const [policyName, setPolicyName] = useState('');
  const [versionInput, setVersionInput] = useState('');
  const [editorYaml, setEditorYaml] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isDirty, setIsDirty] = useState(false);
  const [isPublishing, setIsPublishing] = useState(false);
  const [isDeploying, setIsDeploying] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [simTool, setSimTool] = useState('');
  const [simAgent, setSimAgent] = useState('');
  const [simArgs, setSimArgs] = useState('');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simResponse, setSimResponse] = useState<PolicySimulateResponse | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [catalogue, active] = await Promise.all([
        AegisApi.getPolicies(),
        AegisApi.getActivePolicy().catch((err: unknown) => {
          if (err instanceof ApiError && err.status === 404) return null;
          throw err;
        }),
      ]);
      setPolicies(catalogue.policies);
      setActivePolicy(active);

      const preferred =
        (active && catalogue.policies.find((policy) => policy.id === active.id)) ??
        catalogue.policies[0] ??
        null;

      if (preferred) {
        setSelectedPolicy(preferred);
        setPolicyName(preferred.name);
        setVersionInput(preferred.version);
        setEditorYaml(preferred.rawYaml);
      } else {
        setSelectedPolicy(null);
        setPolicyName('');
        setVersionInput('');
        setEditorYaml('');
      }
      setIsDirty(false);
      setLoading(false);
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : 'Failed to retrieve declarative policies');
    }
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  const handleSelectPolicy = (policy: PolicyRecord) => {
    setSelectedPolicy(policy);
    setPolicyName(policy.name);
    setVersionInput(policy.version);
    setEditorYaml(policy.rawYaml);
    setIsDirty(false);
    setSimResponse(null);
    setSimError(null);
    setActionError(null);
    setActionMessage(null);
  };

  const handleEditorChange = (value: string) => {
    setEditorYaml(value);
    setIsDirty(true);
    setActionMessage(null);
  };

  const handleSimulate = async () => {
    if (!canSimulatePolicy) return;
    setSimError(null);
    setSimResponse(null);

    if (!simAgent.trim() || !simTool.trim()) {
      setSimError('Enter the agent identity and the target tool to evaluate.');
      return;
    }

    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = simArgs.trim() ? JSON.parse(simArgs) : {};
      if (typeof parsedArgs !== 'object' || parsedArgs === null || Array.isArray(parsedArgs)) {
        throw new Error('Arguments must be a JSON object.');
      }
    } catch {
      setSimError('Malformed JSON payload: check the argument JSON syntax.');
      return;
    }

    setIsSimulating(true);
    try {
      const response = await AegisApi.simulatePolicy({
        agentId: simAgent.trim(),
        toolName: simTool.trim(),
        arguments: parsedArgs,
      });
      setSimResponse(response);
    } catch (err: unknown) {
      setSimError(err instanceof Error ? err.message : 'Policy simulation request failed');
    } finally {
      setIsSimulating(false);
    }
  };

  const handlePublishDraft = async () => {
    if (!canManagePolicy) return;
    if (!policyName.trim() || !versionInput.trim() || !editorYaml.trim()) {
      setActionError('A policy name, version, and YAML document are required.');
      return;
    }

    setIsPublishing(true);
    setActionError(null);
    setActionMessage(null);
    try {
      const response = await AegisApi.publishPolicy({
        name: policyName.trim(),
        version: versionInput.trim(),
        rawYaml: editorYaml,
        ...(selectedPolicy?.gitCommitHash
          ? { gitCommitHash: selectedPolicy.gitCommitHash }
          : {}),
      });
      setActionMessage(
        `Saved ${response.name} ${response.version} as a draft. Activate it to govern traffic.`
      );
      await loadPolicies();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : 'Failed to publish the policy draft');
    } finally {
      setIsPublishing(false);
    }
  };

  const handleDeployPolicy = async () => {
    if (!canManagePolicy) return;
    if (!policyName.trim() || !versionInput.trim() || !editorYaml.trim()) {
      setActionError('A policy name, version, and YAML document are required.');
      return;
    }

    setIsDeploying(true);
    setActionError(null);
    setActionMessage(null);
    try {
      const response = await AegisApi.activatePolicy({
        version: versionInput.trim(),
        baseVersionId: activePolicy?.id ?? '',
        rawYaml: editorYaml,
      });
      setActivePolicy(response);
      setActionMessage(`Activated ${response.name} ${response.version}.`);
      await loadPolicies();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : 'Failed to activate the policy');
    } finally {
      setIsDeploying(false);
    }
  };

  if (error) {
    return (
      <div className="p-space-lg max-w-7xl mx-auto">
        <ErrorState message={error} onRetry={loadPolicies} />
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col bg-grey-50 overflow-hidden animate-in fade-in duration-150">
      <div className="p-space-md bg-grey-100 border-b border-grey-300 flex flex-wrap items-center justify-between gap-space-md">
        <div className="flex items-center gap-space-md flex-wrap">
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-primary-500" />
            <h2 className="font-bold text-body-small text-grey-900">Declarative Policy Manager</h2>
          </div>

          <div className="flex items-center gap-space-sm text-caption">
            <label className="sr-only" htmlFor="policy-name-input">
              Policy name
            </label>
            <input
              id="policy-name-input"
              data-testid="policy-name-input"
              value={policyName}
              onChange={(event) => {
                setPolicyName(event.target.value);
                setIsDirty(true);
                setActionMessage(null);
              }}
              placeholder="Policy name"
              className="bg-grey-200 border border-grey-300 rounded-radius-sm px-2 py-1 text-grey-900 outline-none focus:border-primary-500 w-56"
            />
            <label className="sr-only" htmlFor="policy-version-input">
              Policy version
            </label>
            <input
              id="policy-version-input"
              data-testid="policy-version-input"
              value={versionInput}
              onChange={(event) => {
                setVersionInput(event.target.value);
                setIsDirty(true);
                setActionMessage(null);
              }}
              placeholder="Version"
              className="bg-grey-200 border border-grey-300 rounded-radius-sm px-2 py-1 text-grey-900 font-mono outline-none focus:border-primary-500 w-28"
            />
          </div>

          {selectedPolicy && (
            <div className="flex items-center gap-2 text-caption font-mono text-grey-500">
              <span
                className={`px-1.5 py-0.5 rounded-radius-sm font-semibold ${
                  isDirty
                    ? 'bg-warning-100 text-warning-900'
                    : 'bg-success-100 text-success-900'
                }`}
              >
                {isDirty ? 'Draft unsaved' : 'Synced'}
              </span>
              <span className="inline-flex items-center gap-1">
                <GitCommit className="w-3.5 h-3.5" />
                {selectedPolicy.gitCommitHash ?? 'No commit recorded'}
              </span>
            </div>
          )}

          {!canManagePolicy && (
            <span
              data-testid="policy-readonly-notice"
              className="text-caption text-grey-500"
            >
              Read-only: publishing and activation require the admin role.
            </span>
          )}
        </div>

        <div className="flex items-center gap-space-sm">
          <button
            onClick={handlePublishDraft}
            disabled={isPublishing || isDeploying || !canManagePolicy}
            title={
              canManagePolicy
                ? 'Save this document as a draft version'
                : 'The admin role is required to publish a policy'
            }
            data-testid="save-draft-button"
            className="inline-flex items-center gap-1.5 px-space-md py-1.5 bg-grey-200 hover:bg-grey-300 disabled:opacity-40 text-grey-800 font-semibold text-caption rounded-radius-md transition-colors border border-grey-300"
          >
            {isPublishing ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Save className="w-3.5 h-3.5" />
            )}
            <span>Save Draft</span>
          </button>

          <button
            onClick={handleDeployPolicy}
            disabled={isDeploying || isPublishing || !isDirty || !canManagePolicy}
            title={
              canManagePolicy
                ? 'Activate this document'
                : 'The admin role is required to activate a policy'
            }
            data-testid="deploy-policy-button"
            className="inline-flex items-center gap-1.5 px-space-md py-1.5 bg-primary-500 hover:bg-primary-600 disabled:opacity-40 text-grey-900 font-bold text-caption rounded-radius-md transition-colors shadow-sm"
          >
            {isDeploying ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Rocket className="w-3.5 h-3.5" />
            )}
            <span>Deploy Policy</span>
          </button>
        </div>
      </div>

      {(actionMessage || actionError) && (
        <div className="px-space-md py-space-sm border-b border-grey-300 bg-grey-100">
          {actionMessage && (
            <div
              data-testid="policy-action-message"
              className="p-space-sm bg-success-100 border border-success-300 text-success-900 rounded-radius-md text-caption"
            >
              {actionMessage}
            </div>
          )}
          {actionError && (
            <div
              role="alert"
              data-testid="policy-action-error"
              className="p-space-sm bg-error-100 border border-error-300 text-error-900 rounded-radius-md text-caption flex items-start gap-1.5"
            >
              <AlertCircle className="w-4 h-4 text-error-700 shrink-0 mt-0.5" />
              <span>{actionError}</span>
            </div>
          )}
        </div>
      )}

      <div className="flex-1 flex flex-col lg:flex-row overflow-y-auto lg:overflow-hidden">
        <div className="w-full lg:w-64 xl:w-72 border-b lg:border-b-0 lg:border-r border-grey-300 bg-grey-100 p-space-md flex flex-col justify-between flex-shrink-0 max-h-60 lg:max-h-none overflow-y-auto">
          <div className="space-y-space-sm">
            <div className="flex items-center justify-between text-caption font-semibold uppercase text-grey-500 px-1">
              <span>Policy Files</span>
            </div>

            {loading ? (
              <div className="space-y-2">
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </div>
            ) : policies.length === 0 ? (
              <EmptyState
                title="No policy versions"
                description="Publish the first policy draft to begin managing rules."
              />
            ) : (
              policies.map((policy) => {
                const isSelected = selectedPolicy?.id === policy.id;
                return (
                  <button
                    key={policy.id}
                    onClick={() => handleSelectPolicy(policy)}
                    data-testid={`policy-item-${policy.id}`}
                    className={`w-full text-left p-space-sm rounded-radius-md transition-colors text-caption ${
                      isSelected
                        ? 'bg-primary-500/10 border-l-2 border-primary-500 text-grey-900 font-semibold'
                        : 'hover:bg-grey-200 text-grey-600'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-grey-500">{policy.id}</span>
                      <span className="text-caption uppercase font-mono px-1 rounded-radius-sm bg-grey-200 text-grey-700">
                        {policy.status}
                      </span>
                    </div>
                    <div className="truncate text-grey-800">{policy.name}</div>
                    <div className="text-caption font-mono text-grey-500 mt-0.5">
                      {policy.version}
                    </div>
                  </button>
                );
              })
            )}
          </div>

          {activePolicy && (
            <div className="p-space-sm bg-grey-200 rounded-radius-md text-caption text-grey-600 font-mono mt-2 lg:mt-0 space-y-1">
              <div className="flex items-center gap-1 text-grey-700 font-semibold">
                <Layers className="w-3.5 h-3.5 text-primary-500" />
                <span>Active version</span>
              </div>
              <div className="truncate">{activePolicy.name}</div>
              <div>{activePolicy.version}</div>
              <div>{new Date(activePolicy.createdAt).toLocaleString()}</div>
            </div>
          )}
        </div>

        <div className="flex-1 flex flex-col border-b lg:border-b-0 lg:border-r border-grey-300 bg-grey-50 min-h-[300px] lg:min-h-0 overflow-hidden">
          <div className="px-space-md py-space-xs bg-grey-100 border-b border-grey-300 flex items-center justify-between text-caption text-grey-500 font-mono">
            <span>policy.yaml</span>
            <span>Lines: {editorYaml.split('\n').length}</span>
          </div>

          {loading ? (
            <div className="p-space-md">
              <Skeleton className="h-64 w-full" />
            </div>
          ) : (
            <textarea
              data-testid="policy-yaml-editor"
              value={editorYaml}
              onChange={(event) => handleEditorChange(event.target.value)}
              placeholder="apiVersion: security.aegis.io/v1alpha1&#10;kind: SecurityPolicy"
              className="flex-1 w-full min-h-[220px] lg:min-h-0 p-space-md bg-grey-50 text-grey-800 font-mono text-caption leading-relaxed outline-none resize-none selection:bg-primary-300"
              spellCheck={false}
            />
          )}
        </div>

        <div className="w-full lg:w-80 xl:w-96 bg-grey-100 p-space-md flex flex-col justify-between flex-shrink-0 overflow-y-auto">
          <div className="space-y-space-md">
            <div>
              <h3 className="font-bold text-body-small text-grey-900 flex items-center gap-1.5">
                <Play className="w-4 h-4 text-primary-500" />
                <span>Policy Simulator</span>
              </h3>
              <p className="text-caption text-grey-500 mt-0.5">
                Evaluate a sample tool call against the gateway's compiled policy without dispatching it.
              </p>
            </div>

            <div className="space-y-space-sm text-caption font-mono">
              <div>
                <label className="block text-grey-500 mb-1" htmlFor="sim-tool">
                  Target Tool
                </label>
                <input
                  id="sim-tool"
                  type="text"
                  value={simTool}
                  onChange={(event) => setSimTool(event.target.value)}
                  placeholder="e.g. bash_run_command"
                  className="w-full bg-grey-200 border border-grey-300 rounded-radius-md px-2 py-1.5 text-grey-900 outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block text-grey-500 mb-1" htmlFor="sim-agent">
                  Agent Workload Identity
                </label>
                <input
                  id="sim-agent"
                  type="text"
                  value={simAgent}
                  onChange={(event) => setSimAgent(event.target.value)}
                  placeholder="spiffe://..."
                  className="w-full bg-grey-200 border border-grey-300 rounded-radius-md px-2 py-1.5 text-grey-900 outline-none focus:border-primary-500 truncate"
                />
              </div>

              <div>
                <label className="block text-grey-500 mb-1" htmlFor="sim-args">
                  Argument Payload JSON
                </label>
                <textarea
                  id="sim-args"
                  value={simArgs}
                  onChange={(event) => setSimArgs(event.target.value)}
                  rows={4}
                  placeholder='{"key": "value"}'
                  className="w-full bg-grey-200 border border-grey-300 rounded-radius-md p-2 text-grey-900 outline-none focus:border-primary-500 resize-none font-mono"
                />
              </div>

              <button
                onClick={handleSimulate}
                disabled={isSimulating || !canSimulatePolicy}
                title={
                  canSimulatePolicy
                    ? 'Evaluate the sample call against the active policy'
                    : 'The operator or admin role is required to simulate a policy'
                }
                data-testid="simulate-test-button"
                className="w-full py-2 bg-primary-500 hover:bg-primary-600 disabled:opacity-50 text-grey-900 font-bold rounded-radius-md transition-colors flex items-center justify-center gap-1.5"
              >
                {isSimulating ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Evaluating Rules...</span>
                  </>
                ) : (
                  <span>Run Simulation</span>
                )}
              </button>
            </div>

            {simError && (
              <div
                data-testid="simulation-error"
                className="p-space-sm bg-error-100 border border-error-300 text-error-900 rounded-radius-md text-caption font-mono flex items-start gap-1.5"
              >
                <AlertCircle className="w-4 h-4 text-error-700 shrink-0 mt-0.5" />
                <span>{simError}</span>
              </div>
            )}

            {simResponse && (
              <div
                data-testid="simulation-outcome"
                className="p-space-md bg-grey-200 border border-grey-300 rounded-radius-md space-y-2 animate-in fade-in"
              >
                <div className="flex items-center justify-between">
                  <span className="text-caption font-bold text-grey-700">Simulated Outcome:</span>
                  <StatusPill verdict={simResponse.verdict} />
                </div>
                <p className="text-caption text-grey-600 font-mono">
                  <span className="text-grey-500">Trigger: </span>
                  <span className="font-semibold text-grey-900">
                    {simResponse.ruleMatched ?? 'Fail-closed default (no rule matched)'}
                  </span>
                </p>

                {simResponse.violations.length > 0 && (
                  <div className="space-y-1 pt-1.5 border-t border-grey-300">
                    <span className="text-caption font-bold text-error-700 uppercase block font-mono">
                      Policy Violations ({simResponse.violations.length}):
                    </span>
                    <ul className="list-disc list-inside space-y-0.5 text-caption text-error-900 font-mono">
                      {simResponse.violations.map((violation) => (
                        <li key={violation} className="break-words">
                          {violation}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="text-caption text-grey-500 mt-space-md">
            Simulation evaluates the same compiled policy as live traffic and has no network side
            effects.
          </div>
        </div>
      </div>
    </div>
  );
};
