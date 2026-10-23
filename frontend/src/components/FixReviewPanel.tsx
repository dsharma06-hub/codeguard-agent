import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import {
  Wrench,
  CheckCircle2,
  XCircle,
  Clock,
  ShieldCheck,
  FileCode,
  RotateCw,
  GitCommit,
  Check,
  X,
  ChevronRight,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import type { ProposedFix, Severity } from '../types/finding';
import { approveFix, rejectFix, getScanFixes } from '../services/api';
import { SeverityBadge } from './SeverityBadge';

interface FixReviewPanelProps {
  fixes?: ProposedFix[];
  scanId?: string;
  onFixUpdated?: (updatedFix: ProposedFix) => void;
  onFixesLoaded?: (loadedFixes: ProposedFix[]) => void;
}

export const FixReviewPanel: React.FC<FixReviewPanelProps> = ({
  fixes: initialFixes,
  scanId,
  onFixUpdated,
  onFixesLoaded,
}) => {
  const navigate = useNavigate();

  const [fixesList, setFixesList] = useState<ProposedFix[]>(() => {
    return Array.isArray(initialFixes) ? initialFixes : [];
  });
  const [selectedFixId, setSelectedFixId] = useState<string>(() => {
    return initialFixes && initialFixes.length > 0 ? initialFixes[0].id : '';
  });
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(() => {
    // If initialFixes was provided as a populated array, don't start in loading state
    return !initialFixes || initialFixes.length === 0;
  });
  const [loadError, setLoadError] = useState<string | null>(null);

  // Fetch fixes from API if initialFixes is empty or omitted
  const fetchFixesFromApi = useCallback(async () => {
    setIsLoading(true);
    setLoadError(null);
    try {
      const fetched = await getScanFixes(scanId);
      setFixesList(fetched);
      if (fetched.length > 0) {
        setSelectedFixId((prev) => (fetched.some((f) => f.id === prev) ? prev : fetched[0].id));
      }
      if (onFixesLoaded) {
        onFixesLoaded(fetched);
      }
    } catch (err: any) {
      console.warn('[FixReviewPanel] Failed to fetch fixes from backend:', err);
      const message =
        err?.message?.includes('Failed to fetch') || err?.message?.includes('NetworkError')
          ? 'Cannot connect to CodeGuard backend at http://localhost:5000. Verify the service is running.'
          : err?.message || 'Failed to retrieve proposed patches from backend.';
      setLoadError(message);
    } finally {
      setIsLoading(false);
    }
  }, [scanId, onFixesLoaded]);

  // Sync if prop updates with items, otherwise fetch
  useEffect(() => {
    if (Array.isArray(initialFixes) && initialFixes.length > 0) {
      setFixesList(initialFixes);
      setIsLoading(false);
      setLoadError(null);
      if (!selectedFixId || !initialFixes.some((f) => f.id === selectedFixId)) {
        setSelectedFixId(initialFixes[0].id);
      }
    } else {
      fetchFixesFromApi();
    }
  }, [initialFixes, fetchFixesFromApi]);

  const activeFix = fixesList.find((f) => f.id === selectedFixId) || fixesList[0] || null;

  const handleApprove = async () => {
    if (!activeFix || actionLoading) return;
    setActionLoading(true);
    try {
      await approveFix(activeFix.id);
      const updated: ProposedFix = {
        ...activeFix,
        status: 'approved',
      };
      setFixesList((prev) => prev.map((f) => (f.id === activeFix.id ? updated : f)));
      if (onFixUpdated) onFixUpdated(updated);
      toast.success('Patch Approved & Applied', {
        description: `Successfully applied verified patch to ephemeral copy of ${activeFix.filePath}`,
        icon: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
      });
    } catch (err: any) {
      toast.error('Approval Failed', {
        description: err.message || 'Could not apply patch to ephemeral workspace.',
      });
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async () => {
    if (!activeFix || actionLoading) return;
    setActionLoading(true);
    try {
      await rejectFix(activeFix.id, 'User rejected proposed patch');
      const updated: ProposedFix = {
        ...activeFix,
        status: 'rejected',
      };
      setFixesList((prev) => prev.map((f) => (f.id === activeFix.id ? updated : f)));
      if (onFixUpdated) onFixUpdated(updated);
      toast.info('Patch Rejected', {
        description: `Proposed patch for ${activeFix.filePath} was dismissed.`,
        icon: <XCircle className="w-4 h-4 text-rose-400" />,
      });
    } catch (err: any) {
      toast.error('Rejection Failed', {
        description: err.message || 'Could not update patch status.',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // State 1: Loading State
  if (isLoading) {
    return (
      <div className="min-h-[380px] flex flex-col items-center justify-center p-8 rounded-xl border border-slate-800 bg-[#0c0e17] text-center shadow-lg">
        <div className="relative flex items-center justify-center mb-4">
          <div className="w-12 h-12 rounded-full border-2 border-emerald-500/20 border-t-emerald-400 animate-spin" />
          <Wrench className="w-5 h-5 text-emerald-400 absolute animate-pulse" />
        </div>
        <h4 className="text-sm font-semibold text-slate-200">Querying Agent Fix Store</h4>
        <p className="text-xs text-slate-400 mt-1.5 max-w-sm font-mono leading-relaxed">
          Retrieving proposed patches and ReAct rescan verification logs from backend...
        </p>
        <div className="w-48 h-1 bg-slate-900 rounded-full mt-4 overflow-hidden border border-slate-800">
          <div className="w-full h-full bg-gradient-to-r from-emerald-500 to-cyan-500 animate-[shimmer_1.5s_infinite]" />
        </div>
      </div>
    );
  }

  // State 2: Error State (e.g. backend stopped or port 5000 unreachable)
  if (loadError && fixesList.length === 0) {
    return (
      <div className="min-h-[380px] flex flex-col items-center justify-center p-8 rounded-xl border border-rose-500/30 bg-[#0c0e17] text-center shadow-[0_0_25px_rgba(244,63,94,0.08)]">
        <div className="w-12 h-12 rounded-xl bg-rose-950/60 border border-rose-500/40 flex items-center justify-center mb-4 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.2)]">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h4 className="text-sm font-bold text-slate-100">Fix Service Unavailable</h4>
        <p className="text-xs text-slate-400 mt-1 max-w-md">
          Unable to query proposed patches from the CodeGuard backend service.
        </p>
        <div className="mt-3 p-3 rounded-lg bg-rose-950/20 border border-rose-900/50 max-w-lg text-left">
          <span className="font-mono text-[11px] text-rose-300 block break-all">
            {loadError}
          </span>
          <span className="font-mono text-[10px] text-slate-500 mt-1 block">
            Target: http://localhost:5000/api/fixes
          </span>
        </div>
        <div className="flex items-center gap-3 mt-5">
          <button
            type="button"
            onClick={fetchFixesFromApi}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-700 hover:border-slate-600 transition-all cursor-pointer"
          >
            <RotateCw className="w-3.5 h-3.5" />
            Retry Connection
          </button>
          <button
            type="button"
            onClick={() => navigate('/ingest')}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 transition-all cursor-pointer"
          >
            New Scan <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    );
  }

  // State 3: Empty State (Backend reachable, but no fixes generated or pending)
  if (fixesList.length === 0) {
    return (
      <div className="min-h-[380px] flex flex-col items-center justify-center p-8 rounded-xl border border-slate-800/80 bg-[#0c0e17] text-center shadow-lg">
        <div className="w-12 h-12 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-center mb-3 text-slate-500">
          <Wrench className="w-6 h-6 text-slate-600" />
        </div>
        <h4 className="text-sm font-semibold text-slate-200">No Proposed Fixes</h4>
        <p className="text-xs text-slate-400 mt-1.5 max-w-md leading-relaxed">
          The Fix Agent only generates verified patches for findings confirmed as true positives by the Verifier Agent. Run a scan on code with verified vulnerabilities to review AI patches.
        </p>
        <button
          type="button"
          onClick={() => navigate('/ingest')}
          className="mt-5 inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.15)] transition-all cursor-pointer"
        >
          Upload Codebase to Scan <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    );
  }

  // State 4: Fix Review Content View
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      {/* Left Column: Proposed Fixes List (5 cols) */}
      <div className="lg:col-span-5 flex flex-col gap-3">
        <div className="flex items-center justify-between p-3 rounded-xl bg-[#0c0e17] border border-slate-800 text-xs font-mono">
          <span className="text-slate-400">
            Pending Human Review:{' '}
            <strong className="text-amber-400">
              {fixesList.filter((f) => f.status === 'pending').length}
            </strong>
          </span>
          <span className="text-slate-500">
            Total Fixes: <strong className="text-slate-200">{fixesList.length}</strong>
          </span>
        </div>

        {fixesList.map((fix) => {
          const isSelected = activeFix?.id === fix.id;
          const safeSeverity = ((fix.severity || 'medium').toLowerCase() as Severity);
          const safeTitle = fix.title || fix.filePath || 'Security Remediation Patch';

          const statusBadge =
            fix.status === 'approved' ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/80 text-emerald-300 border border-emerald-500/30">
                <Check className="w-3 h-3 text-emerald-400" /> Approved
              </span>
            ) : fix.status === 'rejected' ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950/80 text-rose-300 border border-rose-500/30">
                <X className="w-3 h-3 text-rose-400" /> Rejected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/80 text-amber-300 border border-amber-500/30 animate-pulse">
                <Clock className="w-3 h-3 text-amber-400" /> Pending Review
              </span>
            );

          return (
            <motion.div
              key={fix.id}
              onClick={() => setSelectedFixId(fix.id)}
              role="button"
              tabIndex={0}
              className={`p-4 rounded-xl border text-left cursor-pointer transition-all duration-150 flex flex-col gap-2.5 ${
                isSelected
                  ? 'bg-[#121524] border-emerald-500/50 shadow-[0_0_18px_rgba(16,185,129,0.12)] ring-1 ring-emerald-500/30'
                  : 'bg-[#0c0e17] border-slate-800 hover:bg-[#111422] hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={safeSeverity} size="sm" />
                  {fix.cwe && (
                    <span className="font-mono text-[11px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {fix.cwe}
                    </span>
                  )}
                </div>
                {statusBadge}
              </div>

              <div className="flex items-start justify-between gap-2">
                <h4 className="text-sm font-semibold text-slate-100 leading-snug">
                  {safeTitle}
                </h4>
                <ChevronRight
                  className={`w-4 h-4 shrink-0 transition-transform ${
                    isSelected ? 'text-emerald-400 translate-x-0.5' : 'text-slate-600'
                  }`}
                />
              </div>

              <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 font-mono text-[11px] text-slate-400">
                <div className="flex items-center gap-1.5 truncate">
                  <FileCode className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  <span className="truncate">{fix.filePath}</span>
                </div>
                <span className="shrink-0 text-slate-400 ml-2">
                  {fix.retryCount > 1 ? `${fix.retryCount} ReAct cycles` : 'Clean on pass 1'}
                </span>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Right Column: Fix Details Inspector & Diff (7 cols) */}
      <div className="lg:col-span-7 flex flex-col gap-4 sticky top-20">
        {activeFix ? (
          <div className="flex flex-col gap-4 p-5 rounded-xl bg-[#0c0e17] border border-slate-800">
            {/* Header with Title & Action Controls */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <SeverityBadge
                    severity={((activeFix.severity || 'medium').toLowerCase() as Severity)}
                    size="sm"
                  />
                  <span className="font-mono text-xs text-slate-400">{activeFix.filePath}</span>
                </div>
                <h3 className="text-base font-semibold text-slate-100 mt-1">
                  {activeFix.title || activeFix.filePath || 'Security Remediation Patch'}
                </h3>
              </div>

              {/* Approve / Reject Buttons (Human-in-the-Loop) */}
              <div className="flex items-center gap-2 shrink-0">
                {activeFix.status === 'pending' ? (
                  <>
                    <button
                      type="button"
                      disabled={actionLoading}
                      onClick={handleReject}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-950/40 text-rose-300 border border-rose-500/30 hover:bg-rose-900/50 hover:border-rose-500/60 transition-all cursor-pointer disabled:opacity-50"
                    >
                      <X className="w-3.5 h-3.5 text-rose-400" />
                      Reject
                    </button>
                    <button
                      type="button"
                      disabled={actionLoading}
                      onClick={handleApprove}
                      className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 hover:bg-emerald-500/30 hover:border-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all cursor-pointer disabled:opacity-50"
                    >
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Approve & Apply
                    </button>
                  </>
                ) : activeFix.status === 'approved' ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-500/40">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Applied to Ephemeral Workspace
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-950/60 text-rose-300 border border-rose-500/40">
                    <XCircle className="w-4 h-4 text-rose-400" />
                    Patch Rejected
                  </span>
                )}
              </div>
            </div>

            {/* Verifier Reasoning Card */}
            {activeFix.verifierReasoning && (
              <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-500/30 flex flex-col gap-1.5">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="flex items-center gap-1.5 text-amber-300 font-semibold">
                    <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                    Verifier Agent Evaluation
                  </span>
                  {activeFix.verifierConfidence !== undefined && (
                    <span className="text-amber-400/80">
                      Confidence: {Math.round(activeFix.verifierConfidence * 100)}% True Positive
                    </span>
                  )}
                </div>
                <p className="text-xs text-amber-200/90 leading-relaxed font-sans">
                  {activeFix.verifierReasoning}
                </p>
              </div>
            )}

            {/* ReAct Iterations Card */}
            {((activeFix.history && activeFix.history.length > 0) ||
              ((activeFix as any).iterations && (activeFix as any).iterations.length > 0)) && (
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col gap-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                    <RotateCw className="w-3.5 h-3.5 text-emerald-400" />
                    ReAct Rescan Validation Loop (
                    {(activeFix.history || (activeFix as any).iterations).length} cycles)
                  </span>
                  <span className="text-emerald-400 text-[11px]">
                    FastAPI /rescan Verified
                  </span>
                </div>
                <div className="flex flex-col gap-2">
                  {(activeFix.history || (activeFix as any).iterations || []).map(
                    (step: any, idx: number) => {
                      const reason = step.reason || step.thought || 'Examine code and apply targeted security pattern';
                      const act = step.act || step.action || 'rescan';
                      const observe = step.observe || step.observation || 'Rescan verification completed';
                      const timeStr = step.timestamp
                        ? new Date(step.timestamp).toLocaleTimeString()
                        : `Cycle #${step.iteration || idx + 1}`;

                      return (
                        <div
                          key={idx}
                          className="p-2.5 rounded bg-slate-950/80 border border-slate-900 text-xs font-mono flex flex-col gap-1"
                        >
                          <div className="text-slate-400 font-semibold flex items-center justify-between">
                            <span>Cycle #{step.iteration || idx + 1}:</span>
                            <span className="text-[10px] text-slate-600 font-normal">
                              {timeStr}
                            </span>
                          </div>
                          <div className="text-slate-300 pl-2 border-l border-slate-800">
                            <span className="text-slate-500">Reason:</span> {reason}
                          </div>
                          <div className="text-slate-300 pl-2 border-l border-slate-800">
                            <span className="text-slate-500">Act:</span> {act}
                          </div>
                          <div className="text-emerald-300 pl-2 border-l border-emerald-800/60">
                            <span className="text-emerald-500">Observe:</span> {observe}
                          </div>
                        </div>
                      );
                    }
                  )}
                </div>
              </div>
            )}

            {/* Unified Diff Viewer */}
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <GitCommit className="w-3.5 h-3.5 text-emerald-400" />
                  Proposed Unified Diff
                </span>
                <span>{activeFix.filePath}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#07080e] border border-slate-800 font-mono text-xs overflow-x-auto max-h-[350px] leading-relaxed">
                {activeFix.diff ? (
                  activeFix.diff.split('\n').map((line, idx) => {
                    let color = 'text-slate-400';
                    let bg = '';
                    if (line.startsWith('+') && !line.startsWith('+++')) {
                      color = 'text-emerald-300 font-semibold';
                      bg = 'bg-emerald-950/30';
                    } else if (line.startsWith('-') && !line.startsWith('---')) {
                      color = 'text-rose-300 font-semibold';
                      bg = 'bg-rose-950/30';
                    } else if (line.startsWith('@@')) {
                      color = 'text-cyan-400';
                      bg = 'bg-cyan-950/20';
                    }

                    return (
                      <div key={idx} className={`${color} ${bg} px-1.5 py-0.5 rounded whitespace-pre`}>
                        {line}
                      </div>
                    );
                  })
                ) : (
                  <div className="text-slate-500 italic">No diff available.</div>
                )}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};
