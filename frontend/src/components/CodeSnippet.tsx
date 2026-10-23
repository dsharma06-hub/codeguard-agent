import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Copy,
  Check,
  FileCode2,
  AlertTriangle,
  ShieldCheck,
  Terminal,
  Sparkles,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import type { Finding } from '../types/finding';
import { SeverityBadge } from './SeverityBadge';
import { explainFinding, type ExplainFindingResponse } from '../services/api';

interface CodeSnippetProps {
  finding: Finding | null;
}

export const CodeSnippet: React.FC<CodeSnippetProps> = ({ finding }) => {
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [copiedRemediation, setCopiedRemediation] = useState(false);
  const [aiExplanations, setAiExplanations] = useState<Record<string, ExplainFindingResponse>>({});
  const [loadingAi, setLoadingAi] = useState(false);
  const [copiedAi, setCopiedAi] = useState(false);

  if (!finding) {
    return (
      <div className="h-full min-h-[460px] flex flex-col items-center justify-center p-8 rounded-xl border border-slate-800/80 bg-[#0c0e17] text-center">
        <Terminal className="w-10 h-10 text-slate-700 mb-3" />
        <h3 className="text-sm font-medium text-slate-300">No Finding Selected</h3>
        <p className="text-xs text-slate-500 mt-1 max-w-xs">
          Select any vulnerability or security finding from the list to inspect its source context and attack vector.
        </p>
      </div>
    );
  }

  const { codeSnippet } = finding;
  const aiExplanation = aiExplanations[finding.id];

  const handleCopySnippet = () => {
    navigator.clipboard.writeText(codeSnippet.lines.join('\n'));
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  const handleCopyRemediation = () => {
    navigator.clipboard.writeText(finding.remediation);
    setCopiedRemediation(true);
    setTimeout(() => setCopiedRemediation(false), 2000);
  };

  const handleCopyAi = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedAi(true);
    setTimeout(() => setCopiedAi(false), 2000);
  };

  const handleFetchAiExplanation = async () => {
    if (!finding || loadingAi) return;
    setLoadingAi(true);
    try {
      const res = await explainFinding(finding);
      setAiExplanations((prev) => ({
        ...prev,
        [finding.id]: res,
      }));
    } catch {
      setAiExplanations((prev) => ({
        ...prev,
        [finding.id]: {
          success: true,
          findingId: finding.id,
          explanation: finding.remediation || 'Apply standard security best practices.',
          isFallback: true,
          fallbackReason: 'Network error',
        },
      }));
    } finally {
      setLoadingAi(false);
    }
  };

  // Determine severity glow style
  const sweepGradient =
    finding.severity === 'critical'
      ? 'from-red-950/60 via-red-900/40 to-red-950/60 border-l-red-500 text-red-100'
      : finding.severity === 'high'
      ? 'from-orange-950/50 via-orange-900/35 to-orange-950/50 border-l-orange-500 text-orange-100'
      : 'from-amber-950/40 via-amber-900/30 to-amber-950/40 border-l-amber-500 text-amber-100';

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={finding.id}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="flex flex-col rounded-xl border border-slate-800 bg-[#0a0c14] overflow-hidden shadow-2xl"
      >
        {/* Panel Header */}
        <div className="flex items-center justify-between px-4 py-3 bg-[#0f121d] border-b border-slate-800/80 gap-3 flex-wrap">
          <div className="flex items-center gap-2.5 min-w-0">
            <FileCode2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="font-mono text-xs font-medium text-slate-200 truncate">
              {finding.filePath}
            </span>
            <span className="font-mono text-[11px] text-slate-400 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
              {codeSnippet.language}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} size="sm" />
            <button
              onClick={handleCopySnippet}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-700/80 rounded-md border border-slate-700/60 transition-colors"
              title="Copy snippet"
            >
              {copiedSnippet ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400 font-mono text-[11px]">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span className="font-mono text-[11px]">Copy Code</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Code Lines Container */}
        <div className="relative font-mono text-[13px] leading-6 overflow-x-auto py-3 bg-[#08090f]">
          <div className="min-w-full inline-block">
            {codeSnippet.lines.map((line, idx) => {
              const currentLineNumber = codeSnippet.startLine + idx;
              const isHighlighted = codeSnippet.highlightLines.includes(currentLineNumber);

              return (
                <div key={idx} className="relative group">
                  <div
                    className={`flex items-stretch transition-colors duration-150 ${
                      isHighlighted
                        ? `bg-gradient-to-r ${sweepGradient} border-l-[3px] shadow-[inset_0_0_12px_rgba(239,68,68,0.06)]`
                        : 'border-l-[3px] border-l-transparent hover:bg-slate-900/50'
                    }`}
                  >
                    {/* Line number gutter */}
                    <span
                      className={`select-none w-12 shrink-0 pr-4 text-right tabular-nums text-xs py-0.5 border-r border-slate-800/60 ${
                        isHighlighted
                          ? 'text-red-400 font-bold bg-red-950/20'
                          : 'text-slate-600 group-hover:text-slate-400'
                      }`}
                    >
                      {currentLineNumber}
                    </span>

                    {/* Indicator icon gutter */}
                    <span className="w-6 shrink-0 flex items-center justify-center select-none py-0.5">
                      {isHighlighted ? (
                        <AlertTriangle className="w-3 h-3 text-red-400 animate-pulse" />
                      ) : (
                        <span className="text-slate-700 text-xs opacity-0 group-hover:opacity-100">
                          ·
                        </span>
                      )}
                    </span>

                    {/* Line code content */}
                    <span
                      className={`flex-1 px-3 py-0.5 whitespace-pre font-mono ${
                        isHighlighted
                          ? 'text-white font-medium'
                          : 'text-slate-300'
                      }`}
                    >
                      {formatCodeSyntax(line)}
                    </span>
                  </div>

                  {/* Inline callout on the first highlighted line */}
                  {isHighlighted &&
                    codeSnippet.highlightMessage &&
                    currentLineNumber === codeSnippet.highlightLines[0] && (
                      <div className="my-1 mx-4 ml-18 px-3 py-1.5 rounded-lg bg-red-950/40 border border-red-500/30 flex items-center gap-2 text-xs text-red-300 shadow-md">
                        <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        <span className="font-sans font-medium">
                          {codeSnippet.highlightMessage}
                        </span>
                        <span className="ml-auto font-mono text-[10px] text-red-400/80 bg-red-900/40 px-1.5 py-0.5 rounded">
                          L{finding.startLine}
                        </span>
                      </div>
                    )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Remediation & Attack Vector Section */}
        <div className="p-4 bg-[#0d0f19] border-t border-slate-800/80 flex flex-col gap-3">
          {/* Verifier Agent Assessment */}
          {finding.verifierReasoning && (
            <div className={`p-3 rounded-lg border flex flex-col gap-1.5 text-xs ${
              finding.status === 'dismissed' || finding.verifierVerdict === 'false_positive'
                ? 'bg-slate-900/80 border-slate-700/80'
                : 'bg-amber-950/20 border-amber-500/30'
            }`}>
              <div className="flex items-center justify-between font-mono flex-wrap gap-1">
                <span className={`font-semibold flex items-center gap-1.5 ${
                  finding.status === 'dismissed' || finding.verifierVerdict === 'false_positive'
                    ? 'text-slate-400'
                    : 'text-amber-300'
                }`}>
                  <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                  Verifier Agent: {finding.status === 'dismissed' ? 'False Positive (Dismissed)' : 'Verified True Positive'}
                </span>
                {finding.verifierConfidence !== undefined && (
                  <span className="text-[11px] text-amber-400/90 font-mono">
                    Confidence: {Math.round(finding.verifierConfidence * 100)}%
                  </span>
                )}
              </div>
              <p className="text-slate-300 leading-relaxed font-sans">
                {finding.verifierReasoning}
              </p>
            </div>
          )}

          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-emerald-400 font-medium text-xs">
              <ShieldCheck className="w-4 h-4" />
              <span>Standard Remediation Guidance</span>
            </div>

            <button
              onClick={handleCopyRemediation}
              className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors font-mono cursor-pointer"
            >
              {copiedRemediation ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy Fix</span>
                </>
              )}
            </button>
          </div>

          <p className="text-xs text-slate-300 bg-[#080910] p-3 rounded-lg border border-slate-800/80 leading-relaxed font-sans">
            {finding.remediation}
          </p>

          {/* AI Explanation Section */}
          {!aiExplanation && !loadingAi && (
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-2 text-slate-400 text-xs">
                <Sparkles className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                <span>Want deep contextual reasoning &amp; a tailored code fix?</span>
              </div>
              <button
                onClick={handleFetchAiExplanation}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/50 hover:bg-purple-900/60 border border-purple-500/40 text-purple-200 hover:text-white text-xs font-medium transition-all shadow-sm hover:shadow-[0_0_12px_rgba(168,85,247,0.25)] cursor-pointer"
              >
                <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                <span>Get AI Explanation</span>
              </button>
            </div>
          )}

          {loadingAi && (
            <div className="pt-2 border-t border-slate-800/80">
              <div className="flex items-center gap-2.5 p-3 rounded-lg bg-purple-950/20 border border-purple-500/30 text-xs text-purple-200">
                <Loader2 className="w-4 h-4 text-purple-400 animate-spin shrink-0" />
                <span className="font-sans">Analyzing vulnerability in context and synthesizing tailored fix with Gemini...</span>
              </div>
            </div>
          )}

          {aiExplanation && (
            aiExplanation.isFallback ? (
              <div className="pt-2 border-t border-slate-800/80 flex flex-col gap-2">
                <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs flex flex-col gap-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-amber-300 font-semibold">
                      <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>AI explanation unavailable right now — showing standard guidance</span>
                    </div>
                    <button
                      onClick={handleFetchAiExplanation}
                      disabled={loadingAi}
                      className="text-[11px] text-amber-400 hover:text-amber-200 underline font-mono cursor-pointer"
                    >
                      Retry AI
                    </button>
                  </div>
                  <p className="text-slate-300 leading-relaxed font-sans pl-6">
                    {aiExplanation.explanation}
                  </p>
                </div>
              </div>
            ) : (
              <div className="pt-2 border-t border-slate-800/80 flex flex-col gap-2.5">
                <div className="p-3.5 rounded-xl bg-[#0f0d1c] border border-purple-500/40 shadow-[0_0_24px_rgba(168,85,247,0.1)] flex flex-col gap-3">
                  <div className="flex items-center justify-between gap-2 flex-wrap pb-2.5 border-b border-purple-500/20">
                    <div className="flex items-center gap-2 flex-wrap">
                      <div className="p-1 rounded bg-purple-950/80 border border-purple-500/40 text-purple-300">
                        <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                      </div>
                      <span className="text-xs font-semibold text-purple-200">AI Deep-Dive Explanation</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-900/40 border border-purple-500/30 text-purple-300">
                        {aiExplanation.model || 'gemini-3.5-flash-lite'}
                      </span>
                      {aiExplanation.cached && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700/60">
                          Cached
                        </span>
                      )}
                    </div>

                    <button
                      onClick={() => handleCopyAi(aiExplanation.explanation)}
                      className="inline-flex items-center gap-1 text-[11px] text-purple-300 hover:text-purple-100 transition-colors font-mono cursor-pointer"
                    >
                      {copiedAi ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy AI Explanation</span>
                        </>
                      )}
                    </button>
                  </div>

                  {renderAiExplanation(aiExplanation.explanation)}
                </div>
              </div>
            )
          )}

          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 font-mono">
            <span>Attack Path: Direct Code Exposure → Public Git History</span>
            <span className="text-emerald-400/90 font-sans font-medium">Confidence: 98%</span>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

/**
 * Renders LLM explanations with highlighted section titles, code blocks, and formatted text
 */
function renderAiExplanation(content: string): React.ReactNode {
  // Split on fenced code blocks
  const parts = content.split(/(```[\s\S]*?```)/g);

  return (
    <div className="space-y-2.5 text-xs text-slate-300 leading-relaxed font-sans">
      {parts.map((part, pIdx) => {
        if (part.startsWith('```') && part.endsWith('```')) {
          const rawLines = part.slice(3, -3).trim().split('\n');
          const firstLine = rawLines[0].trim();
          const hasLang = Boolean(firstLine && !firstLine.includes(' ') && firstLine.length < 20);
          const lang = hasLang ? firstLine : '';
          const code = (hasLang ? rawLines.slice(1) : rawLines).join('\n');
          return (
            <div key={pIdx} className="my-2.5 rounded-lg bg-[#05060b] border border-purple-500/20 overflow-hidden font-mono text-[12px] shadow-sm">
              {lang && (
                <div className="px-3 py-1 bg-purple-950/40 border-b border-purple-500/20 text-[10px] text-purple-300 font-semibold uppercase tracking-wider">
                  {lang}
                </div>
              )}
              <pre className="p-3 overflow-x-auto text-emerald-300 leading-relaxed font-mono">
                <code>{code}</code>
              </pre>
            </div>
          );
        }

        const paragraphs = part.split(/\n\s*\n/);
        return paragraphs.map((para, paraIdx) => {
          const trimmed = para.trim();
          if (!trimmed) return null;

          if (trimmed.startsWith('### ')) {
            return (
              <h5 key={`${pIdx}-${paraIdx}`} className="text-xs font-bold text-purple-300 uppercase tracking-wider pt-2 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                {trimmed.replace(/^###\s+/, '')}
              </h5>
            );
          }

          if (trimmed.startsWith('## ')) {
            return (
              <h4 key={`${pIdx}-${paraIdx}`} className="text-xs font-bold text-purple-200 uppercase tracking-wider pt-2">
                {trimmed.replace(/^##\s+/, '')}
              </h4>
            );
          }

          return (
            <p key={`${pIdx}-${paraIdx}`} className="text-slate-300 leading-relaxed">
              {trimmed}
            </p>
          );
        });
      })}
    </div>
  );
}

/**
 * Lightweight helper to highlight standard keywords, strings, and comments
 * without adding heavy dependencies.
 */
function formatCodeSyntax(line: string): React.ReactNode {
  // If line is empty
  if (!line.trim()) return <span>&nbsp;</span>;

  // Comment line
  if (line.trim().startsWith('//') || line.trim().startsWith('#')) {
    return <span className="text-slate-500 italic">{line}</span>;
  }

  // Tokenize basic keywords and strings
  const tokens = line.split(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\b(?:import|from|export|function|const|let|var|return|async|await|try|catch|new|if|else|typeof)\b)/g);

  return (
    <>
      {tokens.map((token, i) => {
        if (!token) return null;

        // Keywords
        if (/^(import|from|export|function|const|let|var|return|async|await|try|catch|new|if|else|typeof)$/.test(token)) {
          return (
            <span key={i} className="text-purple-400 font-semibold">
              {token}
            </span>
          );
        }

        // Strings
        if (/^["'`].*["'`]$/.test(token)) {
          return (
            <span key={i} className="text-emerald-400">
              {token}
            </span>
          );
        }

        // Standard text
        return <span key={i}>{token}</span>;
      })}
    </>
  );
}
