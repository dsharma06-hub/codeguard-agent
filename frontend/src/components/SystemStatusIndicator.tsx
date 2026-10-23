import { useEffect, useState } from 'react';
import { getSystemStatus } from '../services/api';
import type { SystemStatus } from '../services/api';
import { RefreshCw, Server, Cpu, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';

export const SystemStatusIndicator: React.FC = () => {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);

  const fetchStatus = async () => {
    setLoading(true);
    const result = await getSystemStatus();
    setStatus(result);
    setLoading(false);
  };

  useEffect(() => {
    fetchStatus();
    // Poll every 15 seconds to keep diagnostic status fresh
    const interval = setInterval(fetchStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  // Determine overall health state
  const isBackendUp = status?.backend === 'ok';
  const isAnalysisUp = status?.analysisService === 'ok';

  let dotColor = 'bg-slate-500';
  let dotPulse = '';
  let statusText = 'Checking services...';
  let badgeBorder = 'border-slate-800 bg-[#0a0c14]/90';

  if (!loading && status) {
    if (!isBackendUp) {
      // Backend itself down (Gray / Red outline)
      dotColor = 'bg-slate-500';
      statusText = 'Backend Offline';
      badgeBorder = 'border-slate-700/80 bg-[#0c0e17]/90 text-slate-400';
    } else if (!isAnalysisUp) {
      // Backend up, but analysis service down (Yellow / Amber)
      dotColor = 'bg-amber-400';
      dotPulse = 'animate-ping';
      statusText = 'Analysis Offline';
      badgeBorder = 'border-amber-500/40 bg-amber-950/20 text-amber-300';
    } else {
      // All systems up (All Green)
      dotColor = 'bg-emerald-400';
      dotPulse = 'animate-ping';
      statusText = 'Services Nominal';
      badgeBorder = 'border-emerald-500/30 bg-emerald-950/20 text-emerald-300';
    }
  }

  return (
    <div className="fixed bottom-3 left-4 z-50 font-mono text-[11px] select-none">
      {/* Mini status pill */}
      <div
        onClick={() => setExpanded(!expanded)}
        className={`flex items-center gap-2 px-2.5 py-1.5 rounded-full border shadow-lg backdrop-blur-md cursor-pointer transition-all hover:scale-[1.02] ${badgeBorder}`}
        title="Click to view CodeGuard microservice health"
      >
        <span className="relative flex h-2 w-2">
          {dotPulse && (
            <span
              className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${dotColor} ${dotPulse}`}
            />
          )}
          <span className={`relative inline-flex rounded-full h-2 w-2 ${dotColor}`} />
        </span>

        <span className="font-medium tracking-tight">
          {loading && !status ? 'Connecting...' : statusText}
        </span>

        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            fetchStatus();
          }}
          className="text-slate-400 hover:text-white transition-colors ml-0.5"
          title="Re-check health status"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
        </button>
      </div>

      {/* Expanded diagnostic popover */}
      {expanded && (
        <div className="absolute bottom-10 left-0 w-64 p-3 rounded-xl border border-slate-800 bg-[#0c0e17]/95 backdrop-blur-xl shadow-2xl flex flex-col gap-2.5 mb-1 animate-in fade-in slide-in-from-bottom-2 duration-150">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-1.5 text-slate-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Service Mesh Status</span>
            <span className="text-[10px] text-slate-500 font-sans">
              {status?.timestamp ? new Date(status.timestamp).toLocaleTimeString() : ''}
            </span>
          </div>

          {/* Backend Status Row */}
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              <span>Backend API (Node:5000)</span>
            </div>
            {isBackendUp ? (
              <span className="inline-flex items-center gap-1 text-emerald-400 text-[10px] font-bold">
                <CheckCircle2 className="w-3 h-3" /> OK
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-slate-400 text-[10px]">
                <XCircle className="w-3 h-3 text-red-400" /> Unreachable
              </span>
            )}
          </div>

          {/* Analysis Service Status Row */}
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <Cpu className="w-3.5 h-3.5 text-slate-400" />
              <span>Analysis Svc (FastAPI:8000)</span>
            </div>
            {isAnalysisUp ? (
              <span className="inline-flex items-center gap-1 text-emerald-400 text-[10px] font-bold">
                <CheckCircle2 className="w-3 h-3" /> OK
              </span>
            ) : isBackendUp ? (
              <span className="inline-flex items-center gap-1 text-amber-400 text-[10px] font-bold">
                <AlertTriangle className="w-3 h-3" /> Down
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-slate-500 text-[10px]">
                Unknown
              </span>
            )}
          </div>

          <p className="text-[10px] text-slate-500 font-sans pt-1 border-t border-slate-800/60 leading-tight">
            Pipeline: Frontend &rarr; Express Gateway &rarr; FastAPI AST Engine.
          </p>
        </div>
      )}
    </div>
  );
};
