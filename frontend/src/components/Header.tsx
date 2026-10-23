import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import {
  Shield,
  GitBranch,
  GitCommit,
  Clock,
  FileSearch,
  RotateCw,
  Plus,
  Sparkles,
  CheckCircle,
} from 'lucide-react';
import type { ScanMetadata } from '../types/finding';

interface HeaderProps {
  metadata: ScanMetadata;
  isDemo?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ metadata, isDemo = false }) => {
  const navigate = useNavigate();

  const handleRerunScan = () => {
    toast.info('Scan triggered — analyzing repository...', {
      description: 'Re-evaluating AST heuristics, secrets, and dependencies.',
      icon: <RotateCw className="w-4 h-4 text-emerald-400 animate-spin" />,
      duration: 3500,
    });
  };

  return (
    <header className="border-b border-slate-800/80 bg-[#07080e]/90 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Left: Brand + Target Repo Info */}
          <div className="flex items-center gap-3.5">
            <button
              type="button"
              onClick={() => navigate('/ingest')}
              className="h-9 w-9 rounded-lg bg-gradient-to-br from-emerald-500/20 to-cyan-500/10 border border-emerald-500/30 flex items-center justify-center shadow-[0_0_12px_rgba(16,185,129,0.15)] hover:border-emerald-400/50 transition-colors cursor-pointer"
              title="Start New Security Scan"
            >
              <Shield className="w-5 h-5 text-emerald-400" />
            </button>

            <div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => navigate('/ingest')}
                  className="font-semibold text-slate-100 hover:text-white text-sm tracking-tight transition-colors cursor-pointer"
                >
                  CodeGuard
                </button>
                <span className="text-slate-600">/</span>
                <span className="font-mono text-xs text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/20">
                  {metadata.repoName}
                </span>
                {isDemo ? (
                  <span className="hidden sm:inline-flex items-center gap-1 text-[10px] text-amber-300 bg-amber-950/40 border border-amber-500/30 px-1.5 py-0.5 rounded font-mono">
                    <Sparkles className="w-2.5 h-2.5 text-amber-400" /> Demo Sample Data
                  </span>
                ) : (
                  <span className="hidden sm:inline-flex items-center gap-1 text-[10px] text-emerald-300 bg-emerald-950/40 border border-emerald-500/30 px-1.5 py-0.5 rounded font-mono">
                    <CheckCircle className="w-2.5 h-2.5 text-emerald-400" /> Live AST Scan
                  </span>
                )}
              </div>

              {/* Repo meta sub-bar */}
              <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-400 font-mono">
                <span className="inline-flex items-center gap-1 hover:text-slate-300">
                  <GitBranch className="w-3 h-3 text-slate-500" />
                  {metadata.branch}
                </span>
                <span className="inline-flex items-center gap-1 hover:text-slate-300">
                  <GitCommit className="w-3 h-3 text-slate-500" />
                  {metadata.commitHash}
                </span>
                <span className="inline-flex items-center gap-1 text-slate-500">
                  <Clock className="w-3 h-3" />
                  {metadata.scanTimestamp}
                </span>
              </div>
            </div>
          </div>

          {/* Right: Scan Stats and Action Buttons */}
          <div className="flex items-center gap-3 self-start md:self-auto flex-wrap">
            <div className="hidden lg:flex items-center gap-4 px-3 py-1.5 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs font-mono text-slate-400">
              <span className="inline-flex items-center gap-1.5">
                <FileSearch className="w-3.5 h-3.5 text-slate-400" />
                <strong className="text-slate-200">{metadata.filesScanned}</strong> files
              </span>
              <span className="text-slate-700">|</span>
              <span>
                <strong className="text-slate-200">{(metadata.durationMs / 1000).toFixed(2)}s</strong> scan
              </span>
            </div>

            <button
              type="button"
              onClick={() => navigate('/ingest')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800/70 hover:bg-slate-700/80 border border-slate-700/60 transition-all cursor-pointer font-sans"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Scan</span>
            </button>

            <button
              type="button"
              onClick={handleRerunScan}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-[0_0_12px_rgba(16,185,129,0.25)] transition-all cursor-pointer font-sans font-semibold"
            >
              <RotateCw className="w-3.5 h-3.5" />
              <span>Re-run Analysis</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
