import { motion } from 'framer-motion';
import { FileCode, ChevronRight, ShieldAlert, Cpu, Database, PackageCheck, AlertCircle, CodeXml } from 'lucide-react';
import type { Finding, FindingCategory } from '../types/finding';
import { SeverityBadge } from './SeverityBadge';

interface FindingCardProps {
  finding: Finding;
  isSelected: boolean;
  onSelect: () => void;
  index: number;
}

const categoryIcons: Record<FindingCategory, React.ReactNode> = {
  secret: <ShieldAlert className="w-3.5 h-3.5 text-red-400" />,
  injection: <Database className="w-3.5 h-3.5 text-orange-400" />,
  xss: <CodeXml className="w-3.5 h-3.5 text-amber-400" />,
  'Cross-Site Scripting': <CodeXml className="w-3.5 h-3.5 text-amber-400" />,
  dependency: <PackageCheck className="w-3.5 h-3.5 text-amber-400" />,
  validation: <AlertCircle className="w-3.5 h-3.5 text-yellow-400" />,
  complexity: <Cpu className="w-3.5 h-3.5 text-sky-400" />,
  'ai-antipattern': <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />,
};

const categoryLabels: Record<FindingCategory, string> = {
  secret: 'Secret Leak',
  injection: 'Injection Risk',
  xss: 'Cross-Site Scripting',
  'Cross-Site Scripting': 'Cross-Site Scripting',
  dependency: 'CVE / Supply Chain',
  validation: 'Input Validation',
  complexity: 'Maintainability',
  'ai-antipattern': 'AI Antipattern',
};

function getFindingCategoryMeta(finding: Finding): { icon: React.ReactNode; label: string } {
  const titleLower = finding.title.toLowerCase();
  const descLower = finding.description.toLowerCase();
  const isXss =
    finding.category === 'xss' ||
    finding.category === 'Cross-Site Scripting' ||
    titleLower.includes('cross-site') ||
    titleLower.includes('xss') ||
    descLower.includes('cross-site scripting');

  if (isXss) {
    return {
      icon: <CodeXml className="w-3.5 h-3.5 text-amber-400" />,
      label: 'Cross-Site Scripting',
    };
  }

  const icon = categoryIcons[finding.category] || <AlertCircle className="w-3.5 h-3.5 text-slate-400" />;
  const label = categoryLabels[finding.category] || 'Security Finding';
  return { icon, label };
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  isSelected,
  onSelect,
  index,
}) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{
        duration: 0.2,
        delay: index * 0.05,
        ease: [0.16, 1, 0.3, 1], // sharp, confident ease-out
      }}
      onClick={onSelect}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      }}
      className={`group relative flex flex-col gap-2.5 p-4 rounded-xl border text-left cursor-pointer transition-all duration-150 outline-none select-none ${
        isSelected
          ? 'bg-[#121524] border-emerald-500/50 shadow-[0_0_18px_rgba(16,185,129,0.12)] ring-1 ring-emerald-500/30'
          : 'bg-[#0c0e17] border-slate-800/80 hover:bg-[#111422] hover:border-slate-700/80'
      }`}
    >
      {/* Top row: Severity badge, category, CWE */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} size="sm" />
          {(() => {
            const { icon, label } = getFindingCategoryMeta(finding);
            return (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-[11px] text-slate-400 font-mono">
                {icon}
                {label}
              </span>
            );
          })()}
          {finding.status === 'dismissed' && (
            <span className="font-mono text-[10px] text-amber-400 bg-amber-950/70 px-1.5 py-0.5 rounded border border-amber-600/30">
              Dismissed (FP)
            </span>
          )}
        </div>

        {finding.cwe && (
          <span className="font-mono text-[11px] text-slate-400 bg-slate-900/90 px-2 py-0.5 rounded border border-slate-800">
            {finding.cwe}
          </span>
        )}
      </div>

      {/* Finding title */}
      <div className="flex items-start justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-100 group-hover:text-white transition-colors duration-150 leading-snug">
          {finding.title}
        </h4>
        <ChevronRight
          className={`w-4 h-4 shrink-0 transition-transform duration-150 ${
            isSelected
              ? 'text-emerald-400 translate-x-0.5'
              : 'text-slate-600 group-hover:text-slate-400 group-hover:translate-x-0.5'
          }`}
        />
      </div>

      {/* Description */}
      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
        {finding.description}
      </p>

      {/* Bottom metadata: file path and line number */}
      <div className="flex items-center gap-2 pt-1 border-t border-slate-800/60 font-mono text-[11px] text-slate-400">
        <FileCode className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        <span className="truncate hover:text-slate-300 transition-colors">
          {finding.filePath}
        </span>
        <span className="text-slate-400">·</span>
        <span className="shrink-0 text-slate-400">
          L{finding.startLine}
          {finding.endLine !== finding.startLine ? `-${finding.endLine}` : ''}
        </span>
      </div>

      {/* Active selection indicator bar */}
      {isSelected && (
        <span className="absolute left-0 top-3 bottom-3 w-1 bg-emerald-400 rounded-r" />
      )}
    </motion.div>
  );
};
