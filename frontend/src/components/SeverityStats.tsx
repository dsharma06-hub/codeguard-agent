import type { Severity, Finding } from '../types/finding';
import { AnimatedCounter } from './AnimatedCounter';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, Layers } from 'lucide-react';

interface SeverityStatsProps {
  findings: Finding[];
  selectedFilter: Severity | 'all';
  onSelectFilter: (filter: Severity | 'all') => void;
}

export const SeverityStats: React.FC<SeverityStatsProps> = ({
  findings,
  selectedFilter,
  onSelectFilter,
}) => {
  const counts = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low' || f.severity === 'info').length,
  };

  const statItems: Array<{
    key: Severity | 'all';
    label: string;
    count: number;
    icon: React.ReactNode;
    colorClasses: string;
    activeBorder: string;
    glow: string;
  }> = [
    {
      key: 'all',
      label: 'Total Findings',
      count: counts.total,
      icon: <Layers className="w-4 h-4 text-slate-400" />,
      colorClasses: 'text-slate-200',
      activeBorder: 'border-slate-400 bg-slate-800/40 ring-1 ring-slate-500/20',
      glow: '',
    },
    {
      key: 'critical',
      label: 'Critical',
      count: counts.critical,
      icon: <ShieldAlert className="w-4 h-4 text-red-400" />,
      colorClasses: 'text-red-400',
      activeBorder: 'border-red-500/60 bg-red-950/20 ring-1 ring-red-500/30',
      glow: counts.critical > 0 ? 'shadow-[0_0_12px_rgba(239,68,68,0.15)]' : '',
    },
    {
      key: 'high',
      label: 'High Severity',
      count: counts.high,
      icon: <AlertTriangle className="w-4 h-4 text-orange-400" />,
      colorClasses: 'text-orange-400',
      activeBorder: 'border-orange-500/60 bg-orange-950/20 ring-1 ring-orange-500/30',
      glow: counts.high > 0 ? 'shadow-[0_0_10px_rgba(249,115,22,0.12)]' : '',
    },
    {
      key: 'medium',
      label: 'Medium Severity',
      count: counts.medium,
      icon: <AlertCircle className="w-4 h-4 text-amber-400" />,
      colorClasses: 'text-amber-400',
      activeBorder: 'border-amber-500/60 bg-amber-950/20 ring-1 ring-amber-500/30',
      glow: '',
    },
    {
      key: 'low',
      label: 'Low / Informational',
      count: counts.low,
      icon: <Info className="w-4 h-4 text-sky-400" />,
      colorClasses: 'text-sky-400',
      activeBorder: 'border-sky-500/60 bg-sky-950/20 ring-1 ring-sky-500/30',
      glow: '',
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      {statItems.map((item) => {
        const isActive = selectedFilter === item.key;

        return (
          <button
            key={item.key}
            onClick={() => onSelectFilter(item.key)}
            className={`flex flex-col gap-1.5 p-3.5 rounded-xl border text-left transition-all duration-150 cursor-pointer ${
              isActive
                ? `${item.activeBorder} ${item.glow}`
                : 'bg-[#0b0d16] border-slate-800/80 hover:bg-[#101322] hover:border-slate-700/80'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-medium truncate">{item.label}</span>
              {item.icon}
            </div>
            <div className="flex items-baseline gap-1 mt-0.5">
              <AnimatedCounter
                value={item.count}
                duration={900}
                className={`text-2xl font-bold tracking-tight ${item.colorClasses}`}
              />
              <span className="text-[11px] text-slate-500 font-mono">issues</span>
            </div>
          </button>
        );
      })}
    </div>
  );
};
