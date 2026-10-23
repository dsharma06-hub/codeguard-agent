import type { Severity } from '../types/finding';

interface SeverityBadgeProps {
  severity: Severity;
  showDot?: boolean;
  size?: 'sm' | 'md';
}

const severityConfig: Record<
  Severity,
  {
    label: string;
    bg: string;
    text: string;
    border: string;
    dotBg: string;
    glow: string;
    pulse: boolean;
  }
> = {
  critical: {
    label: 'Critical',
    bg: 'bg-red-950/40',
    text: 'text-red-400',
    border: 'border-red-500/30',
    dotBg: 'bg-red-500',
    glow: 'shadow-[0_0_10px_rgba(239,68,68,0.25)]',
    pulse: true,
  },
  high: {
    label: 'High',
    bg: 'bg-orange-950/40',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
    dotBg: 'bg-orange-500',
    glow: 'shadow-[0_0_8px_rgba(249,115,22,0.2)]',
    pulse: true,
  },
  medium: {
    label: 'Medium',
    bg: 'bg-amber-950/30',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
    dotBg: 'bg-amber-400',
    glow: '',
    pulse: false,
  },
  low: {
    label: 'Low',
    bg: 'bg-sky-950/30',
    text: 'text-sky-400',
    border: 'border-sky-500/30',
    dotBg: 'bg-sky-400',
    glow: '',
    pulse: false,
  },
  info: {
    label: 'Info',
    bg: 'bg-slate-900/60',
    text: 'text-slate-400',
    border: 'border-slate-700/50',
    dotBg: 'bg-slate-400',
    glow: '',
    pulse: false,
  },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  showDot = true,
  size = 'md',
}) => {
  const normalizedKey = (severity ? String(severity).toLowerCase() : 'info') as Severity;
  const config = severityConfig[normalizedKey] || severityConfig.info;
  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-[11px]'
      : 'px-2.5 py-1 text-xs font-medium tracking-wide';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border font-mono uppercase transition-all duration-200 ${config.bg} ${config.text} ${config.border} ${config.glow} ${sizeClasses}`}
    >
      {showDot && (
        <span className="relative flex h-2 w-2">
          {config.pulse && (
            <span
              className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${config.dotBg}`}
            />
          )}
          <span
            className={`relative inline-flex h-2 w-2 rounded-full ${config.dotBg}`}
          />
        </span>
      )}
      {config.label}
    </span>
  );
};
