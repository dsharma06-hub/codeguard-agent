import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RotateCw, ArrowLeft, Terminal } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackTitle?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public override state: ErrorBoundaryState = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  public override componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('[CodeGuard ErrorBoundary] Uncaught runtime fault:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = (): void => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  private handleReload = (): void => {
    window.location.reload();
  };

  private handleGoHome = (): void => {
    window.location.href = '/ingest';
  };

  public override render(): ReactNode {
    if (this.state.hasError) {
      const errorMsg = this.state.error?.message || 'Unknown application error';
      const stack = this.state.error?.stack || this.state.errorInfo?.componentStack || '';

      return (
        <div className="min-h-screen bg-[#07080e] text-slate-100 flex items-center justify-center p-4 sm:p-6 font-sans">
          <div className="w-full max-w-2xl bg-[#0c0e17] border border-rose-500/40 rounded-2xl shadow-[0_0_40px_rgba(244,63,94,0.15)] p-6 sm:p-8 flex flex-col gap-6 relative overflow-hidden">
            {/* Ambient Background Glow */}
            <div className="absolute -top-24 -right-24 w-64 h-64 bg-rose-500/10 rounded-full blur-3xl pointer-events-none" />
            <div className="absolute -bottom-24 -left-24 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

            {/* Header Badge & Title */}
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 rounded-xl bg-rose-950/60 border border-rose-500/40 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(244,63,94,0.3)]">
                <AlertTriangle className="w-6 h-6 text-rose-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] uppercase tracking-widest text-rose-400 bg-rose-950/80 px-2 py-0.5 rounded border border-rose-500/30">
                    RUNTIME SYSTEM FAULT
                  </span>
                  <span className="font-mono text-xs text-slate-600">|</span>
                  <span className="font-mono text-xs text-slate-400">ERROR BOUNDARY INTERCEPT</span>
                </div>
                <h2 className="text-xl font-bold text-slate-100 mt-1">
                  {this.props.fallbackTitle || 'Application Render Fault Detected'}
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  A component encountered an unhandled exception. The error boundary caught it to prevent an application crash.
                </p>
              </div>
            </div>

            {/* Error Message Monospace Terminal Box */}
            <div className="bg-[#05060a] border border-slate-800 rounded-xl p-4 flex flex-col gap-2 font-mono text-xs">
              <div className="flex items-center gap-2 text-slate-500 pb-2 border-b border-slate-800/80">
                <Terminal className="w-3.5 h-3.5 text-rose-400" />
                <span className="text-slate-400 font-semibold">Diagnostic Exception Trace</span>
              </div>
              <div className="text-rose-300 font-medium whitespace-pre-wrap break-all leading-relaxed">
                {errorMsg}
              </div>
              {stack && (
                <details className="mt-2 text-[11px] text-slate-500 cursor-pointer">
                  <summary className="hover:text-slate-400 transition-colors">
                    View Callstack Details
                  </summary>
                  <pre className="mt-2 p-2 rounded bg-black/50 border border-slate-900 text-slate-400 overflow-x-auto max-h-48 whitespace-pre font-mono leading-tight">
                    {stack}
                  </pre>
                </details>
              )}
            </div>

            {/* Cyberpunk Action Buttons */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <button
                type="button"
                onClick={this.handleGoHome}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-slate-900/80 text-slate-300 border border-slate-700 hover:bg-slate-800 hover:text-white transition-all cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Return to Ingest
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={this.handleReset}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800/80 text-slate-200 border border-slate-700 hover:bg-slate-700 transition-all cursor-pointer"
                >
                  <RotateCw className="w-3.5 h-3.5" />
                  Try Again
                </button>
                <button
                  type="button"
                  onClick={this.handleReload}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 hover:border-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all cursor-pointer"
                >
                  Reload Page
                </button>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
