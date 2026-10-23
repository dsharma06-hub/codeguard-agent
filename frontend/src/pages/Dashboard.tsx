import { useState, useMemo, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import {
  Search,
  ShieldCheck,
  ArrowUpDown,
  CheckCircle,
  Sparkles,
  Network,
  LayoutList,
  Wrench,
  Activity,
} from 'lucide-react';
import { Header } from '../components/Header';
import { SeverityStats } from '../components/SeverityStats';
import { FindingCard } from '../components/FindingCard';
import { CodeSnippet } from '../components/CodeSnippet';
import { AttackGraphView } from '../components/AttackGraphView';
import { AgentTracePanel } from '../components/AgentTracePanel';
import { FixReviewPanel } from '../components/FixReviewPanel';
import { mockScanMetadata, mockFindings } from '../mocks/findings';
import { mockAttackGraph } from '../mocks/graph';
import type { Severity, Finding, ScanMetadata, AttackGraphData, ProposedFix, AgentTraceEvent } from '../types/finding';

const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const Dashboard: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const [viewMode, setViewMode] = useState<'list' | 'graph' | 'fixes' | 'trace'>('list');

  const isRealScan = Boolean(location.state?.findings && Array.isArray(location.state.findings));

  // Use real findings if present from router state, else fallback to mock findings demo
  const findings: Finding[] = useMemo(() => {
    if (isRealScan) {
      return location.state.findings;
    }
    return mockFindings;
  }, [isRealScan, location.state?.findings]);

  // Dynamic metadata matching real scan if present, or repoSource, or fallback to mock metadata
  const scanMetadata: ScanMetadata = useMemo(() => {
    if (location.state?.metadata) {
      return location.state.metadata;
    }
    if (location.state?.repoSource) {
      return {
        ...mockScanMetadata,
        repoName: location.state.repoSource,
      };
    }
    return mockScanMetadata;
  }, [location.state?.metadata, location.state?.repoSource]);

  // Attack graph data from scan result or fallback to mock attack graph
  const graph: AttackGraphData = useMemo(() => {
    if (location.state?.graph && location.state.graph.nodes && location.state.graph.edges) {
      return location.state.graph;
    }
    return mockAttackGraph;
  }, [location.state?.graph]);

  // Agent fixes and trace
  const [fixes, setFixes] = useState<ProposedFix[]>(() => {
    return Array.isArray(location.state?.fixes) ? location.state.fixes : [];
  });

  const agentTrace: AgentTraceEvent[] = useMemo(() => {
    return Array.isArray(location.state?.agentTrace) ? location.state.agentTrace : [];
  }, [location.state?.agentTrace]);

  const pendingFixesCount = useMemo(() => {
    return fixes.filter((f) => f.status === 'pending').length;
  }, [fixes]);

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilter, setSelectedFilter] = useState<Severity | 'all'>('all');
  const [selectedFindingId, setSelectedFindingId] = useState<string>(
    findings[0]?.id || ''
  );

  // Synchronize selectedFindingId when findings change
  useEffect(() => {
    if (findings.length > 0) {
      setSelectedFindingId((prev) => {
        const match = findings.some((f) => f.id === prev);
        return match ? prev : findings[0].id;
      });
    } else {
      setSelectedFindingId('');
    }
  }, [findings]);

  useEffect(() => {
    if (location.state?.scanCompleted) {
      toast.success(`Analysis complete — ${findings.length} findings detected`, {
        description: isRealScan
          ? `Real static scan of ${scanMetadata.repoName} completed.`
          : 'Severity-ranked report and attack paths are ready to inspect.',
        icon: <CheckCircle className="w-4 h-4 text-emerald-400" />,
        duration: 4000,
      });
    }
  }, [location.state?.scanCompleted, findings.length, isRealScan, scanMetadata.repoName]);

  // Filter & sort findings: critical first, then matching search & category
  const filteredFindings = useMemo(() => {
    return [...findings]
      .sort((a, b) => severityRank[a.severity] - severityRank[b.severity])
      .filter((finding) => {
        // Severity filter
        if (selectedFilter !== 'all') {
          if (selectedFilter === 'low') {
            if (finding.severity !== 'low' && finding.severity !== 'info') {
              return false;
            }
          } else if (finding.severity !== selectedFilter) {
            return false;
          }
        }

        // Search query filter
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchTitle = finding.title.toLowerCase().includes(q);
          const matchPath = finding.filePath.toLowerCase().includes(q);
          const matchDesc = finding.description.toLowerCase().includes(q);
          const matchCwe = finding.cwe?.toLowerCase().includes(q);
          const matchCat =
            finding.category.toLowerCase().includes(q) ||
            ((finding.title.toLowerCase().includes('cross-site') || finding.title.toLowerCase().includes('xss')) &&
              (q.includes('xss') || q.includes('cross-site') || q.includes('scripting')));

          if (!matchTitle && !matchPath && !matchDesc && !matchCwe && !matchCat) {
            return false;
          }
        }

        return true;
      });
  }, [findings, searchQuery, selectedFilter]);

  // Active selected finding
  const activeFinding = useMemo(() => {
    return (
      filteredFindings.find((f) => f.id === selectedFindingId) ||
      filteredFindings[0] ||
      null
    );
  }, [filteredFindings, selectedFindingId]);

  return (
    <div className="min-h-screen flex flex-col bg-[#07080e] text-slate-100">
      {/* Top Application Header */}
      <Header metadata={scanMetadata} isDemo={!isRealScan} />

      {/* Main Workspace Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 flex flex-col gap-6">
        {/* Demo / Sample Notice Banner (only shown if not a real scan) */}
        {!isRealScan && (
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 px-4 py-2.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs text-amber-200 font-mono">
            <div className="flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span>You are viewing sample demo data. Upload your own repository archive to run a live scan.</span>
            </div>
            <button
              type="button"
              onClick={() => navigate('/ingest')}
              className="text-emerald-400 hover:text-emerald-300 font-semibold underline underline-offset-2 shrink-0 cursor-pointer"
            >
              Upload .zip &rarr;
            </button>
          </div>
        )}

        {/* Severity Metrics Row */}
        <section aria-label="Scan Summary Statistics">
          <SeverityStats
            findings={findings}
            selectedFilter={selectedFilter}
            onSelectFilter={setSelectedFilter}
          />
        </section>

        {/* View Mode & Filter Toolbar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 flex-1 max-w-2xl">
            {/* View Mode Switch: List View, Attack Graph, Fix Review, Agent Trace */}
            <div className="inline-flex items-center p-1 bg-[#0c0e17] border border-slate-800 rounded-xl shrink-0 self-start sm:self-auto flex-wrap gap-1">
              <button
                type="button"
                onClick={() => setViewMode('list')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                  viewMode === 'list'
                    ? 'bg-slate-800 text-white shadow-sm font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <LayoutList className="w-3.5 h-3.5" />
                <span>List View</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('graph')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                  viewMode === 'graph'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.2)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Network className="w-3.5 h-3.5 text-emerald-400" />
                <span>Attack Graph</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('fixes')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                  viewMode === 'fixes'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.2)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Wrench className="w-3.5 h-3.5 text-emerald-400" />
                <span>Fix Review</span>
                {pendingFixesCount > 0 ? (
                  <span className="ml-0.5 px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] font-mono">
                    {pendingFixesCount}
                  </span>
                ) : fixes.length > 0 ? (
                  <span className="ml-0.5 px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300 text-[10px] font-mono">
                    {fixes.length}
                  </span>
                ) : null}
              </button>
              <button
                type="button"
                onClick={() => setViewMode('trace')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                  viewMode === 'trace'
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30 shadow-[0_0_12px_rgba(168,85,247,0.2)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Activity className="w-3.5 h-3.5 text-purple-400" />
                <span>Agent Trace</span>
                {agentTrace.length > 0 && (
                  <span className="ml-0.5 px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300 text-[10px] font-mono">
                    {agentTrace.length}
                  </span>
                )}
              </button>
            </div>

            {/* Search Input (List view filter) */}
            {viewMode === 'list' && (
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search findings by title, file path, CWE..."
                  className="w-full pl-10 pr-4 py-2 bg-[#0c0e17] border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/30 transition-all font-sans"
                />
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            {viewMode === 'list' ? (
              <>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
                  <ArrowUpDown className="w-3.5 h-3.5 text-slate-500" />
                  <span>Ranked: Critical first</span>
                </span>
                <span className="text-slate-500">|</span>
                <span>
                  Showing <strong className="text-slate-200">{filteredFindings.length}</strong> of{' '}
                  {findings.length}
                </span>
              </>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
                <Network className="w-3.5 h-3.5 text-emerald-400" />
                <span>Interactive Force-Directed Graph</span>
              </span>
            )}
          </div>
        </div>

        {/* View Mode Switching Area */}
        {viewMode === 'list' ? (
          /* Master-Detail Split Layout */
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left Column: Staggered Findings List (5 cols on lg) */}
            <div className="lg:col-span-5 flex flex-col gap-3">
              {filteredFindings.length === 0 ? (
                <div className="p-8 rounded-xl border border-slate-800/80 bg-[#0c0e17] text-center">
                  <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                  <h4 className="text-sm font-semibold text-slate-200">No findings match filter</h4>
                  <p className="text-xs text-slate-500 mt-1">
                    Try clearing your search query or switching to &quot;Total Findings&quot;.
                  </p>
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      setSelectedFilter('all');
                    }}
                    className="mt-3 px-3 py-1.5 text-xs text-emerald-400 hover:text-emerald-300 font-medium cursor-pointer"
                  >
                    Reset Filters
                  </button>
                </div>
              ) : (
                filteredFindings.map((finding, index) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    index={index}
                    isSelected={activeFinding?.id === finding.id}
                    onSelect={() => setSelectedFindingId(finding.id)}
                  />
                ))
              )}
            </div>

            {/* Right Column: Code Snippet & Remediation Inspector (7 cols on lg) */}
            <div className="lg:col-span-7 sticky top-20">
              <CodeSnippet finding={activeFinding} />
            </div>
          </div>
        ) : viewMode === 'graph' ? (
          /* Attack Graph Visualization View */
          <AttackGraphView
            graph={graph}
            findings={findings}
            selectedFindingId={selectedFindingId}
            onSelectFinding={setSelectedFindingId}
            onSwitchToListView={() => setViewMode('list')}
          />
        ) : viewMode === 'fixes' ? (
          /* Human-in-the-Loop Fix Review Panel */
          <FixReviewPanel
            fixes={fixes}
            scanId={scanMetadata.scanId}
            onFixUpdated={(updatedFix) => {
              setFixes((prev) => prev.map((f) => (f.id === updatedFix.id ? updatedFix : f)));
            }}
            onFixesLoaded={(loadedFixes) => {
              setFixes(loadedFixes);
            }}
          />
        ) : (
          /* Agent Function Calling & Reasoning Trace */
          <AgentTracePanel
            scanId={scanMetadata.scanId}
            initialTrace={agentTrace}
          />
        )}
      </main>
    </div>
  );
};
