import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Terminal,
  Activity,
  Bot,
  Brain,
  ShieldCheck,
  Wrench,
  Radio,
  Clock,
  Filter,
} from 'lucide-react';
import type { AgentTraceEvent } from '../types/finding';
import { getAgentTraceEventSource } from '../services/api';

interface AgentTracePanelProps {
  scanId?: string;
  initialTrace?: AgentTraceEvent[];
}

const agentConfig: Record<
  string,
  { label: string; icon: React.ReactNode; color: string; badge: string }
> = {
  Orchestrator: {
    label: 'Orchestrator',
    icon: <Bot className="w-3.5 h-3.5 text-purple-400" />,
    color: 'border-purple-500/40 text-purple-300',
    badge: 'bg-purple-950/60 text-purple-300 border-purple-800/60',
  },
  Planner: {
    label: 'Planner Agent',
    icon: <Brain className="w-3.5 h-3.5 text-cyan-400" />,
    color: 'border-cyan-500/40 text-cyan-300',
    badge: 'bg-cyan-950/60 text-cyan-300 border-cyan-800/60',
  },
  Verifier: {
    label: 'Verifier Agent',
    icon: <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />,
    color: 'border-amber-500/40 text-amber-300',
    badge: 'bg-amber-950/60 text-amber-300 border-amber-800/60',
  },
  FixAgent: {
    label: 'Fix Agent',
    icon: <Wrench className="w-3.5 h-3.5 text-emerald-400" />,
    color: 'border-emerald-500/40 text-emerald-300',
    badge: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60',
  },
};

export const AgentTracePanel: React.FC<AgentTracePanelProps> = ({
  scanId,
  initialTrace = [],
}) => {
  const [events, setEvents] = useState<AgentTraceEvent[]>(initialTrace);
  const [selectedAgent, setSelectedAgent] = useState<string>('all');
  const [isLive, setIsLive] = useState<boolean>(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Synchronize initialTrace
  useEffect(() => {
    if (initialTrace.length > 0) {
      setEvents((prev) => {
        const existingKeys = new Set(prev.map((e) => `${e.timestamp}-${e.step}-${e.agent}`));
        const newOnes = initialTrace.filter(
          (e) => !existingKeys.has(`${e.timestamp}-${e.step}-${e.agent}`)
        );
        return [...prev, ...newOnes];
      });
    }
  }, [initialTrace]);

  // Connect to SSE stream if scanId is provided
  useEffect(() => {
    if (!scanId) return;

    let eventSource: EventSource | null = null;
    try {
      eventSource = getAgentTraceEventSource(scanId);
      setIsLive(true);

      eventSource.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          if (data && data.agent) {
            setEvents((prev) => [...prev, data]);
          }
        } catch {
          // Ignore keep-alive or ping comments
        }
      };

      eventSource.addEventListener('trace', (msg: MessageEvent) => {
        try {
          const data = JSON.parse(msg.data);
          if (data && data.agent) {
            setEvents((prev) => [...prev, data]);
          }
        } catch {}
      });

      eventSource.onerror = () => {
        setIsLive(false);
        eventSource?.close();
      };
    } catch {
      setIsLive(false);
    }

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, [scanId]);

  // Filter events by agent
  const filteredEvents = events.filter((ev) => {
    if (selectedAgent === 'all') return true;
    return ev.agent.toLowerCase() === selectedAgent.toLowerCase();
  });

  const agentCounts = {
    all: events.length,
    Orchestrator: events.filter((e) => e.agent === 'Orchestrator').length,
    Planner: events.filter((e) => e.agent === 'Planner').length,
    Verifier: events.filter((e) => e.agent === 'Verifier').length,
    FixAgent: events.filter((e) => e.agent === 'FixAgent').length,
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Trace Control Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl bg-[#0c0e17] border border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
            <Activity className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-slate-100">
                Agent Reasoning & Function Calling Trace
              </h3>
              {isLive ? (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/40 text-[10px] text-emerald-300 font-mono">
                  <Radio className="w-2.5 h-2.5 text-emerald-400 animate-pulse" />
                  Live SSE Stream
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-[10px] text-slate-400 font-mono">
                  <Clock className="w-2.5 h-2.5 text-slate-500" />
                  Historical Trace ({events.length} events)
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Real-time audit log of Gemini tool invocations, ReAct rescan loops, and verifier decisions.
            </p>
          </div>
        </div>

        {/* Agent Filter Chips */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-500 mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3" /> Filter:
          </span>
          {(['all', 'Orchestrator', 'Planner', 'Verifier', 'FixAgent'] as const).map((agentKey) => (
            <button
              key={agentKey}
              type="button"
              onClick={() => setSelectedAgent(agentKey)}
              className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                selectedAgent === agentKey
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-[0_0_10px_rgba(16,185,129,0.15)] font-semibold'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
            >
              {agentKey === 'all' ? 'All' : agentKey} ({agentCounts[agentKey] || 0})
            </button>
          ))}
        </div>
      </div>

      {/* Trace Timeline List */}
      <div
        ref={scrollRef}
        className="flex flex-col gap-3 min-h-[500px] max-h-[720px] overflow-y-auto pr-1"
      >
        {filteredEvents.length === 0 ? (
          <div className="h-96 flex flex-col items-center justify-center p-8 rounded-xl border border-slate-800/80 bg-[#0c0e17] text-center">
            <Terminal className="w-10 h-10 text-slate-700 mb-3" />
            <h4 className="text-sm font-semibold text-slate-300">No Agent Trace Events Recorded</h4>
            <p className="text-xs text-slate-500 mt-1 max-w-sm">
              Trigger a scan from the Ingest page to stream real-time Planner function calls, Verifier verdicts, and Fix Agent ReAct loops.
            </p>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {filteredEvents.map((ev, index) => {
              const cfg = agentConfig[ev.agent] || {
                label: ev.agent,
                icon: <Bot className="w-3.5 h-3.5 text-slate-400" />,
                color: 'border-slate-700 text-slate-300',
                badge: 'bg-slate-900 text-slate-300 border-slate-800',
              };

              const timeDisplay = ev.timestamp
                ? new Date(ev.timestamp).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  })
                : `#${index + 1}`;

              return (
                <motion.div
                  key={`${ev.timestamp}-${index}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.15 }}
                  className={`p-4 rounded-xl bg-[#0c0e17] border ${cfg.color} transition-all hover:bg-[#111422] flex flex-col gap-2.5`}
                >
                  {/* Event Header */}
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-xs font-mono font-medium ${cfg.badge}`}
                      >
                        {cfg.icon}
                        {cfg.label}
                      </span>
                      <span className="font-mono text-xs font-semibold text-slate-200">
                        {ev.step.replace(/_/g, ' ')}
                      </span>
                      {ev.tool && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-400">
                          tool: {ev.tool}
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">{timeDisplay}</span>
                  </div>

                  {/* Input / Context Summary */}
                  {ev.input_summary && (
                    <div className="text-xs font-mono bg-slate-950/80 border border-slate-900 rounded-lg p-2.5 text-slate-300 leading-relaxed overflow-x-auto">
                      <span className="text-slate-500 font-semibold select-none mr-2">INPUT:</span>
                      {ev.input_summary}
                    </div>
                  )}

                  {/* Output / Action Summary */}
                  {ev.output_summary && (
                    <div className="text-xs font-mono bg-[#070913] border border-slate-900/90 rounded-lg p-2.5 text-emerald-300/90 leading-relaxed overflow-x-auto">
                      <span className="text-slate-500 font-semibold select-none mr-2">OUTPUT:</span>
                      {ev.output_summary}
                    </div>
                  )}
                </motion.div>
              );
            })}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
};
