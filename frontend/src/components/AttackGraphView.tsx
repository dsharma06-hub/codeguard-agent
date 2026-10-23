import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import {
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Shield,
  FileCode,
  Zap,
  ExternalLink,
  X,
} from 'lucide-react';
import type {
  AttackGraphData,
  AttackGraphNode,
  Finding,
  Severity,
} from '../types/finding';

interface AttackGraphViewProps {
  graph: AttackGraphData;
  findings: Finding[];
  selectedFindingId?: string;
  onSelectFinding: (findingId: string) => void;
  onSwitchToListView?: () => void;
}

interface SimNode extends d3.SimulationNodeDatum, AttackGraphNode {
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

interface SimEdge extends d3.SimulationLinkDatum<SimNode> {
  id: string;
  label: string;
  source: SimNode;
  target: SimNode;
}

const severityColors: Record<Severity, { border: string; bg: string; text: string; glow: string }> = {
  critical: {
    border: '#ef4444',
    bg: '#22080a',
    text: '#fca5a5',
    glow: 'rgba(239, 68, 68, 0.45)',
  },
  high: {
    border: '#f97316',
    bg: '#250f05',
    text: '#fdba74',
    glow: 'rgba(249, 115, 22, 0.4)',
  },
  medium: {
    border: '#eab308',
    bg: '#231804',
    text: '#fde047',
    glow: 'rgba(234, 179, 8, 0.35)',
  },
  low: {
    border: '#10b981',
    bg: '#041f17',
    text: '#6ee7b7',
    glow: 'rgba(16, 185, 129, 0.35)',
  },
  info: {
    border: '#3b82f6',
    bg: '#08172c',
    text: '#93c5fd',
    glow: 'rgba(59, 130, 246, 0.35)',
  },
};

export const AttackGraphView: React.FC<AttackGraphViewProps> = ({
  graph,
  findings,
  selectedFindingId,
  onSelectFinding,
  onSwitchToListView,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [activeNode, setActiveNode] = useState<AttackGraphNode | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<{ id: string; label: string } | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  // Find corresponding finding if activeNode is a vulnerability
  const activeFinding = useMemo(() => {
    if (!activeNode) return null;
    if (activeNode.type === 'vulnerability') {
      const rawId = activeNode.id.replace(/^vuln:/, '');
      return findings.find((f) => f.id === rawId || `vuln:${f.id}` === activeNode.id) || null;
    }
    return null;
  }, [activeNode, findings]);

  // Synchronize activeNode if selectedFindingId changes from parent
  useEffect(() => {
    if (selectedFindingId) {
      const matchNode = graph.nodes.find(
        (n) => n.id === selectedFindingId || n.id === `vuln:${selectedFindingId}`
      );
      if (matchNode) {
        setActiveNode(matchNode);
      }
    }
  }, [selectedFindingId, graph.nodes]);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 800;
    const height = containerRef.current.clientHeight || 560;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Setup SVG defs: Glow filters and Arrow Markers
    const defs = svg.append('defs');

    // Dot grid pattern
    defs
      .append('pattern')
      .attr('id', 'graph-grid')
      .attr('width', 28)
      .attr('height', 28)
      .attr('patternUnits', 'userSpaceOnUse')
      .append('circle')
      .attr('cx', 14)
      .attr('cy', 14)
      .attr('r', 0.9)
      .attr('fill', '#1e293b');

    // Directional Arrow Marker (standard)
    defs
      .append('marker')
      .attr('id', 'arrow-default')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 32)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L9,0L0,4')
      .attr('fill', '#64748b');

    // Directional Arrow Marker (highlighted)
    defs
      .append('marker')
      .attr('id', 'arrow-highlight')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 32)
      .attr('refY', 0)
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L9,0L0,4')
      .attr('fill', '#10b981');

    // Background rect to capture pan/zoom events
    const bgRect = svg
      .append('rect')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('fill', 'url(#graph-grid)')
      .style('cursor', 'grab');

    // Main graph group for pan/zoom
    const g = svg.append('g').attr('class', 'graph-container');

    // Configure zoom & pan
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.35, 2.5])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Prepare deep clones for simulation to avoid mutating props
    const simNodes: SimNode[] = graph.nodes.map((d) => ({ ...d }));
    const simEdges: SimEdge[] = graph.edges.map((d) => ({
      ...d,
      source: d.source as unknown as SimNode,
      target: d.target as unknown as SimNode,
    }));

    // Setup force simulation
    const simulation = d3
      .forceSimulation<SimNode>(simNodes)
      .force(
        'link',
        d3
          .forceLink<SimNode, SimEdge>(simEdges)
          .id((d) => d.id)
          .distance((d) => (d.label === 'flows into' ? 160 : 180))
      )
      .force('charge', d3.forceManyBody().strength(-550))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(48));

    // Draw Links
    const linkGroup = g.append('g').attr('class', 'links');
    const link = linkGroup
      .selectAll<SVGLineElement, SimEdge>('line')
      .data(simEdges)
      .enter()
      .append('line')
      .attr('stroke', '#334155')
      .attr('stroke-width', 2)
      .attr('stroke-dasharray', (d) => (d.label === 'flows into' ? '5,4' : 'none'))
      .attr('marker-end', 'url(#arrow-default)')
      .style('transition', 'stroke 0.2s, stroke-width 0.2s');

    // Draw Link Label Pills (visible on hover)
    const linkLabelsGroup = g.append('g').attr('class', 'link-labels');
    const linkLabel = linkLabelsGroup
      .selectAll<SVGGElement, SimEdge>('g')
      .data(simEdges)
      .enter()
      .append('g')
      .style('opacity', 0.4)
      .style('cursor', 'pointer')
      .on('mouseenter', (_, d) => {
        setHoveredEdge(d);
      })
      .on('mouseleave', () => {
        setHoveredEdge(null);
      });

    linkLabel
      .append('rect')
      .attr('rx', 6)
      .attr('ry', 6)
      .attr('fill', '#070913')
      .attr('stroke', '#334155')
      .attr('stroke-width', 1)
      .attr('height', 18);

    linkLabel
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '0.32em')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('fill', '#94a3b8')
      .text((d) => d.label);

    // Adjust rect dimensions based on text length
    linkLabel.each(function () {
      const textElem = d3.select(this).select('text').node() as SVGTextElement;
      if (textElem) {
        const textWidth = textElem.getComputedTextLength();
        d3.select(this)
          .select('rect')
          .attr('width', textWidth + 14)
          .attr('x', -(textWidth + 14) / 2)
          .attr('y', -9);
      }
    });

    // Draw Nodes
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const node = nodeGroup
      .selectAll<SVGGElement, SimNode>('g')
      .data(simNodes)
      .enter()
      .append('g')
      .attr('class', 'node-item')
      .style('cursor', 'pointer')
      .call(
        d3
          .drag<SVGGElement, SimNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
            bgRect.style('cursor', 'grabbing');
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
            bgRect.style('cursor', 'grab');
          })
      );

    // Node click handler: select node & notify parent
    node.on('click', (event, d) => {
      event.stopPropagation();
      setActiveNode(d);
      if (d.type === 'vulnerability') {
        const rawId = d.id.replace(/^vuln:/, '');
        onSelectFinding(rawId);
      }
    });

    // Deselect when clicking canvas background
    bgRect.on('click', () => {
      setActiveNode(null);
    });

    // Node Pulse Halo for selected node
    node
      .append('circle')
      .attr('r', 27)
      .attr('fill', 'none')
      .attr('stroke', (d) => {
        const isSelected = activeNode?.id === d.id;
        if (!isSelected) return 'none';
        if (d.type === 'source') return '#f59e0b';
        if (d.type === 'file') return '#38bdf8';
        const sev = d.severity || 'low';
        return severityColors[sev]?.border || '#ef4444';
      })
      .attr('stroke-width', 2.5)
      .attr('stroke-opacity', 0.8)
      .attr('class', 'animate-pulse');

    // Node Base Circle
    node
      .append('circle')
      .attr('r', 21)
      .attr('fill', (d) => {
        if (d.type === 'source') return '#291805';
        if (d.type === 'file') return '#0f172a';
        const sev = d.severity || 'low';
        return severityColors[sev]?.bg || '#22080a';
      })
      .attr('stroke', (d) => {
        if (d.type === 'source') return '#f59e0b';
        if (d.type === 'file') return '#38bdf8';
        const sev = d.severity || 'low';
        return severityColors[sev]?.border || '#ef4444';
      })
      .attr('stroke-width', 2.2)
      .style('filter', (d) => {
        if (d.type === 'source') return 'drop-shadow(0 0 8px rgba(245, 158, 11, 0.45))';
        if (d.type === 'file') return 'drop-shadow(0 0 6px rgba(56, 189, 248, 0.25))';
        const sev = d.severity || 'low';
        const glow = severityColors[sev]?.glow || 'rgba(239, 68, 68, 0.4)';
        return `drop-shadow(0 0 10px ${glow})`;
      });

    // Node Centered Icon (File, Zap for source, Shield for vuln)
    node.each(function (d) {
      const sel = d3.select(this);
      if (d.type === 'source') {
        // Lightning icon path for untrusted taint source
        sel
          .append('path')
          .attr('d', 'M13 2L3 14h9l-1 8 10-12h-9l1-8z')
          .attr('transform', 'translate(-11, -11) scale(0.9)')
          .attr('fill', '#f59e0b')
          .attr('pointer-events', 'none');
      } else if (d.type === 'file') {
        // Code file icon path
        sel
          .append('path')
          .attr(
            'd',
            'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M10 13l-2 2 2 2 M14 13l2 2-2 2'
          )
          .attr('transform', 'translate(-11, -11) scale(0.9)')
          .attr('fill', 'none')
          .attr('stroke', '#38bdf8')
          .attr('stroke-width', 2)
          .attr('stroke-linecap', 'round')
          .attr('stroke-linejoin', 'round')
          .attr('pointer-events', 'none');
      } else {
        // Shield icon path for vulnerabilities
        const sev = d.severity || 'low';
        const color = severityColors[sev]?.border || '#ef4444';
        sel
          .append('path')
          .attr('d', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z')
          .attr('transform', 'translate(-11, -11) scale(0.9)')
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', 2)
          .attr('stroke-linecap', 'round')
          .attr('stroke-linejoin', 'round')
          .attr('pointer-events', 'none');
      }
    });

    // Node Type Badge (Small pill under circle)
    const typeBadge = node.append('g').attr('transform', 'translate(0, 32)');

    typeBadge
      .append('rect')
      .attr('rx', 5)
      .attr('ry', 5)
      .attr('height', 15)
      .attr('fill', (d) => {
        if (d.type === 'source') return 'rgba(245, 158, 11, 0.15)';
        if (d.type === 'file') return 'rgba(56, 189, 248, 0.15)';
        const sev = d.severity || 'low';
        return severityColors[sev]?.bg || '#22080a';
      })
      .attr('stroke', (d) => {
        if (d.type === 'source') return 'rgba(245, 158, 11, 0.4)';
        if (d.type === 'file') return 'rgba(56, 189, 248, 0.3)';
        const sev = d.severity || 'low';
        return severityColors[sev]?.border || '#ef4444';
      })
      .attr('stroke-width', 1);

    typeBadge
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '10px')
      .attr('font-size', '8.5px')
      .attr('font-family', 'monospace')
      .attr('font-weight', '600')
      .attr('text-transform', 'uppercase')
      .attr('fill', (d) => {
        if (d.type === 'source') return '#f59e0b';
        if (d.type === 'file') return '#38bdf8';
        const sev = d.severity || 'low';
        return severityColors[sev]?.text || '#ef4444';
      })
      .text((d) => {
        if (d.type === 'source') return 'SOURCE';
        if (d.type === 'file') return 'FILE';
        return (d.severity || 'VULN').toUpperCase();
      });

    typeBadge.each(function () {
      const textElem = d3.select(this).select('text').node() as SVGTextElement;
      if (textElem) {
        const textWidth = textElem.getComputedTextLength();
        d3.select(this)
          .select('rect')
          .attr('width', textWidth + 10)
          .attr('x', -(textWidth + 10) / 2);
      }
    });

    // Node Primary Text Label
    node
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '58px')
      .attr('font-size', '11px')
      .attr('font-weight', '500')
      .attr('font-family', (d) => (d.type === 'vulnerability' ? 'sans-serif' : 'monospace'))
      .attr('fill', '#f1f5f9')
      .attr('paint-order', 'stroke')
      .attr('stroke', '#07080e')
      .attr('stroke-width', 4)
      .attr('stroke-linejoin', 'round')
      .text((d) => {
        if (d.label.length > 28) {
          return d.label.substring(0, 26) + '...';
        }
        return d.label;
      });

    // Simulation tick handler
    simulation.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x || 0)
        .attr('y1', (d) => d.source.y || 0)
        .attr('x2', (d) => d.target.x || 0)
        .attr('y2', (d) => d.target.y || 0);

      linkLabel.attr('transform', (d) => {
        const midX = ((d.source.x || 0) + (d.target.x || 0)) / 2;
        const midY = ((d.source.y || 0) + (d.target.y || 0)) / 2;
        return `translate(${midX}, ${midY})`;
      });

      node.attr('transform', (d) => `translate(${d.x || 0}, ${d.y || 0})`);
    });

    // Initial settle
    simulation.alpha(1).restart();

    return () => {
      simulation.stop();
    };
  }, [graph, activeNode?.id, onSelectFinding]);

  // Zoom control handlers
  const handleZoomIn = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 1.3);
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 0.7);
    }
  };

  const handleResetZoom = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current)
        .transition()
        .duration(350)
        .call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
    }
  };

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[620px] rounded-2xl border border-slate-800 bg-[#07080e] overflow-hidden flex flex-col select-none"
    >
      {/* Top Floating Header & Stats */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[#0c0e17]/90 border border-slate-800 backdrop-blur-md text-xs font-mono">
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
          </span>
          <span className="text-slate-300 font-semibold">{graph.nodes.length} Nodes</span>
          <span className="text-slate-600">·</span>
          <span className="text-slate-400">{graph.edges.length} Taint Edges</span>
        </div>

        {hoveredEdge && (
          <div className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-violet-950/80 border border-violet-500/40 text-xs font-mono text-violet-200 backdrop-blur-md animate-in fade-in duration-150">
            <Zap className="w-3.5 h-3.5 text-violet-400" />
            <span>Relationship: <strong>{hoveredEdge.label}</strong></span>
          </div>
        )}
      </div>

      {/* Floating Canvas Zoom Controls */}
      <div className="absolute top-4 right-4 z-10 flex items-center gap-1 bg-[#0c0e17]/90 border border-slate-800 rounded-xl p-1 backdrop-blur-md shadow-lg">
        <button
          type="button"
          onClick={handleZoomIn}
          title="Zoom in"
          className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800/80 rounded-lg transition-colors cursor-pointer"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={handleZoomOut}
          title="Zoom out"
          className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800/80 rounded-lg transition-colors cursor-pointer"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <div className="w-[1px] h-4 bg-slate-800 mx-0.5" />
        <button
          type="button"
          onClick={handleResetZoom}
          title="Reset view"
          className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800/80 rounded-lg transition-colors cursor-pointer"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* Main SVG Force Graph Canvas */}
      <svg ref={svgRef} className="w-full h-full block" />

      {/* Bottom Visual Legend */}
      <div className="absolute bottom-4 left-4 z-10 flex flex-wrap items-center gap-3 px-3.5 py-2 rounded-xl bg-[#0c0e17]/90 border border-slate-800 backdrop-blur-md text-[11px] font-mono text-slate-400">
        <span className="font-semibold text-slate-300">Legend:</span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-[0_0_6px_rgba(245,158,11,0.6)]" />
          <span>Untrusted Source</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.6)]" />
          <span>Critical Vuln</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-orange-500 shadow-[0_0_6px_rgba(249,115,22,0.6)]" />
          <span>High Vuln</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
          <span>Medium Vuln</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-sky-400 shadow-[0_0_6px_rgba(56,189,248,0.4)]" />
          <span>File Node</span>
        </span>
      </div>

      {/* Floating Node Detail Card when a node is selected */}
      {activeNode && (
        <div className="absolute right-4 bottom-4 z-20 w-80 max-w-[calc(100vw-32px)] p-4 rounded-xl border border-slate-700/80 bg-[#0c0e17]/95 shadow-2xl backdrop-blur-xl flex flex-col gap-3 animate-in fade-in zoom-in-95 duration-200">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              {activeNode.type === 'source' ? (
                <div className="p-1.5 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  <Zap className="w-4 h-4" />
                </div>
              ) : activeNode.type === 'file' ? (
                <div className="p-1.5 rounded-lg bg-sky-500/20 text-sky-400 border border-sky-500/30">
                  <FileCode className="w-4 h-4" />
                </div>
              ) : (
                <div
                  className="p-1.5 rounded-lg border"
                  style={{
                    backgroundColor: severityColors[activeNode.severity || 'low']?.bg,
                    borderColor: severityColors[activeNode.severity || 'low']?.border,
                    color: severityColors[activeNode.severity || 'low']?.border,
                  }}
                >
                  <Shield className="w-4 h-4" />
                </div>
              )}
              <div>
                <span className="text-[10px] uppercase font-mono tracking-wider font-semibold text-slate-400">
                  {activeNode.type === 'source'
                    ? 'Untrusted Taint Source'
                    : activeNode.type === 'file'
                    ? 'Source Code File'
                    : `${activeNode.severity?.toUpperCase()} Vulnerability`}
                </span>
                <h4 className="text-xs font-semibold text-slate-100 line-clamp-1">
                  {activeNode.label}
                </h4>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setActiveNode(null)}
              className="text-slate-500 hover:text-slate-300 p-1 rounded-lg hover:bg-slate-800/60 transition-colors cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          {activeFinding && (
            <>
              <p className="text-xs text-slate-300 leading-relaxed font-sans line-clamp-2">
                {activeFinding.description}
              </p>

              <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                <span>{activeFinding.filePath}</span>
                <span>:</span>
                <span className="text-slate-200">L{activeFinding.startLine}</span>
                {activeFinding.cwe && (
                  <span className="ml-auto px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-300">
                    {activeFinding.cwe}
                  </span>
                )}
              </div>

              {onSwitchToListView && (
                <button
                  type="button"
                  onClick={onSwitchToListView}
                  className="w-full mt-1 inline-flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-emerald-300 transition-colors cursor-pointer"
                >
                  <span>Inspect in Code Inspector</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </>
          )}

          {activeNode.type === 'file' && (
            <div className="text-xs text-slate-400 leading-relaxed">
              Target repository file participating in the attack graph.
            </div>
          )}

          {activeNode.type === 'source' && (
            <div className="text-xs text-slate-400 leading-relaxed">
              External attacker-controlled input source that flows into a sink without adequate sanitization.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
