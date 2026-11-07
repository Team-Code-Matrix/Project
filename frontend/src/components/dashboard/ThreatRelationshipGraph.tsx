import React, { useState, useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { ThreatGraphData, ThreatGraphNode } from '../../types/backend';
import {
  Network,
  Search,
  Filter,
  Globe2,
  Server,
  Lock,
  Cpu,
  ShieldAlert,
  Info,
  X,
} from 'lucide-react';

interface ThreatRelationshipGraphProps {
  graphData: ThreatGraphData;
}

export const ThreatRelationshipGraph: React.FC<ThreatRelationshipGraphProps> = ({ graphData }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [selectedNode, setSelectedNode] = useState<ThreatGraphNode | null>(null);

  // Convert ThreatGraphNode to ReactFlow Node
  const initialNodes: Node[] = useMemo(() => {
    const layoutPositions: Record<string, { x: number; y: number }> = {
      domain: { x: 300, y: 50 },
      ip: { x: 120, y: 220 },
      asn: { x: 120, y: 390 },
      certificate: { x: 500, y: 220 },
      ja4: { x: 300, y: 390 },
      threat_actor: { x: 500, y: 390 },
    };

    return graphData.nodes.map((n, index) => {
      const pos = layoutPositions[n.type] || { x: 200 + (index % 3) * 180, y: 100 + Math.floor(index / 3) * 140 };

      // Styling based on risk state
      let borderStyle = 'border-shield-border';
      let textStyle = 'text-shield-text-primary';
      let bgStyle = 'bg-[#080B09]/80 backdrop-blur-[4px]';

      if (n.riskState === 'malicious') {
        borderStyle = 'border-rose-500/70 shadow-[0_0_15px_rgba(217,120,120,0.3)]';
        textStyle = 'text-rose-300';
        bgStyle = 'bg-[#1C1214]/85 backdrop-blur-[4px]';
      } else if (n.riskState === 'suspicious') {
        borderStyle = 'border-amber-500/60';
        textStyle = 'text-amber-300';
        bgStyle = 'bg-[#1D1812]/85 backdrop-blur-[4px]';
      } else if (n.riskState === 'pki_compromised') {
        borderStyle = 'border-purple-500/70';
        textStyle = 'text-purple-300';
        bgStyle = 'bg-[#19121E]/85 backdrop-blur-[4px]';
      }

      return {
        id: n.id,
        position: { x: pos.x + (index % 2) * 40, y: pos.y },
        data: {
          raw: n,
          label: (
            <div className={`p-3 rounded-xl border ${borderStyle} ${bgStyle} font-mono text-xs select-none shadow-clay-card`}>
              <div className="flex items-center gap-1.5 text-[10px] uppercase text-shield-text-muted mb-1">
                <span className="w-2 h-2 rounded-full bg-shield-accent-light" />
                <span>{n.type.replace('_', ' ')}</span>
              </div>
              <div className={`font-bold ${textStyle} truncate max-w-[160px]`}>{n.label}</div>
              {n.subLabel && <div className="text-[10px] text-shield-text-muted truncate mt-0.5">{n.subLabel}</div>}
            </div>
          ),
        },
      };
    });
  }, [graphData.nodes]);

  // Convert ThreatGraphEdge to ReactFlow Edge
  const initialEdges: Edge[] = useMemo(() => {
    return graphData.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: true,
      style: { stroke: '#367055', strokeWidth: 1.5 },
      labelStyle: { fill: '#79A98B', fontSize: 10, fontFamily: 'monospace' },
      labelBgStyle: { fill: '#0B100E', fillOpacity: 0.8 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#79A98B',
      },
    }));
  }, [graphData.edges]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  const onNodeClick = useCallback(
    (_: any, node: Node) => {
      const raw = (node.data as any)?.raw as ThreatGraphNode;
      setSelectedNode(raw || null);
    },
    []
  );

  return (
    <div className="clay-card rounded-3xl p-6 md:p-8 space-y-6 text-left border border-shield-border/80">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-shield-border/60">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-[#2A2111]/80 border border-[#F3D081]/30 text-[#F3D081]">
            <Network className="w-5 h-5 text-[#F3D081]" />
          </div>
          <div>
            <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Threat Relationship Graph
            </h2>
            <p className="text-xs text-shield-text-secondary mt-0.5">
              Multi-hop STIX 2.1 graph topology linking domains, IPs, ASNs, TLS certificates & actor infrastructure
            </p>
          </div>
        </div>

        {/* Filter / Search Bar */}
        <div className="flex items-center gap-2">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-shield-surface border border-shield-border text-xs font-mono text-shield-text-secondary outline-none cursor-pointer"
          >
            <option value="all">All Entities ({graphData.nodes.length})</option>
            <option value="domain">Domains</option>
            <option value="ip">IP Addresses</option>
            <option value="asn">Autonomous Systems</option>
            <option value="certificate">TLS Certificates</option>
            <option value="threat_actor">Threat Actors</option>
          </select>
        </div>
      </div>

      {/* Main Graph Canvas & Inspector Drawer */}
      <div className="relative w-full h-[460px] rounded-2xl bg-[#080D0A]/70 backdrop-blur-[2px] border border-shield-border/70 overflow-hidden">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          fitView
          attributionPosition="bottom-left"
          className="bg-transparent"
        >
          <Background color="#1A2920" gap={20} size={1} />
          <Controls className="bg-shield-surface border border-shield-border text-shield-text-primary rounded-xl fill-shield-text-primary" />
        </ReactFlow>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 z-20 w-80 p-5 rounded-2xl glass-panel-elevated border border-shield-border shadow-2xl font-mono text-xs space-y-3 animate-fadeIn">
            <div className="flex items-center justify-between border-b border-shield-border/40 pb-2">
              <span className="text-[10px] uppercase font-bold text-shield-accent-light">
                {selectedNode.type} Entity Inspector
              </span>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="p-1 rounded-lg text-shield-text-muted hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <div className="text-sm font-bold text-shield-text-primary truncate">
                {selectedNode.label}
              </div>
              {selectedNode.subLabel && (
                <div className="text-xs text-shield-text-muted truncate mt-0.5">
                  {selectedNode.subLabel}
                </div>
              )}
            </div>

            {selectedNode.details && (
              <div className="pt-2 border-t border-shield-border/30 space-y-1.5 text-shield-text-secondary">
                {Object.entries(selectedNode.details).map(([key, val]) => (
                  <div key={key} className="flex justify-between text-[11px]">
                    <span className="text-shield-text-muted capitalize">{key}:</span>
                    <span className="text-shield-text-primary truncate max-w-[140px]">{String(val)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="text-xs font-mono text-shield-text-muted flex flex-wrap items-center justify-between gap-2 pt-2">
        <span>Click any node to inspect telemetry attributes. Drag or zoom to explore the infrastructure graph.</span>
        <span className="text-[#F3D081]">Graph Engine: STIX 2.1 Graph Normalizer</span>
      </div>
    </div>
  );
};

