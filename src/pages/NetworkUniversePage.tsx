import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { GlassPanel } from '../components/common/GlassPanel';
import { NetworkUniverse } from '../components/network/NetworkUniverse';
import { formatBytes, formatShortTime } from '../utils/formatters';
import type { ProtocolName } from '../core/types';

export const NetworkUniversePage: React.FC = () => {
  const { topology, alerts, selectedNodeIp, setSelectedNodeIp, settings } = useApp();
  const [protoFilter, setProtoFilter] = useState<ProtocolName | 'ALL'>('ALL');

  const visibleNodes =
    protoFilter === 'ALL'
      ? topology.nodes
      : topology.nodes.filter((n) => n.protocols.includes(protoFilter));

  const visibleEdges =
    protoFilter === 'ALL'
      ? topology.edges
      : topology.edges.filter((e) => e.protocols.includes(protoFilter));

  return (
    <div className="space-y-6">
      <NetworkUniverse
        nodes={visibleNodes}
        edges={visibleEdges}
        alerts={alerts}
        selectedNodeIp={selectedNodeIp}
        onSelectNode={setSelectedNodeIp}
        protocolFilter={protoFilter}
        onProtocolFilterChange={setProtoFilter}
        reducedMotion={settings.reducedMotion}
        heightClass="h-[580px]"
      />

      <GlassPanel
        title="Observed Endpoint Directory"
        subtitle="Derived strictly from captured network flows (unknown identities labeled Unknown Endpoint)"
      >
        <div className="overflow-x-auto border border-slate-800/80 rounded-lg">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#080510] border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3 font-medium">IP Address</th>
                <th className="py-2.5 px-3 font-medium">Category</th>
                <th className="py-2.5 px-3 font-medium text-right">Packets</th>
                <th className="py-2.5 px-3 font-medium text-right">Traffic Volume</th>
                <th className="py-2.5 px-3 font-medium">Protocols</th>
                <th className="py-2.5 px-3 font-medium">Alerts</th>
                <th className="py-2.5 px-3 font-medium">Last Observed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {visibleNodes.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No observed endpoints match the current filter.
                  </td>
                </tr>
              ) : (
                visibleNodes.map((node) => (
                  <tr
                    key={node.ip}
                    onClick={() => setSelectedNodeIp(node.ip)}
                    className={`cursor-pointer transition-colors ${
                      selectedNodeIp === node.ip ? 'bg-[#00E5FF]/10' : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-2 px-3 text-[#00E5FF] font-semibold">{node.ip}</td>
                    <td className="py-2 px-3 text-slate-300 font-sans capitalize">
                      {node.category === 'unknown' ? 'Unknown Endpoint' : node.category}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-200 tabular-nums">
                      {node.packetCount}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-300 tabular-nums">
                      {formatBytes(node.byteVolume)}
                    </td>
                    <td className="py-2 px-3 text-slate-400">{node.protocols.join(' · ')}</td>
                    <td className={`py-2 px-3 tabular-nums ${node.alertCount > 0 ? 'text-[#FF3B5C] font-semibold' : 'text-slate-500'}`}>
                      {node.alertCount}
                    </td>
                    <td className="py-2 px-3 text-slate-400 tabular-nums">
                      {formatShortTime(node.lastSeen)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </GlassPanel>
    </div>
  );
};
