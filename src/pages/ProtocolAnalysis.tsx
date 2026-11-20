import React from 'react';
import { useApp } from '../context/AppContext';
import { GlassPanel } from '../components/common/GlassPanel';
import { TrafficCharts } from '../components/traffic/TrafficCharts';
import { formatBytes, getProtocolColor } from '../utils/formatters';
import type { ProtocolName } from '../core/types';

export const ProtocolAnalysis: React.FC = () => {
  const { stats, packets, settings } = useApp();

  const dnsPackets = packets.filter((p) => p.protocol === 'DNS');
  const protoEntries = stats
    ? (Object.entries(stats.protocolDistribution) as [ProtocolName, number][]).filter(
        ([, count]) => count > 0,
      )
    : [];
  const total = stats?.totalPackets || 1;

  return (
    <div className="space-y-6">
      <TrafficCharts stats={stats} reducedMotion={settings.reducedMotion} mode="full" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <GlassPanel
          title="Protocol Layer Breakdown"
          subtitle="Application-aware classification (DNS prioritized over raw UDP/TCP)"
        >
          <div className="space-y-3">
            {protoEntries.length === 0 ? (
              <p className="text-xs text-slate-500 py-6 text-center">No protocol counts recorded yet.</p>
            ) : (
              protoEntries.map(([proto, count]) => {
                const pct = ((count / total) * 100).toFixed(1);
                return (
                  <div key={proto} className="space-y-1 text-xs">
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-semibold" style={{ color: getProtocolColor(proto) }}>
                        {proto}
                      </span>
                      <span className="text-slate-300 tabular-nums">
                        {count} pkts ({pct}%)
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-[#080510] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${pct}%`,
                          backgroundColor: getProtocolColor(proto),
                        }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </GlassPanel>

        <GlassPanel
          title="Top Ports & DNS Activity"
          subtitle="Observed service ports and DNS query metadata"
        >
          <div className="overflow-x-auto border border-slate-800 rounded-lg mb-4">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="bg-[#080510] border-b border-slate-800 text-slate-400 font-sans">
                  <th className="py-2 px-3">Port</th>
                  <th className="py-2 px-3">Service</th>
                  <th className="py-2 px-3 text-right">Packets</th>
                  <th className="py-2 px-3 text-right">Bytes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {(stats?.topPorts ?? []).slice(0, 6).map((p) => (
                  <tr key={p.port}>
                    <td className="py-2 px-3 text-[#00E5FF]">{p.port}</td>
                    <td className="py-2 px-3 text-slate-300">{p.service}</td>
                    <td className="py-2 px-3 text-right tabular-nums">{p.packets}</td>
                    <td className="py-2 px-3 text-right tabular-nums text-slate-400">
                      {formatBytes(p.bytes)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="text-xs space-y-1.5">
            <p className="text-slate-400 font-medium">
              Recent DNS Observations ({dnsPackets.length})
            </p>
            {dnsPackets.slice(0, 4).map((d) => (
              <div
                key={d.id}
                className="flex items-center justify-between px-3 py-1.5 rounded bg-[#080510] border border-slate-800 font-mono"
              >
                <span className="text-[#39FF88] truncate">{d.dnsQuery || `${d.sourceIp} -> ${d.destinationIp}:53`}</span>
                <span className="text-slate-400 shrink-0 ml-2">{d.dnsResponseCode ?? 'QUERY'}</span>
              </div>
            ))}
          </div>
        </GlassPanel>
      </div>
    </div>
  );
};
