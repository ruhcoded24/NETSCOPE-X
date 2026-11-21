import React from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { TrafficStats } from '../../core/types';
import { formatBytes, getProtocolColor } from '../../utils/formatters';

interface TrafficChartsProps {
  stats: TrafficStats | null;
  reducedMotion?: boolean;
  mode?: 'overview' | 'full';
}

const TOOLTIP_STYLE = {
  backgroundColor: '#10091B',
  border: '1px solid rgba(201, 164, 255, 0.25)',
  borderRadius: '8px',
  fontSize: '12px',
  color: '#ede9fe',
};

export const TrafficCharts: React.FC<TrafficChartsProps> = ({
  stats,
  reducedMotion = false,
  mode = 'overview',
}) => {
  if (!stats) {
    return (
      <div className="h-56 flex items-center justify-center text-xs text-[#C9A4FF]/70 border border-[#C9A4FF]/15 rounded-xl bg-[#10091B]/80">
        Awaiting live telemetry aggregation...
      </div>
    );
  }

  const protocolData = Object.entries(stats.protocolDistribution)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({
      name,
      value,
      color: getProtocolColor(name as keyof typeof stats.protocolDistribution),
    }));

  const flagData = Object.entries(stats.tcpFlagDistribution).map(([flag, count]) => ({
    flag,
    count,
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      {/* 1. Live Packet Rate & Alert Timeline */}
      <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-100 font-display">
            Packet Rate & Alert Timeline
          </h3>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {stats.packetsPerSecond} pkt/s
          </span>
        </div>
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={stats.timeSeries}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area
                type="monotone"
                dataKey="packets"
                name="Packets"
                stroke="#00E5FF"
                fill="rgba(0, 229, 255, 0.16)"
                isAnimationActive={!reducedMotion}
              />
              <Area
                type="monotone"
                dataKey="alerts"
                name="Alerts"
                stroke="#FF3B5C"
                fill="rgba(255, 59, 92, 0.2)"
                isAnimationActive={!reducedMotion}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 2. Bandwidth Over Time (Inbound vs Outbound) */}
      <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-100 font-display">
            Bandwidth: Inbound vs Outbound
          </h3>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {formatBytes(stats.totalBytes)} total
          </span>
        </div>
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={stats.timeSeries}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                formatter={(v) => formatBytes(Number(v ?? 0))}
              />
              <Legend wrapperStyle={{ fontSize: '11px' }} />
              <Line
                type="monotone"
                dataKey="inboundBytes"
                name="Inbound"
                stroke="#39FF88"
                strokeWidth={2}
                dot={false}
                isAnimationActive={!reducedMotion}
              />
              <Line
                type="monotone"
                dataKey="outboundBytes"
                name="Outbound"
                stroke="#287BFF"
                strokeWidth={2}
                dot={false}
                isAnimationActive={!reducedMotion}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 3. Protocol Distribution */}
      <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-100 font-display">
            Protocol Distribution
          </h3>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {protocolData.length} active layers
          </span>
        </div>
        <div className="h-56">
          {protocolData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs text-slate-500">
              No packets observed in selected window.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={48}
                  outerRadius={78}
                  paddingAngle={2}
                  isAnimationActive={!reducedMotion}
                >
                  {protocolData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* 4. Top Communicating Endpoints */}
      <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-100 font-display">
            Top Communicating IPs
          </h3>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            Top {Math.min(6, stats.topDevices.length)}
          </span>
        </div>
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={stats.topDevices.slice(0, 6)} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
              <XAxis type="number" stroke="#64748b" fontSize={11} />
              <YAxis dataKey="ip" type="category" width={115} stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar
                dataKey="packets"
                name="Packets"
                fill="#00E5FF"
                radius={[0, 4, 4, 0]}
                isAnimationActive={!reducedMotion}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {mode === 'full' && (
        <>
          {/* 5. Top Ports */}
          <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-slate-100 font-display mb-3">
              Top Destination Ports
            </h3>
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.topPorts.slice(0, 8)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="port" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar
                    dataKey="packets"
                    name="Packets"
                    fill="#9B5CFF"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={!reducedMotion}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* 6. Packet Size & TCP Flags */}
          <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-slate-100 font-display mb-3">
              Packet Size & TCP Flag Distribution
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 h-52">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.packetSizeBuckets}>
                  <XAxis dataKey="label" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar
                    dataKey="count"
                    name="Packets"
                    fill="#287BFF"
                    isAnimationActive={!reducedMotion}
                  />
                </BarChart>
              </ResponsiveContainer>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={flagData}>
                  <XAxis dataKey="flag" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar
                    dataKey="count"
                    name="Flag Hits"
                    fill="#FF9F43"
                    isAnimationActive={!reducedMotion}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
