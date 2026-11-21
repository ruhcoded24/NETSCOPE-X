import React, { useState } from 'react';
import { ArrowUpRight, ShieldAlert } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { GlassPanel } from '../components/common/GlassPanel';
import { AnimatedCounter } from '../components/common/AnimatedCounter';
import { NetworkUniverse } from '../components/network/NetworkUniverse';
import { NetworkRadar } from '../components/network/NetworkRadar';
import { CyberTerminal } from '../components/common/CyberTerminal';
import { TrafficCharts } from '../components/traffic/TrafficCharts';
import { formatBps, formatShortTime, getSeverityColor } from '../utils/formatters';
import type { ProtocolName } from '../core/types';

export const Overview: React.FC = () => {
  const {
    status,
    stats,
    packets,
    alerts,
    events,
    topology,
    selectedNodeIp,
    setSelectedNodeIp,
    setSelectedPacket,
    setSelectedAlert,
    navigate,
    settings,
    clearTerminalEvents,
    windowSeconds,
    setWindowSeconds,
    includeSimulatedInOverview,
    setIncludeSimulatedInOverview,
  } = useApp();

  const [topoProto, setTopoProto] = useState<ProtocolName | 'ALL'>('ALL');
  const openAlerts = alerts.filter((a) => a.status !== 'resolved');

  return (
    <div className="space-y-6">
      {/* Window & Scope Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>Telemetry Window:</span>
          {[
            { label: '1m', val: 60 },
            { label: '5m', val: 300 },
            { label: '15m', val: 900 },
            { label: 'All', val: 0 },
          ].map((opt) => (
            <button
              key={opt.label}
              type="button"
              onClick={() => setWindowSeconds(opt.val)}
              className={`px-2.5 py-1 rounded-md font-mono transition-colors ${
                windowSeconds === opt.val
                  ? 'bg-[#00E5FF]/15 text-[#00E5FF] border border-[#00E5FF]/40'
                  : 'bg-[#10091B] text-slate-400 border border-[#C9A4FF]/20 hover:text-slate-200'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={includeSimulatedInOverview}
            onChange={(e) => setIncludeSimulatedInOverview(e.target.checked)}
            className="rounded border-[#C9A4FF]/30 bg-[#10091B] accent-[#FF9F43]"
          />
          <span>Include [SIMULATED] Lab Traffic in Topology & Alerts</span>
        </label>
      </div>

      {/* 4-Column KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
          <p className="text-xs text-slate-400">Observed Packets</p>
          <p className="text-2xl font-bold text-white mt-1">
            <AnimatedCounter value={stats?.totalPackets ?? 0} reducedMotion={settings.reducedMotion} />
          </p>
          <p className="text-xs font-mono text-[#00E5FF] mt-1 tabular-nums">
            {stats?.packetsPerSecond ?? 0} pkt/s · Avg {stats?.averagePacketSize ?? 0} B
          </p>
        </div>

        <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
          <p className="text-xs text-slate-400">Live Bandwidth</p>
          <p className="text-2xl font-bold text-white mt-1 font-mono tabular-nums">
            {formatBps(stats?.bytesPerSecond ?? 0)}
          </p>
          <p className="text-xs font-mono text-slate-400 mt-1 tabular-nums">
            In {stats?.incomingPackets ?? 0} · Out {stats?.outgoingPackets ?? 0}
          </p>
        </div>

        <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
          <p className="text-xs text-slate-400">Discovered Endpoints</p>
          <p className="text-2xl font-bold text-white mt-1">
            <AnimatedCounter value={topology.nodes.length} reducedMotion={settings.reducedMotion} />
          </p>
          <p className="text-xs font-mono text-[#39FF88] mt-1 tabular-nums">
            {topology.edges.length} active links · {status.activeInterface}
          </p>
        </div>

        <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
          <p className="text-xs text-slate-400">Active Security Alerts</p>
          <p className={`text-2xl font-bold mt-1 ${openAlerts.length > 0 ? 'text-[#FF3B5C]' : 'text-[#39FF88]'}`}>
            <AnimatedCounter value={openAlerts.length} reducedMotion={settings.reducedMotion} />
          </p>
          <p className="text-xs text-slate-400 mt-1">
            {openAlerts.filter((a) => !a.isSimulated).length} live ·{' '}
            {openAlerts.filter((a) => a.isSimulated).length} simulated
          </p>
        </div>
      </div>

      {/* 3D Network Universe Centerpiece */}
      <GlassPanel
        title="Network Universe"
        subtitle="Real-time 3D topology of observed endpoints, directional packet streams, and alert states"
        action={
          <button
            type="button"
            onClick={() => navigate('network-universe')}
            className="inline-flex items-center gap-1 text-xs font-medium text-[#00E5FF] hover:underline whitespace-nowrap"
          >
            Full View
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        }
      >
        <NetworkUniverse
          nodes={
            topoProto === 'ALL'
              ? topology.nodes
              : topology.nodes.filter((n) => n.protocols.includes(topoProto))
          }
          edges={
            topoProto === 'ALL'
              ? topology.edges
              : topology.edges.filter((e) => e.protocols.includes(topoProto))
          }
          alerts={alerts}
          selectedNodeIp={selectedNodeIp}
          onSelectNode={setSelectedNodeIp}
          protocolFilter={topoProto}
          onProtocolFilterChange={setTopoProto}
          reducedMotion={settings.reducedMotion}
          heightClass="h-[440px]"
        />
      </GlassPanel>

      {/* Live Radar + Priority Alerts */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <GlassPanel
          title="Live Packet Radar"
          subtitle="Real-packet telemetry sweep · click any radar blip to inspect metadata"
        >
          <NetworkRadar
            packets={packets}
            alerts={alerts}
            reducedMotion={settings.reducedMotion}
            onSelectPacket={(pkt) => {
              setSelectedPacket(pkt);
              navigate('packet-inspector');
            }}
          />
        </GlassPanel>

        <GlassPanel
          title="Recent Threat Detections"
          subtitle="Explainable heuristic alerts & confirmed incidents"
          action={
            <button
              type="button"
              onClick={() => navigate('threat-centre')}
              className="text-xs font-medium text-[#00E5FF] hover:underline whitespace-nowrap"
            >
              Threat Centre
            </button>
          }
        >
          {alerts.length === 0 ? (
            <div className="py-12 text-center space-y-2">
              <p className="text-sm text-slate-300">No security anomalies flagged yet.</p>
              <p className="text-xs text-slate-500">
                Start live capture or run a scenario in the Simulation Lab to test detection rules.
              </p>
              <button
                type="button"
                onClick={() => navigate('simulation-lab')}
                className="mt-2 px-3.5 py-1.5 text-xs font-medium rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF] hover:text-[#00E5FF]"
              >
                Open Simulation Lab
              </button>
            </div>
          ) : (
            <div className="space-y-2.5 max-h-64 overflow-y-auto pr-1">
              {alerts.slice(0, 6).map((alert) => {
                const sev = getSeverityColor(alert.severity);
                return (
                  <button
                    key={alert.id}
                    type="button"
                    onClick={() => {
                      setSelectedAlert(alert);
                      navigate('ai-investigator');
                    }}
                    className="w-full text-left p-3 rounded-lg bg-[#080510] border border-[#C9A4FF]/15 hover:border-[#00E5FF]/40 transition-colors flex items-start justify-between gap-3"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className={`font-semibold flex items-center gap-1 ${sev.text}`}>
                          <ShieldAlert className="w-3.5 h-3.5" />
                          {alert.severity}
                        </span>
                        <span aria-hidden="true" className="text-slate-600">·</span>
                        <span className="font-mono text-slate-300">Risk {alert.riskScore}/100</span>
                        <span aria-hidden="true" className="text-slate-600">·</span>
                        <span className="text-slate-400">{alert.classification}</span>
                      </div>
                      <p className="text-xs text-slate-200 line-clamp-1">{alert.summary}</p>
                    </div>
                    <span className="font-mono text-[11px] text-slate-500 shrink-0 tabular-nums">
                      {formatShortTime(alert.timestamp)}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </GlassPanel>
      </div>

      {/* Traffic Overview Charts */}
      <TrafficCharts stats={stats} reducedMotion={settings.reducedMotion} mode="overview" />

      {/* Live Cyber Terminal */}
      <CyberTerminal events={events} onClear={clearTerminalEvents} heightClass="h-64" />
    </div>
  );
};
