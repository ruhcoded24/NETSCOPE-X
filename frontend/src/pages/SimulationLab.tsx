import React from 'react';
import { FlaskConical, Play, ShieldAlert, Square, Trash2 } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { GlassPanel } from '../components/common/GlassPanel';
import { formatShortTime, getSeverityColor } from '../utils/formatters';
import type { SimulationScenarioId } from '../core/types';

const SCENARIOS: {
  id: SimulationScenarioId;
  title: string;
  description: string;
  ruleTargeted: string;
}[] = [
  {
    id: 'port_scan',
    title: 'Port Scan Pattern Simulation',
    description:
      'Emits isolated [SIMULATED] TCP SYN probes from 10.240.0.99 across 15 sequential service ports on 10.240.0.10.',
    ruleTargeted: 'Multi-Port Enumeration Rule (PS-01)',
  },
  {
    id: 'syn_flood_metadata',
    title: 'SYN Flood-Like Metadata Simulation',
    description:
      'Emits a burst of 24 unacknowledged [SIMULATED] SYN packets without matching SYN-ACK completions.',
    ruleTargeted: 'Half-Open SYN Burst Heuristic (SYN-02)',
  },
  {
    id: 'traffic_spike',
    title: 'Traffic Volume Spike Simulation',
    description:
      'Emits 32 high-MTU [SIMULATED] frames in rapid succession to exceed baseline packet-rate multipliers.',
    ruleTargeted: 'Bandwidth & Packet-Rate Surge Rule (VOL-03)',
  },
  {
    id: 'dns_anomaly',
    title: 'DNS Query Anomaly Simulation',
    description:
      'Emits 18 high-frequency [SIMULATED] DNS queries with elevated NXDOMAIN responses.',
    ruleTargeted: 'DNS Query Burst & NXDOMAIN Rule (DNS-04)',
  },
  {
    id: 'repeated_connections',
    title: 'Repeated Connection Fanout Simulation',
    description:
      'Emits [SIMULATED] lateral connection attempts from one host across 16 distinct internal peers.',
    ruleTargeted: 'Lateral Peer Fanout Anomaly (CON-05)',
  },
];

export const SimulationLab: React.FC = () => {
  const {
    status,
    alerts,
    events,
    pushToast,
    setSelectedAlert,
    navigate,
    refreshAlerts,
    refreshEvents,
    refreshStatsAndTopology,
  } = useApp();

  const [runningId, setRunningId] = React.useState<SimulationScenarioId | null>(null);

  const simAlerts = alerts.filter((a) => a.isSimulated);
  const simEvents = events.filter((e) => e.isSimulated);

  const handleRun = async (id: SimulationScenarioId) => {
    setRunningId(id);
    try {
      pushToast(`[SIMULATED] Emitting real-time traffic for ${id.replace(/_/g, ' ')}...`, 'warn');
      const res = await api.runSimulation(id);
      
      // Immediately refresh all alerts, terminal events and telemetry
      await Promise.all([
        refreshAlerts(),
        refreshEvents(),
        refreshStatsAndTopology(),
      ]);

      if (res?.alertsTriggered && res.alertsTriggered.length > 0) {
        pushToast(`[SIMULATED] Alert triggered: ${res.alertsTriggered[0].ruleName}`, 'success');
      } else {
        pushToast(`[SIMULATED] Emitted ${res?.packetsGenerated ?? 20} simulated frames into analyzer`, 'info');
      }
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Simulation failed', 'error');
    } finally {
      setTimeout(() => setRunningId(null), 1200);
    }
  };

  const handleStop = async () => {
    try {
      await api.stopSimulation();
      await Promise.all([refreshAlerts(), refreshEvents(), refreshStatsAndTopology()]);
      pushToast('Simulation halted', 'info');
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Failed to halt simulation', 'error');
    }
  };

  const handleClear = async () => {
    try {
      await api.clearSimulation();
      await Promise.all([refreshAlerts(), refreshEvents(), refreshStatsAndTopology()]);
      pushToast('Cleared all [SIMULATED] packets and alerts', 'info');
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Failed to clear simulated data', 'error');
    }
  };

  return (
    <div className="space-y-6">
      {/* Safety Isolation Notice */}
      <div className="p-4 rounded-xl bg-[#FF9F43]/10 border border-[#FF9F43]/40 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-start gap-3 max-w-3xl">
          <FlaskConical className="w-5 h-5 text-[#FF9F43] shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold text-[#FF9F43]">
              Isolated Educational Simulation Sandbox — Zero External Network Transmission
            </p>
            <p className="text-slate-300 leading-relaxed">
              Scenarios emit synthetic metadata inside the local analyzer pipeline tagged{' '}
              <span className="font-mono text-[#FF9F43]">[SIMULATED]</span> to demonstrate how detection
              rules respond. Real host captures remain strictly separated.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {status.simulationActive && (
            <button
              type="button"
              onClick={handleStop}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#FF3B5C] text-white font-semibold"
            >
              <Square className="w-3.5 h-3.5" />
              Stop Simulation
            </button>
          )}
          <button
            type="button"
            onClick={handleClear}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700 text-slate-200 hover:border-[#FF3B5C] hover:text-[#FF3B5C]"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear Simulated Data
          </button>
        </div>
      </div>

      {/* Scenario Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {SCENARIOS.map((sc) => {
          const running = runningId === sc.id || (status.simulationActive && status.activeScenario === sc.id);
          const relatedAlerts = simAlerts.filter(
            (a) =>
              (sc.id === 'port_scan' && a.category === 'port_scan') ||
              (sc.id === 'syn_flood_metadata' && a.category === 'syn_spike') ||
              (sc.id === 'traffic_spike' && a.category === 'traffic_spike') ||
              (sc.id === 'dns_anomaly' && a.category === 'dns_anomaly') ||
              (sc.id === 'repeated_connections' && a.category === 'connection_fanout'),
          );

          return (
            <div
              key={sc.id}
              className={`border rounded-xl p-5 flex flex-col justify-between gap-4 transition-all duration-300 ${
                running
                  ? 'bg-[#190626] border-[#FF9F43] shadow-[0_0_20px_rgba(255,159,67,0.25)]'
                  : relatedAlerts.length > 0
                  ? 'bg-[#10091B]/95 border-[#00E5FF]/40 shadow-[0_0_15px_rgba(0,229,255,0.1)]'
                  : 'bg-[#10091B]/95 border-[#C9A4FF]/15'
              }`}
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <h3 className="font-display font-semibold text-sm text-slate-100">{sc.title}</h3>
                  {relatedAlerts.length > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-[#00E5FF]/15 text-[#00E5FF] border border-[#00E5FF]/30 whitespace-nowrap">
                      {relatedAlerts.length} Active
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{sc.description}</p>
                <p className="text-[11px] font-mono text-[#00E5FF] pt-1">
                  Target: {sc.ruleTargeted}
                </p>
              </div>

              <div className="space-y-2 pt-1">
                <button
                  type="button"
                  onClick={() => handleRun(sc.id)}
                  disabled={running}
                  className={`w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                    running
                      ? 'bg-[#FF9F43] text-[#070910] animate-pulse cursor-wait'
                      : 'bg-[#FF9F43] hover:bg-[#ffb066] text-[#070910] shadow-[0_0_15px_rgba(255,159,67,0.2)]'
                  }`}
                >
                  <Play className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
                  {running ? 'Streaming Simulated Traffic...' : 'Run Simulation'}
                </button>

                {relatedAlerts.length > 0 && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedAlert(relatedAlerts[0]);
                      navigate('ai-investigator');
                    }}
                    className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#00E5FF]/30 hover:border-[#00E5FF] text-[11px] font-mono text-[#00E5FF] hover:bg-[#00E5FF]/10 transition-colors"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Investigate Alert ({relatedAlerts[0].severity} {relatedAlerts[0].riskScore}/100)
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Simulated Alerts & Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <GlassPanel
          title="[SIMULATED] Triggered Alerts"
          subtitle={`${simAlerts.length} simulated detections`}
        >
          {simAlerts.length === 0 ? (
            <p className="text-xs text-slate-500 py-8 text-center">
              Run any simulation scenario above to observe detection engine output.
            </p>
          ) : (
            <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
              {simAlerts.map((a) => (
                <button
                  key={a.id}
                  type="button"
                  onClick={() => {
                    setSelectedAlert(a);
                    navigate('ai-investigator');
                  }}
                  className="w-full text-left p-3 rounded-lg bg-[#080510] border border-slate-800 hover:border-[#FF9F43]/50 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className={`font-semibold flex items-center gap-1 ${getSeverityColor(a.severity).text}`}>
                      <ShieldAlert className="w-3.5 h-3.5" />
                      {a.severity} · Risk {a.riskScore}/100
                    </span>
                    <span className="font-mono text-slate-500">{formatShortTime(a.timestamp)}</span>
                  </div>
                  <p className="text-slate-200">{a.summary}</p>
                </button>
              ))}
            </div>
          )}
        </GlassPanel>

        <GlassPanel
          title="[SIMULATED] Event Feed"
          subtitle={`${simEvents.length} isolated simulation log lines`}
        >
          <div className="space-y-1.5 max-h-72 overflow-y-auto font-mono text-xs">
            {simEvents.length === 0 ? (
              <p className="text-slate-500 py-8 text-center font-sans">
                No simulated events emitted yet.
              </p>
            ) : (
              simEvents.map((e) => (
                <div key={e.id} className="px-2.5 py-1.5 rounded bg-[#080510] border border-slate-800/80 text-slate-300">
                  <span className="text-slate-500 mr-2">{formatShortTime(e.timestamp)}</span>
                  <span className="text-[#FF9F43] mr-1.5">[SIMULATED]</span>
                  <span>{e.message}</span>
                </div>
              ))
            )}
          </div>
        </GlassPanel>
      </div>
    </div>
  );
};
