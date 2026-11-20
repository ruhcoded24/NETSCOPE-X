import React, { useEffect, useState } from 'react';
import { Download, FileSpreadsheet, FileText, HardDrive, ShieldAlert } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { GlassPanel } from '../components/common/GlassPanel';
import { formatBps, formatBytes, formatShortTime } from '../utils/formatters';
import type { CaptureSessionSummary } from '../core/types';

export const Reports: React.FC = () => {
  const { stats, alerts, topology, status, pushToast } = useApp();
  const [sessions, setSessions] = useState<CaptureSessionSummary[]>([]);
  const [includeSimExport, setIncludeSimExport] = useState(false);
  const [pcapPrivacyModal, setPcapPrivacyModal] = useState(false);

  useEffect(() => {
    api
      .getSessions()
      .then((res) => setSessions(res.sessions))
      .catch((err) => console.error('Failed to fetch sessions:', err));
  }, [status.capturing, status.packetCount]);

  const triggerDownload = (url: string) => {
    const link = document.createElement('a');
    link.href = url;
    link.download = '';
    link.click();
  };

  const handleExportMarkdownExecutive = () => {
    const protocols = Object.entries(stats?.protocolDistribution ?? {})
      .filter(([, count]) => count > 0)
      .sort((a, b) => b[1] - a[1]);

    const md = [
      `# NETSCOPE X — Executive Traffic & Threat Summary`,
      `Generated: ${new Date().toISOString()}`,
      ``,
      `## Capture Overview`,
      `- Active Interface: ${status.activeInterface} (${status.captureMode})`,
      `- Total Packets Observed: ${stats?.totalPackets ?? 0}`,
      `- Total Byte Volume: ${formatBytes(stats?.totalBytes ?? 0)}`,
      `- Throughput: ${stats?.packetsPerSecond ?? 0} pkt/s (${formatBps(stats?.bytesPerSecond ?? 0)})`,
      `- Discovered Endpoints: ${topology.nodes.length} (${topology.edges.length} links)`,
      ``,
      `## Protocol Distribution`,
      ...protocols.map(([proto, count]) => `- ${proto}: ${count} packets`),
      ``,
      `## Security Alerts (${alerts.length})`,
      ...(alerts.length === 0
        ? ['- No security alerts recorded.']
        : alerts.map(
            (a) =>
              `- [${a.severity}] ${a.ruleName} (${a.id}) — Source ${a.sourceIp}, Risk ${a.riskScore}/100, Status: ${a.status}${a.isSimulated ? ' [SIMULATED]' : ''}`,
          )),
    ].join('\n');

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'netscope-executive-report.md';
    link.click();
    URL.revokeObjectURL(url);
    pushToast('Downloaded executive Markdown report', 'success');
  };

  return (
    <div className="space-y-6">
      {/* Export Control Strip */}
      <GlassPanel
        title="Telemetry & Forensics Export Centre"
        subtitle="Download header-only packet metadata, session histories, and executive SOC reports"
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={includeSimExport}
              onChange={(e) => setIncludeSimExport(e.target.checked)}
              className="rounded border-slate-700 bg-[#080510] accent-[#FF9F43]"
            />
            <span>Include [SIMULATED] Lab packets in CSV/JSON/PCAP exports</span>
          </label>

          <div className="flex flex-wrap items-center gap-2.5 text-xs">
            <button
              type="button"
              onClick={() =>
                triggerDownload(`/api/packets/export?format=csv&includeSimulated=${includeSimExport}`)
              }
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF] hover:text-[#00E5FF] transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              Export CSV
            </button>

            <button
              type="button"
              onClick={() =>
                triggerDownload(`/api/packets/export?format=json&includeSimulated=${includeSimExport}`)
              }
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF] hover:text-[#00E5FF] transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export JSON
            </button>

            <button
              type="button"
              onClick={() => setPcapPrivacyModal(true)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-[#FF9F43]/50 text-[#FF9F43] hover:bg-[#FF9F43]/10 transition-colors"
            >
              <HardDrive className="w-3.5 h-3.5" />
              Export PCAP (Privacy Gate)
            </button>

            <button
              type="button"
              onClick={handleExportMarkdownExecutive}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#00E5FF] text-[#070910] font-semibold hover:bg-[#33ebff] transition-colors"
            >
              <FileText className="w-3.5 h-3.5" />
              Executive Report (.md)
            </button>
          </div>
        </div>

        {pcapPrivacyModal && (
          <div className="mt-4 p-4 rounded-lg bg-[#080510] border border-[#FF9F43]/50 space-y-3 text-xs">
            <div className="flex items-start gap-2.5 text-[#FF9F43]">
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="font-semibold">PCAP Export Privacy Confirmation</p>
                <p className="text-slate-300">
                  NETSCOPE X exports synthetic L3/L4 header frames only (no application payloads,
                  cookies, or credentials are stored or written). Confirm you are authorized to
                  download network flow headers from interface {status.activeInterface}.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setPcapPrivacyModal(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  triggerDownload(
                    `/api/packets/export?format=pcap&confirmPrivacy=true&includeSimulated=${includeSimExport}`,
                  );
                  setPcapPrivacyModal(false);
                  pushToast('Headers-only PCAP export started', 'success');
                }}
                className="px-3.5 py-1.5 rounded-lg bg-[#FF9F43] text-[#070910] font-semibold hover:bg-[#ffb066]"
              >
                Confirm & Download PCAP
              </button>
            </div>
          </div>
        )}
      </GlassPanel>

      {/* Executive Metrics Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassPanel
          title="Top Communicating Endpoints"
          subtitle="Ranked by packet volume within current telemetry window"
        >
          <div className="space-y-2 text-xs font-mono">
            {(stats?.topDevices ?? []).length === 0 ? (
              <p className="text-slate-500 py-8 text-center font-sans">
                No endpoint telemetry recorded yet. Start capture or analyze a PCAP file.
              </p>
            ) : (
              stats?.topDevices.slice(0, 8).map((dev) => (
                <div
                  key={dev.ip}
                  className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#080510] border border-slate-800/80"
                >
                  <span className="text-[#00E5FF]">{dev.ip}</span>
                  <span className="text-slate-300 tabular-nums">
                    {dev.packets} pkts · {formatBytes(dev.bytes)}
                  </span>
                </div>
              ))
            )}
          </div>
        </GlassPanel>

        <GlassPanel
          title="Top Active Service Ports"
          subtitle="Most observed destination ports & mapped services"
        >
          <div className="space-y-2 text-xs font-mono">
            {(stats?.topPorts ?? []).length === 0 ? (
              <p className="text-slate-500 py-8 text-center font-sans">
                No port activity recorded in the active window.
              </p>
            ) : (
              stats?.topPorts.slice(0, 8).map((p) => (
                <div
                  key={p.port}
                  className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#080510] border border-slate-800/80"
                >
                  <span className="text-slate-100">
                    :{p.port} <span className="text-slate-500 font-sans">({p.service})</span>
                  </span>
                  <span className="text-slate-300 tabular-nums">
                    {p.packets} pkts · {formatBytes(p.bytes)}
                  </span>
                </div>
              ))
            )}
          </div>
        </GlassPanel>
      </div>

      {/* Capture Session History */}
      <GlassPanel
        title="Capture Session History"
        subtitle="Audit trail of started and completed capture sessions"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 pr-4 font-medium">Session ID</th>
                <th className="py-2.5 pr-4 font-medium">Interface</th>
                <th className="py-2.5 pr-4 font-medium">Mode</th>
                <th className="py-2.5 pr-4 font-medium">Started</th>
                <th className="py-2.5 pr-4 font-medium">Stopped</th>
                <th className="py-2.5 pr-4 font-medium text-right">Packets</th>
                <th className="py-2.5 pr-4 font-medium text-right">Bytes</th>
                <th className="py-2.5 font-medium text-right">Alerts</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {sessions.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    No capture sessions logged yet. Click Start Capture in the top bar.
                  </td>
                </tr>
              ) : (
                sessions.map((s) => (
                  <tr key={s.id} className="text-slate-200">
                    <td className="py-2.5 pr-4 text-[#00E5FF]">{s.id}</td>
                    <td className="py-2.5 pr-4">{s.interfaceName}</td>
                    <td className="py-2.5 pr-4 font-sans text-slate-400">{s.mode}</td>
                    <td className="py-2.5 pr-4 tabular-nums">{formatShortTime(s.startedAt)}</td>
                    <td className="py-2.5 pr-4 tabular-nums">
                      {s.stoppedAt ? formatShortTime(s.stoppedAt) : 'Active'}
                    </td>
                    <td className="py-2.5 pr-4 text-right tabular-nums">{s.packetCount}</td>
                    <td className="py-2.5 pr-4 text-right tabular-nums">
                      {formatBytes(s.byteCount)}
                    </td>
                    <td className="py-2.5 text-right tabular-nums">{s.alertCount}</td>
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
