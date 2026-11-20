import React, { useMemo, useState } from 'react';
import { Download, FileUp, FlaskConical, Search } from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { GlassPanel } from '../components/common/GlassPanel';
import { TrafficCharts } from '../components/traffic/TrafficCharts';
import { formatBytes, formatShortTime, getSeverityColor } from '../utils/formatters';
import type { ForensicReport } from '../core/types';

export const PCAPForensics: React.FC = () => {
  const { settings, pushToast, setSelectedPacket, navigate } = useApp();
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const handleFileUpload = async (file: File) => {
    setError(null);
    const lower = file.name.toLowerCase();
    if (!lower.endsWith('.pcap') && !lower.endsWith('.pcapng') && !lower.endsWith('.cap')) {
      setError('Invalid file extension. Upload a .pcap or .pcapng binary capture file.');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('File exceeds 10 MB maximum analysis size.');
      return;
    }

    setLoading(true);
    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let binary = '';
      for (let i = 0; i < bytes.length; i += 8192) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
      }
      const base64 = btoa(binary);
      const res = await api.uploadPcap(file.name, base64);
      setReport(res);
      pushToast(`Analyzed ${res.packetCount} packets from ${file.name}`, 'success');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse PCAP file.');
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeSample = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await api.analyzeSamplePcap();
      setReport(res);
      pushToast(`Sample forensic trace analyzed (${res.packetCount} packets)`, 'success');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sample analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const handleExportForensicReport = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.fileName}-forensic-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredPackets = useMemo(() => {
    if (!report) return [];
    const q = search.trim().toLowerCase();
    if (!q) return report.packets.slice(0, 100);
    return report.packets
      .filter(
        (p) =>
          p.sourceIp.toLowerCase().includes(q) ||
          p.destinationIp.toLowerCase().includes(q) ||
          p.protocol.toLowerCase().includes(q) ||
          p.summary.toLowerCase().includes(q),
      )
      .slice(0, 100);
  }, [report, search]);

  return (
    <div className="space-y-6">
      <GlassPanel
        title="PCAP & PCAPNG Forensics Lab"
        subtitle="Safe, non-executing binary header parsing for historical packet captures (max 10 MB)"
        action={
          report && (
            <button
              type="button"
              onClick={handleExportForensicReport}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-200 hover:border-[#00E5FF]"
            >
              <Download className="w-3.5 h-3.5" />
              Export Forensic JSON
            </button>
          )
        }
      >
        <div className="flex flex-wrap items-center gap-4">
          <label className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#00E5FF] text-[#070910] text-xs font-semibold cursor-pointer hover:bg-[#33ebff] transition-colors">
            <FileUp className="w-4 h-4" />
            <span>{loading ? 'Parsing Binary Trace...' : 'Upload .pcap / .pcapng'}</span>
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileUpload(file);
              }}
            />
          </label>

          <button
            type="button"
            disabled={loading}
            onClick={handleAnalyzeSample}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-slate-700 text-xs font-medium text-slate-200 hover:border-[#9B5CFF] hover:text-[#9B5CFF] transition-colors"
          >
            <FlaskConical className="w-4 h-4" />
            Load & Analyze Sample Lab PCAP
          </button>
        </div>

        {error && (
          <p className="mt-4 text-xs text-[#FF3B5C] bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 rounded-lg px-3.5 py-2.5">
            {error}
          </p>
        )}
      </GlassPanel>

      {report && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            <div className="bg-[#10091B] border border-[#C9A4FF]/15 rounded-xl p-4">
              <span className="text-slate-500 font-sans block">Capture File</span>
              <span className="text-slate-100 font-semibold truncate block mt-1">{report.fileName}</span>
            </div>
            <div className="bg-[#10091B] border border-[#C9A4FF]/15 rounded-xl p-4">
              <span className="text-slate-500 font-sans block">Parsed Packets</span>
              <span className="text-[#00E5FF] text-lg font-bold tabular-nums">{report.packetCount}</span>
            </div>
            <div className="bg-[#10091B] border border-[#C9A4FF]/15 rounded-xl p-4">
              <span className="text-slate-500 font-sans block">Total Volume</span>
              <span className="text-slate-100 text-lg font-bold tabular-nums">{formatBytes(report.totalBytes)}</span>
            </div>
            <div className="bg-[#10091B] border border-[#C9A4FF]/15 rounded-xl p-4">
              <span className="text-slate-500 font-sans block">Forensic Findings</span>
              <span className={`text-lg font-bold tabular-nums ${report.alerts.length > 0 ? 'text-[#FF3B5C]' : 'text-[#39FF88]'}`}>
                {report.alerts.length}
              </span>
            </div>
          </div>

          {report.alerts.length > 0 && (
            <GlassPanel title="Forensic Threat Detections" subtitle="Anomalies discovered in recorded capture">
              <div className="space-y-2.5 text-xs">
                {report.alerts.map((a) => (
                  <div key={a.id} className="p-3.5 rounded-lg bg-[#080510] border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className={`font-semibold ${getSeverityColor(a.severity).text}`}>
                        {a.severity} · {a.ruleName} (Risk {a.riskScore}/100)
                      </span>
                      <span className="font-mono text-slate-400">{a.sourceIp}</span>
                    </div>
                    <p className="text-slate-200">{a.summary}</p>
                  </div>
                ))}
              </div>
            </GlassPanel>
          )}

          <TrafficCharts stats={report.stats} reducedMotion={settings.reducedMotion} mode="overview" />

          <GlassPanel title="Recorded Packets" subtitle="Filter and click any packet to open Packet Inspector">
            <div className="relative mb-3 max-w-md">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search IP or protocol in PCAP..."
                className="w-full pl-8 pr-3 py-2 text-xs bg-[#080510] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-[#00E5FF]"
              />
            </div>

            <div className="overflow-x-auto border border-slate-800 rounded-lg max-h-96 overflow-y-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-[#080510] border-b border-slate-800 text-slate-400 font-sans">
                    <th className="py-2 px-3">Time</th>
                    <th className="py-2 px-3">Source</th>
                    <th className="py-2 px-3">Destination</th>
                    <th className="py-2 px-3">Protocol</th>
                    <th className="py-2 px-3 text-right">Size</th>
                    <th className="py-2 px-3">Flags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredPackets.map((p) => (
                    <tr
                      key={p.id}
                      onClick={() => {
                        setSelectedPacket(p);
                        navigate('packet-inspector');
                      }}
                      className="hover:bg-slate-800/40 cursor-pointer"
                    >
                      <td className="py-2 px-3 text-slate-400 tabular-nums">{formatShortTime(p.timestamp)}</td>
                      <td className="py-2 px-3 text-slate-200">{p.sourceIp}{p.sourcePort ? `:${p.sourcePort}` : ''}</td>
                      <td className="py-2 px-3 text-slate-200">{p.destinationIp}{p.destinationPort ? `:${p.destinationPort}` : ''}</td>
                      <td className="py-2 px-3 text-[#00E5FF] font-semibold">{p.protocol}</td>
                      <td className="py-2 px-3 text-right tabular-nums">{p.size} B</td>
                      <td className="py-2 px-3 text-slate-400">{p.tcpFlags.join(',') || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </GlassPanel>
        </>
      )}
    </div>
  );
};
