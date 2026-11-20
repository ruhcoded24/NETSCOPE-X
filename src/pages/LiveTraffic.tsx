import React, { useCallback, useEffect, useState } from 'react';
import { Download, Play, Search, ShieldAlert, Square } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { GlassPanel } from '../components/common/GlassPanel';
import { TrafficCharts } from '../components/traffic/TrafficCharts';
import { formatBytes, formatShortTime, getProtocolColor } from '../utils/formatters';
import type { PacketRecord, ProtocolName } from '../core/types';

export const LiveTraffic: React.FC = () => {
  const {
    status,
    interfaces,
    startCapture,
    stopCapture,
    stats,
    setSelectedPacket,
    navigate,
    settings,
    packets: wsPackets,
  } = useApp();

  const [selectedIface, setSelectedIface] = useState(status.activeInterface);
  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState<ProtocolName | 'ALL'>('ALL');
  const [tcpFlag, setTcpFlag] = useState('ALL');
  const [sourceIp, setSourceIp] = useState('');
  const [destinationIp, setDestinationIp] = useState('');
  const [portFilter, setPortFilter] = useState('');
  const [trafficScope, setTrafficScope] = useState<'all' | 'real' | 'sim'>('all');
  const [sortBy, setSortBy] = useState<'timestamp' | 'size' | 'protocol'>('timestamp');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<PacketRecord[]>(wsPackets.slice(0, 50));
  const [total, setTotal] = useState(wsPackets.length);
  const [showPcapPrivacyModal, setShowPcapPrivacyModal] = useState(false);

  useEffect(() => {
    setSelectedIface(status.activeInterface);
  }, [status.activeInterface]);

  const fetchFiltered = useCallback(async () => {
    try {
      const res = await api.getPackets({
        search,
        protocol,
        tcpFlag,
        sourceIp,
        destinationIp,
        destinationPort: portFilter,
        includeSimulated: trafficScope !== 'real',
        onlySimulated: trafficScope === 'sim',
        sortBy,
        sortDir,
        page,
        pageSize: 30,
      });
      setRows(res.items);
      setTotal(res.total);
    } catch (err) {
      console.error('Packet query error:', err);
    }
  }, [search, protocol, tcpFlag, sourceIp, destinationIp, portFilter, trafficScope, sortBy, sortDir, page]);

  useEffect(() => {
    fetchFiltered();
    const timer = window.setInterval(fetchFiltered, 2000);
    return () => window.clearInterval(timer);
  }, [fetchFiltered]);

  const handleExport = (format: 'csv' | 'json') => {
    const incSim = trafficScope !== 'real';
    window.location.href = `/api/packets/export?format=${format}&includeSimulated=${incSim}`;
  };

  const handleConfirmPcapDownload = () => {
    setShowPcapPrivacyModal(false);
    const incSim = trafficScope !== 'real';
    window.location.href = `/api/packets/export?format=pcap&includeSimulated=${incSim}&confirmPrivacy=true`;
  };

  const totalPages = Math.max(1, Math.ceil(total / 30));

  return (
    <div className="space-y-6">
      {/* Capture Controls Bar */}
      <GlassPanel
        title="Capture Interface & Stream Controls"
        subtitle="Select an authorized host network interface and manage real-time packet acquisition"
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <label htmlFor="iface-selector" className="text-xs text-slate-400">
              Interface
            </label>
            <select
              id="iface-selector"
              value={selectedIface}
              onChange={(e) => setSelectedIface(e.target.value)}
              className="px-3 py-2 text-xs font-mono bg-[#080510] border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-[#00E5FF]"
            >
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} · {iface.ipv4 ?? iface.ipv6 ?? 'No IP'} ({formatBytes(iface.rxBytes + iface.txBytes)})
                </option>
              ))}
            </select>

            {status.capturing ? (
              <button
                type="button"
                onClick={() => stopCapture()}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#FF3B5C] text-white text-xs font-semibold hover:bg-[#ff5270] transition-colors whitespace-nowrap"
              >
                <Square className="w-3.5 h-3.5" />
                Stop Capture
              </button>
            ) : (
              <button
                type="button"
                onClick={() => startCapture(selectedIface)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#00E5FF] text-[#070910] text-xs font-semibold hover:bg-[#33ebff] transition-colors whitespace-nowrap"
              >
                <Play className="w-3.5 h-3.5" />
                Start Capture
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => handleExport('csv')}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700 text-xs text-slate-200 hover:border-[#00E5FF] transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Export CSV
            </button>
            <button
              type="button"
              onClick={() => handleExport('json')}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700 text-xs text-slate-200 hover:border-[#00E5FF] transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Export JSON
            </button>
            <button
              type="button"
              onClick={() => setShowPcapPrivacyModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-[#FF9F43]/50 text-xs text-[#FF9F43] hover:bg-[#FF9F43]/10 transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Export PCAP
            </button>
          </div>
        </div>
      </GlassPanel>

      {/* Search & Filter Toolbar */}
      <GlassPanel title="Packet Stream" subtitle={`Showing ${rows.length} of ${total} matching packets`}>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 mb-4">
          <div className="relative lg:col-span-2">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search IP, port, protocol, summary..."
              aria-label="Search packets"
              className="w-full pl-8 pr-3 py-2 text-xs bg-[#080510] border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#00E5FF]"
            />
          </div>

          <input
            type="text"
            value={sourceIp}
            onChange={(e) => {
              setSourceIp(e.target.value);
              setPage(1);
            }}
            placeholder="Source IP..."
            aria-label="Filter by source IP"
            className="px-3 py-2 text-xs font-mono bg-[#080510] border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#00E5FF]"
          />

          <input
            type="text"
            value={destinationIp}
            onChange={(e) => {
              setDestinationIp(e.target.value);
              setPage(1);
            }}
            placeholder="Dest IP..."
            aria-label="Filter by destination IP"
            className="px-3 py-2 text-xs font-mono bg-[#080510] border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#00E5FF]"
          />

          <input
            type="text"
            value={portFilter}
            onChange={(e) => {
              setPortFilter(e.target.value);
              setPage(1);
            }}
            placeholder="Dest Port..."
            aria-label="Filter by destination port"
            className="px-3 py-2 text-xs font-mono bg-[#080510] border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#00E5FF]"
          />

          <div className="flex gap-2">
            <select
              value={protocol}
              onChange={(e) => {
                setProtocol(e.target.value as ProtocolName | 'ALL');
                setPage(1);
              }}
              aria-label="Filter by protocol"
              className="flex-1 px-2.5 py-2 text-xs bg-[#080510] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-[#00E5FF]"
            >
              <option value="ALL">All Proto</option>
              <option value="HTTPS/TLS">HTTPS/TLS</option>
              <option value="DNS">DNS</option>
              <option value="HTTP">HTTP</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="ARP">ARP</option>
            </select>

            <select
              value={tcpFlag}
              onChange={(e) => {
                setTcpFlag(e.target.value);
                setPage(1);
              }}
              aria-label="Filter by TCP flag"
              className="px-2.5 py-2 text-xs bg-[#080510] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-[#00E5FF]"
            >
              <option value="ALL">Flags</option>
              <option value="SYN">SYN</option>
              <option value="ACK">ACK</option>
              <option value="PSH">PSH</option>
              <option value="FIN">FIN</option>
              <option value="RST">RST</option>
            </select>
          </div>
        </div>

        {/* Scope & Sort Row */}
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4 text-xs">
          <div className="flex items-center gap-1 p-1 bg-[#080510] border border-slate-800 rounded-lg">
            {[
              { id: 'all', label: 'All Traffic' },
              { id: 'real', label: 'Real Capture Only' },
              { id: 'sim', label: '[SIMULATED] Only' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setTrafficScope(tab.id as 'all' | 'real' | 'sim');
                  setPage(1);
                }}
                className={`px-3 py-1 rounded-md font-medium transition-colors whitespace-nowrap ${
                  trafficScope === tab.id
                    ? 'bg-[#00E5FF]/15 text-[#00E5FF]'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400">Sort by</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'timestamp' | 'size' | 'protocol')}
              aria-label="Sort packets"
              className="px-2.5 py-1.5 bg-[#080510] border border-slate-800 rounded-md text-slate-200"
            >
              <option value="timestamp">Timestamp</option>
              <option value="size">Packet Size</option>
              <option value="protocol">Protocol</option>
            </select>
            <button
              type="button"
              onClick={() => setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'))}
              className="px-2.5 py-1.5 bg-[#080510] border border-slate-800 rounded-md text-slate-200 hover:border-slate-600"
            >
              {sortDir === 'desc' ? 'Newest / High' : 'Oldest / Low'}
            </button>
          </div>
        </div>

        {/* Packet Table */}
        <div className="overflow-x-auto border border-slate-800/80 rounded-lg">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#080510] border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3 font-medium">Time</th>
                <th className="py-2.5 px-3 font-medium">Source</th>
                <th className="py-2.5 px-3 font-medium">Destination</th>
                <th className="py-2.5 px-3 font-medium">Protocol</th>
                <th className="py-2.5 px-3 font-medium">Flags</th>
                <th className="py-2.5 px-3 font-medium text-right">Size</th>
                <th className="py-2.5 px-3 font-medium">Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-500 font-sans">
                    No packets match the active filters.
                  </td>
                </tr>
              ) : (
                rows.map((pkt) => (
                  <tr
                    key={pkt.id}
                    onClick={() => {
                      setSelectedPacket(pkt);
                      navigate('packet-inspector');
                    }}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-2 px-3 text-slate-400 tabular-nums whitespace-nowrap">
                      {formatShortTime(pkt.timestamp)}
                    </td>
                    <td className="py-2 px-3 text-slate-200 whitespace-nowrap">
                      {pkt.sourceIp.includes(':') ? `[${pkt.sourceIp}]` : pkt.sourceIp}
                      {pkt.sourcePort ? `:${pkt.sourcePort}` : ''}
                    </td>
                    <td className="py-2 px-3 text-slate-200 whitespace-nowrap">
                      {pkt.destinationIp.includes(':') ? `[${pkt.destinationIp}]` : pkt.destinationIp}
                      {pkt.destinationPort ? `:${pkt.destinationPort}` : ''}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap font-semibold" style={{ color: getProtocolColor(pkt.protocol) }}>
                      {pkt.protocol}
                    </td>
                    <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                      {pkt.tcpFlags.join(',') || '—'}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-300 tabular-nums whitespace-nowrap">
                      {pkt.size} B
                    </td>
                    <td className="py-2 px-3 text-slate-300 max-w-[220px] xl:max-w-[280px] truncate font-sans">
                      {pkt.isSimulated && (
                        <span className="text-[#FF9F43] font-mono font-semibold mr-1.5">[SIMULATED]</span>
                      )}
                      {pkt.summary}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between mt-4 text-xs text-slate-400">
          <span className="font-mono tabular-nums">
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-3 py-1.5 rounded-md border border-slate-800 text-slate-300 disabled:opacity-40 hover:border-slate-600"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="px-3 py-1.5 rounded-md border border-slate-800 text-slate-300 disabled:opacity-40 hover:border-slate-600"
            >
              Next
            </button>
          </div>
        </div>
      </GlassPanel>

      <TrafficCharts stats={stats} reducedMotion={settings.reducedMotion} mode="overview" />

      {/* Explicit Privacy Warning Modal for PCAP Export */}
      {showPcapPrivacyModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-[#10091B] border border-[#FF9F43]/50 rounded-xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-2.5 text-[#FF9F43]">
              <ShieldAlert className="w-5 h-5" />
              <h3 className="font-display font-semibold text-base">PCAP Export Privacy Notice</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              NETSCOPE X exports synthetic L2/L3/L4 header metadata only (zero raw application payloads,
              passwords, or cookies). However, IP addresses and port metadata can identify internal hosts.
              Confirm you are authorized to export this capture trace.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowPcapPrivacyModal(false)}
                className="px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmPcapDownload}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#FF9F43] text-[#070910] hover:bg-[#ffb066]"
              >
                Confirm & Download PCAP
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
