import React from 'react';
import { Globe, ShieldCheck } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { GlassPanel } from '../components/common/GlassPanel';
import { getPortServiceName } from '../core/protocolClassifier';

export const PacketInspectorPage: React.FC = () => {
  const { selectedPacket, packets, setSelectedPacket, navigate } = useApp();
  const pkt = selectedPacket ?? packets[0] ?? null;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Left Packet Selector List */}
      <GlassPanel
        title="Observed Packets"
        subtitle="Select any frame to inspect header metadata"
        className="lg:col-span-1"
      >
        <div className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1">
          {packets.length === 0 ? (
            <p className="text-xs text-slate-500 py-8 text-center">
              No packets available yet. Start capture or load a PCAP.
            </p>
          ) : (
            packets.slice(0, 60).map((item) => {
              const active = pkt?.id === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSelectedPacket(item)}
                  className={`w-full text-left p-2.5 rounded-lg border text-xs font-mono transition-colors ${
                    active
                      ? 'bg-[#00E5FF]/10 border-[#00E5FF]/50 text-white'
                      : 'bg-[#080510] border-slate-800/80 text-slate-300 hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[#00E5FF] font-semibold">{item.protocol}</span>
                    <span className="text-slate-500 tabular-nums">{item.size} B</span>
                  </div>
                  <p className="truncate mt-1 text-slate-200">
                    {item.sourceIp} → {item.destinationIp}
                  </p>
                </button>
              );
            })
          )}
        </div>
      </GlassPanel>

      {/* Right Deep Metadata Inspector */}
      <GlassPanel
        title={pkt ? `Packet ${pkt.id}` : 'Packet Inspector'}
        subtitle={pkt ? pkt.timestamp : 'Select a packet from the stream'}
        className="lg:col-span-2"
      >
        {!pkt ? (
          <div className="py-20 text-center text-sm text-slate-400">
            Click any packet in Live Traffic or the list on the left to inspect its layers.
          </div>
        ) : (
          <div className="space-y-6">
            {/* Safe Metadata Notice */}
            <div className="flex items-start gap-3 p-3.5 rounded-lg bg-[#080510] border border-slate-800 text-xs text-slate-300">
              <ShieldCheck className="w-4 h-4 text-[#39FF88] shrink-0 mt-0.5" />
              <p>
                Safe Metadata Inspection Active: NETSCOPE X extracts L2/L3/L4 header fields and safe protocol identifiers only. Raw application payloads, credentials, and encrypted TLS content are never captured or stored.
              </p>
            </div>

            {/* Key Endpoint Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
              <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 block font-sans mb-1">Source Endpoint</span>
                <span className="text-slate-100 font-semibold break-all">{pkt.sourceIp}</span>
                <span className="text-slate-400 block mt-0.5">
                  Port {pkt.sourcePort ?? 'N/A'}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 block font-sans mb-1">Destination Endpoint</span>
                <span className="text-slate-100 font-semibold break-all">{pkt.destinationIp}</span>
                <span className="text-slate-400 block mt-0.5">
                  Port {pkt.destinationPort ?? 'N/A'}
                  {pkt.destinationPort ? ` (${getPortServiceName(pkt.destinationPort)})` : ''}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 block font-sans mb-1">Protocol & Transport</span>
                <span className="text-[#00E5FF] font-semibold">{pkt.protocol}</span>
                <span className="text-slate-400 block mt-0.5">Transport: {pkt.transportProtocol}</span>
              </div>

              <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 block font-sans mb-1">Frame Metrics</span>
                <span className="text-slate-100 font-semibold tabular-nums">{pkt.size} bytes</span>
                <span className="text-slate-400 block mt-0.5">
                  TTL: {pkt.ttl ?? 'N/A'} · {pkt.direction}
                </span>
              </div>
            </div>

            {/* Protocol Encapsulation Timeline */}
            <div>
              <h3 className="text-xs font-semibold text-slate-300 mb-3">
                Protocol Layer Encapsulation Stack
              </h3>
              <div className="flex flex-wrap items-center gap-2">
                {pkt.layerStack.map((layer, idx) => (
                  <React.Fragment key={layer}>
                    <div className="px-3.5 py-2 rounded-lg bg-[#080510] border border-slate-700/80 text-xs font-mono text-slate-200">
                      <span className="text-slate-500 mr-2">L{idx + 2}</span>
                      {layer}
                    </div>
                    {idx < pkt.layerStack.length - 1 && (
                      <span className="text-slate-600 font-mono">→</span>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* TCP Flags & Safe Application Metadata */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 space-y-2">
                <h4 className="font-semibold text-slate-200">TCP Control Flags</h4>
                <p className="font-mono text-slate-300">
                  {pkt.tcpFlags.length > 0 ? pkt.tcpFlags.join(' · ') : 'None (Non-TCP or stateless)'}
                </p>
              </div>

              <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 space-y-2">
                <h4 className="font-semibold text-slate-200">Interface & Origin</h4>
                <p className="font-mono text-slate-300">
                  Interface: {pkt.interfaceName} · Origin:{' '}
                  {pkt.isSimulated ? '[SIMULATED] Lab Stream' : 'Live Host Capture'}
                </p>
                {pkt.dnsQuery && (
                  <p className="font-mono text-[#39FF88]">
                    DNS Query: {pkt.dnsQuery} ({pkt.dnsResponseCode ?? 'QUERY'})
                  </p>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                type="button"
                onClick={() => navigate('ip-intelligence')}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#00E5FF] text-[#070910] text-xs font-semibold hover:bg-[#33ebff] transition-colors"
              >
                <Globe className="w-3.5 h-3.5" />
                Investigate IPs in IP Intelligence
              </button>
              <button
                type="button"
                onClick={() => navigate('live-traffic')}
                className="px-4 py-2 rounded-lg border border-slate-700 text-xs text-slate-200 hover:border-slate-500 transition-colors"
              >
                Back to Live Traffic
              </button>
            </div>
          </div>
        )}
      </GlassPanel>
    </div>
  );
};
