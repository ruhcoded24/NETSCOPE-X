import React, { useState } from 'react';
import { Globe, Search, ShieldCheck } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { GlassPanel } from '../components/common/GlassPanel';
import { isPrivateIp } from '../core/protocolClassifier';
import type { IpIntelResult } from '../core/types';

export const IPIntelligence: React.FC = () => {
  const { topology, selectedPacket } = useApp();
  const [ipInput, setIpInput] = useState(selectedPacket?.destinationIp || '8.8.8.8');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IpIntelResult | null>(null);

  const handleLookup = async (targetIp?: string) => {
    const queryIp = (targetIp ?? ipInput).trim();
    if (!queryIp) return;
    setIpInput(queryIp);
    setLoading(true);
    try {
      const res = await api.lookupIp(queryIp);
      setResult(res);
    } finally {
      setLoading(false);
    }
  };

  const observedIps = topology.nodes.slice(0, 10).map((n) => n.ip);

  return (
    <div className="space-y-6">
      <GlassPanel
        title="IP Intelligence Lookup"
        subtitle="External ASN & geolocation lookup for public IPs only (private RFC1918/loopback addresses are blocked locally)"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleLookup();
          }}
          className="flex flex-wrap items-center gap-3"
        >
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="Enter IPv4 or IPv6 address (e.g. 8.8.8.8 or 1.1.1.1)"
              aria-label="IP address to investigate"
              className="w-full pl-9 pr-4 py-2.5 text-sm font-mono bg-[#080510] border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-[#00E5FF]"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#00E5FF] text-[#070910] text-xs font-semibold hover:bg-[#33ebff] disabled:opacity-50"
          >
            <Globe className="w-4 h-4" />
            {loading ? 'Querying...' : 'Investigate IP'}
          </button>
        </form>

        {observedIps.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400">Observed Endpoints:</span>
            {observedIps.map((ip) => (
              <button
                key={ip}
                type="button"
                onClick={() => handleLookup(ip)}
                className="px-2.5 py-1 rounded-md bg-[#080510] border border-slate-800 font-mono text-slate-300 hover:border-[#00E5FF] hover:text-[#00E5FF] transition-colors"
              >
                {ip} ({isPrivateIp(ip) ? 'Private' : 'Public'})
              </button>
            ))}
          </div>
        )}
      </GlassPanel>

      {result && (
        <GlassPanel
          title={`Intelligence Result: ${result.ip}`}
          subtitle={`${result.sourceLabel} · ${result.cached ? 'Cached Response' : 'Fresh Lookup'}`}
        >
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
              <div className="p-3.5 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 font-sans block mb-1">Address Scope</span>
                <span className={result.isPrivate ? 'text-[#39FF88]' : 'text-[#00E5FF]'}>
                  {result.isPrivate ? 'Private / Internal' : 'Public Routable'}
                </span>
              </div>
              <div className="p-3.5 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 font-sans block mb-1">ASN</span>
                <span className="text-slate-100">{result.asn ?? 'N/A'}</span>
              </div>
              <div className="p-3.5 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 font-sans block mb-1">Organization / ISP</span>
                <span className="text-slate-100">{result.org ?? 'N/A'}</span>
              </div>
              <div className="p-3.5 rounded-lg bg-[#080510] border border-slate-800">
                <span className="text-slate-500 font-sans block mb-1">Approximate Location</span>
                <span className="text-slate-100">
                  {[result.city, result.region, result.country].filter(Boolean).join(', ') || 'Not Geolocated'}
                </span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 flex items-start gap-3">
              <ShieldCheck className="w-4 h-4 text-[#00E5FF] shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="font-semibold text-slate-200">{result.reputationStatus}</p>
                <p className="text-slate-400 leading-relaxed">{result.reputationNote}</p>
                {result.error && <p className="text-[#FF9F43] font-mono">{result.error}</p>}
              </div>
            </div>
          </div>
        </GlassPanel>
      )}
    </div>
  );
};
