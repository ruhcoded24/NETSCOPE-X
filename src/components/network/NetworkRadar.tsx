import React, { useEffect, useMemo, useState } from 'react';
import type { PacketRecord, SecurityAlert } from '../../core/types';
import { formatShortTime } from '../../utils/formatters';

interface NetworkRadarProps {
  packets: PacketRecord[];
  alerts: SecurityAlert[];
  reducedMotion?: boolean;
  onSelectPacket: (pkt: PacketRecord) => void;
}

function hashAngle(ip: string): number {
  let h = 0;
  for (let i = 0; i < ip.length; i++) {
    h = (h * 31 + ip.charCodeAt(i)) % 360;
  }
  return (h * Math.PI) / 180;
}

export const NetworkRadar: React.FC<NetworkRadarProps> = ({
  packets,
  alerts,
  reducedMotion = false,
  onSelectPacket,
}) => {
  const [sweepDeg, setSweepDeg] = useState(0);

  useEffect(() => {
    if (reducedMotion) return;
    const id = window.setInterval(() => {
      setSweepDeg((d) => (d + 3) % 360);
    }, 50);
    return () => window.clearInterval(id);
  }, [reducedMotion]);

  const alertIps = useMemo(() => new Set(alerts.map((a) => a.sourceIp)), [alerts]);

  const blips = useMemo(() => {
    const recent = packets.slice(0, 28);
    return recent.map((pkt, idx) => {
      const angle = hashAngle(`${pkt.sourceIp}:${pkt.destinationPort ?? 0}`);
      const radius = 26 + ((idx * 17 + (pkt.size % 53)) % 76);
      const x = 130 + Math.cos(angle) * radius;
      const y = 130 + Math.sin(angle) * radius;
      const suspicious = alertIps.has(pkt.sourceIp) || pkt.isSimulated;
      return { pkt, x, y, suspicious };
    });
  }, [packets, alertIps]);

  return (
    <div className="flex flex-col md:flex-row items-center gap-5">
      <div className="relative w-[260px] h-[260px] shrink-0">
        <svg viewBox="0 0 260 260" className="w-full h-full" role="img" aria-label="Live packet radar">
          <defs>
            <radialGradient id="radarSweepGrad" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00E5FF" stopOpacity="0.22" />
              <stop offset="100%" stopColor="#00E5FF" stopOpacity="0.0" />
            </radialGradient>
          </defs>
          <circle cx="130" cy="130" r="118" fill="#080510" stroke="rgba(0,229,255,0.28)" strokeWidth="1" />
          <circle cx="130" cy="130" r="88" fill="none" stroke="rgba(201,164,255,0.16)" strokeDasharray="3 3" />
          <circle cx="130" cy="130" r="56" fill="none" stroke="rgba(157,0,255,0.22)" strokeDasharray="3 3" />
          <circle cx="130" cy="130" r="24" fill="none" stroke="rgba(0,229,255,0.28)" />
          <line x1="12" y1="130" x2="248" y2="130" stroke="rgba(148,163,184,0.12)" />
          <line x1="130" y1="12" x2="130" y2="248" stroke="rgba(148,163,184,0.12)" />

          {!reducedMotion && (
            <g transform={`rotate(${sweepDeg} 130 130)`}>
              <path d="M 130 130 L 130 12 A 118 118 0 0 1 232 71 Z" fill="url(#radarSweepGrad)" />
              <line x1="130" y1="130" x2="130" y2="12" stroke="#00E5FF" strokeWidth="1.5" strokeOpacity="0.8" />
            </g>
          )}

          {blips.map(({ pkt, x, y, suspicious }) => (
            <g
              key={pkt.id}
              className="cursor-pointer"
              onClick={() => onSelectPacket(pkt)}
            >
              <circle
                cx={x}
                cy={y}
                r={suspicious ? 4.8 : 3.5}
                fill={suspicious ? '#FF3B5C' : '#00E5FF'}
                fillOpacity="0.9"
              />
              <circle
                cx={x}
                cy={y}
                r={suspicious ? 8 : 5.5}
                fill="none"
                stroke={suspicious ? '#FF3B5C' : '#00E5FF'}
                strokeOpacity="0.4"
              />
              <title>{`${pkt.protocol} ${pkt.sourceIp} -> ${pkt.destinationIp} (${pkt.size} B)`}</title>
            </g>
          ))}
        </svg>
      </div>

      <div className="flex-1 w-full min-w-0 space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-400 pb-1 border-b border-slate-800/80">
          <span>Recent Radar Events (Click to Inspect)</span>
          <span className="font-mono tabular-nums">{blips.length} active</span>
        </div>
        <div className="max-h-48 overflow-y-auto space-y-1">
          {blips.length === 0 ? (
            <p className="text-xs text-slate-500 py-6 text-center">
              Start packet capture or run a simulation scenario to plot live radar activity.
            </p>
          ) : (
            blips.slice(0, 7).map(({ pkt, suspicious }) => (
              <button
                key={pkt.id}
                type="button"
                onClick={() => onSelectPacket(pkt)}
                className="w-full text-left px-2.5 py-1.5 rounded-md hover:bg-slate-800/50 transition-colors flex items-center justify-between gap-3 text-xs"
              >
                <div className="min-w-0 flex items-center gap-2">
                  <span className={suspicious ? 'text-[#FF3B5C] font-semibold' : 'text-[#00E5FF] font-semibold'}>
                    {suspicious ? 'ALERT' : pkt.protocol}
                  </span>
                  <span className="font-mono text-slate-200 truncate">
                    {pkt.sourceIp} → {pkt.destinationIp}
                  </span>
                </div>
                <span className="font-mono text-slate-400 tabular-nums shrink-0">
                  {formatShortTime(pkt.timestamp)}
                </span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
