import React from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'motion/react';
import { Lock, Shield } from 'lucide-react';
import { RotatingGlobeCanvas } from './RotatingGlobeCanvas';
import type { PacketRecord } from '../../core/types';

interface CosmosConstellationProps {
  latestPacket?: PacketRecord;
  activeInterface: string;
  interfaceCount: number;
  reducedMotion?: boolean;
}

export const CosmosConstellation: React.FC<CosmosConstellationProps> = ({
  latestPacket,
  activeInterface,
  interfaceCount,
  reducedMotion = false,
}) => {
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);
  const smoothX = useSpring(mouseX, { stiffness: 70, damping: 20 });
  const smoothY = useSpring(mouseY, { stiffness: 70, damping: 20 });

  const outerLayerX = useTransform(smoothX, [-1, 1], [-14, 14]);
  const outerLayerY = useTransform(smoothY, [-1, 1], [-10, 10]);
  const innerLayerX = useTransform(smoothX, [-1, 1], [8, -8]);
  const innerLayerY = useTransform(smoothY, [-1, 1], [6, -6]);

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (reducedMotion) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const nx = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    const ny = ((e.clientY - rect.top) / rect.height) * 2 - 1;
    mouseX.set(nx);
    mouseY.set(ny);
  };

  const handlePointerLeave = () => {
    mouseX.set(0);
    mouseY.set(0);
  };

  const srcDisplay = latestPacket
    ? `${latestPacket.sourceIp}${latestPacket.sourcePort ? `:${latestPacket.sourcePort}` : ''}`
    : '10.240.0.14:51822';
  const dstDisplay = latestPacket
    ? `${latestPacket.destinationIp}${latestPacket.destinationPort ? `:${latestPacket.destinationPort}` : ''}`
    : '172.16.40.9:443';
  const protoDisplay = latestPacket?.protocol ?? 'HTTPS/TLS';
  const sizeDisplay = latestPacket ? `${latestPacket.size} B` : '1,420 B';
  const flagsDisplay = latestPacket?.tcpFlags?.length ? latestPacket.tcpFlags.join(', ') : 'ACK, PSH';

  const floatLoop = (yDelta: number, duration: number, delay = 0) =>
    reducedMotion
      ? undefined
      : {
          y: [0, -yDelta, 0, yDelta * 0.6, 0],
          transition: {
            duration,
            delay,
            repeat: Infinity,
            ease: 'easeInOut' as const,
          },
        };

  return (
    <div
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
      className="relative w-full max-w-[1140px] mx-auto h-[340px] sm:h-[430px] lg:h-[480px] select-none flex items-center justify-center overflow-visible"
      aria-label="NETSCOPE X orbital cybersecurity constellation"
    >
      {/* Subtle Cosmos Ambient Aura (centered behind emblem) */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[320px] h-[320px] sm:w-[460px] sm:h-[460px] rounded-full opacity-80"
        style={{
          background:
            'radial-gradient(circle at 42% 45%, rgba(0, 229, 255, 0.16), transparent 55%), radial-gradient(circle at 60% 58%, rgba(255, 0, 200, 0.14), transparent 60%), radial-gradient(circle, rgba(157, 0, 255, 0.12) 0%, transparent 72%)',
        }}
      />

      {/* Concentric Orbital Rings */}
      <div
        aria-hidden="true"
        className={`pointer-events-none absolute w-[250px] h-[250px] sm:w-[370px] sm:h-[370px] lg:w-[430px] lg:h-[430px] rounded-full border border-[#9D00FF]/25 ${
          reducedMotion ? '' : 'animate-orbit-slow'
        }`}
      >
        <span className="absolute -top-1 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-[#00E5FF]" />
        <span className="absolute -bottom-1 left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full bg-[#FF00C8]" />
      </div>

      <div
        aria-hidden="true"
        className={`pointer-events-none absolute hidden sm:block w-[520px] h-[520px] lg:w-[640px] lg:h-[380px] rounded-[999px] border border-[#00E5FF]/15 ${
          reducedMotion ? '' : 'animate-orbit-reverse'
        }`}
      >
        <span className="absolute top-1/2 -left-1 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-[#C9A4FF]" />
      </div>

      {/* EXACT VISUAL CENTER: Preserved NETSCOPE X Emblem */}
      <motion.div
        initial={reducedMotion ? false : { opacity: 0, scale: 0.92 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.55 }}
        className="relative z-20 flex items-center justify-center"
      >
        <div className="relative w-36 h-36 sm:w-44 sm:h-44 lg:w-52 lg:h-52 rounded-full p-2 bg-[#10091B]/90 border border-[#00E5FF]/40 shadow-[0_0_55px_rgba(0,229,255,0.18),0_0_80px_rgba(255,0,200,0.14)] flex items-center justify-center">
          {/* Precision Reticle SVG Framing */}
          <svg
            aria-hidden="true"
            viewBox="0 0 220 220"
            className="absolute inset-0 w-full h-full pointer-events-none"
          >
            <circle
              cx="110"
              cy="110"
              r="105"
              fill="none"
              stroke="url(#emblemRingGrad)"
              strokeWidth="1.2"
              strokeDasharray="18 10 4 10"
            />
            <defs>
              <linearGradient id="emblemRingGrad" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#00E5FF" stopOpacity="0.85" />
                <stop offset="50%" stopColor="#9D00FF" stopOpacity="0.45" />
                <stop offset="100%" stopColor="#FF00C8" stopOpacity="0.85" />
              </linearGradient>
            </defs>
          </svg>

          <div className="w-full h-full rounded-full overflow-hidden border border-[#C9A4FF]/25 bg-[#080510] flex items-center justify-center relative">
            <img
              src="/src/assets/images/netscope_soc_emblem_1795167718378.jpg"
              alt="NETSCOPE X Central Security Emblem"
              referrerPolicy="no-referrer"
              className="w-full h-full object-cover scale-105"
            />
            <div
              aria-hidden="true"
              className="absolute inset-0 bg-gradient-to-tr from-[#080510]/35 via-transparent to-[#00E5FF]/10"
            />
          </div>
        </div>
      </motion.div>

      {/* INNER ORBIT LAYER (Objects 1, 4, 6, 8) */}
      <motion.div
        style={reducedMotion ? undefined : { x: innerLayerX, y: innerLayerY }}
        className="pointer-events-none absolute inset-0 z-10"
      >
        {/* 1. Network Topology Nodes & Connections (Top-Left Inner) */}
        <motion.div
          animate={floatLoop(7, 6.2, 0.2)}
          className="hidden sm:flex flex-col gap-1.5 absolute left-[6%] md:left-[12%] lg:left-[21%] top-[5%] w-44 p-3 rounded-xl bg-[#190626]/85 border border-[#C9A4FF]/20 shadow-xl"
        >
          <span className="text-[10px] font-mono tracking-wider text-[#C9A4FF]">
            TOPOLOGY MESH
          </span>
          <svg viewBox="0 0 150 56" className="w-full h-12" aria-hidden="true">
            <line x1="22" y1="28" x2="72" y2="14" stroke="#00E5FF" strokeOpacity="0.45" strokeWidth="1.2" />
            <line x1="72" y1="14" x2="128" y2="26" stroke="#FF00C8" strokeOpacity="0.55" strokeWidth="1.2" />
            <line x1="22" y1="28" x2="78" y2="44" stroke="#9D00FF" strokeOpacity="0.5" strokeWidth="1.2" />
            <line x1="78" y1="44" x2="128" y2="26" stroke="#00E5FF" strokeOpacity="0.4" strokeWidth="1.2" />
            <circle cx="22" cy="28" r="4.5" fill="#080510" stroke="#00E5FF" strokeWidth="1.5" />
            <circle cx="72" cy="14" r="4" fill="#080510" stroke="#C9A4FF" strokeWidth="1.5" />
            <circle cx="78" cy="44" r="4" fill="#080510" stroke="#9D00FF" strokeWidth="1.5" />
            <circle cx="128" cy="26" r="5" fill="#080510" stroke="#FF00C8" strokeWidth="1.6" />
          </svg>
          <span className="text-[11px] font-mono text-slate-300 tabular-nums">
            {interfaceCount || 3} host interfaces
          </span>
        </motion.div>

        {/* 4. Digital Security Shield (Top-Right Inner) */}
        <motion.div
          animate={floatLoop(6, 5.4, 0.7)}
          className="hidden md:flex items-center gap-2.5 absolute right-[8%] lg:right-[23%] top-[5%] p-2.5 pr-3.5 rounded-xl bg-[#10091B]/90 border border-[#00E5FF]/25 shadow-xl"
        >
          <div className="w-8 h-8 rounded-lg bg-[#190626] border border-[#00E5FF]/35 flex items-center justify-center">
            <Shield className="w-4 h-4 text-[#00E5FF]" />
          </div>
          <div className="text-left">
            <p className="text-[11px] font-display font-semibold text-white leading-tight">
              Rule Guard
            </p>
            <p className="text-[10px] font-mono text-[#C9A4FF]">5 Detectors Active</p>
          </div>
        </motion.div>

        {/* 6. Rotating 3D Wireframe Network Globe (Right Center) */}
        <motion.div
          animate={floatLoop(8, 7.0, 0.4)}
          className="hidden sm:flex flex-col items-center justify-center absolute right-[4%] lg:right-[4%] top-[33%] lg:top-[36%] p-2 rounded-2xl bg-[#10091B]/75 border border-[#C9A4FF]/20 shadow-2xl"
        >
          <RotatingGlobeCanvas reducedMotion={reducedMotion} size={104} />
          <span className="text-[10px] font-mono text-[#00E5FF] mt-0.5">GLOBAL TELEMETRY</span>
        </motion.div>

        {/* 8. PCAP & Packet-Analysis Visual (Bottom-Left Inner) */}
        <motion.div
          animate={floatLoop(6, 6.5, 1.1)}
          className="hidden sm:flex flex-col gap-1.5 absolute left-[6%] md:left-[12%] lg:left-[17%] bottom-[6%] w-48 p-3 rounded-xl bg-[#190626]/85 border border-[#FF00C8]/25 shadow-xl"
        >
          <div className="flex items-center justify-between text-[10px] font-mono">
            <span className="text-[#FF36E2]">PCAP TRACE</span>
            <span className="text-[#C9A4FF]">L2→L3→L4</span>
          </div>
          <div className="flex items-end gap-1 h-7 pt-1" aria-hidden="true">
            {[38, 65, 48, 92, 56, 78, 42, 85, 60, 72, 46, 68].map((h, i) => (
              <span
                key={i}
                style={{ height: `${h}%` }}
                className={`flex-1 rounded-t-sm ${
                  i === 3 || i === 7 ? 'bg-[#FF00C8]/80' : 'bg-[#00E5FF]/55'
                }`}
              />
            ))}
          </div>
          <span className="text-[10px] font-mono text-slate-300">Header-Only Forensics</span>
        </motion.div>
      </motion.div>

      {/* OUTER ORBIT LAYER (Objects 2, 3, 5, 7) */}
      <motion.div
        style={reducedMotion ? undefined : { x: outerLayerX, y: outerLayerY }}
        className="pointer-events-none absolute inset-0 z-10"
      >
        {/* 3. IP Address & Protocol Information (Mid-Left Outer) */}
        <motion.div
          animate={floatLoop(9, 7.2, 0.3)}
          className="hidden md:block absolute left-[2%] top-[37%] w-52 p-3 rounded-xl bg-[#10091B]/90 border border-[#C9A4FF]/20 shadow-2xl"
        >
          <div className="flex items-center justify-between text-[10px] font-mono text-[#00E5FF] mb-1.5">
            <span>FLOW VECTOR</span>
            <span>{protoDisplay}</span>
          </div>
          <p className="text-[11px] font-mono text-slate-200 truncate">{srcDisplay}</p>
          <p className="text-[11px] font-mono text-[#C9A4FF] truncate mt-0.5">→ {dstDisplay}</p>
        </motion.div>

        {/* 2. Floating Packet-Data Card (Upper-Right Outer) */}
        <motion.div
          animate={floatLoop(8, 6.8, 0.9)}
          className="hidden lg:block absolute right-[2%] top-[10%] w-52 p-3 rounded-xl bg-[#190626]/85 border border-[#C9A4FF]/20 shadow-2xl"
        >
          <div className="flex items-center justify-between text-[10px] font-mono mb-1">
            <span className="text-[#FF36E2]">FRAME METADATA</span>
            <span className="text-slate-400 tabular-nums">{sizeDisplay}</span>
          </div>
          <p className="text-[11px] font-mono text-slate-100">
            FLAGS: <span className="text-[#00E5FF]">{flagsDisplay}</span>
          </p>
          <p className="text-[10px] font-mono text-slate-400 mt-0.5">
            IFACE: {activeInterface}
          </p>
        </motion.div>

        {/* 5. Small Terminal Window (Bottom-Right Outer) */}
        <motion.div
          animate={floatLoop(7, 5.8, 0.5)}
          className="hidden md:block absolute right-[8%] lg:right-[18%] bottom-[5%] w-56 rounded-xl overflow-hidden bg-[#080510]/95 border border-[#9D00FF]/35 shadow-2xl"
        >
          <div className="px-3 py-1.5 bg-[#10091B] border-b border-[#9D00FF]/20 flex items-center justify-between text-[10px] font-mono text-[#C9A4FF]">
            <span>netscope-cli</span>
            <span className="text-[#00E5FF]">live</span>
          </div>
          <div className="p-2.5 font-mono text-[10px] leading-relaxed space-y-0.5">
            <p className="text-slate-300">
              <span className="text-[#FF00C8]">$</span> watch --iface {activeInterface}
            </p>
            <p className="text-[#00E5FF]">engine: heuristic + tls_sni</p>
            <p className="text-slate-400">zero_payload_capture: true</p>
          </div>
        </motion.div>

        {/* 7. Encryption & Data-Stream Symbols (Upper-Left Outer) */}
        <motion.div
          animate={floatLoop(5, 5.0, 1.3)}
          className="hidden lg:flex items-center gap-2 absolute left-[2%] top-[10%] px-3 py-2 rounded-xl bg-[#10091B]/85 border border-[#5B1BFF]/40 shadow-xl"
        >
          <Lock className="w-3.5 h-3.5 text-[#FF36E2]" />
          <span className="text-[10px] font-mono text-[#C9A4FF] tracking-wide">
            ECDHE · SHA-256 · 0x9D
          </span>
        </motion.div>
      </motion.div>

      {/* Compact Mobile Telemetry Strip (visible below central emblem on small screens without clutter) */}
      <div className="sm:hidden absolute bottom-1 inset-x-4 flex items-center justify-between px-3 py-2 rounded-xl bg-[#10091B]/90 border border-[#C9A4FF]/20 text-[10px] font-mono text-[#C9A4FF]">
        <span className="text-[#00E5FF]">{activeInterface}</span>
        <span>{protoDisplay}</span>
        <span className="text-[#FF36E2]">5 Rules Armed</span>
      </div>
    </div>
  );
};
