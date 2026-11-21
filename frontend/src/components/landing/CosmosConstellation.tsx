import React, { useState, useEffect } from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'motion/react';
import { Shield, Lock, Activity, Terminal, Wifi, Layers, Globe, Radio } from 'lucide-react';
import { RotatingGlobeCanvas } from './RotatingGlobeCanvas';
import { HolographicCoreCanvas } from './HolographicCoreCanvas';
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
  const smoothX = useSpring(mouseX, { stiffness: 65, damping: 22 });
  const smoothY = useSpring(mouseY, { stiffness: 65, damping: 22 });

  // 3D Parallax layers
  const outerLayerX = useTransform(smoothX, [-1, 1], [-18, 18]);
  const outerLayerY = useTransform(smoothY, [-1, 1], [-14, 14]);
  const innerLayerX = useTransform(smoothX, [-1, 1], [10, -10]);
  const innerLayerY = useTransform(smoothY, [-1, 1], [8, -8]);
  const coreTiltX = useTransform(smoothY, [-1, 1], [8, -8]);
  const coreTiltY = useTransform(smoothX, [-1, 1], [-10, 10]);

  const [mouseNorm, setMouseNorm] = useState({ x: 0, y: 0 });

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (reducedMotion) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const nx = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    const ny = ((e.clientY - rect.top) / rect.height) * 2 - 1;
    mouseX.set(nx);
    mouseY.set(ny);
    setMouseNorm({ x: nx, y: ny });
  };

  const handlePointerLeave = () => {
    mouseX.set(0);
    mouseY.set(0);
    setMouseNorm({ x: 0, y: 0 });
  };

  // Real or realistic fallback packet telemetry
  const srcDisplay = latestPacket
    ? `${latestPacket.sourceIp}${latestPacket.sourcePort ? `:${latestPacket.sourcePort}` : ''}`
    : '2401:4900:8206:b5ee::c8bb:a...';
  const dstDisplay = latestPacket
    ? `${latestPacket.destinationIp}${latestPacket.destinationPort ? `:${latestPacket.destinationPort}` : ''}`
    : '2404:6800:4013:807::cf:4...';
  const protoDisplay = latestPacket?.protocol ?? 'HTTPS/TLS';
  const sizeDisplay = latestPacket ? `${latestPacket.size} B` : '1,420 B';
  const flagsDisplay = latestPacket?.tcpFlags?.length ? latestPacket.tcpFlags.join(', ') : 'ACK, PSH';

  // Floating ambient motion generator
  const floatLoop = (yDelta: number, duration: number, delay = 0) =>
    reducedMotion
      ? undefined
      : {
          y: [0, -yDelta, 0, yDelta * 0.5, 0],
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
      className="relative w-full max-w-[1240px] mx-auto h-[400px] sm:h-[480px] lg:h-[530px] select-none flex items-center justify-center overflow-visible"
      aria-label="NETSCOPE X Holographic Cyber Command Center Visual"
    >
      {/* 1. ATMOSPHERIC BACKLIGHTING & RADIAL HOLOGRAPHIC BLOOM */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[380px] h-[380px] sm:w-[560px] sm:h-[560px] lg:w-[680px] lg:h-[680px] rounded-full opacity-70 blur-3xl"
        style={{
          background:
            'radial-gradient(circle at 45% 45%, rgba(0, 229, 255, 0.16) 0%, rgba(157, 0, 255, 0.14) 40%, rgba(255, 0, 200, 0.08) 65%, transparent 80%)',
        }}
      />

      {/* 2. PERSPECTIVE CYBER RADAR GRID & ORBITAL RINGS */}
      <HolographicCoreCanvas
        reducedMotion={reducedMotion}
        size={540}
        mouseNormalized={mouseNorm}
      />

      {/* 3. FIBER-OPTIC DATA TRACER LINES (Connecting floating panels to the core) */}
      <svg
        aria-hidden="true"
        className="hidden md:block absolute inset-0 w-full h-full pointer-events-none z-10"
        viewBox="0 0 1200 520"
        preserveAspectRatio="none"
      >
        <defs>
          <linearGradient id="tracerCyan" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00E5FF" stopOpacity="0.8" />
            <stop offset="50%" stopColor="#9D00FF" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#00E5FF" stopOpacity="0.1" />
          </linearGradient>
          <linearGradient id="tracerMagenta" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#FF00C8" stopOpacity="0.8" />
            <stop offset="50%" stopColor="#9D00FF" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#00E5FF" stopOpacity="0.1" />
          </linearGradient>
        </defs>

        {/* Top-Left Panel (Topology) to Core */}
        <path
          d="M 230 85 Q 380 120 480 230"
          fill="none"
          stroke="rgba(0, 229, 255, 0.15)"
          strokeWidth="1.2"
          strokeDasharray="4 6"
        />
        <path
          d="M 230 85 Q 380 120 480 230"
          fill="none"
          stroke="url(#tracerCyan)"
          strokeWidth="1.6"
          strokeDasharray="12 48"
          className="animate-data-stream"
        />

        {/* Mid-Left Panel (Flow Vector) to Core */}
        <path
          d="M 230 240 Q 360 250 470 260"
          fill="none"
          stroke="rgba(0, 229, 255, 0.18)"
          strokeWidth="1.2"
          strokeDasharray="3 5"
        />
        <path
          d="M 230 240 Q 360 250 470 260"
          fill="none"
          stroke="url(#tracerCyan)"
          strokeWidth="1.5"
          strokeDasharray="10 40"
          className="animate-data-stream"
        />

        {/* Bottom-Left Panel (PCAP Trace) to Core */}
        <path
          d="M 250 440 Q 390 390 490 290"
          fill="none"
          stroke="rgba(255, 0, 200, 0.15)"
          strokeWidth="1.2"
          strokeDasharray="4 6"
        />
        <path
          d="M 250 440 Q 390 390 490 290"
          fill="none"
          stroke="url(#tracerMagenta)"
          strokeWidth="1.6"
          strokeDasharray="12 48"
          className="animate-data-stream"
        />

        {/* Top-Right Panel (Rule Guard) to Core */}
        <path
          d="M 970 85 Q 820 120 720 230"
          fill="none"
          stroke="rgba(0, 229, 255, 0.15)"
          strokeWidth="1.2"
          strokeDasharray="4 6"
        />
        <path
          d="M 970 85 Q 820 120 720 230"
          fill="none"
          stroke="url(#tracerCyan)"
          strokeWidth="1.6"
          strokeDasharray="12 48"
          className="animate-data-stream"
        />

        {/* Mid-Right Panel (Global Telemetry) to Core */}
        <path
          d="M 970 250 Q 840 255 730 260"
          fill="none"
          stroke="rgba(201, 164, 255, 0.18)"
          strokeWidth="1.2"
          strokeDasharray="3 5"
        />
        <path
          d="M 970 250 Q 840 255 730 260"
          fill="none"
          stroke="url(#tracerCyan)"
          strokeWidth="1.5"
          strokeDasharray="10 40"
          className="animate-data-stream"
        />

        {/* Bottom-Right Panel (Frame & CLI) to Core */}
        <path
          d="M 950 440 Q 810 390 710 290"
          fill="none"
          stroke="rgba(0, 229, 255, 0.15)"
          strokeWidth="1.2"
          strokeDasharray="4 6"
        />
        <path
          d="M 950 440 Q 810 390 710 290"
          fill="none"
          stroke="url(#tracerCyan)"
          strokeWidth="1.6"
          strokeDasharray="12 48"
          className="animate-data-stream"
        />
      </svg>

      {/* 4. EXACT VISUAL CENTER: HOLOGRAPHIC OBSIDIAN CORE & EMBLEM */}
      <motion.div
        style={reducedMotion ? undefined : { rotateX: coreTiltX, rotateY: coreTiltY, perspective: 1000 }}
        initial={reducedMotion ? false : { opacity: 0, scale: 0.88 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.65, ease: 'easeOut' }}
        className="relative z-30 flex items-center justify-center cursor-pointer group"
      >
        {/* Holographic Projection Housing Glow */}
        <div className="relative w-36 h-36 sm:w-44 sm:h-44 lg:w-52 lg:h-52 rounded-full p-2.5 bg-[#080510]/90 border border-[#00E5FF]/50 shadow-[0_0_60px_rgba(0,229,255,0.28),0_0_90px_rgba(157,0,255,0.2)] flex items-center justify-center transition-all duration-300 group-hover:shadow-[0_0_80px_rgba(0,229,255,0.45),0_0_120px_rgba(255,0,200,0.3)] group-hover:border-[#00E5FF]">
          {/* Tech Reticle SVG Compass Housing */}
          <svg
            aria-hidden="true"
            viewBox="0 0 220 220"
            className="absolute inset-0 w-full h-full pointer-events-none"
          >
            {/* Outer segmented tech ring */}
            <circle
              cx="110"
              cy="110"
              r="105"
              fill="none"
              stroke="url(#emblemRingGrad)"
              strokeWidth="1.5"
              strokeDasharray="24 8 4 8"
            />
            {/* Fine tick ring */}
            <circle
              cx="110"
              cy="110"
              r="98"
              fill="none"
              stroke="rgba(0, 229, 255, 0.3)"
              strokeWidth="0.8"
              strokeDasharray="3 5"
            />
            <defs>
              <linearGradient id="emblemRingGrad" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#00E5FF" stopOpacity="0.9" />
                <stop offset="50%" stopColor="#9D00FF" stopOpacity="0.5" />
                <stop offset="100%" stopColor="#FF00C8" stopOpacity="0.9" />
              </linearGradient>
            </defs>
          </svg>

          {/* Central Protected Physical Netscope SOC Emblem */}
          <div className="w-full h-full rounded-full overflow-hidden border border-[#00E5FF]/35 bg-[#080510] flex items-center justify-center relative shadow-inner">
            <img
              src="/src/assets/images/netscope_soc_emblem_1795167718378.jpg"
              alt="NETSCOPE X Holographic Command Emblem"
              referrerPolicy="no-referrer"
              className="w-full h-full object-cover scale-105 group-hover:scale-110 transition-transform duration-500"
            />
            {/* Holographic Scanline & Glaze Overlay */}
            <div
              aria-hidden="true"
              className="absolute inset-0 bg-gradient-to-tr from-[#080510]/40 via-transparent to-[#00E5FF]/15 pointer-events-none"
            />
            <div
              aria-hidden="true"
              className="absolute inset-0 pointer-events-none opacity-25"
              style={{
                backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 229, 255, 0.15) 2px, rgba(0, 229, 255, 0.15) 4px)',
              }}
            />
          </div>

          {/* Holographic Projection Nodes (North, East, South, West) */}
          <span className="absolute -top-1 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-[#00E5FF] shadow-[0_0_8px_#00E5FF]" />
          <span className="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-[#FF00C8] shadow-[0_0_8px_#FF00C8]" />
          <span className="absolute top-1/2 -left-1 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-[#00E5FF] shadow-[0_0_6px_#00E5FF]" />
          <span className="absolute top-1/2 -right-1 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-[#C9A4FF] shadow-[0_0_6px_#C9A4FF]" />
        </div>
      </motion.div>

      {/* 5. FLOATING HOLOGRAPHIC DATA PANELS - LAYER 1 (PARALLAX INNER) */}
      <motion.div
        style={reducedMotion ? undefined : { x: innerLayerX, y: innerLayerY }}
        className="pointer-events-none absolute inset-0 z-20"
      >
        {/* PANEL 1: TOPOLOGY MESH (Top-Left) */}
        <motion.div
          animate={floatLoop(6, 6.2, 0.2)}
          className="pointer-events-auto hidden sm:flex flex-col gap-2 absolute left-[4%] md:left-[8%] lg:left-[14%] top-[3%] w-48 p-3 rounded-xl bg-[#0c0717]/85 backdrop-blur-md border border-[#00E5FF]/25 shadow-[0_0_25px_rgba(0,229,255,0.1)] hover:border-[#00E5FF]/70 hover:shadow-[0_0_35px_rgba(0,229,255,0.25)] transition-all duration-300 group"
        >
          {/* Tech corner brackets */}
          <span className="absolute top-1 left-1 w-2 h-2 border-t border-l border-[#00E5FF]/60" />
          <span className="absolute top-1 right-1 w-2 h-2 border-t border-r border-[#00E5FF]/60" />
          <span className="absolute bottom-1 left-1 w-2 h-2 border-b border-l border-[#00E5FF]/60" />
          <span className="absolute bottom-1 right-1 w-2 h-2 border-b border-r border-[#00E5FF]/60" />

          <div className="flex items-center justify-between text-[10px] font-mono tracking-wider text-[#C9A4FF]">
            <span className="flex items-center gap-1.5 text-[#00E5FF]">
              <Layers className="w-3 h-3 text-[#00E5FF]" />
              TOPOLOGY MESH
            </span>
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00E5FF] opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#00E5FF]" />
            </span>
          </div>

          <svg viewBox="0 0 150 50" className="w-full h-11" aria-hidden="true">
            {/* Constellation lines */}
            <line x1="24" y1="26" x2="72" y2="12" stroke="#00E5FF" strokeOpacity="0.55" strokeWidth="1.4" />
            <line x1="72" y1="12" x2="126" y2="24" stroke="#FF00C8" strokeOpacity="0.65" strokeWidth="1.4" />
            <line x1="24" y1="26" x2="76" y2="42" stroke="#9D00FF" strokeOpacity="0.55" strokeWidth="1.4" />
            <line x1="76" y1="42" x2="126" y2="24" stroke="#00E5FF" strokeOpacity="0.5" strokeWidth="1.4" />
            {/* Nodes */}
            <circle cx="24" cy="26" r="4.5" fill="#080510" stroke="#00E5FF" strokeWidth="1.8" />
            <circle cx="72" cy="12" r="4" fill="#080510" stroke="#C9A4FF" strokeWidth="1.6" />
            <circle cx="76" cy="42" r="4" fill="#080510" stroke="#9D00FF" strokeWidth="1.6" />
            <circle cx="126" cy="24" r="5" fill="#080510" stroke="#FF00C8" strokeWidth="1.8" />
          </svg>

          <div className="flex items-center justify-between text-[10px] font-mono text-slate-300">
            <span className="text-[#00E5FF] font-semibold">{interfaceCount || 24} host interfaces</span>
            <span className="text-slate-400">1.2ms</span>
          </div>
        </motion.div>

        {/* PANEL 4: RULE GUARD (Top-Right) */}
        <motion.div
          animate={floatLoop(6, 5.5, 0.7)}
          className="pointer-events-auto hidden md:flex items-center gap-3 absolute right-[4%] md:right-[8%] lg:right-[15%] top-[3%] p-3 pr-4 rounded-xl bg-[#0c0717]/85 backdrop-blur-md border border-[#00E5FF]/25 shadow-[0_0_25px_rgba(0,229,255,0.1)] hover:border-[#00E5FF]/70 hover:shadow-[0_0_35px_rgba(0,229,255,0.25)] transition-all duration-300 group"
        >
          {/* Tech corner brackets */}
          <span className="absolute top-1 left-1 w-2 h-2 border-t border-l border-[#00E5FF]/60" />
          <span className="absolute top-1 right-1 w-2 h-2 border-t border-r border-[#00E5FF]/60" />
          <span className="absolute bottom-1 left-1 w-2 h-2 border-b border-l border-[#00E5FF]/60" />
          <span className="absolute bottom-1 right-1 w-2 h-2 border-b border-r border-[#00E5FF]/60" />

          <div className="w-9 h-9 rounded-lg bg-[#140b24] border border-[#00E5FF]/40 flex items-center justify-center relative shadow-inner">
            <Shield className="w-4 h-4 text-[#00E5FF]" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-[#39FF88] shadow-[0_0_6px_#39FF88]" />
          </div>
          <div className="text-left">
            <p className="text-xs font-display font-semibold text-white leading-tight flex items-center gap-1.5">
              <span>Rule Guard</span>
              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-[#00E5FF]/15 text-[#00E5FF] border border-[#00E5FF]/30">ARMED</span>
            </p>
            <p className="text-[10px] font-mono text-[#C9A4FF] mt-0.5">5 Detectors Active · 0 FP</p>
          </div>
        </motion.div>

        {/* PANEL 6: GLOBAL TELEMETRY (Mid-Right) */}
        <motion.div
          animate={floatLoop(7, 7.2, 0.4)}
          className="pointer-events-auto hidden sm:flex flex-col items-center justify-center absolute right-[2%] lg:right-[3%] top-[30%] lg:top-[33%] p-2.5 rounded-2xl bg-[#0c0717]/85 backdrop-blur-md border border-[#C9A4FF]/25 shadow-[0_0_30px_rgba(157,0,255,0.15)] hover:border-[#00E5FF]/60 hover:shadow-[0_0_40px_rgba(0,229,255,0.25)] transition-all duration-300"
        >
          {/* Tech corner brackets */}
          <span className="absolute top-1 left-1 w-2 h-2 border-t border-l border-[#C9A4FF]/60" />
          <span className="absolute top-1 right-1 w-2 h-2 border-t border-r border-[#C9A4FF]/60" />
          <span className="absolute bottom-1 left-1 w-2 h-2 border-b border-l border-[#C9A4FF]/60" />
          <span className="absolute bottom-1 right-1 w-2 h-2 border-b border-r border-[#C9A4FF]/60" />

          <div className="flex items-center gap-1 text-[9px] font-mono text-[#00E5FF] mb-1">
            <Globe className="w-3 h-3 text-[#00E5FF]" />
            <span>GLOBAL TELEMETRY</span>
          </div>
          <RotatingGlobeCanvas reducedMotion={reducedMotion} size={110} />
          <span className="text-[9px] font-mono text-slate-400 mt-1">37.77° N · 122.41° W</span>
        </motion.div>

        {/* PANEL 3: PCAP TRACE (Bottom-Left) */}
        <motion.div
          animate={floatLoop(6, 6.6, 1.1)}
          className="pointer-events-auto hidden sm:flex flex-col gap-2 absolute left-[4%] md:left-[8%] lg:left-[13%] bottom-[4%] w-52 p-3 rounded-xl bg-[#0c0717]/85 backdrop-blur-md border border-[#FF00C8]/30 shadow-[0_0_25px_rgba(255,0,200,0.12)] hover:border-[#FF00C8]/70 hover:shadow-[0_0_35px_rgba(255,0,200,0.25)] transition-all duration-300"
        >
          {/* Tech corner brackets */}
          <span className="absolute top-1 left-1 w-2 h-2 border-t border-l border-[#FF00C8]/60" />
          <span className="absolute top-1 right-1 w-2 h-2 border-t border-r border-[#FF00C8]/60" />
          <span className="absolute bottom-1 left-1 w-2 h-2 border-b border-l border-[#FF00C8]/60" />
          <span className="absolute bottom-1 right-1 w-2 h-2 border-b border-r border-[#FF00C8]/60" />

          <div className="flex items-center justify-between text-[10px] font-mono">
            <span className="text-[#FF36E2] font-semibold flex items-center gap-1">
              <Radio className="w-3 h-3 text-[#FF00C8]" />
              PCAP TRACE
            </span>
            <span className="text-[#00E5FF]">L2→L3→L4</span>
          </div>

          {/* Animated Waveform Equalizer */}
          <div className="flex items-end gap-1 h-8 pt-1" aria-hidden="true">
            {[45, 78, 55, 95, 62, 85, 40, 92, 70, 80, 50, 75, 90, 60].map((h, i) => (
              <span
                key={i}
                style={{ height: `${h}%` }}
                className={`flex-1 rounded-t-sm transition-all duration-500 ${
                  i % 4 === 1
                    ? 'bg-[#FF00C8] shadow-[0_0_6px_#FF00C8]'
                    : i % 4 === 3
                    ? 'bg-[#C9A4FF]'
                    : 'bg-[#00E5FF] shadow-[0_0_6px_#00E5FF]'
                }`}
              />
            ))}
          </div>

          <div className="flex items-center justify-between text-[10px] font-mono text-slate-300">
            <span>Header-Only Forensics</span>
            <span className="text-[#39FF88] text-[9px]">BUFFER 100%</span>
          </div>
        </motion.div>
      </motion.div>

      {/* 6. FLOATING HOLOGRAPHIC DATA PANELS - LAYER 2 (PARALLAX OUTER) */}
      <motion.div
        style={reducedMotion ? undefined : { x: outerLayerX, y: outerLayerY }}
        className="pointer-events-none absolute inset-0 z-20"
      >
        {/* PANEL 2: FLOW VECTOR (Mid-Left) */}
        <motion.div
          animate={floatLoop(8, 7.4, 0.3)}
          className="pointer-events-auto hidden md:block absolute left-[1%] lg:left-[2%] top-[34%] w-56 p-3 rounded-xl bg-[#0c0717]/90 backdrop-blur-md border border-[#00E5FF]/25 shadow-[0_0_30px_rgba(0,229,255,0.12)] hover:border-[#00E5FF]/70 hover:shadow-[0_0_40px_rgba(0,229,255,0.25)] transition-all duration-300"
        >
          {/* Tech corner brackets */}
          <span className="absolute top-1 left-1 w-2 h-2 border-t border-l border-[#00E5FF]/60" />
          <span className="absolute top-1 right-1 w-2 h-2 border-t border-r border-[#00E5FF]/60" />
          <span className="absolute bottom-1 left-1 w-2 h-2 border-b border-l border-[#00E5FF]/60" />
          <span className="absolute bottom-1 right-1 w-2 h-2 border-b border-r border-[#00E5FF]/60" />

          <div className="flex items-center justify-between text-[10px] font-mono text-[#00E5FF] mb-1.5">
            <span className="flex items-center gap-1.5">
              <Activity className="w-3 h-3 text-[#00E5FF]" />
              FLOW VECTOR
            </span>
            <span className="px-1.5 py-0.5 rounded bg-[#00E5FF]/15 text-[#00E5FF] font-semibold text-[9px] border border-[#00E5FF]/30">
              {protoDisplay}
            </span>
          </div>
          <p className="text-[11px] font-mono text-slate-100 truncate">{srcDisplay}</p>
          <p className="text-[11px] font-mono text-[#00E5FF] truncate mt-0.5">→ {dstDisplay}</p>
          <div className="flex items-center justify-between text-[9px] font-mono text-slate-400 mt-2 pt-1.5 border-t border-slate-800">
            <span>CHACHA20-POLY1305</span>
            <span className="text-[#39FF88]">STREAM ACTIVE</span>
          </div>
        </motion.div>

        {/* PANEL 5: FRAME METADATA & NETSCOPE CLI (Bottom-Right) */}
        <motion.div
          animate={floatLoop(7, 6.0, 0.5)}
          className="pointer-events-auto hidden md:block absolute right-[4%] md:right-[8%] lg:right-[12%] bottom-[4%] w-60 rounded-xl overflow-hidden bg-[#0c0717]/95 backdrop-blur-md border border-[#9D00FF]/40 shadow-[0_0_30px_rgba(157,0,255,0.15)] hover:border-[#00E5FF]/70 transition-all duration-300"
        >
          {/* Header */}
          <div className="px-3 py-1.5 bg-[#140b24] border-b border-[#9D00FF]/30 flex items-center justify-between text-[10px] font-mono text-[#C9A4FF]">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-[#FF00C8]" />
              netscope-cli
            </span>
            <span className="flex items-center gap-1 text-[#00E5FF]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00E5FF] animate-pulse" />
              live
            </span>
          </div>

          {/* Terminal Body */}
          <div className="p-3 font-mono text-[10px] leading-relaxed space-y-1">
            <p className="text-slate-200">
              <span className="text-[#FF00C8] font-bold">$</span> watch --iface {activeInterface || 'Wi-Fi'}
            </p>
            <p className="text-[#00E5FF]">engine: heuristic + tls_sni</p>
            <div className="flex items-center justify-between text-slate-400 pt-1 text-[9px] border-t border-slate-800/80">
              <span>FRAME: {sizeDisplay}</span>
              <span className="text-[#FF36E2]">{flagsDisplay}</span>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* 7. COMPACT MOBILE TELEMETRY DOCK (Strictly on small screens) */}
      <div className="sm:hidden absolute bottom-0 inset-x-2 flex items-center justify-between px-3.5 py-2.5 rounded-xl bg-[#0c0717]/90 backdrop-blur-md border border-[#00E5FF]/30 text-[10px] font-mono text-slate-200 shadow-xl z-30">
        <span className="flex items-center gap-1 text-[#00E5FF]">
          <Wifi className="w-3 h-3 text-[#00E5FF]" />
          {activeInterface || 'Wi-Fi'}
        </span>
        <span className="text-[#C9A4FF]">{protoDisplay}</span>
        <span className="text-[#39FF88] flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-[#39FF88] animate-pulse" />
          5 Rules Active
        </span>
      </div>
    </div>
  );
};
