import React, { useState } from 'react';
import { motion } from 'motion/react';
import { ArrowRight, LogIn, LogOut, ShieldCheck, X } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useAuth } from '../context/AuthContext';
import { CosmosConstellation } from '../components/landing/CosmosConstellation';
import { AuthModal } from '../components/common/AuthModal';

export const Launch: React.FC = () => {
  const { navigate, interfaces, packets, status, settings } = useApp();
  const { user, authError, signInWithGoogle, logout } = useAuth();
  const [authModalMode, setAuthModalMode] = useState<'login' | 'signup' | null>(null);
  const rm = settings.reducedMotion;

  return (
    <div className="min-h-screen bg-[#080510] text-slate-100 relative overflow-x-hidden flex flex-col justify-between">
      {/* Deep Cosmos Void Backdrop + Subtle Measured Vignette */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <img
          src="/src/assets/images/netscope_launch_backdrop_1795167717143.jpg"
          alt="NETSCOPE X Void Atmosphere"
          referrerPolicy="no-referrer"
          className="w-full h-full object-cover opacity-20 mix-blend-screen"
        />
        {/* Subtle Cyber Grid Floor */}
        <div className="absolute inset-0 soc-grid-bg opacity-30" />
        <div
          className="absolute inset-0"
          style={{
            background:
              'radial-gradient(ellipse 85% 65% at 50% 40%, rgba(91, 27, 255, 0.18) 0%, rgba(16, 9, 27, 0.76) 52%, #080510 100%)',
          }}
        />
      </div>

      {/* Transparent Minimal Top Navigation */}
      <header className="relative z-30 w-full max-w-7xl mx-auto px-5 sm:px-8 py-5 flex items-center justify-between gap-4">
        <button
          type="button"
          onClick={() => navigate('overview')}
          className="flex items-center gap-3 text-left group whitespace-nowrap shrink-0"
        >
          <img
            src="/src/assets/images/netscope_soc_emblem_1795167718378.jpg"
            alt="NETSCOPE X Emblem"
            referrerPolicy="no-referrer"
            className="w-8 h-8 rounded-full object-cover border border-[#00E5FF]/40 group-hover:border-[#FF00C8]/60 transition-colors"
          />
          <span className="font-display font-bold text-base sm:text-lg tracking-tight text-white">
            NETSCOPE <span className="text-[#00E5FF]">X</span>
          </span>
        </button>

        <nav aria-label="Account Actions" className="flex items-center gap-3 sm:gap-5 shrink-0">
          {user ? (
            <>
              <span className="hidden sm:inline text-xs font-mono text-[#C9A4FF] truncate max-w-[180px]">
                {user.displayName || user.email}
              </span>
              <button
                type="button"
                onClick={() => navigate('overview')}
                className="text-xs sm:text-sm font-medium text-slate-200 hover:text-[#00E5FF] transition-colors whitespace-nowrap"
              >
                Command Centre
              </button>
              <button
                type="button"
                onClick={logout}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs sm:text-sm font-medium rounded-lg border border-[#C9A4FF]/30 text-[#C9A4FF] hover:border-[#FF00C8]/60 hover:text-white transition-colors whitespace-nowrap"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign out
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                onClick={() => setAuthModalMode('login')}
                className="text-xs sm:text-sm font-medium text-[#C9A4FF] hover:text-white transition-colors px-2 py-1.5 whitespace-nowrap"
              >
                Log in
              </button>
              <button
                type="button"
                onClick={() => setAuthModalMode('signup')}
                className="px-4 py-2 text-xs sm:text-sm font-medium rounded-lg bg-[#10091B]/80 border border-[#9D00FF]/45 text-white hover:border-[#FF00C8] hover:bg-[#190626] transition-colors whitespace-nowrap"
              >
                Sign up
              </button>
            </>
          )}
        </nav>
      </header>

      {/* Immersive Central Constellation + Below-Visual Typography & Single Primary CTA */}
      <main className="relative z-20 flex-1 w-full max-w-7xl mx-auto px-5 sm:px-8 pt-2 pb-12 flex flex-col items-center justify-center">
        {/* Orbital Cybersecurity Constellation Centerpiece */}
        <CosmosConstellation
          latestPacket={packets[0]}
          activeInterface={status.activeInterface}
          interfaceCount={interfaces.length}
          reducedMotion={rm}
        />

        {/* Editorial Typography & Primary CTA Directly Below Central Visual */}
        <motion.div
          initial={rm ? false : { opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.08 }}
          className="relative z-30 mt-3 sm:mt-5 max-w-3xl mx-auto text-center flex flex-col items-center space-y-4"
        >
          {/* Eyebrow Technical Pill */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10091B]/80 border border-[#00E5FF]/30 text-[10px] sm:text-xs font-mono tracking-widest text-[#00E5FF] shadow-[0_0_12px_rgba(0,229,255,0.2)]">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00E5FF] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00E5FF]" />
            </span>
            <span>TACTICAL INTELLIGENCE GRID // v2.5 · ACTIVE ENGINE</span>
          </div>

          <h1 className="font-display font-black text-2xl sm:text-4xl lg:text-[44px] tracking-tight text-transparent bg-clip-text bg-gradient-to-b from-white via-slate-100 to-[#C9A4FF]/80 leading-[1.1] [text-wrap:balance] drop-shadow-[0_2px_16px_rgba(0,229,255,0.2)]">
            SEE THE NETWORK. DETECT THE THREAT.
          </h1>

          <p className="font-sans text-xs sm:text-sm lg:text-base text-slate-300 max-w-xl leading-relaxed">
            A unified network intelligence platform for real-time traffic analysis, protocol
            inspection, anomaly detection and PCAP forensics.
          </p>

          {/* Quick Telemetry Capability Badges */}
          <div className="flex flex-wrap items-center justify-center gap-2 text-[10px] sm:text-[11px] font-mono text-[#C9A4FF]/80 pt-0.5">
            <span className="px-2.5 py-1 rounded-md bg-[#10091B]/80 border border-[#C9A4FF]/15">
              ⚡ Zero-Payload Memory
            </span>
            <span className="px-2.5 py-1 rounded-md bg-[#10091B]/80 border border-[#C9A4FF]/15">
              🛡️ 5 Threat Detectors
            </span>
            <span className="px-2.5 py-1 rounded-md bg-[#10091B]/80 border border-[#C9A4FF]/15">
              🌐 Real-Time 3D Topology
            </span>
          </div>

          <div className="pt-2">
            <button
              type="button"
              onClick={() => navigate('overview')}
              className="relative group inline-flex items-center gap-3 px-8 py-3.5 sm:px-9 sm:py-4 rounded-xl bg-gradient-to-r from-[#FF00C8] to-[#9D00FF] hover:from-[#FF1FD0] hover:to-[#B324FF] text-white font-display font-bold text-xs sm:text-sm tracking-wide transition-all duration-300 shadow-[0_0_35px_rgba(255,0,200,0.35),0_0_15px_rgba(0,229,255,0.2)] hover:shadow-[0_0_50px_rgba(255,0,200,0.5),0_0_25px_rgba(0,229,255,0.35)] hover:scale-[1.02] active:scale-[0.98] border border-white/20 whitespace-nowrap cursor-pointer"
            >
              {/* Corner tech ticks */}
              <span className="absolute top-1 left-1 w-2 h-2 border-t-2 border-l-2 border-white/80" />
              <span className="absolute top-1 right-1 w-2 h-2 border-t-2 border-r-2 border-white/80" />
              <span className="absolute bottom-1 left-1 w-2 h-2 border-b-2 border-l-2 border-white/80" />
              <span className="absolute bottom-1 right-1 w-2 h-2 border-b-2 border-r-2 border-white/80" />

              <span className="relative z-10 flex items-center gap-2.5">
                <span>ENTER COMMAND CENTRE</span>
                <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
              </span>
            </button>
          </div>
        </motion.div>
      </main>

      {/* Supabase Authentication Modal */}
      <AuthModal
        isOpen={Boolean(authModalMode)}
        initialMode={authModalMode || 'login'}
        onClose={() => setAuthModalMode(null)}
      />
    </div>
  );
};
