import React, { useState } from 'react';
import {
  Activity,
  BarChart3,
  Cpu,
  FileSearch,
  FlaskConical,
  Globe,
  HardDriveUpload,
  LayoutDashboard,
  ListChecks,
  LogIn,
  LogOut,
  Menu,
  Network,
  Play,
  Radar,
  Settings as SettingsIcon,
  ShieldAlert,
  Square,
  X,
} from 'lucide-react';
import { useApp, type PageId } from '../../context/AppContext';
import { useAuth } from '../../context/AuthContext';

interface NavGroup {
  label: string;
  items: { id: PageId; title: string; icon: React.ComponentType<{ className?: string }> }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Command Operations',
    items: [
      { id: 'overview', title: 'Command Centre', icon: LayoutDashboard },
      { id: 'live-traffic', title: 'Live Traffic', icon: Activity },
      { id: 'packet-inspector', title: 'Packet Inspector', icon: FileSearch },
      { id: 'network-universe', title: 'Network Universe', icon: Network },
      { id: 'protocol-intelligence', title: 'Protocol Intel', icon: Radar },
    ],
  },
  {
    label: 'Threat & Forensics',
    items: [
      { id: 'threat-centre', title: 'Threat Detection', icon: ShieldAlert },
      { id: 'ai-investigator', title: 'AI Investigator', icon: Cpu },
      { id: 'ip-intelligence', title: 'IP Intelligence', icon: Globe },
      { id: 'pcap-forensics', title: 'PCAP Forensics', icon: HardDriveUpload },
    ],
  },
  {
    label: 'Lab & Governance',
    items: [
      { id: 'simulation-lab', title: 'Simulation Lab', icon: FlaskConical },
      { id: 'incidents', title: 'Incidents', icon: ListChecks },
      { id: 'reports', title: 'Reports & Export', icon: BarChart3 },
      { id: 'settings', title: 'Settings', icon: SettingsIcon },
    ],
  },
];

const PAGE_TITLES: Record<PageId, string> = {
  launch: 'NETSCOPE X',
  overview: 'Command Centre',
  'live-traffic': 'Live Traffic',
  'packet-inspector': 'Packet Inspector',
  'network-universe': 'Network Universe 3D',
  'protocol-intelligence': 'Protocol Intelligence',
  'threat-centre': 'Threat Detection Centre',
  'ai-investigator': 'AI Security Investigator',
  'ip-intelligence': 'IP Intelligence',
  'pcap-forensics': 'PCAP Forensics Lab',
  'simulation-lab': 'Attack Simulation Lab',
  incidents: 'Incident Management',
  reports: 'Reports & Analytics',
  settings: 'System Settings',
};

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const {
    activePage,
    navigate,
    status,
    startCapture,
    stopCapture,
    alerts,
    toasts,
  } = useApp();
  const { user, signInWithGoogle, logout } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const openAlertsCount = alerts.filter((a) => a.status !== 'resolved').length;

  const handleToggleCapture = () => {
    if (status.capturing) stopCapture();
    else startCapture(status.activeInterface);
  };

  return (
    <div className="min-h-screen bg-[#080510] text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:w-64 lg:flex-col border-r border-[#C9A4FF]/15 bg-[#10091B] shrink-0">
        <div className="h-16 px-5 flex items-center justify-between border-b border-[#C9A4FF]/15">
          <button
            type="button"
            onClick={() => navigate('launch')}
            className="flex items-center gap-2.5 font-display font-bold text-lg tracking-tight text-white whitespace-nowrap group"
          >
            <img
              src="/src/assets/images/netscope_soc_emblem_1795167718378.jpg"
              alt="NETSCOPE X Emblem"
              referrerPolicy="no-referrer"
              className="w-7 h-7 rounded-full object-cover border border-[#00E5FF]/40 group-hover:border-[#FF00C8]/60 transition-colors"
            />
            <span>
              NETSCOPE <span className="text-[#00E5FF]">X</span>
            </span>
          </button>
        </div>

        <nav aria-label="Primary SOC Navigation" className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              <p className="px-3 mb-2 text-[11px] font-medium text-slate-500">
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active = activePage === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => navigate(item.id)}
                      className={`w-full flex items-center justify-between gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                        active
                          ? 'bg-[#00E5FF]/12 text-[#00E5FF] border border-[#00E5FF]/30'
                          : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                      }`}
                    >
                      <span className="flex items-center gap-2.5 min-w-0 truncate">
                        <Icon className="w-4 h-4 shrink-0" />
                        <span className="truncate">{item.title}</span>
                      </span>
                      {item.id === 'threat-centre' && openAlertsCount > 0 && (
                        <span className="font-mono text-xs tabular-nums text-[#FF3B5C]">
                          {openAlertsCount}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Analyst Auth Footer */}
        <div className="p-3 border-t border-slate-800/80">
          {user ? (
            <div className="flex items-center justify-between gap-2 px-2 py-1.5">
              <div className="min-w-0">
                <p className="text-xs font-medium text-slate-200 truncate">
                  {user.displayName || 'SOC Analyst'}
                </p>
                <p className="text-[11px] text-slate-500 truncate">{user.email}</p>
              </div>
              <button
                type="button"
                onClick={logout}
                aria-label="Sign out"
                className="p-1.5 text-slate-400 hover:text-slate-100 rounded-md hover:bg-slate-800"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={signInWithGoogle}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF]/50 hover:text-[#00E5FF] transition-colors whitespace-nowrap"
            >
              <LogIn className="w-3.5 h-3.5" />
              Sign In to Sync Cloud Incidents
            </button>
          )}
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative w-68 max-w-[82vw] bg-[#10091B] border-r border-[#C9A4FF]/20 flex flex-col h-full z-10">
            <div className="h-14 px-4 flex items-center justify-between border-b border-[#C9A4FF]/15">
              <button
                type="button"
                onClick={() => {
                  navigate('launch');
                  setMobileMenuOpen(false);
                }}
                className="flex items-center gap-2 font-display font-bold text-base text-white whitespace-nowrap group cursor-pointer"
              >
                <img
                  src="/src/assets/images/netscope_soc_emblem_1795167718378.jpg"
                  alt="NETSCOPE X Emblem"
                  referrerPolicy="no-referrer"
                  className="w-6 h-6 rounded-full object-cover border border-[#00E5FF]/40 group-hover:border-[#FF00C8]/60 transition-colors"
                />
                <span>
                  NETSCOPE <span className="text-[#00E5FF]">X</span>
                </span>
              </button>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation"
                className="p-1.5 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 overflow-y-auto px-3 py-3 space-y-5">
              {NAV_GROUPS.map((group) => (
                <div key={group.label}>
                  <p className="px-3 mb-1.5 text-[11px] font-medium text-slate-500">
                    {group.label}
                  </p>
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const active = activePage === item.id;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => {
                          navigate(item.id);
                          setMobileMenuOpen(false);
                        }}
                        className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium ${
                          active
                            ? 'bg-[#00E5FF]/12 text-[#00E5FF]'
                            : 'text-slate-300 hover:bg-slate-800/60'
                        }`}
                      >
                        <Icon className="w-4 h-4 shrink-0" />
                        <span>{item.title}</span>
                      </button>
                    );
                  })}
                </div>
              ))}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Clean 3-Zone Top Bar */}
        <header className="h-16 px-4 lg:px-6 border-b border-[#C9A4FF]/15 bg-[#10091B]/95 flex items-center justify-between gap-6 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden p-2 rounded-lg border border-[#C9A4FF]/20 text-slate-300 hover:text-white"
            >
              <Menu className="w-4 h-4" />
            </button>
            <h1 className="font-display font-semibold text-base lg:text-lg text-white truncate">
              {PAGE_TITLES[activePage]}
            </h1>
          </div>

          <div className="hidden md:flex items-center gap-3 text-xs text-slate-400 font-mono whitespace-nowrap">
            <span>Interface: {status.activeInterface}</span>
            <span aria-hidden="true" className="text-slate-700">/</span>
            <span className={status.capturing ? 'text-[#39FF88]' : 'text-slate-400'}>
              {status.capturing ? `Capturing (${status.captureMode})` : 'Capture Idle'}
            </span>
            {status.simulationActive && (
              <>
                <span aria-hidden="true" className="text-slate-700">/</span>
                <span className="text-[#FF9F43] font-semibold">Simulation Active</span>
              </>
            )}
          </div>

          <div className="shrink-0">
            <button
              type="button"
              onClick={handleToggleCapture}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                status.capturing
                  ? 'bg-[#FF3B5C] text-white hover:bg-[#ff5270]'
                  : 'bg-[#00E5FF] text-[#070910] hover:bg-[#33ebff]'
              }`}
            >
              {status.capturing ? (
                <>
                  <Square className="w-3.5 h-3.5" />
                  Stop Capture
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  Start Capture
                </>
              )}
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 lg:p-6 soc-grid-bg overflow-y-auto">
          <div className="max-w-[1440px] mx-auto space-y-6">{children}</div>
        </main>
      </div>

      {/* Toast Stack */}
      {toasts.length > 0 && (
        <div
          aria-live="polite"
          className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm w-full pointer-events-none"
        >
          {toasts.map((t) => (
            <div
              key={t.id}
              className={`px-4 py-2.5 rounded-lg border text-xs font-medium shadow-xl pointer-events-auto bg-[#190626] ${
                t.tone === 'error'
                  ? 'border-[#FF3B5C]/60 text-[#FF3B5C]'
                  : t.tone === 'warn'
                  ? 'border-[#FF9F43]/60 text-[#FF9F43]'
                  : t.tone === 'success'
                  ? 'border-[#39FF88]/50 text-[#39FF88]'
                  : 'border-[#00E5FF]/50 text-[#00E5FF]'
              }`}
            >
              {t.title}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
