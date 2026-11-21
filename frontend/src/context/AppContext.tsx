import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { api } from '../services/api';
import { DEFAULT_THRESHOLDS } from '../core/detectionEngine';
import type {
  AppSettings,
  CaptureSessionSummary,
  NetworkDeviceNode,
  NetworkEdge,
  NetworkInterfaceInfo,
  PacketRecord,
  SecurityAlert,
  TerminalEvent,
  TrafficStats,
} from '../core/types';

export type PageId =
  | 'launch'
  | 'overview'
  | 'live-traffic'
  | 'packet-inspector'
  | 'network-universe'
  | 'protocol-intelligence'
  | 'threat-centre'
  | 'ai-investigator'
  | 'ip-intelligence'
  | 'pcap-forensics'
  | 'simulation-lab'
  | 'incidents'
  | 'reports'
  | 'settings';

export interface ToastMessage {
  id: string;
  title: string;
  tone: 'info' | 'success' | 'warn' | 'error';
}

interface CaptureStatusState {
  capturing: boolean;
  activeInterface: string;
  captureMode: string;
  activeSession: CaptureSessionSummary | null;
  packetCount: number;
  alertCount: number;
  simulationActive: boolean;
  activeScenario: string | null;
}

interface AppContextValue {
  activePage: PageId;
  navigate: (page: PageId) => void;
  status: CaptureStatusState;
  interfaces: NetworkInterfaceInfo[];
  packets: PacketRecord[];
  alerts: SecurityAlert[];
  events: TerminalEvent[];
  stats: TrafficStats | null;
  topology: { nodes: NetworkDeviceNode[]; edges: NetworkEdge[] };
  settings: AppSettings;
  selectedPacket: PacketRecord | null;
  setSelectedPacket: (pkt: PacketRecord | null) => void;
  selectedAlert: SecurityAlert | null;
  setSelectedAlert: (alert: SecurityAlert | null) => void;
  selectedNodeIp: string | null;
  setSelectedNodeIp: (ip: string | null) => void;
  wsConnected: boolean;
  toasts: ToastMessage[];
  pushToast: (title: string, tone?: ToastMessage['tone']) => void;
  startCapture: (iface?: string) => Promise<void>;
  stopCapture: () => Promise<void>;
  refreshStatsAndTopology: (windowSeconds?: number, includeSimulated?: boolean) => Promise<void>;
  refreshAlerts: () => Promise<void>;
  refreshEvents: () => Promise<void>;
  updateAlertState: (
    id: string,
    patch: Partial<Pick<SecurityAlert, 'status' | 'notes' | 'falsePositive' | 'classification' | 'aiAnalysis'>>,
  ) => Promise<void>;
  updateSettingsState: (patch: Partial<AppSettings>) => Promise<void>;
  clearTerminalEvents: () => void;
  windowSeconds: number;
  setWindowSeconds: (sec: number) => void;
  includeSimulatedInOverview: boolean;
  setIncludeSimulatedInOverview: (val: boolean) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const initialAutostart =
    typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('autostart') === '1';

  const [activePage, setActivePage] = useState<PageId>(initialAutostart ? 'overview' : 'launch');
  const [wsConnected, setWsConnected] = useState(false);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [packets, setPackets] = useState<PacketRecord[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [events, setEvents] = useState<TerminalEvent[]>([]);
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [topology, setTopology] = useState<{ nodes: NetworkDeviceNode[]; edges: NetworkEdge[] }>({
    nodes: [],
    edges: [],
  });
  const [status, setStatus] = useState<CaptureStatusState>({
    capturing: false,
    activeInterface: 'eth1',
    captureMode: 'Stopped',
    activeSession: null,
    packetCount: 0,
    alertCount: 0,
    simulationActive: false,
    activeScenario: null,
  });
  const [settings, setSettings] = useState<AppSettings>({
    defaultInterface: 'eth1',
    maxPackets: 2000,
    retentionMinutes: 60,
    thresholds: { ...DEFAULT_THRESHOLDS },
    reducedMotion: false,
    preferredAiModel: 'gemini-3.8-flash',
    useHighThinking: true,
  });

  const [selectedPacket, setSelectedPacket] = useState<PacketRecord | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [selectedNodeIp, setSelectedNodeIp] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [windowSeconds, setWindowSeconds] = useState<number>(300);
  const [includeSimulatedInOverview, setIncludeSimulatedInOverview] = useState<boolean>(true);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);

  const pushToast = useCallback((title: string, tone: ToastMessage['tone'] = 'info') => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setToasts((prev) => [...prev.slice(-3), { id, title, tone }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  const navigate = useCallback((page: PageId) => {
    setActivePage(page);
  }, []);

  const refreshStatsAndTopology = useCallback(
    async (winSec = windowSeconds, incSim = includeSimulatedInOverview) => {
      try {
        const [nextStats, nextTopo] = await Promise.all([
          api.getStats(winSec, incSim),
          api.getTopology('ALL', incSim),
        ]);
        setStats(nextStats);
        setTopology(nextTopo);
      } catch (err) {
        console.error('Stats/topology refresh failed:', err);
      }
    },
    [windowSeconds, includeSimulatedInOverview],
  );

  const refreshAlerts = useCallback(async () => {
    try {
      const res = await api.getAlerts(true);
      if (Array.isArray(res.alerts)) setAlerts(res.alerts);
    } catch (err) {
      console.error('Failed to refresh alerts:', err);
    }
  }, []);

  const refreshEvents = useCallback(async () => {
    try {
      const res = await api.getEvents();
      if (Array.isArray(res.events)) setEvents(res.events);
    } catch (err) {
      console.error('Failed to refresh events:', err);
    }
  }, []);

  // Initial HTTP bootstrap
  useEffect(() => {
    Promise.all([
      api.getInterfaces(),
      api.getCaptureStatus(),
      api.getSettings(),
      api.getAlerts(true),
      api.getEvents(),
      api.getPackets({ page: 1, pageSize: 100, sortBy: 'timestamp', sortDir: 'desc' }),
    ])
      .then(([ifRes, stRes, setRes, alRes, evRes, pkRes]) => {
        setInterfaces(ifRes.interfaces);
        setStatus(stRes);
        setSettings(setRes);
        setAlerts(alRes.alerts);
        setEvents(evRes.events);
        setPackets(pkRes.items);
      })
      .catch((err) => console.error('Initial bootstrap error:', err));

    refreshStatsAndTopology(300, true);
  }, [refreshStatsAndTopology]);

  // Periodic stats & topology sync every 2.5s
  useEffect(() => {
    const timer = window.setInterval(() => {
      refreshStatsAndTopology(windowSeconds, includeSimulatedInOverview);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [refreshStatsAndTopology, windowSeconds, includeSimulatedInOverview]);

  // WebSocket stream with automatic reconnection
  useEffect(() => {
    let closed = false;

    const connect = () => {
      if (closed) return;
      let wsTarget = '';
      const customBackend = (import.meta.env.VITE_BACKEND_URL || import.meta.env.VITE_WS_URL || '').replace(/\/$/, '');
      if (customBackend) {
        const wsProto = customBackend.startsWith('https') ? 'wss:' : 'ws:';
        const cleanHost = customBackend.replace(/^https?:\/\//, '');
        wsTarget = `${wsProto}//${cleanHost}/ws`;
      } else {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        wsTarget = `${proto}//${window.location.host}/ws`;
      }
      const ws = new WebSocket(wsTarget);
      wsRef.current = ws;

      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => {
        setWsConnected(false);
        if (!closed) {
          reconnectTimerRef.current = window.setTimeout(connect, 2500);
        }
      };
      ws.onerror = () => {
        ws.close();
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'init') {
            if (msg.data.status) setStatus(msg.data.status);
            if (msg.data.stats) setStats(msg.data.stats);
            if (Array.isArray(msg.data.alerts)) setAlerts(msg.data.alerts);
            if (Array.isArray(msg.data.events)) setEvents(msg.data.events);
            if (Array.isArray(msg.data.packets)) {
              const seen = new Set<string>();
              const deduped: PacketRecord[] = [];
              for (const p of (msg.data.packets as PacketRecord[]).slice().reverse()) {
                if (!seen.has(p.id)) {
                  seen.add(p.id);
                  deduped.push(p);
                }
              }
              setPackets(deduped);
            }
          } else if (msg.type === 'packets' && Array.isArray(msg.data)) {
            const incoming = msg.data as PacketRecord[];
            setPackets((prev) => {
              const seen = new Set(prev.map((p) => p.id));
              const fresh = incoming.filter((p) => !seen.has(p.id)).reverse();
              if (fresh.length === 0) return prev;
              return [...fresh, ...prev].slice(0, 400);
            });
          } else if (msg.type === 'alert' && msg.data) {
            const alert = msg.data as SecurityAlert;
            setAlerts((prev) => [alert, ...prev.filter((a) => a.id !== alert.id)].slice(0, 200));
            pushToast(
              `${alert.isSimulated ? '[SIMULATED] ' : ''}${alert.severity} alert: ${alert.ruleName}`,
              alert.severity === 'Critical' || alert.severity === 'High' ? 'error' : 'warn',
            );
          } else if (msg.type === 'alert_updated' && msg.data) {
            const updated = msg.data as SecurityAlert;
            setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
            setSelectedAlert((cur) => (cur?.id === updated.id ? updated : cur));
          } else if (msg.type === 'event' && msg.data) {
            const evt = msg.data as TerminalEvent;
            setEvents((prev) => [evt, ...prev].slice(0, 250));
          } else if (msg.type === 'status' && msg.data) {
            setStatus(msg.data);
          } else if (msg.type === 'simulation_cleared') {
            setAlerts((prev) => prev.filter((a) => !a.isSimulated));
            setEvents((prev) => prev.filter((e) => !e.isSimulated));
            setPackets((prev) => prev.filter((p) => !p.isSimulated));
          }
        } catch {
          // ignore malformed frames
        }
      };
    };

    connect();
    return () => {
      closed = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [pushToast]);

  const startCapture = useCallback(
    async (iface?: string) => {
      try {
        const res = await api.startCapture(iface);
        setStatus(res);
        pushToast(`Live capture active on ${res.activeInterface}`, 'success');
      } catch (err) {
        pushToast(err instanceof Error ? err.message : 'Unable to start capture', 'error');
      }
    },
    [pushToast],
  );

  const stopCapture = useCallback(async () => {
    try {
      const res = await api.stopCapture();
      setStatus(res);
      pushToast('Packet capture stopped', 'info');
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Unable to stop capture', 'error');
    }
  }, [pushToast]);

  const updateAlertState = useCallback(
    async (
      id: string,
      patch: Partial<Pick<SecurityAlert, 'status' | 'notes' | 'falsePositive' | 'classification' | 'aiAnalysis'>>,
    ) => {
      const updated = await api.updateAlert(id, patch);
      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setSelectedAlert((cur) => (cur?.id === updated.id ? updated : cur));
      pushToast(`Updated alert ${id}`, 'success');
    },
    [pushToast],
  );

  const updateSettingsState = useCallback(
    async (patch: Partial<AppSettings>) => {
      const updated = await api.updateSettings(patch);
      setSettings(updated);
      pushToast('Configuration saved', 'success');
    },
    [pushToast],
  );

  const clearTerminalEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return (
    <AppContext.Provider
      value={{
        activePage,
        navigate,
        status,
        interfaces,
        packets,
        alerts,
        events,
        stats,
        topology,
        settings,
        selectedPacket,
        setSelectedPacket,
        selectedAlert,
        setSelectedAlert,
        selectedNodeIp,
        setSelectedNodeIp,
        wsConnected,
        toasts,
        pushToast,
        startCapture,
        stopCapture,
        refreshStatsAndTopology,
        refreshAlerts,
        refreshEvents,
        updateAlertState,
        updateSettingsState,
        clearTerminalEvents,
        windowSeconds,
        setWindowSeconds,
        includeSimulatedInOverview,
        setIncludeSimulatedInOverview,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used inside AppProvider');
  return ctx;
}
