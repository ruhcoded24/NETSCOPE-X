import { supabase } from '../lib/supabase';
import type {
  AppSettings,
  CaptureSessionSummary,
  ForensicReport,
  IpIntelResult,
  NetworkDeviceNode,
  NetworkEdge,
  NetworkInterfaceInfo,
  PacketFilterQuery,
  PacketRecord,
  ProtocolName,
  SecurityAlert,
  SimulationScenarioId,
  TerminalEvent,
  TrafficStats,
} from '../core/types';

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((init?.headers as Record<string, string>) ?? {}),
  };

  // Automatically attach Supabase JWT authorization header when signed in
  if (supabase) {
    try {
      const { data } = await supabase.auth.getSession();
      if (data?.session?.access_token) {
        headers['Authorization'] = `Bearer ${data.session.access_token}`;
      }
    } catch {
      // Standalone mode if session unavailable
    }
  }

  const res = await fetch(url, {
    ...init,
    headers,
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data?.detail || data?.error || `HTTP ${res.status}`);
  }
  return data as T;
}

export const api = {
  getInterfaces: () => requestJson<{ interfaces: NetworkInterfaceInfo[] }>('/api/interfaces'),

  getCaptureStatus: () =>
    requestJson<{
      capturing: boolean;
      activeInterface: string;
      captureMode: string;
      activeSession: CaptureSessionSummary | null;
      packetCount: number;
      alertCount: number;
      simulationActive: boolean;
      activeScenario: string | null;
    }>('/api/capture/status'),

  startCapture: (interfaceName?: string) =>
    requestJson<{
      capturing: boolean;
      activeInterface: string;
      captureMode: string;
      activeSession: CaptureSessionSummary | null;
      packetCount: number;
      alertCount: number;
      simulationActive: boolean;
      activeScenario: string | null;
    }>('/api/capture/start', {
      method: 'POST',
      body: JSON.stringify({ interfaceName }),
    }),

  stopCapture: () =>
    requestJson<{
      capturing: boolean;
      activeInterface: string;
      captureMode: string;
      activeSession: CaptureSessionSummary | null;
      packetCount: number;
      alertCount: number;
      simulationActive: boolean;
      activeScenario: string | null;
    }>('/api/capture/stop', { method: 'POST' }),

  getSessions: () => requestJson<{ sessions: CaptureSessionSummary[] }>('/api/sessions'),

  getPackets: (query: PacketFilterQuery) => {
    const params = new URLSearchParams();
    Object.entries(query).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
    });
    return requestJson<{ items: PacketRecord[]; total: number }>(`/api/packets?${params.toString()}`);
  },

  getStats: (windowSeconds = 300, includeSimulated = false) =>
    requestJson<TrafficStats>(
      `/api/stats?windowSeconds=${windowSeconds}&includeSimulated=${includeSimulated}`,
    ),

  getTopology: (protocol: ProtocolName | 'ALL' = 'ALL', includeSimulated = true) =>
    requestJson<{ nodes: NetworkDeviceNode[]; edges: NetworkEdge[] }>(
      `/api/topology?protocol=${encodeURIComponent(protocol)}&includeSimulated=${includeSimulated}`,
    ),

  getAlerts: (includeSimulated = true) =>
    requestJson<{ alerts: SecurityAlert[] }>(`/api/alerts?includeSimulated=${includeSimulated}`),

  updateAlert: (
    id: string,
    patch: Partial<Pick<SecurityAlert, 'status' | 'notes' | 'falsePositive' | 'classification' | 'aiAnalysis'>>,
  ) =>
    requestJson<SecurityAlert>(`/api/alerts/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),

  getEvents: () => requestJson<{ events: TerminalEvent[] }>('/api/events'),

  getSettings: () => requestJson<AppSettings>('/api/settings'),

  updateSettings: (settings: Partial<AppSettings>) =>
    requestJson<AppSettings>('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    }),

  uploadPcap: (fileName: string, base64Data: string) =>
    requestJson<ForensicReport>('/api/forensics/upload', {
      method: 'POST',
      body: JSON.stringify({ fileName, base64Data }),
    }),

  analyzeSamplePcap: () =>
    requestJson<ForensicReport>('/api/forensics/sample', { method: 'POST' }),

  runSimulation: (scenario: SimulationScenarioId) =>
    requestJson<{
      simulationActive: boolean;
      scenario: string;
      packetsGenerated: number;
      alertsTriggered?: SecurityAlert[];
    }>('/api/simulation/run', {
      method: 'POST',
      body: JSON.stringify({ scenario }),
    }),

  stopSimulation: () => requestJson('/api/simulation/stop', { method: 'POST' }),

  clearSimulation: () => requestJson('/api/simulation/clear', { method: 'POST' }),

  lookupIp: (ip: string) => requestJson<IpIntelResult>(`/api/intel/${encodeURIComponent(ip)}`),

  investigateAlert: (
    alert: SecurityAlert,
    model: AppSettings['preferredAiModel'],
    useHighThinking: boolean,
  ) =>
    requestJson<{
      source: 'gemini' | 'rule-based-fallback';
      modelUsed: string;
      analysis: string;
      warning?: string;
    }>('/api/ai/investigate', {
      method: 'POST',
      body: JSON.stringify({ alertId: alert.id, alert, model, useHighThinking }),
    }),

  generateThreatVisual: (alert: SecurityAlert, imageSize: '1K' | '2K' | '4K') =>
    requestJson<{
      imageDataUrl?: string;
      modelUsed: string;
      error?: string;
    }>('/api/ai/generate-visual', {
      method: 'POST',
      body: JSON.stringify({ alertId: alert.id, alert, imageSize }),
    }),
};
