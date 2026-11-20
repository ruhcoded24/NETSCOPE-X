import React, { useEffect, useState } from 'react';
import { RotateCcw, Save } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { DEFAULT_THRESHOLDS } from '../core/detectionEngine';
import { GlassPanel } from '../components/common/GlassPanel';
import type { AppSettings } from '../core/types';

export const Settings: React.FC = () => {
  const { settings, interfaces, updateSettingsState, pushToast } = useApp();
  const [draft, setDraft] = useState<AppSettings>(settings);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await updateSettingsState(draft);
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Failed to save configuration', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleResetThresholds = () => {
    setDraft((prev) => ({
      ...prev,
      thresholds: { ...DEFAULT_THRESHOLDS },
    }));
    pushToast('Thresholds reset to defaults (click Save Changes to apply)', 'info');
  };

  return (
    <form onSubmit={handleSave} className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Capture & Interface Preferences */}
        <GlassPanel
          title="Capture & Buffer Configuration"
          subtitle="Default interface binding and bounded memory limits"
        >
          <div className="space-y-4 text-xs">
            <label className="block space-y-1.5">
              <span className="text-slate-300 font-medium">Default Network Interface</span>
              <select
                value={draft.defaultInterface}
                onChange={(e) => setDraft({ ...draft, defaultInterface: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
              >
                {interfaces.length === 0 ? (
                  <option value={draft.defaultInterface}>{draft.defaultInterface}</option>
                ) : (
                  interfaces.map((iface) => (
                    <option key={iface.name} value={iface.name}>
                      {iface.name} {iface.ipv4 ? `(${iface.ipv4})` : ''} [{iface.status}]
                    </option>
                  ))
                )}
              </select>
            </label>

            <label className="block space-y-1.5">
              <span className="text-slate-300 font-medium">Max Packet Ring Buffer</span>
              <input
                type="number"
                min={100}
                max={50000}
                step={100}
                value={draft.maxPackets}
                onChange={(e) =>
                  setDraft({ ...draft, maxPackets: Math.max(100, Number(e.target.value) || 2000) })
                }
                className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
              />
              <span className="text-slate-500 block">
                Bounds server memory usage (100 – 50,000 header records).
              </span>
            </label>

            <label className="flex items-center justify-between gap-4 p-3 rounded-lg bg-[#080510] border border-slate-800 cursor-pointer">
              <div>
                <span className="text-slate-200 font-medium block">Reduced Motion Mode</span>
                <span className="text-slate-500">
                  Slows or halts 3D auto-rotation, radar sweeps, and animated counters.
                </span>
              </div>
              <input
                type="checkbox"
                checked={draft.reducedMotion}
                onChange={(e) => setDraft({ ...draft, reducedMotion: e.target.checked })}
                className="rounded border-slate-700 bg-[#080510] accent-[#00E5FF]"
              />
            </label>
          </div>
        </GlassPanel>

        {/* AI Investigator Preferences */}
        <GlassPanel
          title="AI Security Investigator Preferences"
          subtitle="Optional server-side Gemini reasoning layer (core analyzer operates independently)"
        >
          <div className="space-y-4 text-xs">
            <label className="block space-y-1.5">
              <span className="text-slate-300 font-medium">Preferred Reasoning Model</span>
              <select
                value={draft.preferredAiModel}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    preferredAiModel: e.target.value as AppSettings['preferredAiModel'],
                  })
                }
                className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
              >
                <option value="gemini-4-hydrogen">gemini-4-hydrogen (Fast SOC Triage)</option>
                <option value="gemini-4-neon">gemini-4-neon (Balanced Reasoning)</option>
                <option value="gemini-4-carbon">gemini-4-carbon (Deep Investigation)</option>
                <option value="gemini-3.1-flash-lite">gemini-3.1-flash-lite (Lightweight)</option>
              </select>
            </label>

            <label className="flex items-center justify-between gap-4 p-3 rounded-lg bg-[#080510] border border-slate-800 cursor-pointer">
              <div>
                <span className="text-slate-200 font-medium block">High Thinking Depth</span>
                <span className="text-slate-500">
                  Enables extended multi-step threat correlation for complex alerts.
                </span>
              </div>
              <input
                type="checkbox"
                checked={draft.useHighThinking}
                onChange={(e) => setDraft({ ...draft, useHighThinking: e.target.checked })}
                className="rounded border-slate-700 bg-[#080510] accent-[#00E5FF]"
              />
            </label>

            <div className="p-3 rounded-lg bg-[#080510] border border-slate-800 text-slate-400 space-y-1">
              <p className="font-medium text-slate-300">Privacy & Key Isolation</p>
              <p>
                API keys are managed strictly on the server via environment variables. Structured
                incident summaries (never raw payloads or credentials) are sent only when an
                analyst explicitly triggers investigation.
              </p>
            </div>
          </div>
        </GlassPanel>
      </div>

      {/* Detection Engine Thresholds */}
      <GlassPanel
        title="Explainable Detection Thresholds"
        subtitle="Calibrate heuristic sensitivity across all five cybersecurity detectors"
        action={
          <button
            type="button"
            onClick={handleResetThresholds}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:text-white"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Defaults
          </button>
        }
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          <label className="block space-y-1.5">
            <span className="text-slate-300 font-medium">Port Scan Unique Ports</span>
            <input
              type="number"
              min={2}
              max={500}
              value={draft.thresholds.portScanUniquePorts}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresholds: {
                    ...draft.thresholds,
                    portScanUniquePorts: Math.max(2, Number(e.target.value) || 8),
                  },
                })
              }
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-slate-300 font-medium">Port Scan Window (seconds)</span>
            <input
              type="number"
              min={5}
              max={3600}
              value={draft.thresholds.portScanWindowSec}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresholds: {
                    ...draft.thresholds,
                    portScanWindowSec: Math.max(5, Number(e.target.value) || 30),
                  },
                })
              }
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-slate-300 font-medium">SYN Spike Count</span>
            <input
              type="number"
              min={3}
              max={1000}
              value={draft.thresholds.synSpikeCount}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresholds: {
                    ...draft.thresholds,
                    synSpikeCount: Math.max(3, Number(e.target.value) || 25),
                  },
                })
              }
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-slate-300 font-medium">Traffic Spike Multiplier</span>
            <input
              type="number"
              min={1.2}
              max={50}
              step={0.1}
              value={draft.thresholds.trafficSpikeMultiplier}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresholds: {
                    ...draft.thresholds,
                    trafficSpikeMultiplier: Math.max(1.2, Number(e.target.value) || 3),
                  },
                })
              }
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-slate-300 font-medium">DNS Query Rate Threshold</span>
            <input
              type="number"
              min={3}
              max={1000}
              value={draft.thresholds.dnsQueryRateThreshold}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresholds: {
                    ...draft.thresholds,
                    dnsQueryRateThreshold: Math.max(3, Number(e.target.value) || 18),
                  },
                })
              }
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-slate-300 font-medium">Connection Fan-out Threshold</span>
            <input
              type="number"
              min={3}
              max={1000}
              value={draft.thresholds.connectionFanoutThreshold}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresholds: {
                    ...draft.thresholds,
                    connectionFanoutThreshold: Math.max(3, Number(e.target.value) || 15),
                  },
                })
              }
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-[#C9A4FF]/25 text-slate-100 font-mono focus:outline-none focus:border-[#00E5FF]"
            />
          </label>
        </div>

        <div className="pt-5 flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#00E5FF] text-[#070910] text-xs font-semibold hover:bg-[#33ebff] disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </GlassPanel>
    </form>
  );
};
