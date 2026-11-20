import React, { useMemo, useState } from 'react';
import { Cpu, ShieldAlert } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useAuth } from '../context/AuthContext';
import { GlassPanel } from '../components/common/GlassPanel';
import { formatShortTime, getSeverityColor } from '../utils/formatters';
import type { SecurityAlert, SeverityLevel } from '../core/types';

export const ThreatCentre: React.FC = () => {
  const { alerts, selectedAlert, setSelectedAlert, navigate, pushToast } = useApp();
  const { user, saveIncidentToCloud } = useAuth();
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [scope, setScope] = useState<'all' | 'real' | 'sim'>('all');

  const filtered = useMemo(() => {
    return alerts.filter((a) => {
      if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
      if (scope === 'real' && a.isSimulated) return false;
      if (scope === 'sim' && !a.isSimulated) return false;
      return true;
    });
  }, [alerts, severityFilter, scope]);

  const active = selectedAlert ?? filtered[0] ?? null;

  const handleSaveCloud = async (alert: SecurityAlert) => {
    if (!user) {
      pushToast('Sign in with Google in the sidebar to sync incidents to Firestore.', 'info');
      return;
    }
    await saveIncidentToCloud(alert);
    pushToast(`Saved ${alert.id} to cloud incident log`, 'success');
  };

  return (
    <div className="space-y-6">
      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-[#10091B] border border-[#C9A4FF]/20 rounded-lg text-xs">
          {(['ALL', 'Critical', 'High', 'Medium', 'Low', 'Informational'] as const).map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors whitespace-nowrap ${
                severityFilter === sev
                  ? 'bg-[#00E5FF]/15 text-[#00E5FF]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1 p-1 bg-[#10091B] border border-[#C9A4FF]/20 rounded-lg text-xs">
          {[
            { id: 'all', label: 'All Alerts' },
            { id: 'real', label: 'Real Traffic Only' },
            { id: 'sim', label: '[SIMULATED] Only' },
          ].map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setScope(opt.id as 'all' | 'real' | 'sim')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors whitespace-nowrap ${
                scope === opt.id ? 'bg-[#00E5FF]/15 text-[#00E5FF]' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Alert List */}
        <GlassPanel
          title="Detection Feed"
          subtitle={`${filtered.length} alerts matched`}
          className="lg:col-span-2"
        >
          <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
            {filtered.length === 0 ? (
              <div className="py-12 text-center space-y-2 text-xs text-slate-400">
                <p>No alerts matching this filter.</p>
                <button
                  type="button"
                  onClick={() => navigate('simulation-lab')}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF]"
                >
                  Test Detection Rules in Simulation Lab
                </button>
              </div>
            ) : (
              filtered.map((a) => {
                const sev = getSeverityColor(a.severity);
                const isSel = active?.id === a.id;
                return (
                  <button
                    key={a.id}
                    type="button"
                    onClick={() => setSelectedAlert(a)}
                    className={`w-full text-left p-3.5 rounded-lg border transition-colors ${
                      isSel
                        ? 'bg-[#00E5FF]/10 border-[#00E5FF]/50'
                        : 'bg-[#080510] border-slate-800/80 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className={`font-semibold flex items-center gap-1.5 ${sev.text}`}>
                        <ShieldAlert className="w-3.5 h-3.5" />
                        {a.severity} · {a.riskScore}/100
                      </span>
                      <span className="font-mono text-slate-500 tabular-nums">
                        {formatShortTime(a.timestamp)}
                      </span>
                    </div>
                    <p className="text-xs font-medium text-slate-100">{a.ruleName}</p>
                    <p className="text-xs text-slate-400 line-clamp-2 mt-1">{a.summary}</p>
                  </button>
                );
              })
            )}
          </div>
        </GlassPanel>

        {/* Evidence & Risk Breakdown */}
        <GlassPanel
          title={active ? active.ruleName : 'Evidence & Risk Assessment'}
          subtitle={active ? `${active.id} · ${active.classification}` : 'Select an alert'}
          className="lg:col-span-3"
        >
          {!active ? (
            <div className="py-20 text-center text-sm text-slate-500">
              Select an alert from the detection feed to inspect supporting evidence.
            </div>
          ) : (
            <div className="space-y-5 text-xs">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                  <span className="text-slate-500 font-sans block mb-1">Source IP</span>
                  <span className="text-[#00E5FF] font-semibold">{active.sourceIp}</span>
                </div>
                <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                  <span className="text-slate-500 font-sans block mb-1">Target IP</span>
                  <span className="text-slate-200 font-semibold">
                    {active.destinationIp ?? 'Multiple'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                  <span className="text-slate-500 font-sans block mb-1">Risk Score</span>
                  <span className={`font-semibold tabular-nums ${getSeverityColor(active.severity).text}`}>
                    {active.riskScore} / 100
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[#080510] border border-slate-800">
                  <span className="text-slate-500 font-sans block mb-1">Classification</span>
                  <span className="text-slate-200 font-sans">{active.classification}</span>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 space-y-1.5">
                <h3 className="font-semibold text-slate-200">Documented Scoring Formula</h3>
                <p className="font-mono text-[#00E5FF]">{active.riskBreakdown.formula}</p>
              </div>

              <div className="space-y-2">
                <h3 className="font-semibold text-slate-200">Supporting Evidence</h3>
                <ul className="space-y-1.5 text-slate-300 bg-[#080510] border border-slate-800 rounded-lg p-4">
                  {active.evidence.map((ev, i) => (
                    <li key={i} className="font-mono">
                      • {ev}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="space-y-2">
                <h3 className="font-semibold text-slate-200">Recommended Investigation Steps</h3>
                <ol className="space-y-1.5 text-slate-300 bg-[#080510] border border-slate-800 rounded-lg p-4 list-decimal list-inside">
                  {active.recommendedSteps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>

              <div className="flex flex-wrap items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setSelectedAlert(active);
                    navigate('ai-investigator');
                  }}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#00E5FF] text-[#070910] font-semibold hover:bg-[#33ebff] transition-colors"
                >
                  <Cpu className="w-3.5 h-3.5" />
                  Investigate with AI
                </button>
                <button
                  type="button"
                  onClick={() => handleSaveCloud(active)}
                  className="px-4 py-2 rounded-lg border border-slate-700 text-slate-200 hover:border-slate-500 transition-colors"
                >
                  Persist to Incident Log
                </button>
              </div>
            </div>
          )}
        </GlassPanel>
      </div>
    </div>
  );
};
