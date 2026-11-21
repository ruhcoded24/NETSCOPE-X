import React, { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  CloudUpload,
  Cpu,
  Download,
  FileWarning,
  ShieldAlert,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useAuth, type CloudIncidentRecord } from '../context/AuthContext';
import { GlassPanel } from '../components/common/GlassPanel';
import { formatShortTime, getSeverityColor } from '../utils/formatters';
import type { IncidentStatus, SecurityAlert } from '../core/types';

export const Incidents: React.FC = () => {
  const {
    alerts,
    selectedAlert,
    setSelectedAlert,
    updateAlertState,
    navigate,
    pushToast,
  } = useApp();
  const {
    user,
    cloudIncidents,
    saveIncidentToCloud,
    updateCloudIncident,
    signInWithGoogle,
  } = useAuth();

  const [statusFilter, setStatusFilter] = useState<IncidentStatus | 'all'>('all');
  const [selectedId, setSelectedId] = useState<string | null>(selectedAlert?.id ?? null);
  const [notesDraft, setNotesDraft] = useState('');
  const [falsePositiveDraft, setFalsePositiveDraft] = useState(false);
  const [classificationDraft, setClassificationDraft] = useState<
    'Heuristic Alert' | 'Confirmed Incident'
  >('Heuristic Alert');
  const [saving, setSaving] = useState(false);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (statusFilter !== 'all' && a.status !== statusFilter) return false;
      return true;
    });
  }, [alerts, statusFilter]);

  const activeIncident: SecurityAlert | null = useMemo(() => {
    if (selectedId) {
      const found = alerts.find((a) => a.id === selectedId);
      if (found) return found;
    }
    return filteredAlerts[0] ?? null;
  }, [alerts, filteredAlerts, selectedId]);

  useEffect(() => {
    if (activeIncident) {
      setNotesDraft(activeIncident.notes || '');
      setFalsePositiveDraft(Boolean(activeIncident.falsePositive));
      setClassificationDraft(activeIncident.classification);
    }
  }, [activeIncident]);

  const cloudMatch: CloudIncidentRecord | undefined = useMemo(() => {
    if (!activeIncident) return undefined;
    const safeId = activeIncident.id.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 128);
    return cloudIncidents.find((c) => c.incidentId === safeId);
  }, [activeIncident, cloudIncidents]);

  const counts = useMemo(() => {
    return {
      new: alerts.filter((a) => a.status === 'new').length,
      investigating: alerts.filter((a) => a.status === 'investigating').length,
      resolved: alerts.filter((a) => a.status === 'resolved').length,
    };
  }, [alerts]);

  const handleTransition = async (nextStatus: IncidentStatus) => {
    if (!activeIncident) return;
    setSaving(true);
    try {
      await updateAlertState(activeIncident.id, { status: nextStatus });
      if (user && cloudMatch && cloudMatch.status !== 'resolved') {
        await updateCloudIncident(activeIncident.id, { status: nextStatus });
      }
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Status update failed', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleSaveNotesAndTriage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeIncident) return;
    setSaving(true);
    try {
      await updateAlertState(activeIncident.id, {
        notes: notesDraft,
        falsePositive: falsePositiveDraft,
        classification: classificationDraft,
      });
      if (user && cloudMatch && cloudMatch.status !== 'resolved') {
        await updateCloudIncident(activeIncident.id, {
          notes: notesDraft,
          falsePositive: falsePositiveDraft,
          classification: classificationDraft,
        });
      }
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Unable to save notes', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleCloudSync = async (alert: SecurityAlert) => {
    if (!user) {
      await signInWithGoogle();
      return;
    }
    setSaving(true);
    try {
      await saveIncidentToCloud(alert);
      pushToast(`Synced ${alert.id} to Firestore`, 'success');
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Cloud sync failed', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleExportIncidentMarkdown = () => {
    if (!activeIncident) return;
    const md = [
      `# NETSCOPE X Incident Report — ${activeIncident.id}`,
      ``,
      `- **Rule:** ${activeIncident.ruleName}`,
      `- **Timestamp:** ${activeIncident.timestamp}`,
      `- **Severity:** ${activeIncident.severity} (Risk ${activeIncident.riskScore}/100)`,
      `- **Workflow Status:** ${activeIncident.status}`,
      `- **Classification:** ${activeIncident.classification}`,
      `- **False Positive:** ${activeIncident.falsePositive ? 'Yes' : 'No'}`,
      `- **Source IP:** ${activeIncident.sourceIp}`,
      `- **Destination IP:** ${activeIncident.destinationIp ?? 'Multiple'}`,
      `- **Origin Scope:** ${activeIncident.isSimulated ? '[SIMULATED] Lab Scenario' : 'Observed Traffic'}`,
      ``,
      `## Summary`,
      activeIncident.summary,
      ``,
      `## Risk Formula`,
      `\`${activeIncident.riskBreakdown.formula}\``,
      ``,
      `## Supporting Evidence`,
      ...activeIncident.evidence.map((item) => `- ${item}`),
      ``,
      `## Recommended Steps`,
      ...activeIncident.recommendedSteps.map((step, i) => `${i + 1}. ${step}`),
      ``,
      `## Analyst Notes`,
      notesDraft || '(None recorded)',
      ``,
      activeIncident.aiAnalysis ? `## AI Security Assessment\n${activeIncident.aiAnalysis}` : '',
    ]
      .filter(Boolean)
      .join('\n');

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${activeIncident.id.toLowerCase()}-report.md`;
    link.click();
    URL.revokeObjectURL(url);
    pushToast(`Exported ${activeIncident.id} Markdown report`, 'success');
  };

  return (
    <div className="space-y-6">
      {/* Workflow KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
          <p className="text-xs text-slate-400">New Incidents</p>
          <p className="text-2xl font-bold font-mono text-[#FF3B5C] mt-1 tabular-nums">
            {counts.new}
          </p>
          <p className="text-xs text-slate-500 mt-1">Awaiting analyst triage</p>
        </div>
        <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
          <p className="text-xs text-slate-400">Investigating</p>
          <p className="text-2xl font-bold font-mono text-[#FF9F43] mt-1 tabular-nums">
            {counts.investigating}
          </p>
          <p className="text-xs text-slate-500 mt-1">Active forensic review</p>
        </div>
        <div className="bg-[#10091B]/95 border border-[#C9A4FF]/15 rounded-xl p-4">
          <p className="text-xs text-slate-400">Resolved</p>
          <p className="text-2xl font-bold font-mono text-[#39FF88] mt-1 tabular-nums">
            {counts.resolved}
          </p>
          <p className="text-xs text-slate-500 mt-1">Closed or mitigated cases</p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-[#10091B] border border-[#C9A4FF]/20 rounded-lg text-xs">
          {(
            [
              { id: 'all', label: 'All Cases' },
              { id: 'new', label: 'New' },
              { id: 'investigating', label: 'Investigating' },
              { id: 'resolved', label: 'Resolved' },
            ] as const
          ).map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setStatusFilter(opt.id)}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors whitespace-nowrap ${
                statusFilter === opt.id
                  ? 'bg-[#00E5FF]/15 text-[#00E5FF]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <div className="text-xs text-slate-400">
          {user ? (
            <span>
              Cloud Workspace: <span className="text-[#39FF88] font-mono">{cloudIncidents.length}</span>{' '}
              incidents synced
            </span>
          ) : (
            <button
              type="button"
              onClick={signInWithGoogle}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF] hover:text-[#00E5FF] transition-colors"
            >
              <CloudUpload className="w-3.5 h-3.5" />
              Sign In for Firestore Sync
            </button>
          )}
        </div>
      </div>

      {/* Master-Detail Split */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <GlassPanel
          title="Incident Queue"
          subtitle={`${filteredAlerts.length} cases matched`}
          className="lg:col-span-2"
        >
          <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
            {filteredAlerts.length === 0 ? (
              <div className="py-12 text-center space-y-3 text-xs text-slate-400">
                <p>No incidents match the selected workflow filter.</p>
                <button
                  type="button"
                  onClick={() => navigate('simulation-lab')}
                  className="px-3.5 py-1.5 rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF]"
                >
                  Generate Test Evidence in Simulation Lab
                </button>
              </div>
            ) : (
              filteredAlerts.map((inc) => {
                const sev = getSeverityColor(inc.severity);
                const selected = activeIncident?.id === inc.id;
                return (
                  <button
                    key={inc.id}
                    type="button"
                    onClick={() => {
                      setSelectedId(inc.id);
                      setSelectedAlert(inc);
                    }}
                    className={`w-full text-left p-3.5 rounded-lg border transition-colors ${
                      selected
                        ? 'bg-[#00E5FF]/10 border-[#00E5FF]/50'
                        : 'bg-[#080510] border-slate-800/80 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className={`font-semibold flex items-center gap-1.5 ${sev.text}`}>
                        <ShieldAlert className="w-3.5 h-3.5" />
                        {inc.severity} · {inc.status.toUpperCase()}
                      </span>
                      <span className="font-mono text-slate-500 tabular-nums">
                        {formatShortTime(inc.timestamp)}
                      </span>
                    </div>
                    <p className="text-xs font-medium text-slate-100">{inc.ruleName}</p>
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-1.5">
                      <span>{inc.sourceIp}</span>
                      <span>
                        {inc.falsePositive ? 'False Positive' : `Risk ${inc.riskScore}/100`}
                      </span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </GlassPanel>

        <GlassPanel
          title={activeIncident ? `${activeIncident.id} · Case File` : 'Incident Case File'}
          subtitle={
            activeIncident
              ? `${activeIncident.ruleName} · ${activeIncident.isSimulated ? '[SIMULATED]' : 'Observed'}`
              : 'Select an incident from the queue'
          }
          action={
            activeIncident && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleExportIncidentMarkdown}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-200 hover:border-slate-500"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export MD
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedAlert(activeIncident);
                    navigate('ai-investigator');
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#00E5FF] text-[#070910] text-xs font-semibold hover:bg-[#33ebff]"
                >
                  <Cpu className="w-3.5 h-3.5" />
                  AI Triage
                </button>
              </div>
            )
          }
          className="lg:col-span-3"
        >
          {!activeIncident ? (
            <div className="py-20 text-center text-sm text-slate-500">
              Select an alert or incident from the queue to update workflow status and analyst notes.
            </div>
          ) : (
            <div className="space-y-5 text-xs">
              {/* Workflow Transitions */}
              <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <span className="text-slate-400 block">Current State</span>
                  <span className="font-mono font-semibold text-sm text-white uppercase">
                    {activeIncident.status}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {activeIncident.status === 'new' && (
                    <button
                      type="button"
                      disabled={saving}
                      onClick={() => handleTransition('investigating')}
                      className="px-3.5 py-2 rounded-lg border border-[#FF9F43]/50 text-[#FF9F43] font-medium hover:bg-[#FF9F43]/10 disabled:opacity-50"
                    >
                      Mark Investigating
                    </button>
                  )}
                  {activeIncident.status !== 'resolved' ? (
                    <button
                      type="button"
                      disabled={saving}
                      onClick={() => handleTransition('resolved')}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#39FF88] text-[#070910] font-semibold hover:bg-[#5cff9d] disabled:opacity-50"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Resolve Case
                    </button>
                  ) : (
                    <span className="text-[#39FF88] font-medium flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4" />
                      Case Resolved
                    </span>
                  )}

                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => handleCloudSync(activeIncident)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-slate-700 text-slate-200 hover:border-[#00E5FF] disabled:opacity-50"
                  >
                    <CloudUpload className="w-3.5 h-3.5" />
                    {cloudMatch ? 'Synced in Supabase' : 'Sync to Supabase'}
                  </button>
                </div>
              </div>

              {/* Summary & Evidence */}
              <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 space-y-2">
                <p className="text-slate-200 leading-relaxed">{activeIncident.summary}</p>
                <div className="flex flex-wrap gap-4 pt-2 font-mono text-slate-400">
                  <span>Source: {activeIncident.sourceIp}</span>
                  <span>Target: {activeIncident.destinationIp ?? 'Multiple'}</span>
                  <span>Risk: {activeIncident.riskScore}/100</span>
                </div>
              </div>

              {/* Triage & Notes Form */}
              <form onSubmit={handleSaveNotesAndTriage} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <label className="block space-y-1.5">
                    <span className="text-slate-400 font-medium">Incident Classification</span>
                    <select
                      value={classificationDraft}
                      onChange={(e) =>
                        setClassificationDraft(
                          e.target.value as 'Heuristic Alert' | 'Confirmed Incident',
                        )
                      }
                      disabled={activeIncident.status === 'resolved' && Boolean(cloudMatch)}
                      className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 focus:outline-none focus:border-[#00E5FF]"
                    >
                      <option value="Heuristic Alert">Heuristic Alert</option>
                      <option value="Confirmed Incident">Confirmed Incident</option>
                    </select>
                  </label>

                  <label className="flex items-center gap-2.5 pt-5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={falsePositiveDraft}
                      onChange={(e) => setFalsePositiveDraft(e.target.checked)}
                      disabled={activeIncident.status === 'resolved' && Boolean(cloudMatch)}
                      className="rounded border-slate-700 bg-[#080510] accent-[#FF9F43]"
                    />
                    <span className="text-slate-200 flex items-center gap-1.5">
                      <FileWarning className="w-3.5 h-3.5 text-[#FF9F43]" />
                      Mark as False Positive
                    </span>
                  </label>
                </div>

                <label className="block space-y-1.5">
                  <span className="text-slate-400 font-medium">Analyst Investigation Notes</span>
                  <textarea
                    rows={4}
                    value={notesDraft}
                    onChange={(e) => setNotesDraft(e.target.value)}
                    disabled={activeIncident.status === 'resolved' && Boolean(cloudMatch)}
                    placeholder="Document root cause, host verification, firewall action, or containment findings..."
                    className="w-full px-3 py-2.5 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-[#00E5FF]"
                  />
                </label>

                <div className="flex items-center justify-between gap-3">
                  {activeIncident.status === 'resolved' && cloudMatch ? (
                    <span className="text-slate-500">
                      Resolved cloud records are locked against post-closure tampering.
                    </span>
                  ) : (
                    <span className="text-slate-500">
                      Updates local session state and synced Firestore records.
                    </span>
                  )}
                  <button
                    type="submit"
                    disabled={saving || (activeIncident.status === 'resolved' && Boolean(cloudMatch))}
                    className="px-4 py-2 rounded-lg bg-[#00E5FF] text-[#070910] font-semibold hover:bg-[#33ebff] disabled:opacity-50"
                  >
                    Save Triage & Notes
                  </button>
                </div>
              </form>
            </div>
          )}
        </GlassPanel>
      </div>
    </div>
  );
};
