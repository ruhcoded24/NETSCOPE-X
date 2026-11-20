import React, { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { BrainCircuit, Download, Image as ImageIcon, ShieldAlert } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { GlassPanel } from '../components/common/GlassPanel';
import { getSeverityColor } from '../utils/formatters';
import type { AppSettings, SecurityAlert } from '../core/types';

function renderLocalThreatSchematic(alert: SecurityAlert, imageSize: '1K' | '2K' | '4K'): string {
  const dims =
    imageSize === '4K'
      ? { w: 1920, h: 1080 }
      : imageSize === '2K'
        ? { w: 1600, h: 900 }
        : { w: 1280, h: 720 };

  const canvas = document.createElement('canvas');
  canvas.width = dims.w;
  canvas.height = dims.h;
  const ctx = canvas.getContext('2d');
  if (!ctx) return '';

  const s = dims.w / 1280;
  ctx.scale(s, s);

  // Midnight Cosmos background
  ctx.fillStyle = '#080510';
  ctx.fillRect(0, 0, 1280, 720);

  // Subtle radial aura
  const aura = ctx.createRadialGradient(640, 340, 40, 640, 340, 560);
  aura.addColorStop(0, 'rgba(157, 0, 255, 0.16)');
  aura.addColorStop(0.55, 'rgba(0, 229, 255, 0.06)');
  aura.addColorStop(1, 'rgba(8, 5, 16, 0)');
  ctx.fillStyle = aura;
  ctx.fillRect(0, 0, 1280, 720);

  // Coordinate grid
  ctx.strokeStyle = 'rgba(201, 164, 255, 0.08)';
  ctx.lineWidth = 1;
  for (let x = 0; x <= 1280; x += 48) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, 720);
    ctx.stroke();
  }
  for (let y = 0; y <= 720; y += 48) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(1280, y);
    ctx.stroke();
  }

  const sevAccent =
    alert.severity === 'Critical' || alert.severity === 'High'
      ? '#FF3B5C'
      : alert.severity === 'Medium'
        ? '#FF9F43'
        : '#00E5FF';

  // Header strip
  ctx.fillStyle = 'rgba(16, 9, 27, 0.9)';
  ctx.strokeStyle = 'rgba(201, 164, 255, 0.22)';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.roundRect(44, 36, 1192, 68, 12);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = '#00E5FF';
  ctx.font = '600 14px "JetBrains Mono", monospace';
  ctx.fillText(`NETSCOPE X // THREAT SCHEMATIC BRIEF [${alert.id}]`, 68, 66);

  ctx.fillStyle = '#E2E8F0';
  ctx.font = '700 20px "Space Grotesk", Inter, sans-serif';
  ctx.fillText(`${alert.ruleName} · ${alert.category.replace(/_/g, ' ').toUpperCase()}`, 68, 92);

  // Severity Pill
  ctx.fillStyle = `${sevAccent}22`;
  ctx.strokeStyle = sevAccent;
  ctx.beginPath();
  ctx.roundRect(980, 50, 232, 40, 8);
  ctx.fill();
  ctx.stroke();
  ctx.fillStyle = sevAccent;
  ctx.font = '700 15px "JetBrains Mono", monospace';
  ctx.textAlign = 'center';
  ctx.fillText(`${alert.severity.toUpperCase()} · RISK ${alert.riskScore}/100`, 1096, 75);
  ctx.textAlign = 'left';

  // Topology Link Lines
  const grad = ctx.createLinearGradient(250, 320, 1030, 320);
  grad.addColorStop(0, sevAccent);
  grad.addColorStop(0.5, '#9D00FF');
  grad.addColorStop(1, '#00E5FF');

  ctx.strokeStyle = grad;
  ctx.lineWidth = 3;
  ctx.setLineDash([10, 8]);
  ctx.beginPath();
  ctx.moveTo(270, 320);
  ctx.lineTo(560, 320);
  ctx.moveTo(720, 320);
  ctx.lineTo(1010, 320);
  ctx.stroke();
  ctx.setLineDash([]);

  // Secondary telemetry arcs
  ctx.strokeStyle = 'rgba(0, 229, 255, 0.3)';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(260, 290);
  ctx.quadraticCurveTo(640, 175, 1020, 290);
  ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(260, 350);
  ctx.quadraticCurveTo(640, 465, 1020, 350);
  ctx.stroke();

  const drawNode = (
    cx: number,
    cy: number,
    r: number,
    color: string,
    title: string,
    sub: string,
  ) => {
    ctx.fillStyle = `${color}18`;
    ctx.beginPath();
    ctx.arc(cx, cy, r + 24, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = '#10091B';
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(cx, cy, 8, 0, Math.PI * 2);
    ctx.fill();

    ctx.textAlign = 'center';
    ctx.fillStyle = '#94A3B8';
    ctx.font = '600 12px "JetBrains Mono", monospace';
    ctx.fillText(title, cx, cy + r + 30);
    ctx.fillStyle = '#FFFFFF';
    ctx.font = '700 16px "JetBrains Mono", monospace';
    ctx.fillText(sub, cx, cy + r + 54);
    ctx.textAlign = 'left';
  };

  drawNode(220, 320, 46, sevAccent, 'SOURCE ENDPOINT', alert.sourceIp);
  drawNode(640, 320, 56, '#9D00FF', 'DETECTION ENGINE', alert.classification.toUpperCase());
  drawNode(
    1060,
    320,
    46,
    '#00E5FF',
    'TARGET SCOPE',
    alert.destinationIp || 'Multiple Ports / Hosts',
  );

  // Evidence footer box
  ctx.fillStyle = 'rgba(16, 9, 27, 0.92)';
  ctx.strokeStyle = 'rgba(201, 164, 255, 0.22)';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.roundRect(44, 515, 1192, 162, 12);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = '#C9A4FF';
  ctx.font = '600 13px "JetBrains Mono", monospace';
  ctx.fillText('STRUCTURED EVIDENCE & RISK TELEMETRY', 68, 545);

  ctx.fillStyle = '#E2E8F0';
  ctx.font = '400 14px "JetBrains Mono", monospace';
  const lines = [
    `Formula: ${alert.riskBreakdown.formula}`,
    ...alert.evidence.slice(0, 3).map((ev, idx) => `0${idx + 1}. ${ev}`),
  ];
  lines.forEach((line, i) => {
    const clipped = line.length > 112 ? `${line.slice(0, 109)}...` : line;
    ctx.fillText(clipped, 68, 575 + i * 26);
  });

  return canvas.toDataURL('image/png');
}

export const Investigator: React.FC = () => {
  const { alerts, selectedAlert, setSelectedAlert, settings, updateAlertState, pushToast } = useApp();
  const active = selectedAlert ?? alerts[0] ?? null;

  const [model, setModel] = useState<AppSettings['preferredAiModel']>(settings.preferredAiModel);
  const [highThinking, setHighThinking] = useState<boolean>(settings.useHighThinking);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const [analysisText, setAnalysisText] = useState<string>(active?.aiAnalysis ?? '');
  const [analysisMeta, setAnalysisMeta] = useState<{ source: string; modelUsed: string; warning?: string } | null>(null);

  useEffect(() => {
    setAnalysisText(active?.aiAnalysis ?? '');
    setAnalysisMeta(null);
    setVisualUrl(null);
    setVisualSource(null);
  }, [active?.id]);

  const [imageSize, setImageSize] = useState<'1K' | '2K' | '4K'>('1K');
  const [loadingVisual, setLoadingVisual] = useState(false);
  const [visualUrl, setVisualUrl] = useState<string | null>(null);
  const [visualSource, setVisualSource] = useState<'gemini' | 'local' | null>(null);

  const handleRunInvestigation = async () => {
    if (!active) return;
    setLoadingAnalysis(true);
    setAnalysisMeta(null);
    try {
      const res = await api.investigateAlert(active, model, highThinking);
      setAnalysisText(res.analysis);
      setAnalysisMeta({ source: res.source, modelUsed: res.modelUsed, warning: res.warning });
      await updateAlertState(active.id, { aiAnalysis: res.analysis });
      pushToast(`Investigation generated (${res.modelUsed})`, 'success');
    } catch (err) {
      pushToast(err instanceof Error ? err.message : 'Investigation failed', 'error');
    } finally {
      setLoadingAnalysis(false);
    }
  };

  const handleGenerateVisual = async () => {
    if (!active) return;
    setLoadingVisual(true);
    setVisualUrl(null);
    setVisualSource(null);
    try {
      const res = await api.generateThreatVisual(active, imageSize);
      if (res.imageDataUrl) {
        setVisualUrl(res.imageDataUrl);
        setVisualSource('gemini');
        pushToast(`Threat brief visual generated (${imageSize})`, 'success');
        return;
      }
      throw new Error(res.error || 'No image returned');
    } catch {
      const fallbackUrl = renderLocalThreatSchematic(active, imageSize);
      if (fallbackUrl) {
        setVisualUrl(fallbackUrl);
        setVisualSource('local');
        pushToast(`Local threat schematic rendered (${imageSize})`, 'info');
      } else {
        pushToast('Unable to render threat schematic visual.', 'error');
      }
    } finally {
      setLoadingVisual(false);
    }
  };

  const handleDownloadVisual = () => {
    if (!visualUrl || !active) return;
    const a = document.createElement('a');
    a.href = visualUrl;
    a.download = `${active.id}-threat-schematic-${imageSize}.png`;
    a.click();
  };

  const handleDownloadReport = () => {
    if (!active) return;
    const md = [
      `# NETSCOPE X Incident Investigation Report`,
      `- Alert ID: ${active.id}`,
      `- Timestamp: ${active.timestamp}`,
      `- Source IP: ${active.sourceIp}`,
      `- Destination IP: ${active.destinationIp ?? 'Multiple'}`,
      `- Category: ${active.category}`,
      `- Severity: ${active.severity} (Risk Score: ${active.riskScore}/100)`,
      `- Rule: ${active.ruleName}`,
      ``,
      `## Evidence`,
      ...active.evidence.map((e) => `- ${e}`),
      ``,
      `## Investigation Analysis`,
      analysisText || active.aiAnalysis || 'No analysis generated yet.',
    ].join('\n');

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${active.id}-investigation.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Alert Selector */}
      <GlassPanel
        title="Incident Queue"
        subtitle="Select an alert for evidence-grounded triage"
        className="lg:col-span-1"
      >
        <div className="space-y-2 max-h-[580px] overflow-y-auto pr-1">
          {alerts.length === 0 ? (
            <p className="text-xs text-slate-500 py-8 text-center">
              No alerts available. Trigger a detection or simulation scenario first.
            </p>
          ) : (
            alerts.map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => {
                  setSelectedAlert(a);
                  setAnalysisText(a.aiAnalysis ?? '');
                  setAnalysisMeta(null);
                  setVisualUrl(null);
                  setVisualSource(null);
                }}
                className={`w-full text-left p-3 rounded-lg border text-xs transition-colors ${
                  active?.id === a.id
                    ? 'bg-[#00E5FF]/10 border-[#00E5FF]/50'
                    : 'bg-[#080510] border-slate-800 hover:border-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`font-semibold ${getSeverityColor(a.severity).text}`}>
                    {a.severity} · {a.riskScore}/100
                  </span>
                  {a.isSimulated && <span className="font-mono text-[#FF9F43]">[SIM]</span>}
                </div>
                <p className="text-slate-100 font-medium">{a.ruleName}</p>
                <p className="font-mono text-slate-400 mt-0.5 truncate">{a.sourceIp}</p>
              </button>
            ))
          )}
        </div>
      </GlassPanel>

      {/* AI Investigation Workspace */}
      <div className="lg:col-span-2 space-y-6">
        <GlassPanel
          title="AI Security Investigator"
          subtitle="Structured backend evidence only · never invents packets or executes network actions"
          action={
            active && (
              <button
                type="button"
                onClick={handleDownloadReport}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-200 hover:border-[#00E5FF]"
              >
                <Download className="w-3.5 h-3.5" />
                Export Report
              </button>
            )
          }
        >
          {!active ? (
            <div className="py-16 text-center text-sm text-slate-500">
              Select an alert from the queue to start an investigation.
            </div>
          ) : (
            <div className="space-y-5 text-xs">
              {/* Structured Evidence Summary */}
              <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 space-y-2">
                <div className="flex items-center gap-2 text-slate-200 font-semibold">
                  <ShieldAlert className={`w-4 h-4 ${getSeverityColor(active.severity).text}`} />
                  <span>{active.summary}</span>
                </div>
                <p className="font-mono text-slate-400">
                  Risk Formula: {active.riskBreakdown.formula}
                </p>
              </div>

              {/* Model & Thinking Controls */}
              <div className="flex flex-wrap items-center justify-between gap-4 p-3.5 rounded-lg bg-[#080510] border border-slate-800">
                <div className="flex flex-wrap items-center gap-3">
                  <label htmlFor="ai-model-select" className="text-slate-400">
                    Model
                  </label>
                  <select
                    id="ai-model-select"
                    value={model}
                    onChange={(e) => setModel(e.target.value as AppSettings['preferredAiModel'])}
                    className="px-2.5 py-1.5 bg-[#10091B] border border-[#C9A4FF]/25 rounded-md text-slate-100 font-mono"
                  >
                    <option value="gemini-4-hydrogen">gemini-4-hydrogen (General)</option>
                    <option value="gemini-4-neon">gemini-4-neon (Complex)</option>
                    <option value="gemini-4-carbon">gemini-4-carbon (Deep Reasoning)</option>
                    <option value="gemini-3.1-flash-lite">gemini-3.1-flash-lite (Fast)</option>
                  </select>

                  <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={highThinking}
                      onChange={(e) => setHighThinking(e.target.checked)}
                      className="accent-[#9B5CFF]"
                    />
                    <span>High Thinking (ThinkingLevel.HIGH)</span>
                  </label>
                </div>

                <button
                  type="button"
                  disabled={loadingAnalysis}
                  onClick={handleRunInvestigation}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#00E5FF] text-[#070910] font-semibold hover:bg-[#33ebff] disabled:opacity-50 transition-colors"
                >
                  <BrainCircuit className="w-4 h-4" />
                  {loadingAnalysis ? 'Analyzing Evidence...' : 'Run Investigation'}
                </button>
              </div>

              {analysisMeta?.warning && (
                <div className="p-3 rounded-lg bg-[#FF9F43]/10 border border-[#FF9F43]/40 text-[#FF9F43]">
                  {analysisMeta.warning}
                </div>
              )}

              {/* Investigation Output */}
              <div className="p-4 rounded-lg bg-[#080510] border border-slate-800 min-h-[220px] whitespace-pre-wrap leading-relaxed text-slate-200 font-sans">
                {analysisText || active.aiAnalysis || 'Click "Run Investigation" to analyze this alert using Gemini or the built-in deterministic rule engine.'}
              </div>

              {/* Incident Visual Brief Generator (gemini-3-pro-image-preview + local schematic fallback) */}
              <motion.div
                whileHover={
                  settings.reducedMotion
                    ? {
                        boxShadow:
                          '0 0 28px rgba(157, 0, 255, 0.34), 0 0 16px rgba(0, 229, 255, 0.2)',
                        borderColor: 'rgba(0, 229, 255, 0.55)',
                      }
                    : {
                        scale: 1.05,
                        boxShadow:
                          '0 0 28px rgba(157, 0, 255, 0.34), 0 0 16px rgba(0, 229, 255, 0.2)',
                        borderColor: 'rgba(0, 229, 255, 0.55)',
                      }
                }
                transition={{ type: 'spring', stiffness: 320, damping: 24 }}
                style={{ boxShadow: '0 0 12px rgba(157, 0, 255, 0.1)' }}
                className="p-4 rounded-lg bg-[#080510] border border-[#9D00FF]/35 space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="font-semibold text-slate-200">Threat Schematic Brief (Image Generation)</h3>
                    <p className="text-slate-400 mt-0.5">
                      Render an executive incident topology visual with gemini-3-pro-image-preview or local schematic telemetry.
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <label htmlFor="brief-img-size" className="text-slate-400">
                      Resolution
                    </label>
                    <select
                      id="brief-img-size"
                      value={imageSize}
                      onChange={(e) => setImageSize(e.target.value as '1K' | '2K' | '4K')}
                      className="px-2.5 py-1.5 bg-[#10091B] border border-[#C9A4FF]/25 rounded-md font-mono text-slate-100"
                    >
                      <option value="1K">1K</option>
                      <option value="2K">2K</option>
                      <option value="4K">4K</option>
                    </select>
                    <button
                      type="button"
                      disabled={loadingVisual}
                      onClick={handleGenerateVisual}
                      className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-[#9B5CFF]/60 text-[#9B5CFF] hover:bg-[#9B5CFF]/15 disabled:opacity-50 transition-colors font-medium"
                    >
                      <ImageIcon className="w-3.5 h-3.5" />
                      {loadingVisual ? 'Generating...' : 'Generate Visual'}
                    </button>
                    {visualUrl && (
                      <button
                        type="button"
                        onClick={handleDownloadVisual}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#00E5FF]/40 text-[#00E5FF] hover:bg-[#00E5FF]/10 transition-colors font-medium"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Download PNG
                      </button>
                    )}
                  </div>
                </div>

                {loadingVisual && (
                  <div className="h-48 rounded-lg border border-[#C9A4FF]/20 bg-[#10091B]/80 flex items-center justify-center font-mono text-xs text-[#C9A4FF] animate-pulse">
                    Rendering {imageSize} threat topology schematic...
                  </div>
                )}

                {visualUrl && (
                  <div className="space-y-1.5">
                    <img
                      src={visualUrl}
                      alt={`Threat schematic for ${active.id}`}
                      referrerPolicy="no-referrer"
                      className="w-full aspect-video rounded-lg border border-[#C9A4FF]/20 object-contain bg-[#080510]"
                    />
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>
                        Renderer: {visualSource === 'gemini' ? 'gemini-3-pro-image-preview' : 'Local Deterministic Schematic Engine'}
                      </span>
                      <span>Resolution: {imageSize} (16:9 PNG)</span>
                    </div>
                  </div>
                )}
              </motion.div>
            </div>
          )}
        </GlassPanel>
      </div>
    </div>
  );
};
