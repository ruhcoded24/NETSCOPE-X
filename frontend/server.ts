import 'dotenv/config';
import express from 'express';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer as createViteServer } from 'vite';
import { CaptureService } from './src/server/captureService.ts';
import { lookupIpIntelligence } from './src/server/ipIntelService.ts';
import {
  generateThreatVisualBrief,
  investigateAlertWithGemini,
  type SupportedTextModel,
} from './src/server/geminiService.ts';
import { filterAndSortPackets, packetsToCsv, computeTrafficStats, buildNetworkTopology } from './src/core/statisticsEngine.ts';
import { parsePcapBuffer, packetsToPcapBuffer, generateSamplePcapBuffer } from './src/core/pcapParser.ts';
import { analyzeTrafficForThreats } from './src/core/detectionEngine.ts';
import type { ForensicReport, PacketFilterQuery, SimulationScenarioId } from './src/core/types.ts';

const PORT = 3000;
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const captureService = new CaptureService();

const allowedOrigins = new Set(
  [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    process.env.FRONTEND_ORIGIN,
    process.env.APP_URL,
  ].filter((x): x is string => Boolean(x)),
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (allowedOrigins.has(origin) || origin.endsWith('.run.app'))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

app.use(express.json({ limit: '15mb' }));

// Observe real HTTP requests hitting the platform when live capture is active
app.use('/api', (req, res, next) => {
  res.on('finish', () => {
    if (req.path.startsWith('/packets') || req.path.startsWith('/stats')) return;
    const remoteIp = req.socket.remoteAddress || '127.0.0.1';
    const localIp = req.socket.localAddress || '127.0.0.1';
    const bytes = Number(res.getHeader('content-length') || 240);
    captureService.recordHttpExchange(
      remoteIp,
      localIp,
      req.socket.remotePort || 54000,
      req.socket.localPort || PORT,
      bytes,
    );
  });
  next();
});

function broadcast(payload: unknown) {
  const raw = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(raw);
    }
  }
}

// Buffer packet broadcasts to keep UI smooth during bursts
let pendingPackets: unknown[] = [];
setInterval(() => {
  if (pendingPackets.length > 0) {
    const batch = pendingPackets.splice(0, 60);
    broadcast({ type: 'packets', data: batch });
  }
}, 250);

captureService.on('packet', (pkt) => {
  pendingPackets.push(pkt);
});
captureService.on('alert', (alert) => {
  broadcast({ type: 'alert', data: alert });
});
captureService.on('event', (evt) => {
  broadcast({ type: 'event', data: evt });
});
captureService.on('status', (status) => {
  broadcast({ type: 'status', data: status });
});

wss.on('connection', (ws) => {
  ws.send(
    JSON.stringify({
      type: 'init',
      data: {
        status: captureService.getStatus(),
        stats: captureService.getStats(300, true),
        alerts: captureService.getAlerts(true).slice(0, 50),
        events: captureService.getEvents().slice(0, 80),
        packets: captureService.getPackets(true).slice(-80),
      },
    }),
  );
});

// --- API ROUTES ---

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'netscope-x', timestamp: new Date().toISOString() });
});

app.get('/api/interfaces', (_req, res) => {
  res.json({ interfaces: captureService.listInterfaces() });
});

app.get('/api/capture/status', (_req, res) => {
  res.json(captureService.getStatus());
});

app.post('/api/capture/start', (req, res) => {
  try {
    const iface = typeof req.body?.interfaceName === 'string' ? req.body.interfaceName : undefined;
    const status = captureService.startCapture(iface);
    res.json(status);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Failed to start capture' });
  }
});

app.post('/api/capture/stop', (_req, res) => {
  const status = captureService.stopCapture();
  res.json(status);
});

app.get('/api/sessions', (_req, res) => {
  res.json({ sessions: captureService.getSessions() });
});

app.get('/api/packets', (req, res) => {
  const query: PacketFilterQuery = {
    search: typeof req.query.search === 'string' ? req.query.search : undefined,
    sourceIp: typeof req.query.sourceIp === 'string' ? req.query.sourceIp : undefined,
    destinationIp: typeof req.query.destinationIp === 'string' ? req.query.destinationIp : undefined,
    sourcePort: typeof req.query.sourcePort === 'string' ? req.query.sourcePort : undefined,
    destinationPort: typeof req.query.destinationPort === 'string' ? req.query.destinationPort : undefined,
    protocol: typeof req.query.protocol === 'string' ? (req.query.protocol as PacketFilterQuery['protocol']) : 'ALL',
    minSize: req.query.minSize ? Number(req.query.minSize) : undefined,
    maxSize: req.query.maxSize ? Number(req.query.maxSize) : undefined,
    tcpFlag: typeof req.query.tcpFlag === 'string' ? req.query.tcpFlag : 'ALL',
    includeSimulated: req.query.includeSimulated !== 'false',
    onlySimulated: req.query.onlySimulated === 'true',
    sortBy: (req.query.sortBy as PacketFilterQuery['sortBy']) || 'timestamp',
    sortDir: (req.query.sortDir as PacketFilterQuery['sortDir']) || 'desc',
    page: req.query.page ? Number(req.query.page) : 1,
    pageSize: req.query.pageSize ? Number(req.query.pageSize) : 50,
  };
  const packets = captureService.getPackets(true);
  res.json(filterAndSortPackets(packets, query));
});

app.get('/api/packets/export', (req, res) => {
  const format = String(req.query.format || 'json').toLowerCase();
  const includeSim = req.query.includeSimulated === 'true';
  const packets = captureService.getPackets(includeSim);

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="netscope-capture.csv"');
    res.send(packetsToCsv(packets));
    return;
  }

  if (format === 'pcap') {
    if (req.query.confirmPrivacy !== 'true') {
      res.status(400).json({
        error: 'PCAP export requires explicit privacy confirmation (?confirmPrivacy=true).',
      });
      return;
    }
    const buf = packetsToPcapBuffer(packets);
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    res.setHeader('Content-Disposition', 'attachment; filename="netscope-headers-only.pcap"');
    res.send(Buffer.from(buf));
    return;
  }

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="netscope-capture.json"');
  res.send(JSON.stringify({ exportedAt: new Date().toISOString(), count: packets.length, packets }, null, 2));
});

app.get('/api/stats', (req, res) => {
  const windowSec = req.query.windowSeconds ? Number(req.query.windowSeconds) : 300;
  const includeSim = req.query.includeSimulated === 'true';
  res.json(captureService.getStats(Number.isNaN(windowSec) ? 300 : windowSec, includeSim));
});

app.get('/api/topology', (req, res) => {
  const protocol = (req.query.protocol as PacketFilterQuery['protocol']) || 'ALL';
  const includeSim = req.query.includeSimulated !== 'false';
  res.json(captureService.getTopology(protocol, includeSim));
});

app.get('/api/alerts', (req, res) => {
  const includeSim = req.query.includeSimulated !== 'false';
  res.json({ alerts: captureService.getAlerts(includeSim) });
});

app.patch('/api/alerts/:id', (req, res) => {
  const updated = captureService.updateAlert(req.params.id, {
    status: req.body?.status,
    notes: req.body?.notes,
    falsePositive: req.body?.falsePositive,
    classification: req.body?.classification,
    aiAnalysis: req.body?.aiAnalysis,
  });
  if (!updated) {
    res.status(404).json({ error: 'Alert not found' });
    return;
  }
  broadcast({ type: 'alert_updated', data: updated });
  res.json(updated);
});

app.get('/api/events', (_req, res) => {
  res.json({ events: captureService.getEvents() });
});

app.get('/api/settings', (_req, res) => {
  res.json(captureService.getSettings());
});

app.put('/api/settings', (req, res) => {
  const updated = captureService.updateSettings(req.body ?? {});
  res.json(updated);
});

// --- PCAP FORENSICS LAB ---

function buildForensicReport(
  fileName: string,
  fileSize: number,
  bytes: Uint8Array,
): ForensicReport {
  const parsed = parsePcapBuffer(bytes, `forensic:${fileName}`, 5000);
  const alerts = analyzeTrafficForThreats(
    parsed.packets,
    captureService.getSettings().thresholds,
    [],
    Date.now(),
  );
  const latestEpoch = parsed.packets.reduce((m, p) => Math.max(m, p.epochMs), Date.now());
  const minEpoch = parsed.packets.reduce((m, p) => Math.min(m, p.epochMs), latestEpoch);
  const durationSec = Math.max(1, Math.round((latestEpoch - minEpoch) / 1000));
  const stats = computeTrafficStats(parsed.packets, alerts, 0, latestEpoch);
  const topo = buildNetworkTopology(parsed.packets, alerts);

  const timeline = stats.timeSeries.map((pt) => ({
    time: pt.time,
    packets: pt.packets,
    bytes: pt.bytes,
    suspicious: pt.alerts,
  }));

  const topPeers = topo.edges.slice(0, 12).map((e) => ({
    pair: `${e.source} -> ${e.target}`,
    packets: e.packets,
    bytes: e.bytes,
    protocols: e.protocols,
  }));

  captureService.addEvent(
    'forensics',
    'success',
    `PCAP analysis completed for ${fileName}: ${parsed.packets.length} packets, ${alerts.length} findings.`,
  );

  return {
    id: `FOR-${Date.now()}`,
    fileName,
    fileSize,
    format: parsed.format,
    analyzedAt: new Date().toISOString(),
    packetCount: parsed.packets.length,
    totalBytes: parsed.packets.reduce((s, p) => s + p.size, 0),
    durationSec,
    packets: parsed.packets,
    stats,
    alerts,
    timeline,
    topPeers,
  };
}

app.post('/api/forensics/upload', (req, res) => {
  try {
    const fileName = String(req.body?.fileName || 'capture.pcap');
    const base64 = String(req.body?.base64Data || '');
    if (!base64) {
      res.status(400).json({ error: 'No PCAP/PCAPNG file payload supplied.' });
      return;
    }
    const lower = fileName.toLowerCase();
    if (!lower.endsWith('.pcap') && !lower.endsWith('.pcapng') && !lower.endsWith('.cap')) {
      res.status(400).json({ error: 'Only .pcap, .pcapng, or .cap binary files are permitted.' });
      return;
    }
    const buf = Buffer.from(base64, 'base64');
    if (buf.length > 10 * 1024 * 1024) {
      res.status(413).json({ error: 'File exceeds 10 MB safety limit.' });
      return;
    }
    const report = buildForensicReport(fileName, buf.length, new Uint8Array(buf));
    res.json(report);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Failed to parse capture file.' });
  }
});

app.post('/api/forensics/sample', (_req, res) => {
  const buf = generateSamplePcapBuffer();
  const report = buildForensicReport('lab-recon-sample.pcap', buf.length, buf);
  res.json(report);
});

// --- ATTACK SIMULATION LAB (CONTROLLED) ---

app.post('/api/simulation/run', (req, res) => {
  const scenario = req.body?.scenario as SimulationScenarioId;
  const valid: SimulationScenarioId[] = [
    'port_scan',
    'traffic_spike',
    'repeated_connections',
    'dns_anomaly',
    'syn_flood_metadata',
  ];
  if (!valid.includes(scenario)) {
    res.status(400).json({ error: 'Unsupported simulation scenario.' });
    return;
  }
  res.json(captureService.startSimulation(scenario));
});

app.post('/api/simulation/stop', (_req, res) => {
  captureService.stopSimulation();
  res.json(captureService.getStatus());
});

app.post('/api/simulation/clear', (_req, res) => {
  res.json(captureService.clearSimulationData());
});

// --- IP INTELLIGENCE ---

app.get('/api/intel/:ip', async (req, res) => {
  const result = await lookupIpIntelligence(req.params.ip);
  res.json(result);
});

// --- AI SECURITY INVESTIGATOR ---

app.post('/api/ai/investigate', async (req, res) => {
  const alertId = typeof req.body?.alertId === 'string' ? req.body.alertId : '';
  const alertObj = req.body?.alert || captureService.getAlerts(true).find((a) => a.id === alertId);
  if (!alertObj) {
    res.status(404).json({ error: 'Alert evidence not found.' });
    return;
  }
  const model = (req.body?.model || 'gemini-4-hydrogen') as SupportedTextModel;
  const useHighThinking = Boolean(req.body?.useHighThinking);

  const result = await investigateAlertWithGemini(alertObj, model, useHighThinking);
  captureService.updateAlert(alertObj.id, { aiAnalysis: result.analysis });
  captureService.addEvent(
    'ai',
    'info',
    `AI investigation completed for ${alertObj.id} using ${result.modelUsed}.`,
    alertObj.isSimulated,
  );
  res.json(result);
});

app.post('/api/ai/generate-visual', async (req, res) => {
  const alertId = typeof req.body?.alertId === 'string' ? req.body.alertId : '';
  const alertObj = req.body?.alert || captureService.getAlerts(true).find((a) => a.id === alertId);
  if (!alertObj) {
    res.status(404).json({ error: 'Alert evidence not found.' });
    return;
  }
  const size = (['1K', '2K', '4K'].includes(req.body?.imageSize) ? req.body.imageSize : '1K') as
    | '1K'
    | '2K'
    | '4K';
  const result = await generateThreatVisualBrief(alertObj, size);
  if (result.error) {
    res.status(402).json(result);
    return;
  }
  res.json(result);
});

// --- VITE / STATIC SERVING ---

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(path.resolve('dist/index.html'));

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve('dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`NETSCOPE X Command Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start NETSCOPE X server:', err);
  process.exit(1);
});

function gracefulExit() {
  captureService.shutdown();
  wss.close();
  server.close(() => process.exit(0));
}

process.on('SIGINT', gracefulExit);
process.on('SIGTERM', gracefulExit);
