import React, { useEffect, useRef } from 'react';

interface HolographicCoreCanvasProps {
  reducedMotion?: boolean;
  size?: number;
  mouseNormalized?: { x: number; y: number };
}

interface RadarTarget {
  id: string;
  angle: number; // in radians
  dist: number;  // 0.42 to 0.88 normalized radius
  label: string;
  type: 'core' | 'peer' | 'threat' | 'gateway';
  lastHit: number;
  pulseSize: number;
}

export const HolographicCoreCanvas: React.FC<HolographicCoreCanvasProps> = ({
  reducedMotion = false,
  size = 500,
  mouseNormalized = { x: 0, y: 0 },
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let sweepAngle = 0;
    const sweepSpeed = reducedMotion ? 0 : 0.022;

    // Fixed network targets on the radar grid
    const targets: RadarTarget[] = [
      { id: 'T1', angle: 0.6, dist: 0.68, label: '10.240.0.1 (GW)', type: 'gateway', lastHit: 0, pulseSize: 0 },
      { id: 'T2', angle: 1.4, dist: 0.82, label: '172.16.40.9', type: 'peer', lastHit: 0, pulseSize: 0 },
      { id: 'T3', angle: 2.3, dist: 0.58, label: 'AUTH-NODE // TLS', type: 'core', lastHit: 0, pulseSize: 0 },
      { id: 'T4', angle: 3.2, dist: 0.74, label: 'SUSPECT_BURST', type: 'threat', lastHit: 0, pulseSize: 0 },
      { id: 'T5', angle: 4.1, dist: 0.64, label: 'DNS-RESOLVER', type: 'peer', lastHit: 0, pulseSize: 0 },
      { id: 'T6', angle: 4.9, dist: 0.86, label: 'EXT_PEER:443', type: 'peer', lastHit: 0, pulseSize: 0 },
      { id: 'T7', angle: 5.7, dist: 0.52, label: 'INT-SWARM-01', type: 'core', lastHit: 0, pulseSize: 0 },
    ];

    // Floating cyber micro-particles
    const particles = Array.from({ length: 24 }, (_, i) => ({
      angle: (i / 24) * Math.PI * 2 + Math.random() * 0.2,
      radius: 0.44 + Math.random() * 0.42,
      speed: 0.003 + Math.random() * 0.005,
      size: 1 + Math.random() * 1.5,
      opacity: 0.2 + Math.random() * 0.5,
    }));

    // Setup high-DPI scaling
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = size * dpr;
    canvas.height = size * dpr;

    let outerRingAngle = 0;
    let innerRingAngle = 0;

    const render = () => {
      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, size, size);

      const cx = size / 2 + mouseNormalized.x * 6;
      const cy = size / 2 + mouseNormalized.y * 6;
      const maxR = size * 0.47;
      const centerCutout = maxR * 0.38;

      if (!reducedMotion) {
        sweepAngle = (sweepAngle + sweepSpeed) % (Math.PI * 2);
        outerRingAngle = (outerRingAngle + 0.003) % (Math.PI * 2);
        innerRingAngle = (innerRingAngle - 0.004) % (Math.PI * 2);
      }

      const now = performance.now();

      // 1. Concentric Distance Grid Rings
      const ringSteps = [0.42, 0.58, 0.74, 0.90];
      ringSteps.forEach((step, idx) => {
        const r = maxR * step;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = idx === ringSteps.length - 1 ? 'rgba(0, 229, 255, 0.22)' : 'rgba(201, 164, 255, 0.08)';
        ctx.lineWidth = 1;
        if (idx % 2 === 1) {
          ctx.setLineDash([4, 6]);
        } else {
          ctx.setLineDash([]);
        }
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // 2. Crosshair Grid Lines
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.09)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(cx - maxR, cy);
      ctx.lineTo(cx + maxR, cy);
      ctx.moveTo(cx, cy - maxR);
      ctx.lineTo(cx, cy + maxR);
      ctx.stroke();

      // Diagonal crosshairs (faint)
      ctx.strokeStyle = 'rgba(157, 0, 255, 0.05)';
      ctx.beginPath();
      const diag = maxR * 0.7071;
      ctx.moveTo(cx - diag, cy - diag);
      ctx.lineTo(cx + diag, cy + diag);
      ctx.moveTo(cx - diag, cy + diag);
      ctx.lineTo(cx + diag, cy - diag);
      ctx.stroke();

      // 3. Outer Azimuth Compass Ring (Ticked ring)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(outerRingAngle * 0.2);
      const azR = maxR * 0.94;
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.35)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(0, 0, azR, 0, Math.PI * 2);
      ctx.stroke();

      // Draw azimuth tick marks every 6 degrees
      for (let a = 0; a < 360; a += 6) {
        const rad = (a * Math.PI) / 180;
        const isMajor = a % 30 === 0;
        const isCardinal = a % 90 === 0;
        const len = isCardinal ? 8 : isMajor ? 5 : 2.5;
        const x1 = Math.cos(rad) * azR;
        const y1 = Math.sin(rad) * azR;
        const x2 = Math.cos(rad) * (azR - len);
        const y2 = Math.sin(rad) * (azR - len);

        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = isCardinal
          ? '#00E5FF'
          : isMajor
          ? 'rgba(201, 164, 255, 0.65)'
          : 'rgba(201, 164, 255, 0.18)';
        ctx.lineWidth = isCardinal ? 1.5 : 1;
        ctx.stroke();

        if (isCardinal) {
          const textR = azR - 14;
          const tx = Math.cos(rad) * textR;
          const ty = Math.sin(rad) * textR;
          ctx.save();
          ctx.translate(tx, ty);
          ctx.rotate(rad + Math.PI / 2);
          ctx.font = '700 8px "JetBrains Mono", monospace';
          ctx.fillStyle = '#00E5FF';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          const cardLabel = a === 0 ? '090°' : a === 90 ? '180°' : a === 180 ? '270°' : '000°';
          ctx.fillText(cardLabel, 0, 0);
          ctx.restore();
        }
      }
      ctx.restore();

      // 4. Counter-rotating Segmented Arc Ring (Mid Ring)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(innerRingAngle);
      const segR = maxR * 0.82;
      const numSegments = 6;
      for (let s = 0; s < numSegments; s++) {
        const start = (s * Math.PI * 2) / numSegments;
        const end = start + (Math.PI * 2) / numSegments * 0.55;
        ctx.beginPath();
        ctx.arc(0, 0, segR, start, end);
        ctx.strokeStyle = s % 2 === 0 ? 'rgba(0, 229, 255, 0.45)' : 'rgba(255, 0, 200, 0.45)';
        ctx.lineWidth = 1.6;
        ctx.stroke();

        // Terminal dots on segment heads
        const dotX = Math.cos(start) * segR;
        const dotY = Math.sin(start) * segR;
        ctx.beginPath();
        ctx.arc(dotX, dotY, 1.8, 0, Math.PI * 2);
        ctx.fillStyle = s % 2 === 0 ? '#00E5FF' : '#FF00C8';
        ctx.fill();
      }
      ctx.restore();

      // 5. Radar Sweep (Smooth Phosphor Gradient Cone)
      ctx.save();
      const sweepSpread = Math.PI * 0.32; // ~57 degrees
      const sweepSteps = 24;
      for (let i = 0; i < sweepSteps; i++) {
        const factor = i / sweepSteps;
        const a1 = sweepAngle - sweepSpread * (1 - factor);
        const a2 = a1 + (sweepSpread / sweepSteps) * 1.05;
        const alpha = Math.pow(factor, 2.2) * 0.22; // exponential fade

        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, maxR * 0.94, a1, a2);
        ctx.closePath();
        ctx.fillStyle = `rgba(0, 229, 255, ${alpha.toFixed(3)})`;
        ctx.fill();
      }

      // Sweep Beam Leading Edge (Electric Cyan Needle)
      const leadX = cx + Math.cos(sweepAngle) * (maxR * 0.94);
      const leadY = cy + Math.sin(sweepAngle) * (maxR * 0.94);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(leadX, leadY);
      ctx.strokeStyle = '#00E5FF';
      ctx.lineWidth = 1.8;
      ctx.shadowColor = '#00E5FF';
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.restore();

      // 6. Floating Cyber Particles
      particles.forEach((p) => {
        if (!reducedMotion) {
          p.angle = (p.angle + p.speed) % (Math.PI * 2);
        }
        const px = cx + Math.cos(p.angle) * (maxR * p.radius);
        const py = cy + Math.sin(p.angle) * (maxR * p.radius);
        ctx.beginPath();
        ctx.arc(px, py, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 229, 255, ${p.opacity})`;
        ctx.fill();
      });

      // 7. Radar Targets & Constellation Vector Pings
      targets.forEach((target) => {
        const targetX = cx + Math.cos(target.angle) * (maxR * target.dist);
        const targetY = cy + Math.sin(target.angle) * (maxR * target.dist);

        // Check if sweep beam is currently passing target
        let diff = sweepAngle - target.angle;
        while (diff < -Math.PI) diff += Math.PI * 2;
        while (diff > Math.PI) diff -= Math.PI * 2;

        if (Math.abs(diff) < 0.05 && now - target.lastHit > 1000) {
          target.lastHit = now;
        }

        const elapsed = now - target.lastHit;
        const isHit = elapsed < 1600;
        const decay = isHit ? Math.max(0, 1 - elapsed / 1600) : 0;

        const mainColor =
          target.type === 'threat'
            ? '#FF00C8'
            : target.type === 'gateway'
            ? '#00E5FF'
            : '#C9A4FF';

        // Outer pulsing ring on hit
        if (isHit) {
          const pulseR = 6 + (1 - decay) * 22;
          ctx.beginPath();
          ctx.arc(targetX, targetY, pulseR, 0, Math.PI * 2);
          ctx.strokeStyle = target.type === 'threat' ? `rgba(255, 0, 200, ${decay * 0.7})` : `rgba(0, 229, 255, ${decay * 0.7})`;
          ctx.lineWidth = 1.2;
          ctx.stroke();

          // Reticle target brackets
          const bSize = 6;
          ctx.strokeStyle = mainColor;
          ctx.lineWidth = 1;
          ctx.beginPath();
          // Top-left
          ctx.moveTo(targetX - bSize, targetY - bSize + 2);
          ctx.lineTo(targetX - bSize, targetY - bSize);
          ctx.lineTo(targetX - bSize + 2, targetY - bSize);
          // Bottom-right
          ctx.moveTo(targetX + bSize, targetY + bSize - 2);
          ctx.lineTo(targetX + bSize, targetY + bSize);
          ctx.lineTo(targetX + bSize - 2, targetY + bSize);
          ctx.stroke();

          // Target telemetry label pill
          ctx.save();
          ctx.font = '600 8px "JetBrains Mono", monospace';
          ctx.fillStyle = `rgba(226, 232, 240, ${decay * 0.9})`;
          ctx.fillText(target.label, targetX + 10, targetY + 3);
          ctx.restore();
        }

        // Target core dot
        ctx.beginPath();
        ctx.arc(targetX, targetY, isHit ? 3.5 : 2.2, 0, Math.PI * 2);
        ctx.fillStyle = isHit ? mainColor : 'rgba(201, 164, 255, 0.45)';
        if (isHit) {
          ctx.shadowColor = mainColor;
          ctx.shadowBlur = 8;
        }
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // 8. Connect active targets with telemetry vector lines
      for (let i = 0; i < targets.length; i++) {
        const next = targets[(i + 1) % targets.length];
        const t1 = targets[i];
        const t2 = next;
        const e1 = now - t1.lastHit;
        const e2 = now - t2.lastHit;
        if (e1 < 2000 || e2 < 2000) {
          const x1 = cx + Math.cos(t1.angle) * (maxR * t1.dist);
          const y1 = cy + Math.sin(t1.angle) * (maxR * t1.dist);
          const x2 = cx + Math.cos(t2.angle) * (maxR * t2.dist);
          const y2 = cy + Math.sin(t2.angle) * (maxR * t2.dist);
          ctx.beginPath();
          ctx.moveTo(x1, y1);
          ctx.lineTo(x2, y2);
          ctx.strokeStyle = 'rgba(0, 229, 255, 0.14)';
          ctx.lineWidth = 1;
          ctx.setLineDash([3, 4]);
          ctx.stroke();
          ctx.setLineDash([]);
        }
      }

      // 9. Cutout clearing for the central physical emblem housing
      // This ensures the central emblem sits cleanly on its own obsidian lens
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, centerCutout, 0, Math.PI * 2);
      ctx.clip();
      ctx.clearRect(cx - centerCutout, cy - centerCutout, centerCutout * 2, centerCutout * 2);
      ctx.restore();

      // Border ring around center cutout
      ctx.beginPath();
      ctx.arc(cx, cy, centerCutout, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.55)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.restore();

      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [reducedMotion, size, mouseNormalized.x, mouseNormalized.y]);

  return (
    <canvas
      ref={canvasRef}
      style={{ width: size, height: size }}
      className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-10"
      aria-hidden="true"
    />
  );
};
