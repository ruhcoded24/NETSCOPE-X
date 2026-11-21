import React, { useEffect, useState } from 'react';

interface AnimatedCounterProps {
  value: number;
  formatter?: (val: number) => string;
  reducedMotion?: boolean;
  className?: string;
}

export const AnimatedCounter: React.FC<AnimatedCounterProps> = ({
  value,
  formatter = (v) => Math.round(v).toLocaleString(),
  reducedMotion = false,
  className = '',
}) => {
  const [display, setDisplay] = useState(value);

  useEffect(() => {
    if (reducedMotion) {
      setDisplay(value);
      return;
    }
    const start = display;
    const diff = value - start;
    if (Math.abs(diff) < 0.5) {
      setDisplay(value);
      return;
    }
    const duration = 260;
    const startTime = performance.now();
    let rafId = 0;

    const tick = (now: number) => {
      const t = Math.min(1, (now - startTime) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(start + diff * eased);
      if (t < 1) rafId = requestAnimationFrame(tick);
    };

    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [value, reducedMotion]);

  return <span className={`tabular-nums font-mono ${className}`}>{formatter(display)}</span>;
};
