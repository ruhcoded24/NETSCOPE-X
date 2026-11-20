import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Pause, Play, Search, Trash2 } from 'lucide-react';
import type { TerminalEvent } from '../../core/types';
import { formatShortTime } from '../../utils/formatters';

interface CyberTerminalProps {
  events: TerminalEvent[];
  onClear: () => void;
  heightClass?: string;
}

const CATEGORIES: Array<'ALL' | TerminalEvent['category']> = [
  'ALL',
  'capture',
  'alert',
  'detection',
  'forensics',
  'ai',
  'simulation',
  'system',
];

export const CyberTerminal: React.FC<CyberTerminalProps> = ({
  events,
  onClear,
  heightClass = 'h-72',
}) => {
  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<'ALL' | TerminalEvent['category']>('ALL');
  const [frozenEvents, setFrozenEvents] = useState<TerminalEvent[]>(events);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!paused) {
      setFrozenEvents(events);
    }
  }, [events, paused]);

  const visibleEvents = useMemo(() => {
    const q = search.trim().toLowerCase();
    return frozenEvents.filter((evt) => {
      if (category !== 'ALL' && evt.category !== category) return false;
      if (q && !evt.message.toLowerCase().includes(q) && !evt.category.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
  }, [frozenEvents, category, search]);

  useEffect(() => {
    if (autoScroll && !paused && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [visibleEvents, autoScroll, paused]);

  const severityColor = (sev: TerminalEvent['severity']) => {
    switch (sev) {
      case 'alert':
        return 'text-[#FF3B5C]';
      case 'warn':
        return 'text-[#FF9F43]';
      case 'success':
        return 'text-[#39FF88]';
      default:
        return 'text-[#00E5FF]';
    }
  };

  return (
    <div className="bg-[#080510] border border-[#C9A4FF]/15 rounded-xl overflow-hidden flex flex-col">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-[#10091B] border-b border-[#C9A4FF]/15">
        <div className="flex items-center gap-3 text-xs text-slate-300">
          <span className="font-semibold text-slate-100 font-display">Event Console</span>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <span className="tabular-nums font-mono text-slate-400">
            {visibleEvents.length} events
          </span>
          {paused && (
            <>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className="text-[#FF9F43] font-medium">Paused</span>
            </>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter logs..."
              aria-label="Filter terminal events"
              className="pl-8 pr-3 py-1.5 text-xs bg-[#080510] border border-[#C9A4FF]/20 rounded-md text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-[#00E5FF]"
            />
          </div>

          <select
            value={category}
            onChange={(e) => setCategory(e.target.value as 'ALL' | TerminalEvent['category'])}
            aria-label="Filter terminal event category"
            className="px-2.5 py-1.5 text-xs bg-[#080510] border border-[#C9A4FF]/20 rounded-md text-slate-200 focus:outline-none focus:border-[#00E5FF]"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c === 'ALL' ? 'All Categories' : c.toUpperCase()}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={() => setAutoScroll((v) => !v)}
            className={`px-2.5 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 ${
              autoScroll
                ? 'border-[#00E5FF]/50 text-[#00E5FF] bg-[#00E5FF]/10'
                : 'border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            Auto-Scroll
          </button>

          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            aria-label={paused ? 'Resume event stream' : 'Pause event stream'}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border border-slate-800 text-slate-300 hover:border-slate-600 transition-colors whitespace-nowrap shrink-0"
          >
            {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {paused ? 'Resume' : 'Pause'}
          </button>

          <button
            type="button"
            onClick={onClear}
            aria-label="Clear event console"
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border border-slate-800 text-slate-400 hover:text-[#FF3B5C] hover:border-[#FF3B5C]/40 transition-colors whitespace-nowrap shrink-0"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        className={`${heightClass} overflow-y-auto p-3 font-mono text-xs space-y-1.5`}
      >
        {visibleEvents.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-500">
            No matching application events recorded yet.
          </div>
        ) : (
          visibleEvents.map((evt) => (
            <div
              key={evt.id}
              className="flex items-start gap-2.5 px-2 py-1 rounded hover:bg-slate-900/60 transition-colors"
            >
              <span className="text-slate-500 shrink-0 tabular-nums">
                {formatShortTime(evt.timestamp)}
              </span>
              <span className={`uppercase font-semibold shrink-0 w-20 ${severityColor(evt.severity)}`}>
                {evt.category}
              </span>
              <span className="text-slate-200 break-all">
                {evt.isSimulated && (
                  <span className="text-[#FF9F43] font-semibold mr-1.5">[SIMULATED]</span>
                )}
                {evt.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
