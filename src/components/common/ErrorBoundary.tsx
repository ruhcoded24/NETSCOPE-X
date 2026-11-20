import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface State {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  state: State = { hasError: false, message: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error.message || 'Unexpected runtime error' };
  }

  componentDidCatch(error: Error) {
    console.error('ErrorBoundary caught:', error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#080510] text-slate-100 flex items-center justify-center p-6">
          <div className="max-w-lg w-full bg-[#10091B] border border-[#FF3B5C]/40 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-3 text-[#FF3B5C]">
              <AlertTriangle className="w-5 h-5 shrink-0" />
              <h2 className="text-lg font-semibold font-display">NETSCOPE X Module Recovery</h2>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed break-words">
              {this.state.message}
            </p>
            <button
              type="button"
              onClick={() => this.setState({ hasError: false, message: '' })}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[#00E5FF] text-[#080510] hover:bg-[#33ECFF] transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Recover Workspace
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
