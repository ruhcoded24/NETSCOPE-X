import React, { useState } from 'react';
import { LogIn, UserPlus, X, ShieldCheck, Database, AlertCircle } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialMode?: 'login' | 'signup';
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  initialMode = 'login',
}) => {
  const {
    signInWithEmail,
    signUpWithEmail,
    signInWithGoogle,
    authError,
    supabaseConnected,
  } = useAuth();

  const [mode, setMode] = useState<'login' | 'signup'>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [localMsg, setLocalMsg] = useState<{ type: 'error' | 'success'; text: string } | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalMsg(null);
    if (!email.trim() || !password.trim()) {
      setLocalMsg({ type: 'error', text: 'Please fill in all required fields.' });
      return;
    }
    setLoading(true);

    try {
      if (mode === 'signup') {
        const { error } = await signUpWithEmail(email, password, fullName);
        if (error) {
          setLocalMsg({ type: 'error', text: error.message });
        } else {
          setLocalMsg({
            type: 'success',
            text: 'Account created! Please check your email or proceed to sign in.',
          });
          setMode('login');
        }
      } else {
        const { error } = await signInWithEmail(email, password);
        if (error) {
          setLocalMsg({ type: 'error', text: error.message });
        } else {
          onClose();
        }
      }
    } catch (err) {
      setLocalMsg({
        type: 'error',
        text: err instanceof Error ? err.message : 'Authentication failed',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
      <div className="relative w-full max-w-md p-6 rounded-2xl bg-[#10091B] border border-[#00E5FF]/30 shadow-2xl space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[#00E5FF]" />
            <h2 className="text-base font-bold text-white tracking-wide">
              {mode === 'login' ? 'SOC Analyst Sign In' : 'Register New SOC Analyst'}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800/60 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Supabase Status Pill */}
        <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#080510] border border-slate-800 text-[11px]">
          <div className="flex items-center gap-2 text-slate-300">
            <Database className="w-3.5 h-3.5 text-[#00E5FF]" />
            <span>Supabase PostgreSQL + RLS</span>
          </div>
          <span
            className={`font-mono text-[10px] px-2 py-0.5 rounded-full ${
              supabaseConnected
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
            }`}
          >
            {supabaseConnected ? '● Cloud Connected' : '○ Local Mode'}
          </span>
        </div>

        {/* Tab switch */}
        <div className="flex rounded-lg bg-[#080510] p-1 border border-slate-800">
          <button
            type="button"
            onClick={() => {
              setMode('login');
              setLocalMsg(null);
            }}
            className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-colors ${
              mode === 'login'
                ? 'bg-[#00E5FF]/20 text-[#00E5FF] border border-[#00E5FF]/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('signup');
              setLocalMsg(null);
            }}
            className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-colors ${
              mode === 'signup'
                ? 'bg-[#00E5FF]/20 text-[#00E5FF] border border-[#00E5FF]/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Alerts / Error messages */}
        {(localMsg || authError) && (
          <div
            className={`p-3 rounded-lg text-xs flex items-start gap-2 ${
              localMsg?.type === 'success'
                ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
                : 'bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 text-[#FF3B5C]'
            }`}
          >
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{localMsg?.text || authError}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
          {mode === 'signup' && (
            <div>
              <label className="block text-slate-400 mb-1">Full Name</label>
              <input
                type="text"
                placeholder="e.g. Ruhani Analyst"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 focus:outline-none focus:border-[#00E5FF]"
              />
            </div>
          )}

          <div>
            <label className="block text-slate-400 mb-1">Email Address</label>
            <input
              type="email"
              required
              placeholder="analyst@netscope.internal"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 focus:outline-none focus:border-[#00E5FF]"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Password</label>
            <input
              type="password"
              required
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[#080510] border border-slate-700 text-slate-100 focus:outline-none focus:border-[#00E5FF]"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#00E5FF] text-[#080510] font-semibold hover:bg-[#33ebff] transition-colors disabled:opacity-50"
          >
            {mode === 'login' ? (
              <>
                <LogIn className="w-4 h-4" />
                {loading ? 'Authenticating...' : 'Sign In with Supabase'}
              </>
            ) : (
              <>
                <UserPlus className="w-4 h-4" />
                {loading ? 'Creating...' : 'Register Analyst'}
              </>
            )}
          </button>
        </form>

        {/* Divider & OAuth */}
        <div className="relative py-1">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-slate-800" />
          </div>
          <div className="relative flex justify-center text-[10px] uppercase font-mono">
            <span className="bg-[#10091B] px-2 text-slate-500">or continue with</span>
          </div>
        </div>

        <button
          type="button"
          onClick={signInWithGoogle}
          className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-slate-700 hover:border-[#00E5FF]/50 text-xs font-medium text-slate-200 transition-colors"
        >
          <LogIn className="w-3.5 h-3.5 text-[#00E5FF]" />
          Google Workspace OAuth
        </button>

        <p className="text-[11px] text-slate-500 text-center">
          Row Level Security (RLS) ensures each analyst can only access their authorized incident records and capture logs.
        </p>
      </div>
    </div>
  );
};
