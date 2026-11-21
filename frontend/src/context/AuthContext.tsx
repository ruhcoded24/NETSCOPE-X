import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import type { User, Session } from '@supabase/supabase-js';
import { supabase, isSupabaseConfigured } from '../lib/supabase';
import type { SecurityAlert } from '../core/types';

export interface UserProfile {
  id: string;
  email: string | null;
  fullName: string | null;
  role: string;
  organization?: string;
}

export interface CloudIncidentRecord {
  incidentId: string;
  ownerId: string;
  sourceIp: string;
  destinationIp: string;
  category: SecurityAlert['category'];
  severity: SecurityAlert['severity'];
  riskScore: number;
  classification: SecurityAlert['classification'];
  ruleName: string;
  summary: string;
  status: SecurityAlert['status'];
  falsePositive: boolean;
  notes: string;
  aiAnalysis: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface AuthUser {
  id: string;
  uid: string; // alias for backwards-compatibility
  email?: string | null;
  displayName?: string | null;
  role?: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  rawUser: User | null;
  session: Session | null;
  profile: UserProfile | null;
  authReady: boolean;
  supabaseConnected: boolean;
  firestoreConnected: boolean; // backwards-compatibility alias
  cloudIncidents: CloudIncidentRecord[];
  authError: string | null;
  signInWithEmail: (email: string, pass: string) => Promise<{ error: Error | null }>;
  signUpWithEmail: (email: string, pass: string, fullName?: string) => Promise<{ error: Error | null }>;
  signInWithGoogle: () => Promise<void>;
  signInWithOAuth: (provider: 'google' | 'github') => Promise<void>;
  logout: () => Promise<void>;
  refreshCloudIncidents: () => Promise<void>;
  saveIncidentToCloud: (alert: SecurityAlert) => Promise<void>;
  updateCloudIncident: (
    incidentId: string,
    patch: Partial<Pick<CloudIncidentRecord, 'status' | 'notes' | 'falsePositive' | 'classification' | 'aiAnalysis'>>,
  ) => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [rawUser, setRawUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [cloudIncidents, setCloudIncidents] = useState<CloudIncidentRecord[]>([]);
  const [authError, setAuthError] = useState<string | null>(null);

  const supabaseConnected = isSupabaseConfigured && Boolean(supabase);

  // Map Supabase User to convenient AuthUser format
  const user: AuthUser | null = rawUser
    ? {
        id: rawUser.id,
        uid: rawUser.id,
        email: rawUser.email,
        displayName:
          profile?.fullName ||
          rawUser.user_metadata?.full_name ||
          rawUser.email?.split('@')[0] ||
          'SOC Analyst',
        role: profile?.role || rawUser.user_metadata?.role || 'analyst',
      }
    : null;

  const fetchProfile = useCallback(async (userId: string) => {
    if (!supabase) return;
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .maybeSingle();

      if (!error && data) {
        setProfile({
          id: data.id,
          email: data.email,
          fullName: data.full_name,
          role: data.role || 'analyst',
          organization: data.organization,
        });
      }
    } catch (err) {
      console.warn('Profile fetch note:', err);
    }
  }, []);

  const refreshCloudIncidents = useCallback(async () => {
    if (!supabase || !rawUser) {
      setCloudIncidents([]);
      return;
    }
    try {
      const { data, error } = await supabase
        .from('incidents')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(100);

      if (!error && Array.isArray(data)) {
        const mapped: CloudIncidentRecord[] = data.map((d) => ({
          incidentId: d.id,
          ownerId: d.user_id,
          sourceIp: d.source_ip || '',
          destinationIp: d.target_ip || '',
          category: (d.category as SecurityAlert['category']) || 'port_scan',
          severity: (d.severity as SecurityAlert['severity']) || 'Medium',
          riskScore: d.severity === 'Critical' ? 95 : d.severity === 'High' ? 75 : 50,
          classification: 'Confirmed Incident',
          ruleName: d.mitre_technique || d.title,
          summary: d.title,
          status: (d.status as SecurityAlert['status']) || 'open',
          falsePositive: false,
          notes: d.notes || '',
          aiAnalysis: d.ai_analysis || '',
          createdAt: d.created_at,
          updatedAt: d.updated_at,
        }));
        setCloudIncidents(mapped);
      }
    } catch (err) {
      console.error('Failed to load cloud incidents from Supabase:', err);
    }
  }, [rawUser]);

  // Initialize Supabase Auth state listener
  useEffect(() => {
    if (!supabase) {
      setAuthReady(true);
      return;
    }

    supabase.auth.getSession().then(({ data: { session: currentSession } }) => {
      setSession(currentSession);
      setRawUser(currentSession?.user ?? null);
      if (currentSession?.user) {
        fetchProfile(currentSession.user.id);
      }
      setAuthReady(true);
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(async (_event, nextSession) => {
      setSession(nextSession);
      setRawUser(nextSession?.user ?? null);
      if (nextSession?.user) {
        await fetchProfile(nextSession.user.id);
      } else {
        setProfile(null);
        setCloudIncidents([]);
      }
      setAuthReady(true);
    });

    return () => {
      subscription.unsubscribe();
    };
  }, [fetchProfile]);

  // Synchronize cloud incidents on auth change
  useEffect(() => {
    if (rawUser) {
      refreshCloudIncidents();
    } else {
      setCloudIncidents([]);
    }
  }, [rawUser, refreshCloudIncidents]);

  // Real-time Supabase subscription on incidents table
  useEffect(() => {
    if (!supabase || !rawUser) return;

    const channel = supabase
      .channel('public:incidents-realtime')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'incidents' },
        () => {
          refreshCloudIncidents();
        }
      )
      .subscribe();

    return () => {
      supabase?.removeChannel(channel);
    };
  }, [rawUser, refreshCloudIncidents]);

  const signInWithEmail = useCallback(async (email: string, pass: string) => {
    setAuthError(null);
    if (!supabase) {
      const err = new Error('Supabase client is not configured');
      setAuthError(err.message);
      return { error: err };
    }
    const { error } = await supabase.auth.signInWithPassword({
      email: email.trim(),
      password: pass,
    });
    if (error) {
      setAuthError(error.message);
      return { error };
    }
    return { error: null };
  }, []);

  const signUpWithEmail = useCallback(
    async (email: string, pass: string, fullName?: string) => {
      setAuthError(null);
      if (!supabase) {
        const err = new Error('Supabase client is not configured');
        setAuthError(err.message);
        return { error: err };
      }
      const { data, error } = await supabase.auth.signUp({
        email: email.trim(),
        password: pass,
        options: {
          data: {
            full_name: fullName?.trim() || email.split('@')[0],
            role: 'analyst',
          },
        },
      });
      if (error) {
        setAuthError(error.message);
        return { error };
      }
      if (data.user) {
        setRawUser(data.user);
      }
      return { error: null };
    },
    []
  );

  const signInWithOAuth = useCallback(async (provider: 'google' | 'github') => {
    setAuthError(null);
    if (!supabase) {
      setAuthError('Supabase is not configured. Please check environment variables.');
      return;
    }
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: window.location.origin,
      },
    });
    if (error) setAuthError(error.message);
  }, []);

  const signInWithGoogle = useCallback(async () => {
    await signInWithOAuth('google');
  }, [signInWithOAuth]);

  const logout = useCallback(async () => {
    setAuthError(null);
    if (supabase) {
      await supabase.auth.signOut();
    }
    setRawUser(null);
    setSession(null);
    setProfile(null);
    setCloudIncidents([]);
  }, []);

  const saveIncidentToCloud = useCallback(
    async (alert: SecurityAlert) => {
      if (!supabase || !rawUser) return;
      const safeId = alert.id.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 128);

      try {
        // Upsert alert into security_alerts table
        await supabase.from('security_alerts').upsert({
          id: safeId,
          user_id: rawUser.id,
          source_ip: alert.sourceIp,
          destination_ip: alert.destinationIp,
          category: alert.category,
          severity: alert.severity,
          risk_score: alert.riskScore,
          risk_breakdown: alert.riskBreakdown,
          classification: alert.classification,
          rule_name: alert.ruleName,
          summary: alert.summary,
          evidence: alert.evidence,
          recommended_steps: alert.recommendedSteps,
          status: alert.status,
          false_positive: Boolean(alert.falsePositive),
          notes: alert.notes || '',
          is_simulated: Boolean(alert.isSimulated),
          ai_analysis: alert.aiAnalysis || '',
          epoch_ms: alert.epochMs || Date.now(),
          timestamp: alert.timestamp || new Date().toISOString(),
        });

        // Upsert incident record
        await supabase.from('incidents').upsert({
          id: `inc_${safeId}`,
          user_id: rawUser.id,
          alert_id: safeId,
          title: `${alert.ruleName}: ${alert.summary.slice(0, 80)}`,
          severity: alert.severity,
          status: alert.status === 'resolved' ? 'resolved' : 'open',
          source_ip: alert.sourceIp,
          target_ip: alert.destinationIp,
          mitre_technique: alert.ruleName,
          notes: alert.notes || '',
          ai_analysis: alert.aiAnalysis || '',
        });

        await refreshCloudIncidents();
      } catch (err) {
        console.error('Failed to save incident to Supabase:', err);
      }
    },
    [rawUser, refreshCloudIncidents]
  );

  const updateCloudIncident = useCallback(
    async (
      incidentId: string,
      patch: Partial<Pick<CloudIncidentRecord, 'status' | 'notes' | 'falsePositive' | 'classification' | 'aiAnalysis'>>,
    ) => {
      if (!supabase || !rawUser) return;

      try {
        const payload: Record<string, unknown> = {
          updated_at: new Date().toISOString(),
        };
        if (patch.status !== undefined) payload.status = patch.status;
        if (patch.notes !== undefined) payload.notes = patch.notes.slice(0, 4000);
        if (patch.aiAnalysis !== undefined) payload.ai_analysis = patch.aiAnalysis.slice(0, 8000);

        await supabase.from('incidents').update(payload).eq('id', incidentId);
        await refreshCloudIncidents();
      } catch (err) {
        console.error('Failed to update cloud incident in Supabase:', err);
      }
    },
    [rawUser, refreshCloudIncidents]
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        rawUser,
        session,
        profile,
        authReady,
        supabaseConnected,
        firestoreConnected: supabaseConnected,
        cloudIncidents,
        authError,
        signInWithEmail,
        signUpWithEmail,
        signInWithGoogle,
        signInWithOAuth,
        logout,
        refreshCloudIncidents,
        saveIncidentToCloud,
        updateCloudIncident,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
