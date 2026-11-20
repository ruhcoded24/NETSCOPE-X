import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import {
  onAuthStateChanged,
  signInWithPopup,
  signOut,
  type User,
} from 'firebase/auth';
import {
  collection,
  doc,
  getDoc,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
} from 'firebase/firestore';
import {
  auth,
  db,
  googleAuthProvider,
  handleFirestoreError,
  OperationType,
  testFirestoreConnection,
} from '../lib/firebase';
import type { SecurityAlert } from '../core/types';

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
  createdAt?: unknown;
  updatedAt?: unknown;
}

interface AuthContextValue {
  user: User | null;
  authReady: boolean;
  firestoreConnected: boolean;
  cloudIncidents: CloudIncidentRecord[];
  authError: string | null;
  signInWithGoogle: () => Promise<void>;
  logout: () => Promise<void>;
  saveIncidentToCloud: (alert: SecurityAlert) => Promise<void>;
  updateCloudIncident: (
    incidentId: string,
    patch: Partial<Pick<CloudIncidentRecord, 'status' | 'notes' | 'falsePositive' | 'classification' | 'aiAnalysis'>>,
  ) => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [firestoreConnected, setFirestoreConnected] = useState(true);
  const [cloudIncidents, setCloudIncidents] = useState<CloudIncidentRecord[]>([]);
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    testFirestoreConnection().then((ok) => setFirestoreConnected(ok));
  }, []);

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (nextUser) => {
      setUser(nextUser);
      setAuthReady(true);
      if (nextUser) {
        const userRef = doc(db, 'users', nextUser.uid);
        try {
          const snap = await getDoc(userRef);
          if (!snap.exists()) {
            await setDoc(userRef, {
              uid: nextUser.uid,
              displayName: (nextUser.displayName || 'SOC Analyst').slice(0, 100),
              email: (nextUser.email || 'analyst@local').slice(0, 254),
              createdAt: serverTimestamp(),
            });
          }
        } catch (err) {
          // Surface permission issues cleanly without crashing shell
          console.error('User profile sync notice:', err);
        }
      } else {
        setCloudIncidents([]);
      }
    });
    return () => unsub();
  }, []);

  useEffect(() => {
    if (!authReady || !user) return;
    const incidentsRef = collection(db, 'incidents');
    const q = query(incidentsRef, where('ownerId', '==', user.uid));
    const unsub = onSnapshot(
      q,
      (snapshot) => {
        const list: CloudIncidentRecord[] = snapshot.docs.map(
          (d) => d.data() as CloudIncidentRecord,
        );
        setCloudIncidents(list);
      },
      (error) => {
        handleFirestoreError(error, OperationType.LIST, 'incidents');
      },
    );
    return () => unsub();
  }, [authReady, user]);

  const signInWithGoogle = useCallback(async () => {
    setAuthError(null);
    try {
      await signInWithPopup(auth, googleAuthProvider);
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Google Sign-In failed');
    }
  }, []);

  const logout = useCallback(async () => {
    await signOut(auth);
  }, []);

  const saveIncidentToCloud = useCallback(
    async (alert: SecurityAlert) => {
      if (!user) return;
      const safeId = alert.id.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 128);
      const path = `incidents/${safeId}`;
      try {
        const ref = doc(db, 'incidents', safeId);
        await setDoc(ref, {
          incidentId: safeId,
          ownerId: user.uid,
          sourceIp: alert.sourceIp.slice(0, 64),
          destinationIp: (alert.destinationIp ?? '').slice(0, 64),
          category: alert.category,
          severity: alert.severity,
          riskScore: Math.max(0, Math.min(100, alert.riskScore)),
          classification: alert.classification,
          ruleName: alert.ruleName.slice(0, 120),
          summary: alert.summary.slice(0, 1000),
          status: alert.status,
          falsePositive: Boolean(alert.falsePositive),
          notes: (alert.notes || '').slice(0, 4000),
          aiAnalysis: (alert.aiAnalysis || '').slice(0, 8000),
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.WRITE, path);
      }
    },
    [user],
  );

  const updateCloudIncident = useCallback(
    async (
      incidentId: string,
      patch: Partial<Pick<CloudIncidentRecord, 'status' | 'notes' | 'falsePositive' | 'classification' | 'aiAnalysis'>>,
    ) => {
      if (!user) return;
      const safeId = incidentId.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 128);
      const path = `incidents/${safeId}`;
      try {
        const ref = doc(db, 'incidents', safeId);
        const payload: Record<string, unknown> = { updatedAt: serverTimestamp() };
        if (patch.status !== undefined) payload.status = patch.status;
        if (patch.notes !== undefined) payload.notes = patch.notes.slice(0, 4000);
        if (patch.falsePositive !== undefined) payload.falsePositive = patch.falsePositive;
        if (patch.classification !== undefined) payload.classification = patch.classification;
        if (patch.aiAnalysis !== undefined) payload.aiAnalysis = patch.aiAnalysis.slice(0, 8000);
        await updateDoc(ref, payload);
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, path);
      }
    },
    [user],
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        authReady,
        firestoreConnected,
        cloudIncidents,
        authError,
        signInWithGoogle,
        logout,
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
