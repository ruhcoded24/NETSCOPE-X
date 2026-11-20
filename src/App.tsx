/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import React from 'react';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { AuthProvider } from './context/AuthContext';
import { AppProvider, useApp } from './context/AppContext';
import { AppShell } from './components/layout/AppShell';
import { Launch } from './pages/Launch';
import { Overview } from './pages/Overview';
import { LiveTraffic } from './pages/LiveTraffic';
import { PacketInspectorPage } from './pages/PacketInspectorPage';
import { NetworkUniversePage } from './pages/NetworkUniversePage';
import { ProtocolAnalysis } from './pages/ProtocolAnalysis';
import { ThreatCentre } from './pages/ThreatCentre';
import { Investigator } from './pages/Investigator';
import { IPIntelligence } from './pages/IPIntelligence';
import { PCAPForensics } from './pages/PCAPForensics';
import { SimulationLab } from './pages/SimulationLab';
import { Incidents } from './pages/Incidents';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';

const ActiveView: React.FC = () => {
  const { activePage } = useApp();

  if (activePage === 'launch') {
    return <Launch />;
  }

  let content: React.ReactNode;
  switch (activePage) {
    case 'overview':
      content = <Overview />;
      break;
    case 'live-traffic':
      content = <LiveTraffic />;
      break;
    case 'packet-inspector':
      content = <PacketInspectorPage />;
      break;
    case 'network-universe':
      content = <NetworkUniversePage />;
      break;
    case 'protocol-intelligence':
      content = <ProtocolAnalysis />;
      break;
    case 'threat-centre':
      content = <ThreatCentre />;
      break;
    case 'ai-investigator':
      content = <Investigator />;
      break;
    case 'ip-intelligence':
      content = <IPIntelligence />;
      break;
    case 'pcap-forensics':
      content = <PCAPForensics />;
      break;
    case 'simulation-lab':
      content = <SimulationLab />;
      break;
    case 'incidents':
      content = <Incidents />;
      break;
    case 'reports':
      content = <Reports />;
      break;
    case 'settings':
      content = <Settings />;
      break;
    default:
      content = <Overview />;
  }

  return <AppShell>{content}</AppShell>;
};

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <AppProvider>
          <ActiveView />
        </AppProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}
