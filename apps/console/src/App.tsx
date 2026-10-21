/**
 * Specification Anchors: FEAT-008, C-002..C-010
 * Main Application Shell & Navigation
 */

import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, ScreenId } from './components/Sidebar';
import { OfflineBanner } from './components/OfflineBanner';
import { KillSwitchModal } from './components/KillSwitchModal';
import { DashboardScreen } from './screens/DashboardScreen';
import { LiveInspectorScreen } from './screens/LiveInspectorScreen';
import { ApprovalsQueueScreen } from './screens/ApprovalsQueueScreen';
import { PolicyManagerScreen } from './screens/PolicyManagerScreen';
import { AuditExplorerScreen } from './screens/AuditExplorerScreen';
import { AegisApi } from './services/api';
import { ThreatLevel } from './types/contracts';

export const App: React.FC = () => {
  // Navigation state initialized from URL hash or path
  const getInitialScreen = (): ScreenId => {
    const hash = window.location.hash.replace('#/', '').replace('#', '');
    if (['dashboard', 'inspector', 'approvals', 'policies', 'audit'].includes(hash)) {
      return hash as ScreenId;
    }
    const path = window.location.pathname.replace('/', '');
    if (['dashboard', 'inspector', 'approvals', 'policies', 'audit'].includes(path)) {
      return path as ScreenId;
    }
    return 'dashboard';
  };

  const [currentScreen, setCurrentScreen] = useState<ScreenId>(getInitialScreen());
  const [isOffline, setIsOffline] = useState(!navigator.onLine);
  const [threatLevel, setThreatLevel] = useState<ThreatLevel>('NORMAL');
  const [isKillSwitchOpen, setIsKillSwitchOpen] = useState(false);
  const [pendingCount, setPendingCount] = useState(3);

  // Synchronize hash with currentScreen
  const handleNavigate = (screen: ScreenId) => {
    setCurrentScreen(screen);
    window.location.hash = `#/${screen}`;
  };

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#/', '').replace('#', '');
      if (['dashboard', 'inspector', 'approvals', 'policies', 'audit'].includes(hash)) {
        setCurrentScreen(hash as ScreenId);
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // Offline detection
  useEffect(() => {
    const handleOnline = () => setIsOffline(false);
    const handleOffline = () => setIsOffline(true);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Fetch initial threat level and approvals count
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const status = await AegisApi.getSystemStatus();
        setThreatLevel(status.status);
        const approvals = await AegisApi.getApprovals('pending');
        setPendingCount(approvals.tickets.length);
      } catch {
        // Fallback
      }
    };
    checkStatus();
  }, []);

  const handleKillSwitchConfirm = async (req: Parameters<typeof AegisApi.triggerEmergencyKill>[0]) => {
    const res = await AegisApi.triggerEmergencyKill(req);
    setThreatLevel('LOCKDOWN');
    return res;
  };

  return (
    <div className="min-h-screen bg-grey-50 text-grey-900 flex flex-col font-sans">
      {/* Offline Alert Banner */}
      <OfflineBanner isOffline={isOffline} />

      {/* Top Navbar */}
      <Navbar
        threatLevel={threatLevel}
        onOpenKillSwitch={() => setIsKillSwitchOpen(true)}
      />

      {/* Body Layout: Sidebar + Main Screen */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          currentScreen={currentScreen}
          onNavigate={handleNavigate}
          pendingApprovalsCount={pendingCount}
        />

        <main className="flex-1 overflow-y-auto">
          {currentScreen === 'dashboard' && (
            <DashboardScreen
              onNavigateTo={handleNavigate}
              onOpenKillSwitch={() => setIsKillSwitchOpen(true)}
              threatLevel={threatLevel}
            />
          )}
          {currentScreen === 'inspector' && <LiveInspectorScreen />}
          {currentScreen === 'approvals' && <ApprovalsQueueScreen />}
          {currentScreen === 'policies' && <PolicyManagerScreen />}
          {currentScreen === 'audit' && <AuditExplorerScreen />}
        </main>
      </div>

      {/* Emergency Kill-Switch Confirmation Modal (C-008) */}
      <KillSwitchModal
        isOpen={isKillSwitchOpen}
        onClose={() => setIsKillSwitchOpen(false)}
        onConfirm={handleKillSwitchConfirm}
      />
    </div>
  );
};
export default App;
