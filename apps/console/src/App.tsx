/**
 * Specification Anchors: FEAT-008, FEAT-009, NFR-029, screens.md, C-002..C-010
 * Application shell: authentication gate, screen routing, fleet posture, and
 * global overlays. Fleet values come from the gateway; no value is seeded.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, ScreenId } from './components/Sidebar';
import { OfflineBanner } from './components/OfflineBanner';
import { KillSwitchModal } from './components/KillSwitchModal';
import { SessionTimeoutModal } from './components/SessionTimeoutModal';
import { LoginScreen } from './components/LoginScreen';
import { DashboardScreen } from './screens/DashboardScreen';
import { LiveInspectorScreen } from './screens/LiveInspectorScreen';
import { ApprovalsQueueScreen } from './screens/ApprovalsQueueScreen';
import { PolicyManagerScreen } from './screens/PolicyManagerScreen';
import { AuditExplorerScreen } from './screens/AuditExplorerScreen';
import { AegisApi } from './services/api';
import { ThreatLevel } from './types/contracts';
import { AuthProvider, useAuth } from './context/AuthContext';

const SCREEN_IDS: ScreenId[] = ['dashboard', 'inspector', 'approvals', 'policies', 'audit'];

const AppContent: React.FC = () => {
  const { isAuthenticated, isSessionExpired, renewSession, logout, user } = useAuth();

  const getInitialScreen = (): ScreenId => {
    const hash = window.location.hash.replace('#/', '').replace('#', '');
    if (SCREEN_IDS.includes(hash as ScreenId)) {
      return hash as ScreenId;
    }
    return 'dashboard';
  };

  const [currentScreen, setCurrentScreen] = useState<ScreenId>(getInitialScreen());
  const [isOffline, setIsOffline] = useState(!navigator.onLine);
  const [threatLevel, setThreatLevel] = useState<ThreatLevel | null>(null);
  const [isKillSwitchOpen, setIsKillSwitchOpen] = useState(false);
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);

  const handleNavigate = (screen: ScreenId) => {
    setCurrentScreen(screen);
    setIsMobileSidebarOpen(false);
    window.location.hash = `#/${screen}`;
  };

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#/', '').replace('#', '');
      if (SCREEN_IDS.includes(hash as ScreenId)) {
        setCurrentScreen(hash as ScreenId);
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

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

  const refreshPendingCount = useCallback(async () => {
    try {
      const approvals = await AegisApi.getPendingApprovals(3);
      setPendingCount(approvals.tickets.length);
    } catch {
      setPendingCount(null);
    }
  }, []);

  const applySystemEvent = useCallback((status: ThreatLevel, pendingApprovals: number) => {
    setThreatLevel(status);
    setPendingCount(pendingApprovals);
  }, []);

  useEffect(() => {
    if (!isAuthenticated) return;

    let cancelled = false;
    const loadFleetSummary = async () => {
      try {
        const status = await AegisApi.getSystemStatus();
        if (!cancelled) setThreatLevel(status.status);
      } catch {
        if (!cancelled) setThreatLevel(null);
      }
      await refreshPendingCount();
    };

    loadFleetSummary();
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, refreshPendingCount]);

  const handleKillSwitchConfirm = async (
    req: Parameters<typeof AegisApi.triggerEmergencyKill>[0]
  ) => {
    const res = await AegisApi.triggerEmergencyKill(req);
    if (res.status === 'LOCKDOWN') {
      setThreatLevel('LOCKDOWN');
    } else {
      try {
        const status = await AegisApi.getSystemStatus();
        setThreatLevel(status.status);
      } catch {
        setThreatLevel(null);
      }
    }
    await refreshPendingCount();
    return res;
  };

  if (!isAuthenticated) {
    return <LoginScreen />;
  }

  return (
    <div className="min-h-screen bg-grey-50 text-grey-900 flex flex-col font-sans">
      <OfflineBanner isOffline={isOffline} />

      <Navbar
        threatLevel={threatLevel}
        onOpenKillSwitch={() => setIsKillSwitchOpen(true)}
        onToggleMobileMenu={() => setIsMobileSidebarOpen((prev) => !prev)}
      />

      <div className="flex-1 flex overflow-hidden relative">
        <Sidebar
          currentScreen={currentScreen}
          onNavigate={handleNavigate}
          pendingApprovalsCount={pendingCount ?? 0}
          isOpen={isMobileSidebarOpen}
          onClose={() => setIsMobileSidebarOpen(false)}
        />

        <main className="flex-1 overflow-y-auto">
          {currentScreen === 'dashboard' && (
            <DashboardScreen
              onNavigateTo={handleNavigate}
              onOpenKillSwitch={() => setIsKillSwitchOpen(true)}
              threatLevel={threatLevel}
            />
          )}
          {currentScreen === 'inspector' && (
            <LiveInspectorScreen
              onReconnected={refreshPendingCount}
              onSystemEvent={applySystemEvent}
              onApprovalEvent={refreshPendingCount}
            />
          )}
          {currentScreen === 'approvals' && <ApprovalsQueueScreen />}
          {currentScreen === 'policies' && <PolicyManagerScreen />}
          {currentScreen === 'audit' && <AuditExplorerScreen />}
        </main>
      </div>

      <KillSwitchModal
        isOpen={isKillSwitchOpen}
        onClose={() => setIsKillSwitchOpen(false)}
        onConfirm={handleKillSwitchConfirm}
      />

      <SessionTimeoutModal
        isOpen={isSessionExpired}
        userName={user?.name ?? ''}
        onRenew={renewSession}
        onLogout={logout}
      />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};
export default App;
