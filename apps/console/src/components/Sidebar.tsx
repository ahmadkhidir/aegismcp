import React from 'react';
import {
  LayoutDashboard,
  Activity,
  CheckSquare,
  FileCode,
  ScrollText,
  X,
} from 'lucide-react';

export type ScreenId = 'dashboard' | 'inspector' | 'approvals' | 'policies' | 'audit';

interface SidebarProps {
  currentScreen: ScreenId;
  onNavigate: (screen: ScreenId) => void;
  pendingApprovalsCount?: number;
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentScreen,
  onNavigate,
  pendingApprovalsCount = 0,
  isOpen = false,
  onClose,
}) => {
  const navItems = [
    {
      id: 'dashboard' as const,
      label: 'Security Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'inspector' as const,
      label: 'Live Inspector',
      icon: Activity,
      badge: 'LIVE',
    },
    {
      id: 'approvals' as const,
      label: 'Approvals Queue',
      icon: CheckSquare,
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : null,
      badgeColor: 'warning',
    },
    {
      id: 'policies' as const,
      label: 'Policy Manager',
      icon: FileCode,
      badge: null,
    },
    {
      id: 'audit' as const,
      label: 'Audit Explorer',
      icon: ScrollText,
      badge: null,
    },
  ];

  const handleItemClick = (screen: ScreenId) => {
    onNavigate(screen);
    if (onClose) onClose();
  };

  const navContent = (
    <>
      <nav className="space-y-1">
        <div className="flex items-center justify-between px-space-sm pb-space-xs text-[11px] font-semibold uppercase tracking-wider text-grey-500">
          <span>Navigation</span>
          {onClose && (
            <button
              onClick={onClose}
              className="lg:hidden p-1 text-grey-500 hover:text-grey-900 rounded-radius-sm"
              aria-label="Close navigation drawer"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentScreen === item.id;
          return (
            <button
              key={item.id}
              onClick={() => handleItemClick(item.id)}
              data-testid={`nav-item-${item.id}`}
              className={`w-full flex items-center justify-between px-space-md py-2.5 rounded-radius-md text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-primary-500/10 text-primary-800 border-l-2 border-primary-500 font-semibold'
                  : 'text-grey-600 hover:text-grey-900 hover:bg-grey-200'
              }`}
            >
              <div className="flex items-center gap-space-sm">
                <Icon className={`w-4 h-4 ${isActive ? 'text-primary-500' : 'text-grey-500'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== null && (
                <span
                  data-testid={`nav-badge-${item.id}`}
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded-radius-full font-bold ${
                    item.badgeColor === 'warning'
                      ? 'bg-warning-100 text-warning-900 border border-warning-300'
                      : 'bg-success-100 text-success-900 border border-success-300'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer system info */}
      <div className="p-space-sm bg-grey-200 border border-grey-300 rounded-radius-md text-[11px] text-grey-500 font-mono space-y-1 mt-auto">
        <div className="flex justify-between">
          <span>Protocol:</span>
          <span className="text-grey-700">JSON-RPC 2.0</span>
        </div>
        <div className="flex justify-between">
          <span>SVID:</span>
          <span className="text-grey-700">X.509 Active</span>
        </div>
        <div className="flex justify-between">
          <span>Gateway:</span>
          <span className="text-success-500 font-semibold">Healthy</span>
        </div>
      </div>
    </>
  );

  return (
    <>
      {/* Desktop Persistent Sidebar */}
      <aside className="hidden lg:flex w-64 border-r border-grey-300 bg-grey-100 flex-col justify-between p-space-md flex-shrink-0">
        {navContent}
      </aside>

      {/* Mobile Off-Canvas Drawer */}
      {isOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-grey-900/60 backdrop-blur-sm transition-opacity"
            onClick={onClose}
            aria-hidden="true"
          />
          {/* Slide-out Drawer Panel */}
          <aside className="relative flex flex-col justify-between w-72 max-w-[80vw] h-full bg-grey-100 border-r border-grey-300 p-space-md shadow-2xl z-50 animate-in slide-in-from-left duration-200">
            {navContent}
          </aside>
        </div>
      )}
    </>
  );
};
