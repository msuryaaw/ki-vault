import React, { useState } from 'react';
import { useVault } from '../stores/VaultContext';
import { TagManagerModal } from './TagManagerModal';
import { LogoManagerModal } from './LogoManagerModal';
import {
  Shield,
  Lock,
  Unlock,
  KeyRound,
  LayoutDashboard,
  Users,
  Globe,
  Star,
  Tag,
  Image,
  Sliders,
  LogOut,
} from 'lucide-react';

export type NavTab =
  | 'overview'
  | 'accounts'
  | 'favorites'
  | 'platforms'
  | 'vault-details'
  | 'settings';


interface LayoutProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  activeTab,
  onTabChange,
  children,
}) => {
  const { status, summary, lockVault } = useVault();
  const [isTagModalOpen, setIsTagModalOpen] = useState(false);
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);

  return (
    <div className="flex h-screen w-screen bg-background text-foreground overflow-hidden font-sans select-none">
      {/* Sidebar Navigation per docs/ui-ux-spec.md §2 */}
      <aside className="w-60 border-r border-border bg-card/60 flex flex-col justify-between shrink-0">
        <div>
          {/* Logo & Product Title */}
          <div className="h-14 flex items-center gap-3 px-5 border-b border-border shrink-0">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-black border border-white/20 text-white shadow-md">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight">KiVault</h1>
              <p className="text-[10px] text-muted-foreground uppercase font-mono">v0.1.0 MVP</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            <div className="px-3 py-1.5 text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
              Navigation
            </div>

            {/* Overview / Dashboard tab */}
            <button
              onClick={() => onTabChange('overview')}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : activeTab === 'overview'
                  ? 'bg-accent text-accent-foreground shadow-sm font-semibold'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <LayoutDashboard className={`h-4 w-4 ${activeTab === 'overview' && status === 'Unlocked' ? 'text-primary' : ''}`} />
              <span>Overview</span>
            </button>

            {/* Accounts tab (Phase 6 Step 4) */}
            <button
              onClick={() => onTabChange('accounts')}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : activeTab === 'accounts'
                  ? 'bg-accent text-accent-foreground shadow-sm font-semibold'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <Users className={`h-4 w-4 ${activeTab === 'accounts' && status === 'Unlocked' ? 'text-primary' : ''}`} />
              <span>Accounts</span>
            </button>

            {/* Favorites tab (Phase 6 Step 4) */}
            <button
              onClick={() => onTabChange('favorites')}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : activeTab === 'favorites'
                  ? 'bg-accent text-accent-foreground shadow-sm font-semibold'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <Star className={`h-4 w-4 ${activeTab === 'favorites' && status === 'Unlocked' ? 'text-amber-500 fill-amber-500' : ''}`} />
              <span>Favorites</span>
            </button>

            {/* Platforms tab (Phase 6 Step 3) */}
            <button
              onClick={() => onTabChange('platforms')}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : activeTab === 'platforms'
                  ? 'bg-accent text-accent-foreground shadow-sm font-semibold'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <Globe className={`h-4 w-4 ${activeTab === 'platforms' && status === 'Unlocked' ? 'text-primary' : ''}`} />
              <span>Platforms</span>
            </button>

            {/* Vault Details tab */}
            <button
              onClick={() => onTabChange('vault-details')}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : activeTab === 'vault-details'
                  ? 'bg-accent text-accent-foreground shadow-sm font-semibold'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <KeyRound className={`h-4 w-4 ${activeTab === 'vault-details' && status === 'Unlocked' ? 'text-primary' : ''}`} />
              <span>Vault Details</span>
            </button>

            {/* Tags modal trigger */}
            <button
              onClick={() => setIsTagModalOpen(true)}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <Tag className="h-4 w-4" />
              <span>Tags</span>
            </button>

            {/* Logo Manager modal trigger */}
            <button
              onClick={() => setIsLogoModalOpen(true)}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <Image className="h-4 w-4" />
              <span>Logo Manager</span>
            </button>

            {/* Settings tab (Phase 6 Step 7) */}
            <button
              onClick={() => onTabChange('settings')}
              disabled={status !== 'Unlocked'}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                status !== 'Unlocked'
                  ? 'text-muted-foreground/50 opacity-50 cursor-not-allowed'
                  : activeTab === 'settings'
                  ? 'bg-accent text-accent-foreground shadow-sm font-semibold'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              }`}
            >
              <Sliders className={`h-4 w-4 ${activeTab === 'settings' && status === 'Unlocked' ? 'text-primary' : ''}`} />
              <span>Settings</span>
            </button>
          </nav>
        </div>


        {/* Footer info & Vault Lock Status */}
        <div className="p-4 border-t border-border space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Status:</span>
            {status === 'Unlocked' ? (
              <span className="flex items-center gap-1 font-semibold text-emerald-400">
                <Unlock className="h-3.5 w-3.5" /> Unlocked
              </span>
            ) : status === 'Locked' ? (
              <span className="flex items-center gap-1 font-semibold text-amber-400">
                <Lock className="h-3.5 w-3.5" /> Locked
              </span>
            ) : (
              <span className="text-muted-foreground font-mono">Uninitialised</span>
            )}
          </div>

          {status === 'Unlocked' && (
            <button
              onClick={() => lockVault()}
              className="w-full flex items-center justify-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground hover:text-destructive hover:border-destructive/40 transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" /> Lock & Close
            </button>
          )}

          {summary && (
            <div className="text-[10px] text-muted-foreground/80 truncate font-mono">
              {summary.vault_name}
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 bg-background overflow-y-auto">
        <header className="h-14 border-b border-border flex items-center justify-between px-8 bg-card/20 shrink-0">
          <div className="text-xs text-muted-foreground">
            {summary ? `Active Vault: ${summary.vault_name}` : 'Local-first Credential Manager'}
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
            <span>RAM-only SQLite</span>
            <span className="text-border">•</span>
            <span>AES-256-GCM</span>
          </div>
        </header>

        <div className="p-8 flex-1 flex items-start justify-center">
          {children}
        </div>
      </main>

      {/* Tag Manager Modal */}
      <TagManagerModal
        isOpen={isTagModalOpen}
        onClose={() => setIsTagModalOpen(false)}
      />

      {/* Logo Manager Modal */}
      <LogoManagerModal
        isOpen={isLogoModalOpen}
        onClose={() => setIsLogoModalOpen(false)}
      />
    </div>
  );
};
