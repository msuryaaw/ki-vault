import React from 'react';
import { useVault } from '../stores/VaultContext';
import {
  Shield,
  Lock,
  Unlock,
  KeyRound,
  Layers,
  Star,
  Tag,
  Image,
  Sliders,
  LogOut,
} from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { status, summary, lockVault } = useVault();

  return (
    <div className="flex h-screen w-screen bg-background text-foreground overflow-hidden font-sans select-none">
      {/* Sidebar Navigation per docs/ui-ux-spec.md §2 */}
      <aside className="w-60 border-r border-border bg-card/60 flex flex-col justify-between shrink-0">
        <div>
          {/* Logo & Product Title */}
          <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
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

            <button
              className="flex w-full items-center gap-2.5 rounded-lg bg-accent px-3 py-2 text-xs font-medium text-accent-foreground shadow-sm"
              disabled
            >
              <KeyRound className="h-4 w-4 text-primary" />
              <span>Vault Status</span>
            </button>

            <button
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-muted-foreground hover:bg-muted/50 hover:text-foreground opacity-60 cursor-not-allowed"
              title="Available in Phase 6 Step 2"
              disabled
            >
              <Layers className="h-4 w-4" />
              <span>Overview</span>
            </button>

            <button
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-muted-foreground hover:bg-muted/50 hover:text-foreground opacity-60 cursor-not-allowed"
              title="Available in Phase 6 Step 2"
              disabled
            >
              <Star className="h-4 w-4" />
              <span>Favorites</span>
            </button>

            <button
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-muted-foreground hover:bg-muted/50 hover:text-foreground opacity-60 cursor-not-allowed"
              title="Available in Phase 6 Step 3"
              disabled
            >
              <Tag className="h-4 w-4" />
              <span>Tags</span>
            </button>

            <button
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-muted-foreground hover:bg-muted/50 hover:text-foreground opacity-60 cursor-not-allowed"
              title="Available in Phase 7"
              disabled
            >
              <Image className="h-4 w-4" />
              <span>Logo Manager</span>
            </button>

            <button
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-muted-foreground hover:bg-muted/50 hover:text-foreground opacity-60 cursor-not-allowed"
              title="Available in Phase 6 Step 4"
              disabled
            >
              <Sliders className="h-4 w-4" />
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

        <div className="p-8 flex-1 flex items-center justify-center">
          {children}
        </div>
      </main>
    </div>
  );
};
