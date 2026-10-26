import React, { useEffect, useState, useCallback } from 'react';
import { useVault } from '../stores/VaultContext';
import { fetchDashboardStats } from '../services/domain';
import type { DashboardStats } from '../types/domain';
import type { CommandError } from '../types/vault';
import { Button } from '../components/Button';
import {
  Users,
  Star,
  Globe,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  Plus,
  RefreshCw,
  Lock,
  Clock,
  Key,
} from 'lucide-react';

interface DashboardProps {
  onAddAccountClick?: () => void;
  onViewVaultStatus?: () => void;
  onNavigateToAccounts?: () => void;
  onNavigateToFavorites?: () => void;
  onNavigateToPlatforms?: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  onAddAccountClick,
  onViewVaultStatus,
  onNavigateToAccounts,
  onNavigateToFavorites,
  onNavigateToPlatforms,
}) => {

  const { summary } = useVault();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CommandError | null>(null);

  const loadStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchDashboardStats();
      setStats(data);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const handleAddAccount = () => {
    if (onAddAccountClick) {
      onAddAccountClick();
    }
  };


  return (
    <div className="w-full max-w-5xl mx-auto space-y-6 text-left">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <span>Overview</span>
            {summary && (
              <span className="text-xs font-mono font-normal text-muted-foreground bg-muted/40 px-2 py-0.5 rounded border border-border/50">
                {summary.vault_name}
              </span>
            )}
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time status and credential metrics for your active vault.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={loadStats}
            disabled={loading}
            title="Refresh overview metrics"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          </Button>

          {onViewVaultStatus && (
            <Button
              variant="outline"
              size="sm"
              onClick={onViewVaultStatus}
              title="View vault container metadata"
            >
              <Key className="mr-1.5 h-3.5 w-3.5 text-muted-foreground" />
              Vault Details
            </Button>
          )}

          <Button
            variant="primary"
            size="sm"
            onClick={handleAddAccount}
          >
            <Plus className="mr-1.5 h-4 w-4" /> Add Account
          </Button>
        </div>
      </div>



      {/* Error state */}
      {error && !loading && (
        <div className="rounded-xl border border-destructive/40 bg-destructive/15 p-4 text-xs text-destructive flex items-start gap-3">
          <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold">Failed to load overview data</p>
            <p className="opacity-90">{error.message} (Code: {error.code})</p>
            <Button
              variant="outline"
              size="sm"
              onClick={loadStats}
              className="mt-2 text-xs border-destructive/40 hover:bg-destructive/20"
            >
              Retry
            </Button>
          </div>
        </div>
      )}

      {/* Loading Skeleton */}
      {loading && !stats && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm animate-pulse"
            >
              <div className="h-4 w-24 bg-muted/60 rounded" />
              <div className="h-8 w-16 bg-muted/80 rounded" />
              <div className="h-3 w-32 bg-muted/40 rounded" />
            </div>
          ))}
        </div>
      )}

      {/* 4 Main Summary Cards per docs/ui-ux-spec.md §5 */}
      {stats && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Total Accounts */}
            <div
              onClick={onNavigateToAccounts}
              className={`rounded-xl border border-border bg-card p-5 space-y-2 shadow-sm relative overflow-hidden group hover:border-primary/40 transition-colors ${
                onNavigateToAccounts ? 'cursor-pointer hover:bg-card/80' : ''
              }`}
            >
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-xs font-semibold uppercase tracking-wider">
                  Total Accounts
                </span>
                <div className="h-8 w-8 rounded-lg bg-accent flex items-center justify-center text-primary group-hover:scale-105 transition-transform">
                  <Users className="h-4 w-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-foreground tracking-tight">
                {stats.totalAccounts}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {stats.totalAccounts === 0
                  ? 'No accounts stored yet'
                  : `${stats.totalAccounts} active credentials`}
              </p>
            </div>

            {/* Card 2: Total Favorites */}
            <div
              onClick={onNavigateToFavorites}
              className={`rounded-xl border border-border bg-card p-5 space-y-2 shadow-sm relative overflow-hidden group hover:border-amber-500/40 transition-colors ${
                onNavigateToFavorites ? 'cursor-pointer hover:bg-card/80' : ''
              }`}
            >
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-xs font-semibold uppercase tracking-wider">
                  Favorites
                </span>
                <div className="h-8 w-8 rounded-lg bg-amber-500/10 flex items-center justify-center text-amber-400 group-hover:scale-105 transition-transform">
                  <Star className="h-4 w-4 fill-amber-400/20" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-foreground tracking-tight">
                {stats.totalFavorites}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {stats.totalFavorites === 0
                  ? 'No starred accounts'
                  : `${stats.totalFavorites} starred for quick access`}
              </p>
            </div>

            {/* Card 3: Total Platforms */}
            <div
              onClick={onNavigateToPlatforms}
              className={`rounded-xl border border-border bg-card p-5 space-y-2 shadow-sm relative overflow-hidden group hover:border-blue-500/40 transition-colors ${
                onNavigateToPlatforms ? 'cursor-pointer hover:bg-card/80' : ''
              }`}
            >
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-xs font-semibold uppercase tracking-wider">
                  Platforms
                </span>
                <div className="h-8 w-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform">
                  <Globe className="h-4 w-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-foreground tracking-tight">
                {stats.totalPlatforms}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {stats.totalPlatforms === 0
                  ? 'No platforms configured'
                  : `${stats.totalPlatforms} distinct services`}
              </p>
            </div>


            {/* Card 4: Security Summary */}
            <div className="rounded-xl border border-border bg-card p-5 space-y-2 shadow-sm relative overflow-hidden group hover:border-emerald-500/40 transition-colors">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-xs font-semibold uppercase tracking-wider">
                  Vault Security
                </span>
                <div className="h-8 w-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                  <ShieldCheck className="h-4 w-4" />
                </div>
              </div>
              <div className="text-xl font-bold text-emerald-400 tracking-tight flex items-center gap-1.5 pt-1">
                <span>{stats.security.vault_integrity === 'OK' ? 'Healthy' : stats.security.vault_integrity}</span>
              </div>
              <p className="text-[11px] text-muted-foreground font-mono">
                {stats.security.encryption} • {stats.security.kdf}
              </p>
            </div>
          </div>

          {/* Detailed Security & Password Health breakdown section */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Password Health Section */}
            <div className="lg:col-span-2 rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
              <div className="flex items-center justify-between border-b border-border/60 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-primary" />
                  <h3 className="text-sm font-semibold text-foreground">
                    Password Health Analysis
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-muted-foreground bg-muted/40 px-2 py-0.5 rounded">
                  Calculated in Rust
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-1.5">
                  <span className="text-xs text-muted-foreground font-medium">Weak Passwords</span>
                  <div className="flex items-baseline gap-2">
                    <span className={`text-2xl font-bold ${stats.passwordHealth.weak_count > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {stats.passwordHealth.weak_count}
                    </span>
                    <span className="text-xs text-muted-foreground">accounts</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground/80">
                    {stats.passwordHealth.weak_count > 0
                      ? 'Passwords shorter than 12 chars or low entropy.'
                      : 'All stored passwords meet complexity rules.'}
                  </p>
                </div>

                <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-1.5">
                  <span className="text-xs text-muted-foreground font-medium">Reused Passwords</span>
                  <div className="flex items-baseline gap-2">
                    <span className={`text-2xl font-bold ${stats.passwordHealth.reused_count > 0 ? 'text-destructive' : 'text-emerald-400'}`}>
                      {stats.passwordHealth.reused_count}
                    </span>
                    <span className="text-xs text-muted-foreground">duplicates</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground/80">
                    {stats.passwordHealth.reused_count > 0
                      ? 'Multiple accounts share identical passwords.'
                      : 'No password reuse detected across accounts.'}
                  </p>
                </div>
              </div>
            </div>

            {/* Runtime Parameters Summary */}
            <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center gap-2 border-b border-border/60 pb-3">
                  <Lock className="h-4 w-4 text-primary" />
                  <h3 className="text-sm font-semibold text-foreground">
                    Runtime Policies
                  </h3>
                </div>

                <div className="space-y-2.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5" /> Auto-Lock Timer:
                    </span>
                    <span className="font-mono text-foreground font-semibold">
                      {stats.security.auto_lock}
                    </span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground flex items-center gap-1.5">
                      <RefreshCw className="h-3.5 w-3.5" /> Clipboard Timeout:
                    </span>
                    <span className="font-mono text-foreground font-semibold">
                      {stats.security.clipboard_timeout}s
                    </span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5" /> Storage Mode:
                    </span>
                    <span className="font-mono text-emerald-400 font-semibold">
                      RAM SQLite
                    </span>
                  </div>
                </div>
              </div>

              {stats.totalAccounts === 0 && (
                <div className="rounded-lg border border-dashed border-border p-3 text-center text-xs text-muted-foreground mt-4">
                  Ready to add your first account.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
