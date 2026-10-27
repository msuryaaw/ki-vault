import React, { useEffect, useState, useCallback } from 'react';
import { useVault } from '../stores/VaultContext';
import { Button } from '../components/Button';
import { getSecurityStatus, getPasswordHealth } from '../services/domain';
import type { SecurityStatus, PasswordHealth } from '../types/domain';
import type { CommandError } from '../types/vault';
import {
  Lock,
  Unlock,
  ShieldCheck,
  ShieldAlert,
  Calendar,
  Clock,
  Fingerprint,
  RefreshCw,
  KeyRound,
  Binary,
  Layers,
  AlertTriangle,
  Loader2,
  AlertCircle,
  Copy,
} from 'lucide-react';

export const VaultStatusView: React.FC = () => {
  const { summary, lockVault, refreshStatus, loading: vaultLoading } = useVault();

  const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null);
  const [passwordHealth, setPasswordHealth] = useState<PasswordHealth | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CommandError | null>(null);

  const fetchSecurityData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [sec, health] = await Promise.all([
        getSecurityStatus(),
        getPasswordHealth(),
      ]);
      setSecurityStatus(sec);
      setPasswordHealth(health);
    } catch (err) {
      // Do not invent fallback values; record genuine error
      setError(err as CommandError);
      setSecurityStatus(null);
      setPasswordHealth(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchSecurityData();
  }, [fetchSecurityData]);

  const handleRefreshAll = async () => {
    await Promise.all([refreshStatus(), fetchSecurityData()]);
  };

  const formatDate = (timestampSecs: number | undefined) => {
    if (!timestampSecs) return 'N/A';
    return new Date(timestampSecs * 1000).toLocaleString();
  };

  const isDegraded = securityStatus?.vault_integrity === 'Degraded';

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 text-left">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-border pb-4 gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
            <span>Security Center & Vault Status</span>
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Active cryptographic health, runtime policies, and memory database telemetry.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefreshAll}
            disabled={loading || vaultLoading}
            title="Refresh security status"
            className="h-9 px-3 text-xs gap-1.5"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading || vaultLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={lockVault}
            loading={vaultLoading}
            className="h-9 px-3 text-xs gap-1.5 shadow-sm"
          >
            <Lock className="h-4 w-4" />
            <span>Lock Vault</span>
          </Button>
        </div>
      </div>

      {/* Degraded Integrity Warning Banner */}
      {isDegraded && (
        <div className="rounded-xl border border-destructive/80 bg-destructive/15 p-4 text-destructive flex items-start gap-3 shadow-sm animate-pulse">
          <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-sm font-semibold">Security Warning: Vault Integrity Degraded</h4>
            <p className="text-xs leading-relaxed text-destructive/90">
              The in-memory SQLite integrity check (`PRAGMA quick_check`) did not return `ok`. 
              This could indicate corruption or memory tampering. It is strongly advised to export or back up your records and re-create your vault container.
            </p>
          </div>
        </div>
      )}

      {/* IPC Error Banner */}
      {error && !loading && (
        <div className="rounded-xl border border-destructive/50 bg-destructive/10 p-4 text-destructive flex items-start gap-3">
          <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-sm font-semibold">Failed to Retrieve Security Status</h4>
            <p className="text-xs text-destructive/90">
              {error.message || 'An unexpected error occurred while querying the security subsystem.'}
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-2 text-xs border-destructive/40 hover:bg-destructive/10"
              onClick={fetchSecurityData}
            >
              Retry Check
            </Button>
          </div>
        </div>
      )}

      {/* Loading Skeleton */}
      {loading && !securityStatus && (
        <div className="rounded-xl border border-border bg-card p-12 flex flex-col items-center justify-center space-y-3 text-muted-foreground">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-xs font-mono">Auditing cryptographic status & password health...</p>
        </div>
      )}

      {/* Main Content Grid */}
      {securityStatus && (
        <div className="space-y-6">
          {/* Top Overview Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Vault State & Name */}
            <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Vault State
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-500/20">
                  <Unlock className="h-3 w-3" /> {securityStatus.vault_state}
                </span>
              </div>
              <div className="space-y-1">
                <p className="text-lg font-bold text-foreground truncate" title={summary?.vault_name}>
                  {summary?.vault_name || 'Active Vault'}
                </p>
                <p className="text-xs text-muted-foreground">
                  Decrypted in RAM SQLite. Zero plaintext on disk.
                </p>
              </div>
            </div>

            {/* Cryptographic Encryption */}
            <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Payload Cipher
                </span>
                <Binary className="h-4 w-4 text-primary" />
              </div>
              <div className="space-y-1">
                <p className="text-lg font-bold text-foreground font-mono">
                  {securityStatus.encryption}
                </p>
                <p className="text-xs text-muted-foreground">
                  Authenticated 256-bit Galois/Counter Mode
                </p>
              </div>
            </div>

            {/* KDF & Derivation */}
            <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm sm:col-span-2 lg:col-span-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Key Derivation (KDF)
                </span>
                <KeyRound className="h-4 w-4 text-primary" />
              </div>
              <div className="space-y-1">
                <p className="text-lg font-bold text-foreground font-mono">
                  {securityStatus.kdf}
                </p>
                <p className="text-xs text-muted-foreground">
                  Memory-hard Argon2id (64 MiB, t=3, p=4)
                </p>
              </div>
            </div>
          </div>

          {/* Password Health Section */}
          <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
            <div className="flex items-center justify-between border-b border-border/60 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-primary" />
                <h3 className="text-sm font-semibold text-foreground">
                  Password Health Telemetry
                </h3>
              </div>
              <span className="text-[11px] font-mono text-muted-foreground bg-muted/40 px-2 py-0.5 rounded">
                Aggregated in Rust
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Weak Passwords Card */}
              <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-1.5">
                <span className="text-xs text-muted-foreground font-medium">Weak Passwords</span>
                <div className="flex items-baseline gap-2">
                  <span
                    className={`text-2xl font-bold ${
                      (passwordHealth?.weak_count ?? 0) > 0 ? 'text-amber-400' : 'text-emerald-400'
                    }`}
                  >
                    {passwordHealth ? passwordHealth.weak_count : '—'}
                  </span>
                  <span className="text-xs text-muted-foreground">accounts</span>
                </div>
                <p className="text-[11px] text-muted-foreground/80">
                  {(passwordHealth?.weak_count ?? 0) > 0
                    ? 'Passwords shorter than 12 characters or lacking character variety.'
                    : 'All stored account passwords satisfy complexity requirements.'}
                </p>
              </div>

              {/* Reused Passwords Card */}
              <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-1.5">
                <span className="text-xs text-muted-foreground font-medium">Reused Passwords</span>
                <div className="flex items-baseline gap-2">
                  <span
                    className={`text-2xl font-bold ${
                      (passwordHealth?.reused_count ?? 0) > 0 ? 'text-destructive' : 'text-emerald-400'
                    }`}
                  >
                    {passwordHealth ? passwordHealth.reused_count : '—'}
                  </span>
                  <span className="text-xs text-muted-foreground">duplicates</span>
                </div>
                <p className="text-[11px] text-muted-foreground/80">
                  {(passwordHealth?.reused_count ?? 0) > 0
                    ? 'Identical passwords shared across two or more accounts.'
                    : 'No password reuse detected across any stored accounts.'}
                </p>
              </div>
            </div>
          </div>

          {/* Runtime Policies & Container Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Runtime Policies */}
            <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
              <div className="flex items-center gap-2 border-b border-border/60 pb-3">
                <Clock className="h-4 w-4 text-primary" />
                <h3 className="text-sm font-semibold text-foreground">
                  Runtime Security Policies
                </h3>
              </div>

              <div className="space-y-3 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" /> Auto-Lock Inactivity Timeout:
                  </span>
                  <span className="font-mono text-foreground font-semibold px-2 py-0.5 rounded bg-muted/40">
                    {securityStatus.auto_lock}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground flex items-center gap-1.5">
                    <Copy className="h-3.5 w-3.5 text-muted-foreground" /> Clipboard Auto-Clear Timeout:
                  </span>
                  <span className="font-mono text-foreground font-semibold px-2 py-0.5 rounded bg-muted/40">
                    {securityStatus.clipboard_timeout}s
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground flex items-center gap-1.5">
                    <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground" /> Vault Physical Integrity:
                  </span>
                  <span
                    className={`font-semibold px-2 py-0.5 rounded ${
                      isDegraded
                        ? 'bg-destructive/20 text-destructive border border-destructive/30'
                        : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    }`}
                  >
                    {securityStatus.vault_integrity}
                  </span>
                </div>
              </div>
            </div>

            {/* Container Metadata & Timestamps */}
            <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
              <div className="flex items-center gap-2 border-b border-border/60 pb-3">
                <Layers className="h-4 w-4 text-primary" />
                <h3 className="text-sm font-semibold text-foreground">
                  Container Metadata
                </h3>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <div className="flex items-center justify-between text-muted-foreground mb-1">
                    <span className="flex items-center gap-1.5">
                      <Fingerprint className="h-3.5 w-3.5 text-muted-foreground" /> Container Vault ID:
                    </span>
                  </div>
                  <p
                    className="font-mono text-[11px] text-muted-foreground bg-muted/40 p-2 rounded truncate"
                    title={summary?.vault_id}
                  >
                    {summary?.vault_id || 'Generating...'}
                  </p>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-muted-foreground flex items-center gap-1.5">
                    <Calendar className="h-3.5 w-3.5 text-muted-foreground" /> Created:
                  </span>
                  <span className="text-foreground font-medium">
                    {formatDate(summary?.created_at)}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" /> Last Saved:
                  </span>
                  <span className="text-foreground font-medium">
                    {formatDate(summary?.updated_at)}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
