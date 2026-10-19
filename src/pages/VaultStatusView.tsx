import React from 'react';
import { useVault } from '../stores/VaultContext';
import { Button } from '../components/Button';
import {
  Lock,
  Unlock,
  ShieldCheck,
  Calendar,
  Clock,
  Fingerprint,
  RefreshCw,
} from 'lucide-react';

export const VaultStatusView: React.FC = () => {
  const { summary, lockVault, refreshStatus, loading } = useVault();

  const formatDate = (timestampSecs: number | undefined) => {
    if (!timestampSecs) return 'N/A';
    return new Date(timestampSecs * 1000).toLocaleString();
  };

  return (
    <div className="w-full max-w-2xl mx-auto space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
            {summary?.vault_name || 'Active Vault'}
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Vault is currently decrypted and loaded into in-memory SQLite.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={refreshStatus}
            loading={loading}
            title="Refresh vault status"
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={lockVault}
            loading={loading}
          >
            <Lock className="mr-1.5 h-4 w-4" /> Lock Vault
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Status Card */}
        <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Runtime State
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-500/20">
              <Unlock className="h-3 w-3" /> Unlocked
            </span>
          </div>
          <p className="text-sm text-foreground">
            In-memory SQLite database is active. Zero plaintext is stored on disk.
          </p>
        </div>

        {/* Cryptographic Container Info */}
        <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Container ID
            </span>
            <Fingerprint className="h-4 w-4 text-muted-foreground" />
          </div>
          <p className="text-xs font-mono text-muted-foreground truncate" title={summary?.vault_id}>
            {summary?.vault_id || 'Generating...'}
          </p>
        </div>
      </div>

      {/* Metadata Timestamps */}
      <div className="rounded-xl border border-border bg-muted/20 p-5 space-y-3">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Vault Timestamps
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="flex items-center gap-2 text-muted-foreground">
            <Calendar className="h-4 w-4 text-primary shrink-0" />
            <span>Created:</span>
            <span className="text-foreground font-medium">{formatDate(summary?.created_at)}</span>
          </div>
          <div className="flex items-center gap-2 text-muted-foreground">
            <Clock className="h-4 w-4 text-primary shrink-0" />
            <span>Last Updated:</span>
            <span className="text-foreground font-medium">{formatDate(summary?.updated_at)}</span>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-border/60 bg-muted/30 p-4 text-xs text-muted-foreground space-y-1">
        <p className="font-semibold text-foreground">Phase 6 Step 1 Status:</p>
        <p>
          Vault lifecycle, authentication transitions, and core status presentation are fully integrated.
          Domain dashboards, platforms, accounts, and settings UI will be connected in subsequent steps.
        </p>
      </div>
    </div>
  );
};
