import React, { useState } from 'react';
import type { PlatformSummary } from '../types/domain';
import { Button } from './Button';
import { Input } from './Input';
import { AlertTriangle, Trash2, X } from 'lucide-react';

interface DeletePlatformModalProps {
  platform: PlatformSummary;
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (platformId: string, confirmationToken: string) => Promise<void>;
  loading?: boolean;
}

export const DeletePlatformModal: React.FC<DeletePlatformModalProps> = ({
  platform,
  isOpen,
  onClose,
  onConfirm,
  loading = false,
}) => {
  const [tokenInput, setTokenInput] = useState('');
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const isTokenMatching = tokenInput.trim() === platform.id;

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!isTokenMatching) {
      setError('Confirmation token does not match the platform ID.');
      return;
    }

    try {
      await onConfirm(platform.id, tokenInput.trim());
      setTokenInput('');
      onClose();
    } catch (err: unknown) {
      const maybeErr = err as { message?: string };
      setError(maybeErr.message || 'Failed to delete platform.');
    }
  };

  const handleClose = () => {
    setTokenInput('');
    setError(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-2xl space-y-5 text-left">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2 text-destructive font-bold text-base">
            <Trash2 className="h-5 w-5" />
            <span>Delete Platform</span>
          </div>
          <button
            onClick={handleClose}
            className="text-muted-foreground hover:text-foreground p-1 rounded-md transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-3 text-xs text-muted-foreground">
          <p className="text-foreground">
            You are about to delete platform <strong>{platform.name}</strong>.
          </p>

          {platform.account_count > 0 ? (
            <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 flex items-start gap-2.5 text-destructive">
              <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="font-semibold text-xs">Cascading Deletion Warning</p>
                <p className="text-[11px] leading-relaxed">
                  This platform currently contains <strong>{platform.account_count} account(s)</strong>.
                  Deleting it will permanently delete all associated credentials via SQLite foreign key cascade.
                </p>
              </div>
            </div>
          ) : (
            <p>This platform has no associated accounts.</p>
          )}

          <p className="leading-relaxed">
            To confirm this destructive action, please copy and paste the Platform ID below into the confirmation field:
          </p>

          <div className="rounded bg-muted/40 p-2 font-mono text-[11px] text-foreground select-all break-all border border-border/50">
            {platform.id}
          </div>
        </div>

        <form onSubmit={handleConfirm} className="space-y-4">
          <Input
            label="Confirmation Token (Platform ID)"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="Paste exact Platform ID"
            disabled={loading}
            autoFocus
            required
          />

          {error && (
            <p className="text-xs text-destructive">{error}</p>
          )}

          <div className="flex items-center justify-end gap-2.5 pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleClose}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="destructive"
              size="sm"
              loading={loading}
              disabled={!isTokenMatching}
            >
              <Trash2 className="mr-1.5 h-3.5 w-3.5" /> Confirm Deletion
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
