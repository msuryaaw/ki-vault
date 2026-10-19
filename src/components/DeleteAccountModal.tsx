import React, { useState } from 'react';
import type { AccountSummary } from '../types/domain';
import { Button } from './Button';
import { AlertTriangle, Trash2, X } from 'lucide-react';

interface DeleteAccountModalProps {
  account: AccountSummary | null;
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (accountId: string) => Promise<void>;
  loading?: boolean;
}

export const DeleteAccountModal: React.FC<DeleteAccountModalProps> = ({
  account,
  isOpen,
  onClose,
  onConfirm,
  loading = false,
}) => {
  const [error, setError] = useState<string | null>(null);

  if (!isOpen || !account) return null;

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    try {
      await onConfirm(account.id);
      onClose();
    } catch (err: unknown) {
      const maybeErr = err as { message?: string };
      setError(maybeErr.message || 'Failed to delete account.');
    }
  };

  const displayName = account.display_name || account.username || account.email || 'Untitled Account';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget && !loading) onClose();
      }}
    >
      <div className="w-full max-w-md rounded-2xl border border-destructive/30 bg-card p-6 shadow-2xl space-y-5 text-left">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2 text-destructive font-bold text-base">
            <Trash2 className="h-5 w-5" />
            <span>Delete Account</span>
          </div>
          <button
            onClick={onClose}
            disabled={loading}
            className="rounded-lg p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Warning text */}
        <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-3.5 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
          <div className="text-xs space-y-1 text-destructive">
            <p className="font-semibold">Irreversible Action</p>
            <p className="text-destructive/90 leading-relaxed">
              Are you sure you want to permanently delete{' '}
              <strong className="text-foreground font-bold">"{displayName}"</strong> under{' '}
              <strong className="text-foreground font-bold">{account.platform_name}</strong>?
            </p>
          </div>
        </div>

        <p className="text-xs text-muted-foreground">
          All associated credentials, custom fields, and tags will be permanently removed from this encrypted vault.
        </p>

        {error && (
          <div className="rounded-lg bg-destructive/10 border border-destructive/20 p-2 text-xs text-destructive">
            {error}
          </div>
        )}

        {/* Action buttons */}
        <div className="flex justify-end gap-3 pt-3 border-t border-border">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onClose}
            disabled={loading}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="sm"
            onClick={handleConfirm}
            loading={loading}
          >
            Delete Account
          </Button>

        </div>
      </div>
    </div>
  );
};
