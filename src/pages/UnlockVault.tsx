import React, { useState } from 'react';
import { useVault } from '../stores/VaultContext';
import { Input } from '../components/Input';
import { Button } from '../components/Button';
import { KeyRound, PlusCircle, Shield } from 'lucide-react';

interface UnlockVaultProps {
  onSwitchToCreate?: () => void;
}

export const UnlockVault: React.FC<UnlockVaultProps> = ({ onSwitchToCreate }) => {
  const { status, unlockVault, loading, error, clearError } = useVault();

  const [password, setPassword] = useState('');
  const [vaultPath, setVaultPath] = useState(status === 'Uninitialised' ? 'kivault.kivault' : '');
  const [clientError, setClientError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setClientError(null);
    clearError();

    if (!password) {
      setClientError('Master password is required.');
      return;
    }

    if (status === 'Uninitialised' && !vaultPath.trim()) {
      setClientError('Vault path is required when initialising from disk.');
      return;
    }

    try {
      await unlockVault(password, status === 'Uninitialised' ? vaultPath.trim() : undefined);
      // Clear password state immediately upon unlock attempt completion
      setPassword('');
    } catch {
      // Error handled in VaultContext
    }
  };

  return (
    <div className="w-full max-w-md mx-auto space-y-6">
      <div className="text-center space-y-2">
        <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-black border border-white/20 shadow-xl">
          <Shield className="h-7 w-7 text-white" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-foreground">Unlock KiVault</h2>
        <p className="text-xs text-muted-foreground">
          Enter your master password to decrypt the in-memory database.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="rounded-xl border border-border bg-card p-6 shadow-xl space-y-4">
        {status === 'Uninitialised' && (
          <Input
            label="Vault File Path"
            value={vaultPath}
            onChange={(e) => setVaultPath(e.target.value)}
            onClear={() => setVaultPath('')}
            placeholder="C:\Users\Name\Documents\KiVault\kivault.kivault"
            helperText="Enter the full path to your vault file (.kivault)."
            exampleText="e.g. C:\Users\Name\Documents\KiVault\kivault.kivault"
            disabled={loading}
            required
          />
        )}

        <Input
          label="Master Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter your master password"
          helperText="Minimum 8 characters. Use a combination of letters, numbers, and symbols."
          exampleText="e.g. At least 8 unique characters for vault protection"
          disabled={loading}
          autoFocus
          required
        />

        {(clientError || error) && (
          <div className="rounded-lg border border-destructive/40 bg-destructive/15 p-3 text-xs text-destructive">
            {clientError || (error?.code === 'AuthenticationFailed' ? 'Incorrect master password or corrupted vault. Please verify your password.' : error?.message)}
          </div>
        )}

        <Button type="submit" className="w-full" size="lg" loading={loading}>
          <KeyRound className="mr-2 h-4 w-4" /> Unlock Vault
        </Button>
      </form>

      {onSwitchToCreate && (
        <div className="text-center">
          <button
            type="button"
            onClick={onSwitchToCreate}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors inline-flex items-center gap-1"
          >
            <PlusCircle className="h-3.5 w-3.5" /> Belum punya vault? Buat vault baru
          </button>
        </div>
      )}
    </div>
  );
};

