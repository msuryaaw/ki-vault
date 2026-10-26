import React, { useState } from 'react';
import { useVault } from '../stores/VaultContext';
import { Input } from '../components/Input';
import { Button } from '../components/Button';
import { PasswordStrengthMeter } from '../components/PasswordStrengthMeter';
import { Shield, AlertTriangle, ArrowRight } from 'lucide-react';

interface CreateVaultProps {
  onSwitchToUnlock?: () => void;
}

export const CreateVault: React.FC<CreateVaultProps> = ({ onSwitchToUnlock }) => {
  const { createVault, loading, error, clearError } = useVault();

  const [vaultName, setVaultName] = useState('My KiVault');
  const [vaultPath, setVaultPath] = useState('kivault.kivault');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [clientError, setClientError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setClientError(null);
    clearError();

    if (!vaultName.trim()) {
      setClientError('Vault name is required.');
      return;
    }
    if (!vaultPath.trim()) {
      setClientError('Vault file path is required.');
      return;
    }
    if (!password) {
      setClientError('Master password is required.');
      return;
    }
    if (password.length < 8) {
      setClientError('Master password must be at least 8 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      setClientError('Passwords do not match.');
      return;
    }

    try {
      await createVault(vaultPath.trim(), vaultName.trim(), password);
    } catch {
      // Error is tracked in VaultContext
    }
  };

  return (
    <div className="w-full max-w-md mx-auto space-y-6">
      <div className="text-center space-y-2">
        <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-black border border-white/20 shadow-xl">
          <Shield className="h-7 w-7 text-white" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-foreground">Create New Vault</h2>
        <p className="text-xs text-muted-foreground">
          Initialize a secure, encrypted local storage container.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="rounded-xl border border-border bg-card p-6 shadow-xl space-y-4">
        <Input
          label="Vault Name"
          value={vaultName}
          onChange={(e) => setVaultName(e.target.value)}
          onClear={() => setVaultName('')}
          placeholder="Personal Vault"
          helperText="Nama pengenal untuk brankas kredensial ini (maks. 256 karakter)."
          exampleText="Contoh: Personal Vault, Work Credentials"
          maxLength={256}
          showCharCount
          disabled={loading}
          required
        />

        <Input
          label="Vault File Path"
          value={vaultPath}
          onChange={(e) => setVaultPath(e.target.value)}
          onClear={() => setVaultPath('')}
          placeholder="C:\Users\Nama\Documents\KiVault\kivault.kivault"
          helperText="Lokasi file container terenkripsi (.kivault) akan disimpan."
          exampleText="Contoh: C:\Users\Nama\Documents\KiVault\kivault.kivault atau kivault.kivault"
          disabled={loading}
          required
        />

        <div className="space-y-2">
          <Input
            label="Master Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Masukkan master password baru"
            helperText="Kunci utama enkripsi vault (minimal 8 karakter). Jangan sampai lupa."
            exampleText="Gunakan kombinasi huruf besar/kecil, angka, dan simbol."
            disabled={loading}
            required
          />
          <PasswordStrengthMeter password={password} />
        </div>

        <Input
          label="Confirm Master Password"
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Ketik ulang master password baru"
          helperText="Masukkan kembali password yang sama persis untuk verifikasi."
          disabled={loading}
          required
        />

        {/* Security Warning per docs/ui-ux-spec.md §3 */}
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 flex items-start gap-2.5 text-xs text-amber-200/90">
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong>Important:</strong> KiVault does not store your master password and cannot reset it through a server. Losing it will permanently render the vault inaccessible.
          </p>
        </div>

        {(clientError || error) && (
          <div className="rounded-lg border border-destructive/40 bg-destructive/15 p-3 text-xs text-destructive">
            {clientError || error?.message}
          </div>
        )}

        <Button type="submit" className="w-full" size="lg" loading={loading}>
          Create Vault <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </form>

      {onSwitchToUnlock && (
        <div className="text-center">
          <button
            type="button"
            onClick={onSwitchToUnlock}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors inline-flex items-center gap-1"
          >
            <Shield className="h-3.5 w-3.5" /> Already have a vault? Unlock existing vault
          </button>
        </div>
      )}
    </div>
  );
};
