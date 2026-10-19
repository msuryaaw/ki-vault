import React, { useEffect, useState, useCallback } from 'react';
import { useVault } from '../stores/VaultContext';
import {
  getSettings,
  updateSecuritySettings,
  updatePasswordGeneratorSettings,
  getSecurityStatus,
} from '../services/domain';
import { changeMasterPassword } from '../services/vault';
import type {
  VaultSettings,
  SecurityStatus,
} from '../types/domain';
import type { CommandError } from '../types/vault';
import { Button } from '../components/Button';
import { Input } from '../components/Input';
import { PasswordStrengthMeter } from '../components/PasswordStrengthMeter';
import {
  Shield,
  KeyRound,
  Sliders,
  Sparkles,
  Palette,
  Info,
  Clock,
  Clipboard,
  AlertCircle,
  CheckCircle2,
  Lock,
  RefreshCw,
} from 'lucide-react';


export const Settings: React.FC = () => {
  const { summary } = useVault();

  // Settings State
  const [settings, setSettings] = useState<VaultSettings | null>(null);
  const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [savingSection, setSavingSection] = useState<string | null>(null);
  const [error, setError] = useState<CommandError | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  // Security Form State
  const [autoLock, setAutoLock] = useState<string>('5m');
  const [clipboardTimeout, setClipboardTimeout] = useState<number>(15);

  // Password Generator Preferences State
  const [genLength, setGenLength] = useState<number>(16);
  const [genUppercase, setGenUppercase] = useState<boolean>(true);
  const [genLowercase, setGenLowercase] = useState<boolean>(true);
  const [genNumbers, setGenNumbers] = useState<boolean>(true);
  const [genSymbols, setGenSymbols] = useState<boolean>(true);

  // Change Master Password State
  const [isChangingPassword, setIsChangingPassword] = useState<boolean>(false);
  const [currentPassword, setCurrentPassword] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [passwordError, setPasswordError] = useState<string | null>(null);

  // Appearance State (stored in localStorage for UX preference)
  const [themePreference, setThemePreference] = useState<'system' | 'dark' | 'light'>(() => {
    return (localStorage.getItem('kivault_theme') as 'system' | 'dark' | 'light') || 'system';
  });

  // Load all initial data
  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [settingsData, secData] = await Promise.all([
        getSettings(),
        getSecurityStatus().catch(() => null),
      ]);
      setSettings(settingsData);
      setSecurityStatus(secData);

      // Hydrate local form states
      setAutoLock(settingsData.security.auto_lock);
      setClipboardTimeout(settingsData.security.clipboard_timeout);

      setGenLength(settingsData.password_generator.length);
      setGenUppercase(settingsData.password_generator.use_uppercase);
      setGenLowercase(settingsData.password_generator.use_lowercase);
      setGenNumbers(settingsData.password_generator.use_numbers);
      setGenSymbols(settingsData.password_generator.use_symbols);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Save Security Settings
  const handleSaveSecurity = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSection('security');
    setError(null);
    try {
      const updated = await updateSecuritySettings({
        auto_lock: autoLock,
        clipboard_timeout: Number(clipboardTimeout),
      });
      setSettings((prev) => prev ? { ...prev, security: updated } : null);
      setSuccessNotice('Security timeout settings updated.');
      setTimeout(() => setSuccessNotice(null), 3500);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setSavingSection(null);
    }
  };

  // Save Password Generator Preferences
  const handleSaveGenerator = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSection('generator');
    setError(null);
    try {
      const updated = await updatePasswordGeneratorSettings({
        length: Number(genLength),
        use_uppercase: genUppercase,
        use_lowercase: genLowercase,
        use_numbers: genNumbers,
        use_symbols: genSymbols,
      });
      setSettings((prev) => prev ? { ...prev, password_generator: updated } : null);
      setSuccessNotice('Password generator preferences saved.');
      setTimeout(() => setSuccessNotice(null), 3500);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setSavingSection(null);
    }
  };

  // Submit Change Master Password
  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);

    if (!currentPassword) {
      setPasswordError('Current master password is required.');
      return;
    }
    if (!newPassword || newPassword.length < 8) {
      setPasswordError('New master password must be at least 8 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('New password confirmation does not match.');
      return;
    }
    if (currentPassword === newPassword) {
      setPasswordError('New master password must be different from current password.');
      return;
    }

    setSavingSection('password');
    try {
      await changeMasterPassword(currentPassword, newPassword);
      setSuccessNotice('Master password changed successfully. Encryption key rotated.');
      setTimeout(() => setSuccessNotice(null), 4000);

      // Wipe sensitive passwords from memory
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setIsChangingPassword(false);
    } catch (err) {
      const cmdErr = err as CommandError;
      setPasswordError(cmdErr.message || 'Failed to change master password.');
    } finally {
      setSavingSection(null);
    }
  };

  // Update Appearance Theme
  const handleThemeChange = (newTheme: 'system' | 'dark' | 'light') => {
    setThemePreference(newTheme);
    localStorage.setItem('kivault_theme', newTheme);
    setSuccessNotice(`Theme preference set to "${newTheme}".`);
    setTimeout(() => setSuccessNotice(null), 3000);
  };

  // Format date helper
  const formatDate = (timestampSecs?: number) => {
    if (!timestampSecs) return 'N/A';
    return new Date(timestampSecs * 1000).toLocaleString();
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8 p-8 text-left">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <Sliders className="h-6 w-6 text-primary" />
            <span>Settings</span>
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Configure security parameters, generator defaults, and vault environment.
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={loadData}
          disabled={loading}
          className="text-xs gap-1.5 h-8 self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Global Success / Error Banners */}
      {successNotice && (
        <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 flex items-center justify-between text-xs text-emerald-500 animate-in fade-in duration-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{successNotice}</span>
          </div>
          <button
            onClick={() => setSuccessNotice(null)}
            className="text-muted-foreground hover:text-foreground text-xs"
          >
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl border border-destructive/30 bg-destructive/10 flex items-start gap-3 text-xs text-destructive animate-in fade-in duration-200">
          <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold">{error.code}</h4>
            <p className="opacity-90">{error.message}</p>
          </div>
        </div>
      )}

      {loading && !settings ? (
        <div className="py-20 flex flex-col items-center justify-center space-y-3 text-muted-foreground">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          <p className="text-xs">Loading vault configuration...</p>
        </div>
      ) : (
        <div className="space-y-8">
          {/* ─── 1. Security & Master Password (docs/ui-ux-spec.md §14.1) ─── */}
          <section className="rounded-2xl border border-border bg-card p-6 space-y-6 shadow-xs">
            <div className="flex items-center justify-between border-b border-border/60 pb-3">
              <div className="flex items-center gap-2 text-foreground font-bold text-sm">
                <Shield className="h-4 w-4 text-primary" />
                <span>Security Configuration</span>
              </div>
              <span className="text-[11px] text-muted-foreground font-mono">
                Encrypted SQLite Settings
              </span>
            </div>

            {/* Timeouts Form */}
            <form onSubmit={handleSaveSecurity} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Auto-Lock Timeout */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                    Auto-Lock Timeout
                  </label>
                  <p className="text-[11px] text-muted-foreground">
                    Inactivity duration before vault locks automatically.
                  </p>
                  <div className="flex items-center bg-background border border-input rounded-lg px-3 py-2 focus-within:ring-1 focus-within:ring-primary focus-within:border-primary">
                    <select
                      value={autoLock}
                      onChange={(e) => setAutoLock(e.target.value)}
                      className="w-full bg-transparent text-xs text-foreground focus:outline-none cursor-pointer"
                    >
                      <option value="1m">1 minute</option>
                      <option value="5m">5 minutes (Default)</option>
                      <option value="15m">15 minutes</option>
                      <option value="30m">30 minutes</option>
                      <option value="never">Never (Not recommended)</option>
                    </select>
                  </div>
                </div>

                {/* Clipboard Timeout */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <Clipboard className="h-3.5 w-3.5 text-muted-foreground" />
                    Clipboard Auto-Clear
                  </label>
                  <p className="text-[11px] text-muted-foreground">
                    Time before copied credentials are wiped from system clipboard.
                  </p>
                  <div className="flex items-center bg-background border border-input rounded-lg px-3 py-2 focus-within:ring-1 focus-within:ring-primary focus-within:border-primary">
                    <select
                      value={clipboardTimeout}
                      onChange={(e) => setClipboardTimeout(Number(e.target.value))}
                      className="w-full bg-transparent text-xs text-foreground focus:outline-none cursor-pointer"
                    >
                      <option value={5}>5 seconds</option>
                      <option value={15}>15 seconds (Default)</option>
                      <option value={30}>30 seconds</option>
                      <option value={60}>60 seconds</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-between">
                <span className="text-[11px] text-muted-foreground italic">
                  Note: Runtime OS background monitoring is part of Phase 8.
                </span>
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  loading={savingSection === 'security'}
                  className="text-xs h-8"
                >
                  Save Security Settings
                </Button>
              </div>
            </form>

            {/* Change Master Password Sub-panel */}
            <div className="border-t border-border/60 pt-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold text-foreground flex items-center gap-1.5">
                    <KeyRound className="h-3.5 w-3.5 text-primary" />
                    Rotate Master Password
                  </h3>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Rewraps the Vault Data Key (VDK) without altering underlying encrypted data.
                  </p>
                </div>

                {!isChangingPassword && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setIsChangingPassword(true);
                      setPasswordError(null);
                    }}
                    className="text-xs h-8"
                  >
                    Change Password...
                  </Button>
                )}
              </div>

              {isChangingPassword && (
                <form
                  onSubmit={handleChangePassword}
                  className="rounded-xl border border-primary/20 bg-primary/5 p-4 space-y-4 animate-in fade-in duration-150"
                >
                  {passwordError && (
                    <div className="rounded-lg bg-destructive/10 border border-destructive/20 p-2.5 text-xs text-destructive flex items-center gap-2">
                      <AlertCircle className="h-4 w-4 shrink-0" />
                      <span>{passwordError}</span>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <Input
                      label="Current Master Password"
                      type="password"
                      placeholder="••••••••••••"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      required
                    />

                    <Input
                      label="New Master Password"
                      type="password"
                      placeholder="••••••••••••"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                    />

                    <Input
                      label="Confirm New Password"
                      type="password"
                      placeholder="••••••••••••"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                    />
                  </div>

                  {newPassword && (
                    <div className="space-y-1">
                      <PasswordStrengthMeter password={newPassword} />
                    </div>
                  )}

                  <div className="flex justify-end gap-2 pt-2 border-t border-primary/10">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setIsChangingPassword(false);
                        setCurrentPassword('');
                        setNewPassword('');
                        setConfirmPassword('');
                        setPasswordError(null);
                      }}
                      disabled={savingSection === 'password'}
                      className="text-xs h-8"
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      variant="primary"
                      size="sm"
                      loading={savingSection === 'password'}
                      className="text-xs h-8"
                    >
                      Rotate Master Password
                    </Button>
                  </div>
                </form>
              )}
            </div>
          </section>

          {/* ─── 2. Password Generator Defaults (docs/ui-ux-spec.md §14.1) ─── */}
          <section className="rounded-2xl border border-border bg-card p-6 space-y-6 shadow-xs">
            <div className="flex items-center justify-between border-b border-border/60 pb-3">
              <div className="flex items-center gap-2 text-foreground font-bold text-sm">
                <Sparkles className="h-4 w-4 text-primary" />
                <span>Password Generator Defaults</span>
              </div>
              <span className="text-[11px] text-muted-foreground font-mono">
                Preferred Complexity
              </span>
            </div>

            <form onSubmit={handleSaveGenerator} className="space-y-5">
              {/* Length Slider / Number */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-foreground">Default Length:</span>
                  <span className="font-mono text-primary font-bold px-2 py-0.5 rounded bg-primary/10">
                    {genLength} characters
                  </span>
                </div>
                <input
                  type="range"
                  min={8}
                  max={64}
                  value={genLength}
                  onChange={(e) => setGenLength(Number(e.target.value))}
                  className="w-full accent-primary cursor-pointer"
                />
              </div>

              {/* Character set checkboxes */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                <label className="flex items-center gap-2 p-2.5 rounded-lg border border-border bg-background/50 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={genUppercase}
                    onChange={(e) => setGenUppercase(e.target.checked)}
                    className="rounded border-input text-primary"
                  />
                  <span className="text-xs text-foreground font-medium">Uppercase (A-Z)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 rounded-lg border border-border bg-background/50 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={genLowercase}
                    onChange={(e) => setGenLowercase(e.target.checked)}
                    className="rounded border-input text-primary"
                  />
                  <span className="text-xs text-foreground font-medium">Lowercase (a-z)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 rounded-lg border border-border bg-background/50 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={genNumbers}
                    onChange={(e) => setGenNumbers(e.target.checked)}
                    className="rounded border-input text-primary"
                  />
                  <span className="text-xs text-foreground font-medium">Numbers (0-9)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 rounded-lg border border-border bg-background/50 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={genSymbols}
                    onChange={(e) => setGenSymbols(e.target.checked)}
                    className="rounded border-input text-primary"
                  />
                  <span className="text-xs text-foreground font-medium">Symbols (!@#$)</span>
                </label>
              </div>

              <div className="flex justify-end pt-2 border-t border-border/40">
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  loading={savingSection === 'generator'}
                  className="text-xs h-8"
                >
                  Save Generator Preferences
                </Button>
              </div>
            </form>
          </section>

          {/* ─── 3. Appearance (docs/ui-ux-spec.md §14.2) ─── */}
          <section className="rounded-2xl border border-border bg-card p-6 space-y-4 shadow-xs">
            <div className="flex items-center justify-between border-b border-border/60 pb-3">
              <div className="flex items-center gap-2 text-foreground font-bold text-sm">
                <Palette className="h-4 w-4 text-primary" />
                <span>Appearance</span>
              </div>
              <span className="text-[11px] text-muted-foreground font-mono">UI Preference</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {(['system', 'dark', 'light'] as const).map((t) => (
                <div
                  key={t}
                  onClick={() => handleThemeChange(t)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    themePreference === t
                      ? 'border-primary bg-primary/10 text-primary font-semibold'
                      : 'border-border bg-background/50 text-muted-foreground hover:text-foreground'
                  }`}
                >
                  <p className="text-xs capitalize">{t} Mode</p>
                  <p className="text-[10px] text-muted-foreground font-normal mt-0.5">
                    {t === 'system'
                      ? 'Sync with OS desktop configuration'
                      : t === 'dark'
                      ? 'High-contrast dark desktop theme'
                      : 'Clean light desktop theme'}
                  </p>
                </div>
              ))}
            </div>
          </section>

          {/* ─── 4. Vault Info & About (docs/ui-ux-spec.md §14.3 & §14.4) ─── */}
          <section className="rounded-2xl border border-border bg-card p-6 space-y-4 shadow-xs">
            <div className="flex items-center justify-between border-b border-border/60 pb-3">
              <div className="flex items-center gap-2 text-foreground font-bold text-sm">
                <Info className="h-4 w-4 text-primary" />
                <span>Vault Info & About</span>
              </div>
              <span className="text-[11px] text-muted-foreground font-mono">
                Container Metadata
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
              <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                <span className="text-[11px] text-muted-foreground">Vault Name</span>
                <p className="font-semibold text-foreground">{summary?.vault_name || 'Active Vault'}</p>
              </div>

              <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                <span className="text-[11px] text-muted-foreground">Encryption Cipher</span>
                <p className="font-semibold text-foreground">
                  {securityStatus?.encryption || 'AES-256-GCM'}
                </p>
              </div>

              <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                <span className="text-[11px] text-muted-foreground">Key Derivation</span>
                <p className="font-semibold text-foreground font-mono">
                  {securityStatus?.kdf || 'Argon2id'}
                </p>
              </div>

              <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                <span className="text-[11px] text-muted-foreground">Schema Version</span>
                <p className="font-semibold text-foreground font-mono">
                  v1 (SQLite)
                </p>
              </div>

              <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                <span className="text-[11px] text-muted-foreground">Created</span>
                <p className="font-mono text-muted-foreground text-[11px]">
                  {formatDate(summary?.created_at)}
                </p>
              </div>

              <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                <span className="text-[11px] text-muted-foreground">Application</span>
                <p className="font-semibold text-foreground">KiVault Desktop v0.1.0 MVP</p>
              </div>
            </div>

            {/* Backup & Restore Notice (Planned for Phase 9) */}
            <div className="border-t border-border/60 pt-4 flex items-center justify-between text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-muted-foreground/80" />
                Encrypted Backup & Restore:
              </span>
              <span className="text-[11px] font-mono bg-muted/60 px-2 py-0.5 rounded border border-border/60">
                Roadmap Phase 9
              </span>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};
