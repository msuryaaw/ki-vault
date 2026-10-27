import React, { useEffect, useState, useCallback } from 'react';
import { useVault } from '../stores/VaultContext';
import {
  getSettings,
  updateSecuritySettings,
  updatePasswordGeneratorSettings,
  getSecurityStatus,
} from '../services/domain';
import { changeMasterPassword, createBackup, restoreBackup } from '../services/vault';
import { save, open } from '@tauri-apps/plugin-dialog';
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
  RefreshCw,
  Archive,
  Download,
  Upload,
  AlertTriangle,
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

  // Backup & Restore State
  const [backupDestination, setBackupDestination] = useState<string>('');
  const [backupLoading, setBackupLoading] = useState<boolean>(false);
  const [backupStatusMessage, setBackupStatusMessage] = useState<string | null>(null);
  const [backupError, setBackupError] = useState<string | null>(null);

  const [restoreSource, setRestoreSource] = useState<string>('');
  const [restorePassword, setRestorePassword] = useState<string>('');
  const [restoreConfirmation, setRestoreConfirmation] = useState<string>('');
  const [isRestoreModalOpen, setIsRestoreModalOpen] = useState<boolean>(false);
  const [restoreLoading, setRestoreLoading] = useState<boolean>(false);
  const [restoreStatusMessage, setRestoreStatusMessage] = useState<string | null>(null);
  const [restoreError, setRestoreError] = useState<string | null>(null);

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

  // ─── Backup Handlers ──────────────────────────────────────────────────────────

  const handleChooseBackupPath = async () => {
    setBackupError(null);
    setBackupStatusMessage(null);
    try {
      const defaultName = `kivault-backup-${new Date().toISOString().slice(0, 10)}.kivault`;
      const selected = await save({
        title: 'Save Encrypted KiVault Backup',
        defaultPath: defaultName,
        filters: [{ name: 'KiVault Container', extensions: ['kivault'] }],
      });
      if (selected) {
        setBackupDestination(selected);
      }
    } catch {
      setBackupError('Failed to open file save dialog.');
    }
  };

  const handleCreateBackup = async (e: React.FormEvent) => {
    e.preventDefault();
    setBackupError(null);
    setBackupStatusMessage(null);

    const dest = backupDestination.trim();
    if (!dest) {
      setBackupError('Please select or specify a destination path for the backup.');
      return;
    }

    if (!dest.toLowerCase().endsWith('.kivault')) {
      setBackupError('Backup file must have a .kivault extension.');
      return;
    }

    setBackupLoading(true);
    try {
      await createBackup(dest);
      setBackupStatusMessage(`Backup successfully created at ${dest}`);
      setBackupDestination('');
      setTimeout(() => setBackupStatusMessage(null), 5000);
    } catch (err) {
      const cmdErr = err as CommandError;
      setBackupError(cmdErr.message || 'Failed to create backup.');
    } finally {
      setBackupLoading(false);
    }
  };

  // ─── Restore Handlers ─────────────────────────────────────────────────────────

  const handleChooseRestoreFile = async () => {
    setRestoreError(null);
    setRestoreStatusMessage(null);
    try {
      const selected = await open({
        title: 'Select KiVault Backup File',
        multiple: false,
        directory: false,
        filters: [{ name: 'KiVault Container', extensions: ['kivault'] }],
      });
      if (selected && typeof selected === 'string') {
        setRestoreSource(selected);
        setIsRestoreModalOpen(true);
      }
    } catch {
      setRestoreError('Failed to open file picker.');
    }
  };

  const handleCloseRestoreModal = () => {
    setIsRestoreModalOpen(false);
    // Explicitly wipe sensitive password from memory
    setRestorePassword('');
    setRestoreConfirmation('');
    setRestoreError(null);
  };

  const handleExecuteRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    setRestoreError(null);
    setRestoreStatusMessage(null);

    if (!restoreSource.trim()) {
      setRestoreError('No backup file selected.');
      return;
    }

    if (!restorePassword) {
      setRestoreError('Backup master password is required.');
      return;
    }

    if (restoreConfirmation.trim() !== 'CONFIRM_RESTORE') {
      setRestoreError('You must type CONFIRM_RESTORE exactly to authorize overwriting the active vault.');
      return;
    }

    setRestoreLoading(true);
    try {
      await restoreBackup(restoreSource.trim(), restorePassword, 'CONFIRM_RESTORE');
      // Clear password immediately on success
      setRestorePassword('');
      setRestoreConfirmation('');
      setIsRestoreModalOpen(false);
      setRestoreStatusMessage('Vault restored successfully. Active master password remains in force.');
      // Refresh settings and vault summary in view
      await loadData();
      setTimeout(() => setRestoreStatusMessage(null), 6000);
    } catch (err) {
      const cmdErr = err as CommandError;
      setRestoreError(cmdErr.message || 'Failed to restore backup.');
      // Wipe password on failure as well
      setRestorePassword('');
    } finally {
      setRestoreLoading(false);
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
                      placeholder="Enter current master password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      helperText="The master password currently in use."
                      required
                    />

                    <Input
                      label="New Master Password"
                      type="password"
                      placeholder="Min. 8 characters"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      helperText="Minimum 8 characters with letters, numbers, and symbols."
                      exampleText="e.g. Must differ from current password."
                      required
                    />

                    <Input
                      label="Confirm New Password"
                      type="password"
                      placeholder="Repeat new master password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      helperText="Must match new password exactly."
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

            {/* Backup & Restore Section */}
            <div className="border-t border-border/60 pt-4 flex items-center justify-between text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5 font-medium text-foreground">
                <Archive className="h-3.5 w-3.5 text-primary" />
                Backup & Restore System:
              </span>
              <span className="text-[11px] font-mono text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                Active & Verified
              </span>
            </div>
          </section>

          {/* ─── 5. Encrypted Backup & Restore Section ─── */}
          <section className="rounded-2xl border border-border bg-card p-6 space-y-6 shadow-xs">
            <div className="flex items-center justify-between border-b border-border/60 pb-3">
              <div className="flex items-center gap-2 text-foreground font-bold text-sm">
                <Archive className="h-4 w-4 text-primary" />
                <span>Encrypted Backup & Restore</span>
              </div>
              <span className="text-[11px] text-muted-foreground font-mono">
                Container Snapshots
              </span>
            </div>

            <p className="text-xs text-muted-foreground">
              Create an encrypted full container snapshot (<code className="font-mono text-[11px] text-primary">.kivault</code>) or restore from an existing backup. The active master password remains in force after restoring.
            </p>

            {/* Global Backup/Restore Notices */}
            {backupStatusMessage && (
              <div className="flex items-center gap-2 p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded-xl text-xs font-medium">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>{backupStatusMessage}</span>
              </div>
            )}
            {restoreStatusMessage && (
              <div className="flex items-center gap-2 p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded-xl text-xs font-medium">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>{restoreStatusMessage}</span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-1">
              {/* Create Backup Box */}
              <div className="rounded-xl border border-border/80 bg-background/50 p-5 space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-foreground font-semibold text-xs">
                    <Download className="h-4 w-4 text-primary" />
                    <span>Create Backup Snapshot</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    Saves an encrypted snapshot of the current active database to a chosen location.
                  </p>

                  <form onSubmit={handleCreateBackup} className="space-y-3 pt-1">
                    <div className="space-y-1.5">
                      <label className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider block">
                        Backup Destination Path
                      </label>
                      <div className="flex items-center gap-2">
                        <Input
                          placeholder="e.g. C:\Backups\my-vault.kivault"
                          value={backupDestination}
                          onChange={(e) => setBackupDestination(e.target.value)}
                          className="text-xs"
                          disabled={backupLoading}
                        />
                        <Button
                          type="button"
                          variant="outline"
                          size="md"
                          onClick={handleChooseBackupPath}
                          disabled={backupLoading}
                          className="shrink-0 text-xs px-3"
                        >
                          Browse...
                        </Button>
                      </div>
                    </div>

                    {backupError && (
                      <div className="flex items-start gap-1.5 text-xs text-destructive bg-destructive/10 p-2.5 rounded-lg border border-destructive/20">
                        <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                        <span>{backupError}</span>
                      </div>
                    )}

                    <Button
                      type="submit"
                      variant="primary"
                      size="sm"
                      loading={backupLoading}
                      disabled={!backupDestination.trim()}
                      className="w-full text-xs"
                    >
                      <Download className="h-3.5 w-3.5 mr-1.5" />
                      Create Encrypted Backup
                    </Button>
                  </form>
                </div>
              </div>

              {/* Restore Backup Box */}
              <div className="rounded-xl border border-border/80 bg-background/50 p-5 space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-foreground font-semibold text-xs">
                    <Upload className="h-4 w-4 text-amber-500" />
                    <span>Restore from Backup</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    Restore credentials and vault data from a <code className="font-mono text-[10px] text-primary">.kivault</code> backup container. Re-encrypts with your active master password.
                  </p>

                  <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl space-y-1">
                    <div className="flex items-center gap-1.5 text-amber-500 font-semibold text-[11px]">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                      <span>Destructive Operation</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                      Restoring replaces the active database with the backup data. A password check and explicit confirmation token are required.
                    </p>
                  </div>
                </div>

                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleChooseRestoreFile}
                  className="w-full text-xs border-amber-500/30 text-amber-500 hover:bg-amber-500/10"
                >
                  <Upload className="h-3.5 w-3.5 mr-1.5" />
                  Select Backup File & Restore...
                </Button>
              </div>
            </div>
          </section>

          {/* ─── Restore Confirmation Modal ─── */}
          {isRestoreModalOpen && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150">
              <div
                role="dialog"
                aria-modal="true"
                className="w-full max-w-lg rounded-2xl border border-border bg-card p-6 shadow-2xl space-y-5 text-left"
              >
                <div className="flex items-center justify-between border-b border-border/60 pb-3">
                  <div className="flex items-center gap-2 text-foreground font-bold text-sm">
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                    <span>Confirm Vault Restore</span>
                  </div>
                  <button
                    onClick={handleCloseRestoreModal}
                    disabled={restoreLoading}
                    className="text-xs text-muted-foreground hover:text-foreground font-mono"
                  >
                    ✕
                  </button>
                </div>

                <div className="space-y-2 text-xs text-muted-foreground">
                  <p>
                    You are restoring from file:
                  </p>
                  <p className="font-mono text-[11px] text-foreground bg-muted/60 p-2 rounded-lg border border-border break-all">
                    {restoreSource}
                  </p>
                  <p className="text-[11px] text-amber-500 font-medium">
                    ⚠️ Current active credentials and metadata will be completely replaced by the backup snapshot.
                  </p>
                </div>

                <form onSubmit={handleExecuteRestore} className="space-y-4">
                  <Input
                    label="Backup Master Password"
                    type="password"
                    placeholder="Password used to encrypt the backup file"
                    value={restorePassword}
                    onChange={(e) => setRestorePassword(e.target.value)}
                    disabled={restoreLoading}
                    className="text-xs"
                    helperText="Required to decrypt and verify the backup container before import."
                  />

                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">
                      Type &quot;CONFIRM_RESTORE&quot; to authorize
                    </label>
                    <Input
                      placeholder="CONFIRM_RESTORE"
                      value={restoreConfirmation}
                      onChange={(e) => setRestoreConfirmation(e.target.value)}
                      disabled={restoreLoading}
                      className="text-xs font-mono"
                    />
                  </div>

                  {restoreError && (
                    <div className="flex items-start gap-1.5 text-xs text-destructive bg-destructive/10 p-2.5 rounded-lg border border-destructive/20">
                      <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                      <span>{restoreError}</span>
                    </div>
                  )}

                  <div className="flex items-center justify-end gap-2 pt-2 border-t border-border/60">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={handleCloseRestoreModal}
                      disabled={restoreLoading}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      variant="destructive"
                      size="sm"
                      loading={restoreLoading}
                      disabled={!restorePassword || restoreConfirmation.trim() !== 'CONFIRM_RESTORE'}
                    >
                      Restore & Replace Vault
                    </Button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
