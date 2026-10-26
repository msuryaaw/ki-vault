import React, { useEffect, useState, useCallback, useRef } from 'react';
import { getAccountDetail, revealSecret, copySecret, getPlatform, getSettings } from '../services/domain';
import type { AccountDetail, Platform, AccountSummary } from '../types/domain';
import type { CommandError } from '../types/vault';
import { useVault } from '../stores/VaultContext';
import { Button } from '../components/Button';
import { PlatformLogo } from './PlatformLogo';
import {
  X,
  Eye,
  EyeOff,
  Copy,
  Check,
  ExternalLink,
  User,
  Tag as TagIcon,
  FileText,
  Star,
  Lock,
  AlertCircle,
  RefreshCw,
  Shield,
  Layers,
  Edit2,
  Trash2,
} from 'lucide-react';


interface AccountDetailModalProps {
  accountId: string | null;
  onClose: () => void;
  onEdit?: (account: AccountDetail) => void;
  onDelete?: (accountSummary: AccountSummary) => void;
}

export const AccountDetailModal: React.FC<AccountDetailModalProps> = ({
  accountId,
  onClose,
  onEdit,
  onDelete,
}) => {

  const [detail, setDetail] = useState<AccountDetail | null>(null);
  const [platform, setPlatform] = useState<Platform | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CommandError | null>(null);

  // In-memory plaintext secret state (strictly wiped on hide, switch account, or modal close)
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, string>>({});
  const [revealingField, setRevealingField] = useState<string | null>(null);
  const autoHideTimersRef = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  // Clipboard copy state feedback and settings
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [copyingField, setCopyingField] = useState<string | null>(null);
  const [clipboardTimeout, setClipboardTimeout] = useState<number>(15);

  const clearAllAutoHideTimers = useCallback(() => {
    for (const key of Object.keys(autoHideTimersRef.current)) {
      clearTimeout(autoHideTimersRef.current[key]);
    }
    autoHideTimersRef.current = {};
  }, []);

  // Fetch actual clipboard timeout setting from vault database
  useEffect(() => {
    let isMounted = true;
    void getSettings()
      .then((settings) => {
        if (isMounted && settings?.security?.clipboard_timeout) {
          setClipboardTimeout(settings.security.clipboard_timeout);
        }
      })
      .catch(() => {
        // Fallback to default 15s if settings query fails
      });
    return () => {
      isMounted = false;
    };
  }, []);

  // Load account detail and platform data
  const loadDetail = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    clearAllAutoHideTimers();
    setRevealedSecrets({});
    setCopiedField(null);
    try {
      const data = await getAccountDetail(id);
      setDetail(data);

      // Attempt to load platform metadata (website, category, etc.)
      if (data.account.platform_id) {
        try {
          const plat = await getPlatform(data.account.platform_id);
          setPlatform(plat);
        } catch {
          // platform info is optional
        }
      }
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setLoading(false);
    }
  }, [clearAllAutoHideTimers]);

  useEffect(() => {
    if (accountId) {
      loadDetail(accountId);
    } else {
      // Clear secrets from memory immediately when closed
      clearAllAutoHideTimers();
      setRevealedSecrets({});
      setDetail(null);
      setPlatform(null);
    }
  }, [accountId, loadDetail, clearAllAutoHideTimers]);

  const { status: vaultStatus } = useVault();

  useEffect(() => {
    if (vaultStatus !== 'Unlocked') {
      clearAllAutoHideTimers();
      setRevealedSecrets({});
      setDetail(null);
      setPlatform(null);
      onClose();
    }
  }, [vaultStatus, onClose, clearAllAutoHideTimers]);

  // Clean up in-memory secrets and timers on unmount
  useEffect(() => {
    return () => {
      clearAllAutoHideTimers();
      setRevealedSecrets({});
    };
  }, [clearAllAutoHideTimers]);

  if (!accountId || vaultStatus !== 'Unlocked') return null;

  // Reveal secret in-memory toggle
  const handleToggleReveal = async (fieldName: string) => {
    // If already revealed, hide it and remove from memory immediately
    if (revealedSecrets[fieldName]) {
      if (autoHideTimersRef.current[fieldName]) {
        clearTimeout(autoHideTimersRef.current[fieldName]);
        delete autoHideTimersRef.current[fieldName];
      }
      setRevealedSecrets((prev) => {
        const next = { ...prev };
        delete next[fieldName];
        return next;
      });
      return;
    }

    // Otherwise fetch short-lived secret from Rust
    setRevealingField(fieldName);
    setError(null);
    try {
      const secret = await revealSecret(accountId, fieldName);
      setRevealedSecrets((prev) => ({
        ...prev,
        [fieldName]: secret,
      }));

      // Schedule automatic hide after 30 seconds to minimize exposure duration
      if (autoHideTimersRef.current[fieldName]) {
        clearTimeout(autoHideTimersRef.current[fieldName]);
      }
      autoHideTimersRef.current[fieldName] = setTimeout(() => {
        delete autoHideTimersRef.current[fieldName];
        setRevealedSecrets((prev) => {
          const next = { ...prev };
          delete next[fieldName];
          return next;
        });
      }, 30000);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setRevealingField(null);
    }
  };

  // Copy secret directly from Rust to clipboard without returning to React
  const handleCopySecret = async (fieldName: string) => {
    setCopyingField(fieldName);
    setError(null);
    try {
      await copySecret(accountId, fieldName, clipboardTimeout);
      setCopiedField(fieldName);
      setTimeout(() => {
        setCopiedField((curr) => (curr === fieldName ? null : curr));
      }, 3000);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setCopyingField(null);
    }
  };

  // Format date helper
  const formatDate = (timestampMs: number) => {
    if (!timestampMs) return '-';
    const ms = timestampMs < 10000000000 ? timestampMs * 1000 : timestampMs;
    return new Date(ms).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const account = detail?.account;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          setRevealedSecrets({});
          onClose();
        }
      }}
    >
      <div className="w-full max-w-2xl bg-card border border-border rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-card/50 shrink-0">
          <div className="flex items-center gap-3">
            <PlatformLogo
              logoId={account?.logo_id || platform?.logo_id}
              platformName={platform?.name}
              size="lg"
            />
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-foreground">
                  {account
                    ? account.display_name || account.username || account.email || 'Account Details'
                    : 'Account Details'}
                </h2>
                {account?.is_favorite && (
                  <span className="flex items-center gap-1 text-[11px] font-semibold text-amber-500 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded-full">
                    <Star className="h-3 w-3 fill-amber-500" />
                    Favorite
                  </span>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                Platform: <strong className="text-foreground">{platform?.name || 'Loading...'}</strong>
                {platform?.category ? ` (${platform.category})` : ''}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setRevealedSecrets({});
                onClose();
              }}
              className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
              title="Close (Esc)"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Error Banner */}
          {error && (
            <div className="p-4 rounded-xl border border-destructive/40 bg-destructive/10 text-xs text-destructive flex items-start gap-3">
              <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <span className="font-semibold">{error.code}</span>
                <p>{error.message}</p>
              </div>
            </div>
          )}

          {loading ? (
            <div className="py-20 flex flex-col items-center justify-center text-center space-y-3">
              <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              <p className="text-xs text-muted-foreground">
                Decrypting account metadata securely...
              </p>
            </div>
          ) : !account ? (
            <div className="py-12 text-center text-xs text-muted-foreground">
              Account information could not be retrieved.
            </div>
          ) : (
            <>
              {/* Primary Identity Section */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <User className="h-3.5 w-3.5" />
                  Credentials & Identity
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {/* Display Name */}
                  <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                    <span className="text-[11px] font-medium text-muted-foreground">Display Name</span>
                    <p className="text-xs font-semibold text-foreground">
                      {account.display_name || <span className="text-muted-foreground italic font-normal">None</span>}
                    </p>
                  </div>

                  {/* Username */}
                  <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                    <span className="text-[11px] font-medium text-muted-foreground">Username</span>
                    <p className="text-xs font-mono font-semibold text-foreground">
                      {account.username || <span className="text-muted-foreground italic font-normal font-sans">None</span>}
                    </p>
                  </div>

                  {/* Email */}
                  <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                    <span className="text-[11px] font-medium text-muted-foreground">Email</span>
                    <p className="text-xs font-mono text-foreground">
                      {account.email || <span className="text-muted-foreground italic font-normal font-sans">None</span>}
                    </p>
                  </div>

                  {/* Website / URL */}
                  <div className="bg-background/80 border border-border/80 rounded-xl p-3 space-y-1">
                    <span className="text-[11px] font-medium text-muted-foreground">Target URL</span>
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xs font-mono truncate text-foreground">
                        {account.url || platform?.website || (
                          <span className="text-muted-foreground italic font-normal font-sans">None</span>
                        )}
                      </p>
                      {(account.url || platform?.website) && (
                        <a
                          href={account.url || platform?.website || '#'}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="text-primary hover:text-primary/80 shrink-0"
                          title="Open website"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                        </a>
                      )}
                    </div>
                  </div>
                </div>

                {/* Password Box per docs/ui-ux-spec.md §8 */}
                <div className="bg-card border border-border rounded-xl p-4 space-y-2 mt-4 shadow-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                      <Lock className="h-3.5 w-3.5 text-primary" />
                      Password
                    </span>
                    {copiedField === 'password' && (
                      <span className="text-[11px] text-emerald-500 font-medium flex items-center gap-1 animate-in fade-in">
                        <Check className="h-3 w-3" />
                        Copied (clears in 15s)
                      </span>
                    )}
                  </div>

                  <div className="flex items-center justify-between gap-3 bg-background border border-input rounded-lg px-3 py-2">
                    <div className="font-mono text-xs tracking-wider select-all overflow-x-auto text-foreground">
                      {revealedSecrets['password'] ? (
                        <span>{revealedSecrets['password']}</span>
                      ) : (
                        <span className="text-muted-foreground tracking-widest">••••••••••••••••</span>
                      )}
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      {/* Separate Reveal Button */}
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        disabled={revealingField === 'password'}
                        onClick={() => handleToggleReveal('password')}
                        className="h-7 px-2 text-xs gap-1 text-muted-foreground hover:text-foreground"
                        title={revealedSecrets['password'] ? 'Hide password' : 'Reveal password'}
                      >
                        {revealedSecrets['password'] ? (
                          <>
                            <EyeOff className="h-3.5 w-3.5" />
                            <span>Hide</span>
                          </>
                        ) : (
                          <>
                            <Eye className="h-3.5 w-3.5" />
                            <span>Reveal</span>
                          </>
                        )}
                      </Button>

                      {/* Separate Copy Button: Rust clipboard directly */}
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={copyingField === 'password'}
                        onClick={() => handleCopySecret('password')}
                        className="h-7 px-2.5 text-xs gap-1 border-input hover:bg-accent"
                        title="Copy password securely to clipboard"
                      >
                        {copiedField === 'password' ? (
                          <>
                            <Check className="h-3.5 w-3.5 text-emerald-500" />
                            <span className="text-emerald-500">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3.5 w-3.5" />
                            <span>Copy</span>
                          </>
                        )}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Tags Section */}
              {detail.tags.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <TagIcon className="h-3.5 w-3.5" />
                    Tags
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {detail.tags.map((tag) => (
                      <span
                        key={tag.id}
                        className="text-xs px-2.5 py-1 rounded-md bg-secondary text-secondary-foreground border border-border/80 font-medium"
                      >
                        #{tag.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Custom Fields Section */}
              {detail.custom_fields.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Layers className="h-3.5 w-3.5" />
                    Custom Fields
                  </h3>
                  <div className="space-y-2">
                    {detail.custom_fields.map((cf) => {
                      const isRevealed = !!revealedSecrets[cf.field_name];
                      const isCopied = copiedField === cf.field_name;

                      return (
                        <div
                          key={cf.id}
                          className="bg-background/80 border border-border/80 rounded-xl p-3 flex flex-col md:flex-row md:items-center justify-between gap-2"
                        >
                          <div className="space-y-0.5 min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className="text-xs font-semibold text-foreground">
                                {cf.field_name}
                              </span>
                              {cf.is_sensitive && (
                                <span className="text-[10px] text-amber-500 bg-amber-500/10 px-1.5 py-0.2 rounded font-mono uppercase">
                                  Sensitive
                                </span>
                              )}
                              <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.2 rounded font-mono">
                                {cf.field_type}
                              </span>
                            </div>

                            <div className="text-xs font-mono text-muted-foreground truncate">
                              {cf.is_sensitive ? (
                                isRevealed ? (
                                  <span className="text-foreground">{revealedSecrets[cf.field_name]}</span>
                                ) : (
                                  <span className="tracking-widest">••••••••</span>
                                )
                              ) : (
                                <span className="text-foreground">{cf.field_value}</span>
                              )}
                            </div>
                          </div>

                          {cf.is_sensitive && (
                            <div className="flex items-center gap-1.5 shrink-0 self-end md:self-center">
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                onClick={() => handleToggleReveal(cf.field_name)}
                                className="h-7 px-2 text-xs gap-1"
                              >
                                {isRevealed ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                                <span>{isRevealed ? 'Hide' : 'Reveal'}</span>
                              </Button>

                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                onClick={() => handleCopySecret(cf.field_name)}
                                className="h-7 px-2 text-xs gap-1"
                              >
                                {isCopied ? (
                                  <Check className="h-3 w-3 text-emerald-500" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                                <span>{isCopied ? 'Copied' : 'Copy'}</span>
                              </Button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Notes Section */}
              {account.notes && (
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <FileText className="h-3.5 w-3.5" />
                    Notes
                  </h3>
                  <div className="bg-background/80 border border-border/80 rounded-xl p-3.5 text-xs text-foreground whitespace-pre-wrap font-mono leading-relaxed">
                    {account.notes}
                  </div>
                </div>
              )}

              {/* Audit Timestamps */}
              <div className="pt-2 border-t border-border/50 flex flex-wrap items-center justify-between gap-2 text-[11px] text-muted-foreground font-mono">
                <span>Created: {formatDate(account.created_at)}</span>
                <span>Last Updated: {formatDate(account.updated_at)}</span>
              </div>
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-3.5 border-t border-border bg-card/60 shrink-0">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Shield className="h-3.5 w-3.5 text-primary" />
            <span>Encrypted zero-knowledge storage</span>
          </div>

          <div className="flex items-center gap-2">
            {onDelete && account && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setRevealedSecrets({});
                  onClose();
                  onDelete({
                    id: account.id,
                    platform_id: account.platform_id,
                    platform_name: platform?.name || 'Platform',
                    logo_id: account.logo_id,
                    display_name: account.display_name,
                    username: account.username,
                    email: account.email,
                    is_favorite: account.is_favorite,
                    updated_at: account.updated_at,
                  });
                }}
                className="text-xs h-8 text-destructive hover:bg-destructive/10 border-destructive/30 gap-1.5"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Delete</span>
              </Button>
            )}

            {onEdit && detail && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setRevealedSecrets({});
                  onClose();
                  onEdit(detail);
                }}
                className="text-xs h-8 gap-1.5"
              >
                <Edit2 className="h-3.5 w-3.5" />
                <span>Edit</span>
              </Button>
            )}

            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                setRevealedSecrets({});
                onClose();
              }}
              className="text-xs h-8"
            >
              Done
            </Button>
          </div>

        </div>
      </div>
    </div>
  );
};
