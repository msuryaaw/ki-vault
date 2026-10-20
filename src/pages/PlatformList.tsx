import React, { useEffect, useState, useCallback } from 'react';
import {
  listPlatforms,
  createPlatform,
  updatePlatform,
  deletePlatform,
  listAccounts,
  createAccount,
  updateAccount,
  deleteAccount,
} from '../services/domain';
import type {
  PlatformSummary,
  AccountSummary,
  AccountDetail,
  CreatePlatformInput,
  UpdatePlatformInput,
  CreateAccountInput,
  UpdateAccountInput,
} from '../types/domain';
import type { CommandError } from '../types/vault';
import { Button } from '../components/Button';
import { PlatformFormModal } from '../components/PlatformFormModal';
import { DeletePlatformModal } from '../components/DeletePlatformModal';
import { AccountDetailModal } from '../components/AccountDetailModal';
import { AccountFormModal } from '../components/AccountFormModal';
import { DeleteAccountModal } from '../components/DeleteAccountModal';
import { LogoManagerModal } from '../components/LogoManagerModal';
import { PlatformLogo } from '../components/PlatformLogo';
import {


  Globe,
  Plus,
  RefreshCw,
  Search,
  ExternalLink,
  Edit2,
  Trash2,
  FolderOpen,
  ArrowLeft,
  Key,
  User,
  Mail,
  AlertCircle,
  Tag,
  Image as ImageIcon,
} from 'lucide-react';

interface PlatformListProps {
  onAddAccountForPlatform?: (platformId: string) => void;
}

export const PlatformList: React.FC<PlatformListProps> = ({
  onAddAccountForPlatform,
}) => {
  const [platforms, setPlatforms] = useState<PlatformSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<CommandError | null>(null);

  // Selected Platform for Detail / Account View per docs/ui-ux-spec.md §7
  const [selectedPlatform, setSelectedPlatform] = useState<PlatformSummary | null>(null);
  const [platformAccounts, setPlatformAccounts] = useState<AccountSummary[]>([]);
  const [accountsLoading, setAccountsLoading] = useState<boolean>(false);

  // Filter & Search state
  const [searchQuery, setSearchQuery] = useState('');

  // Modals state
  const [isFormModalOpen, setIsFormModalOpen] = useState(false);
  const [isLogoManagerModalOpen, setIsLogoManagerModalOpen] = useState(false);
  const [editingPlatform, setEditingPlatform] = useState<PlatformSummary | null>(null);
  const [deletingPlatform, setDeletingPlatform] = useState<PlatformSummary | null>(null);
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null);

  // Account modal states (Phase 6 Step 6)
  const [isAccountFormModalOpen, setIsAccountFormModalOpen] = useState(false);
  const [editingAccount, setEditingAccount] = useState<AccountDetail | null>(null);
  const [deletingAccount, setDeletingAccount] = useState<AccountSummary | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);


  const loadPlatforms = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listPlatforms();
      setPlatforms(data);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadPlatformAccounts = useCallback(async (platformId: string) => {
    setAccountsLoading(true);
    try {
      const data = await listAccounts(platformId);
      setPlatformAccounts(data);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setAccountsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPlatforms();
  }, [loadPlatforms]);

  // When selected platform changes, fetch its accounts
  const handleSelectPlatform = (platform: PlatformSummary) => {
    setSelectedPlatform(platform);
    loadPlatformAccounts(platform.id);
  };

  const handleBackToList = () => {
    setSelectedPlatform(null);
    setPlatformAccounts([]);
    setSuccessNotice(null);
  };


  // Form submit handler (Create / Edit)
  const handleFormSubmit = async (data: CreatePlatformInput | UpdatePlatformInput) => {
    setActionLoading(true);
    try {
      if (editingPlatform) {
        await updatePlatform(editingPlatform.id, data as UpdatePlatformInput);
      } else {
        await createPlatform(data as CreatePlatformInput);
      }
      await loadPlatforms();
      if (selectedPlatform && editingPlatform && selectedPlatform.id === editingPlatform.id) {
        // Refresh selected platform state
        const updated = await listPlatforms();
        const found = updated.find((p) => p.id === selectedPlatform.id);
        if (found) setSelectedPlatform(found);
      }
    } finally {
      setActionLoading(false);
    }
  };

  // Delete submit handler
  const handleDeleteConfirm = async (platformId: string, confirmationToken: string) => {
    setActionLoading(true);
    try {
      await deletePlatform(platformId, confirmationToken);
      if (selectedPlatform && selectedPlatform.id === platformId) {
        setSelectedPlatform(null);
        setPlatformAccounts([]);
      }
      await loadPlatforms();
    } finally {
      setActionLoading(false);
    }
  };

  // Account CRUD handlers (Phase 6 Step 6)
  const handleCreateAccount = async (data: CreateAccountInput) => {
    setActionLoading(true);
    try {
      await createAccount(data);
      setSuccessNotice(`Account "${data.display_name || data.username || 'Account'}" added.`);
      setTimeout(() => setSuccessNotice(null), 4000);
      setIsAccountFormModalOpen(false);
      if (selectedPlatform) {
        await loadPlatformAccounts(selectedPlatform.id);
      }
      await loadPlatforms();
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleUpdateAccount = async (id: string, data: UpdateAccountInput) => {
    setActionLoading(true);
    try {
      await updateAccount(id, data);
      setSuccessNotice('Account updated successfully.');
      setTimeout(() => setSuccessNotice(null), 4000);
      setIsAccountFormModalOpen(false);
      setEditingAccount(null);
      if (selectedPlatform) {
        await loadPlatformAccounts(selectedPlatform.id);
      }
      await loadPlatforms();
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteAccount = async (id: string) => {
    setActionLoading(true);
    try {
      await deleteAccount(id);
      setSuccessNotice('Account deleted successfully.');
      setTimeout(() => setSuccessNotice(null), 4000);
      setDeletingAccount(null);
      setSelectedAccountId(null);
      if (selectedPlatform) {
        await loadPlatformAccounts(selectedPlatform.id);
      }
      await loadPlatforms();
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleTriggerAddAccount = () => {
    if (onAddAccountForPlatform && selectedPlatform) {
      onAddAccountForPlatform(selectedPlatform.id);
    } else {
      setEditingAccount(null);
      setIsAccountFormModalOpen(true);
    }
  };


  const filteredPlatforms = platforms.filter((p) => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return true;
    return (
      p.name.toLowerCase().includes(q) ||
      (p.category && p.category.toLowerCase().includes(q)) ||
      (p.website && p.website.toLowerCase().includes(q))
    );
  });

  return (
    <div className="w-full max-w-5xl mx-auto space-y-6 text-left">
      {/* ─── Detail / Account View for Selected Platform (§7) ─── */}
      {selectedPlatform ? (
        <div className="space-y-6 animate-in fade-in duration-150">
          {/* Header with Back Button */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={handleBackToList}
                title="Back to Platforms list"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
              <PlatformLogo
                logoId={selectedPlatform.logo_id}
                platformName={selectedPlatform.name}
                size="lg"
              />
              <div>
                <h2 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                  <span>{selectedPlatform.name}</span>
                </h2>
                <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                  <span>{selectedPlatform.account_count} Accounts</span>
                  {selectedPlatform.category && (
                    <>
                      <span>•</span>
                      <span className="flex items-center gap-1">
                        <Tag className="h-3 w-3 text-muted-foreground" /> {selectedPlatform.category}
                      </span>
                    </>
                  )}
                  {selectedPlatform.website && (
                    <>
                      <span>•</span>
                      <a
                        href={selectedPlatform.website}
                        target="_blank"
                        rel="noreferrer"
                        className="text-primary/80 hover:text-primary flex items-center gap-1 underline"
                      >
                        {selectedPlatform.website} <ExternalLink className="h-3 w-3" />
                      </a>
                    </>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setEditingPlatform(selectedPlatform);
                  setIsFormModalOpen(true);
                }}
              >
                <Edit2 className="mr-1.5 h-3.5 w-3.5" /> Edit Platform
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setDeletingPlatform(selectedPlatform)}
              >
                <Trash2 className="mr-1.5 h-3.5 w-3.5" /> Delete
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleTriggerAddAccount}
              >
                <Plus className="mr-1.5 h-4 w-4" /> Add Account
              </Button>
            </div>
          </div>

          {/* Success Notification Banner */}
          {successNotice && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 flex items-center justify-between text-xs text-emerald-500 animate-in fade-in duration-200">
              <span>{successNotice}</span>
              <button
                onClick={() => setSuccessNotice(null)}
                className="underline ml-4 text-muted-foreground hover:text-foreground"
              >
                Dismiss
              </button>
            </div>
          )}


          {/* Accounts List for this Platform (docs/ui-ux-spec.md §7) */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Associated Accounts ({platformAccounts.length})
            </h3>

            {accountsLoading ? (
              <div className="rounded-xl border border-border bg-card p-8 text-center text-xs text-muted-foreground animate-pulse">
                Loading associated accounts...
              </div>
            ) : platformAccounts.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border bg-card/40 p-8 text-center text-xs text-muted-foreground space-y-2">
                <FolderOpen className="h-8 w-8 mx-auto text-muted-foreground/60" />
                <p>No accounts configured under {selectedPlatform.name} yet.</p>
                <Button variant="outline" size="sm" onClick={handleTriggerAddAccount}>
                  <Plus className="mr-1.5 h-3.5 w-3.5" /> Create First Account
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {platformAccounts.map((acc) => (
                  <div
                    key={acc.id}
                    onClick={() => setSelectedAccountId(acc.id)}
                    className="rounded-lg border border-border bg-card p-4 space-y-2 shadow-sm hover:border-primary/40 hover:bg-card/80 transition-all cursor-pointer group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-sm text-foreground truncate group-hover:text-primary transition-colors">
                        {acc.display_name || acc.username || 'Account'}
                      </span>
                      {acc.is_favorite && (
                        <span className="text-amber-400 text-xs font-bold" title="Starred favorite">★</span>
                      )}
                    </div>

                    <div className="space-y-1 text-xs text-muted-foreground">
                      {acc.username && (
                        <div className="flex items-center gap-1.5 truncate">
                          <User className="h-3 w-3 shrink-0" />
                          <span className="truncate">{acc.username}</span>
                        </div>
                      )}
                      {acc.email && (
                        <div className="flex items-center gap-1.5 truncate">
                          <Mail className="h-3 w-3 shrink-0" />
                          <span className="truncate">{acc.email}</span>
                        </div>
                      )}
                    </div>

                    <div className="pt-2 border-t border-border/40 text-[10px] text-muted-foreground/60 flex items-center justify-between">
                      <span className="text-primary font-medium">View Detail →</span>
                      <span className="font-mono">ID: {acc.id.slice(0, 8)}...</span>
                    </div>
                  </div>
                ))}
              </div>

            )}
          </div>
        </div>
      ) : (
        /* ─── Platform Master List ─── */
        <div className="space-y-6">
          {/* Header Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
            <div>
              <h2 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <Globe className="h-6 w-6 text-primary" />
                <span>Platforms</span>
              </h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                Manage services, providers, and organizational domains.
              </p>
            </div>

            <div className="flex items-center gap-2.5">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsLogoManagerModalOpen(true)}
                className="gap-1.5"
                title="Manage Logos"
              >
                <ImageIcon className="h-3.5 w-3.5" />
                <span>Logos</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={loadPlatforms}
                loading={loading}
                title="Refresh platform list"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => {
                  setEditingPlatform(null);
                  setIsFormModalOpen(true);
                }}
              >
                <Plus className="mr-1.5 h-4 w-4" /> Add Platform
              </Button>
            </div>
          </div>

          {/* Search / Filter bar */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search platforms by name, category, or website..."
                className="w-full rounded-lg border border-border bg-input/40 pl-9 pr-3 py-2 text-xs text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
          </div>

          {/* Error State */}
          {error && !loading && (
            <div className="rounded-xl border border-destructive/40 bg-destructive/15 p-4 text-xs text-destructive flex items-start gap-3">
              <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="font-semibold">Failed to load platforms</p>
                <p className="opacity-90">{error.message} (Code: {error.code})</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={loadPlatforms}
                  className="mt-2 text-xs border-destructive/40 hover:bg-destructive/20"
                >
                  Retry
                </Button>
              </div>
            </div>
          )}

          {/* Loading Skeleton */}
          {loading && platforms.length === 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3, 4, 5, 6].map((i) => (
                <div
                  key={i}
                  className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm animate-pulse"
                >
                  <div className="h-5 w-32 bg-muted/60 rounded" />
                  <div className="h-4 w-20 bg-muted/40 rounded" />
                  <div className="h-3 w-40 bg-muted/30 rounded" />
                </div>
              ))}
            </div>
          )}

          {/* Empty State */}
          {!loading && platforms.length === 0 && (
            <div className="rounded-xl border border-dashed border-border bg-card/30 p-12 text-center text-xs text-muted-foreground space-y-3">
              <Globe className="h-10 w-10 mx-auto text-muted-foreground/50" />
              <div className="space-y-1">
                <p className="font-semibold text-foreground text-sm">No Platforms Configured</p>
                <p>Create your first platform to organize accounts under specific services.</p>
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={() => {
                  setEditingPlatform(null);
                  setIsFormModalOpen(true);
                }}
              >
                <Plus className="mr-1.5 h-4 w-4" /> Add Platform
              </Button>
            </div>
          )}

          {/* Platform Grid */}
          {!loading && platforms.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredPlatforms.map((p) => (
                <div
                  key={p.id}
                  onClick={() => handleSelectPlatform(p)}
                  className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm hover:border-primary/50 hover:bg-muted/10 transition-all cursor-pointer group relative flex flex-col justify-between text-left"
                >
                  <div className="space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <PlatformLogo
                          logoId={p.logo_id}
                          platformName={p.name}
                          size="md"
                        />
                        <div>
                          <h3 className="font-bold text-sm text-foreground group-hover:text-primary transition-colors">
                            {p.name}
                          </h3>
                          {p.category && (
                            <span className="text-[10px] text-muted-foreground bg-muted/40 px-1.5 py-0.5 rounded border border-border/40">
                              {p.category}
                            </span>
                          )}
                        </div>
                      </div>

                      <div
                        className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          onClick={() => {
                            setEditingPlatform(p);
                            setIsFormModalOpen(true);
                          }}
                          className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-muted"
                          title="Edit platform"
                        >
                          <Edit2 className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setDeletingPlatform(p)}
                          className="p-1 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                          title="Delete platform"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>

                    {p.website && (
                      <p className="text-xs text-muted-foreground truncate" title={p.website}>
                        {p.website}
                      </p>
                    )}
                  </div>

                  <div className="pt-3 border-t border-border/50 flex items-center justify-between text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Key className="h-3.5 w-3.5 text-primary" />
                      <strong>{p.account_count}</strong> {p.account_count === 1 ? 'account' : 'accounts'}
                    </span>
                    <span className="text-[11px] text-primary/80 group-hover:translate-x-0.5 transition-transform">
                      View Accounts →
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Form Modal (Add / Edit) */}
      <PlatformFormModal
        isOpen={isFormModalOpen}
        onClose={() => {
          setIsFormModalOpen(false);
          setEditingPlatform(null);
        }}
        onSubmit={handleFormSubmit}
        initialData={editingPlatform}
        loading={actionLoading}
      />

      {/* Delete Confirmation Modal */}
      {deletingPlatform && (
        <DeletePlatformModal
          platform={deletingPlatform}
          isOpen={Boolean(deletingPlatform)}
          onClose={() => setDeletingPlatform(null)}
          onConfirm={handleDeleteConfirm}
          loading={actionLoading}
        />
      )}

      {/* Account Detail Modal per docs/ui-ux-spec.md §8 (Phase 6 Step 5) */}
      <AccountDetailModal
        accountId={selectedAccountId}
        onClose={() => setSelectedAccountId(null)}
        onEdit={(accDetail) => {
          setSelectedAccountId(null);
          setEditingAccount(accDetail);
          setIsAccountFormModalOpen(true);
        }}
        onDelete={(accSummary) => {
          setSelectedAccountId(null);
          setDeletingAccount(accSummary);
        }}
      />

      {/* Account Form Modal (Add / Edit) per docs/ui-ux-spec.md §9 (Phase 6 Step 6) */}
      <AccountFormModal
        isOpen={isAccountFormModalOpen}
        onClose={() => {
          setIsAccountFormModalOpen(false);
          setEditingAccount(null);
        }}
        onSubmitCreate={handleCreateAccount}
        onSubmitUpdate={handleUpdateAccount}
        initialAccount={editingAccount}
        defaultPlatformId={selectedPlatform?.id || null}
        platforms={platforms}
        loading={actionLoading}
      />

      {/* Delete Account Confirmation Modal (Phase 6 Step 6) */}
      <DeleteAccountModal
        account={deletingAccount}
        isOpen={Boolean(deletingAccount)}
        onClose={() => setDeletingAccount(null)}
        onConfirm={handleDeleteAccount}
        loading={actionLoading}
      />

      {/* Logo Manager Modal (Phase 7 Step 3) */}
      <LogoManagerModal
        isOpen={isLogoManagerModalOpen}
        onClose={() => setIsLogoManagerModalOpen(false)}
        onLogosUpdated={loadPlatforms}
      />
    </div>
  );
};


