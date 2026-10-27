import React, { useEffect, useState, useCallback } from 'react';
import {
  searchAccounts,
  listPlatforms,
  createAccount,
  updateAccount,
  deleteAccount,
  listTags,
} from '../services/domain';
import type {
  AccountSummary,
  AccountDetail,
  PlatformSummary,
  SortOrder,
  CreateAccountInput,
  UpdateAccountInput,
  Tag,
} from '../types/domain';
import type { CommandError } from '../types/vault';
import { Button } from '../components/Button';
import { AccountDetailModal } from '../components/AccountDetailModal';
import { AccountFormModal } from '../components/AccountFormModal';
import { DeleteAccountModal } from '../components/DeleteAccountModal';
import { TagManagerModal } from '../components/TagManagerModal';
import { PlatformLogo } from '../components/PlatformLogo';
import { Dropdown } from '../components/Dropdown';
import {
  Users,
  Star,
  Search,
  RefreshCw,
  AlertCircle,
  Globe,
  User,
  Mail,
  Calendar,
  ArrowUpDown,
  Plus,
  CheckCircle2,
  Tag as TagIcon,
  X,
} from 'lucide-react';


interface AccountListProps {
  /**
   * If true, forces the view to only show favorite accounts (for the 'Favorites' nav tab)
   */
  favoriteOnlyMode?: boolean;
  onNavigateToPlatforms?: () => void;
}

export const AccountList: React.FC<AccountListProps> = ({
  favoriteOnlyMode = false,
  onNavigateToPlatforms,
}) => {
  const [accounts, setAccounts] = useState<AccountSummary[]>([]);
  const [platforms, setPlatforms] = useState<PlatformSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CommandError | null>(null);

  // Selected account for Account Detail View (Phase 6 Step 5)
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null);

  // Form & Delete Modals (Phase 6 Step 6)
  const [isFormModalOpen, setIsFormModalOpen] = useState(false);
  const [editingAccount, setEditingAccount] = useState<AccountDetail | null>(null);
  const [deletingAccount, setDeletingAccount] = useState<AccountSummary | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedPlatformId, setSelectedPlatformId] = useState<string>('all');
  const [selectedTagId, setSelectedTagId] = useState<string>('all');
  const [tags, setTags] = useState<Tag[]>([]);
  const [isTagModalOpen, setIsTagModalOpen] = useState(false);
  const [sortOrder, setSortOrder] = useState<SortOrder>('updated_at_desc');
  // Local favorite toggle (only active when not in forced favoriteOnlyMode)
  const [localFavoriteOnly, setLocalFavoriteOnly] = useState<boolean>(false);

  const effectiveFavoriteOnly = favoriteOnlyMode || localFavoriteOnly;

  // Load platforms for the platform filter dropdown
  const loadPlatformsList = useCallback(async () => {
    try {
      const data = await listPlatforms();
      setPlatforms(data);
    } catch {
      // Platform dropdown will simply be empty if platforms fail to load
    }
  }, []);

  // Load tags for the tag filter dropdown
  const loadTagsList = useCallback(async () => {
    try {
      const data = await listTags();
      setTags(data);
    } catch {
      // Tag dropdown will simply be empty if tags fail to load
    }
  }, []);

  // Fetch accounts based on query, filters, and sort order
  const fetchAccounts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const trimmedQuery = searchQuery.trim();
      const platformFilter = selectedPlatformId === 'all' ? null : selectedPlatformId;
      const tagFilter = selectedTagId === 'all' ? null : selectedTagId;

      let data: AccountSummary[];
      if (trimmedQuery.length > 0) {
        // Use backend search_accounts with full filters and sort
        data = await searchAccounts(
          trimmedQuery,
          {
            platform_id: platformFilter,
            tag_id: tagFilter,
            favorite_only: effectiveFavoriteOnly ? true : null,
          },
          sortOrder
        );
      } else {
        // Use searchAccounts with null query for filtering and sorting
        data = await searchAccounts(
          '',
          {
            platform_id: platformFilter,
            tag_id: tagFilter,
            favorite_only: effectiveFavoriteOnly ? true : null,
          },
          sortOrder
        );
      }
      setAccounts(data);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, selectedPlatformId, selectedTagId, effectiveFavoriteOnly, sortOrder]);

  useEffect(() => {
    loadPlatformsList();
    loadTagsList();
  }, [loadPlatformsList, loadTagsList]);

  // Debounced search / query reload
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchAccounts();
    }, 200);
    return () => clearTimeout(timer);
  }, [fetchAccounts]);

  // Account CRUD handlers (Phase 6 Step 6)
  const handleCreateAccount = async (data: CreateAccountInput) => {
    setActionLoading(true);
    setError(null);
    try {
      await createAccount(data);
      setSuccessNotice(`Account "${data.display_name || data.username || 'Account'}" created successfully.`);
      setTimeout(() => setSuccessNotice(null), 4000);
      setIsFormModalOpen(false);
      await fetchAccounts();
      await loadPlatformsList();
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleUpdateAccount = async (id: string, data: UpdateAccountInput) => {
    setActionLoading(true);
    setError(null);
    try {
      await updateAccount(id, data);
      setSuccessNotice('Account updated successfully.');
      setTimeout(() => setSuccessNotice(null), 4000);
      setIsFormModalOpen(false);
      setEditingAccount(null);
      await fetchAccounts();
      await loadPlatformsList();
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteAccount = async (id: string) => {
    setActionLoading(true);
    setError(null);
    try {
      await deleteAccount(id);
      setSuccessNotice('Account deleted successfully.');
      setTimeout(() => setSuccessNotice(null), 4000);
      setDeletingAccount(null);
      setSelectedAccountId(null);
      await fetchAccounts();
      await loadPlatformsList();
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  // Format timestamp helper
  const formatDate = (timestampMs: number) => {
    if (!timestampMs) return '-';
    // If timestamp is in seconds (10 digits), multiply by 1000
    const ms = timestampMs < 10000000000 ? timestampMs * 1000 : timestampMs;
    const date = new Date(ms);
    return date.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };


  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 text-left">
      {/* Header section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            {favoriteOnlyMode ? (
              <Star className="h-6 w-6 text-amber-400 fill-amber-400/20" />
            ) : (
              <Users className="h-6 w-6 text-primary" />
            )}
            <span>{favoriteOnlyMode ? 'Favorite Accounts' : 'All Accounts'}</span>
            <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-medium bg-muted text-muted-foreground border border-border">
              {accounts.length}
            </span>
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {favoriteOnlyMode
              ? 'Quick access to your starred and frequently used credentials.'
              : 'Secure overview of all credentials organized by platform and identity.'}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsTagModalOpen(true)}
            className="h-9 px-3 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <TagIcon className="h-3.5 w-3.5" />
            Manage Tags
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={fetchAccounts}
            disabled={loading}
            className="h-9 px-3 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              setEditingAccount(null);
              setIsFormModalOpen(true);
            }}
            className="h-9 px-3 gap-1.5 text-xs shadow-sm"
          >
            <Plus className="h-4 w-4" />
            Add Account
          </Button>
        </div>
      </div>

      {/* Success Notification Banner */}
      {successNotice && (
        <div className="p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 flex items-center justify-between gap-3 text-xs text-emerald-500 animate-in fade-in duration-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{successNotice}</span>
          </div>
          <button
            onClick={() => setSuccessNotice(null)}
            className="text-xs text-muted-foreground hover:text-foreground px-2 py-0.5"
          >
            Dismiss
          </button>
        </div>
      )}


      {/* Controls Bar: Search, Platform Filter, Tag Filter, Favorites Toggle, Sorting */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-3 bg-card border border-border p-3.5 rounded-xl shadow-xs">
        {/* Search Input */}
        <div className="relative sm:col-span-2 lg:col-span-4 flex items-center">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          <input
            type="text"
            placeholder="Search account name, username, email, platform..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-9 bg-background border border-input rounded-lg pl-9 pr-8 py-2 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-colors"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5 rounded cursor-pointer"
              title="Clear search"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Platform Filter */}
        <div className="relative lg:col-span-2 flex items-center">
          <Dropdown
            value={selectedPlatformId}
            onChange={(val) => setSelectedPlatformId(val)}
            prefixIcon={<Globe className="h-3.5 w-3.5" />}
            ariaLabel="Filter accounts by platform"
            options={[
              { value: 'all', label: `All Platforms (${platforms.length})` },
              ...platforms.map((p) => ({
                value: p.id,
                label: `${p.name} (${p.account_count})`,
              })),
            ]}
          />
        </div>

        {/* Tag Filter */}
        <div className="relative lg:col-span-2 flex items-center">
          <Dropdown
            value={selectedTagId}
            onChange={(val) => setSelectedTagId(val)}
            prefixIcon={<TagIcon className="h-3.5 w-3.5" />}
            ariaLabel="Filter accounts by tag"
            options={[
              { value: 'all', label: `All Tags (${tags.length})` },
              ...tags.map((t) => ({
                value: t.id,
                label: `#${t.name}`,
              })),
            ]}
          />
        </div>

        {/* Sort Order */}
        <div className="relative lg:col-span-2 flex items-center">
          <Dropdown
            value={sortOrder}
            onChange={(val) => setSortOrder(val as SortOrder)}
            prefixIcon={<ArrowUpDown className="h-3.5 w-3.5" />}
            ariaLabel="Sort accounts"
            options={[
              { value: 'updated_at_desc', label: 'Recently Updated' },
              { value: 'updated_at_asc', label: 'Oldest Updated' },
              { value: 'title_asc', label: 'Title (A - Z)' },
              { value: 'title_desc', label: 'Title (Z - A)' },
              { value: 'created_at_desc', label: 'Recently Created' },
              { value: 'created_at_asc', label: 'Oldest Created' },
            ]}
          />
        </div>

        {/* Favorite toggle (only shown when not already locked into Favorites view) */}
        {!favoriteOnlyMode && (
          <div className="lg:col-span-2 flex items-center justify-end">
            <button
              onClick={() => setLocalFavoriteOnly(!localFavoriteOnly)}
              className={`w-full h-9 flex items-center justify-center gap-1.5 px-3 rounded-lg text-xs font-medium border transition-colors ${
                localFavoriteOnly
                  ? 'bg-amber-500/10 text-amber-500 border-amber-500/30'
                  : 'bg-background text-muted-foreground border-input hover:text-foreground'
              }`}
            >
              <Star className={`h-3.5 w-3.5 ${localFavoriteOnly ? 'fill-amber-500' : ''}`} />
              <span>Favorites Only</span>
            </button>
          </div>
        )}
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl border border-destructive/30 bg-destructive/5 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-xs font-semibold text-destructive">{error.code}</h4>
            <p className="text-xs text-destructive/80">{error.message}</p>
          </div>
        </div>
      )}

      {/* Content Area: Loading, Empty, or Account Cards */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center text-center space-y-3">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          <p className="text-xs text-muted-foreground">Retrieving accounts from encrypted vault...</p>
        </div>
      ) : accounts.length === 0 ? (
        <div className="py-20 border border-dashed border-border rounded-xl flex flex-col items-center justify-center text-center px-4 bg-card/20">
          <div className="h-12 w-12 rounded-full bg-muted flex items-center justify-center text-muted-foreground mb-3">
            {effectiveFavoriteOnly ? <Star className="h-6 w-6" /> : <Users className="h-6 w-6" />}
          </div>
          <h3 className="text-sm font-semibold text-foreground">
            {effectiveFavoriteOnly
              ? 'No favorite accounts found'
              : searchQuery.trim() || selectedPlatformId !== 'all' || selectedTagId !== 'all'
              ? 'No accounts match your search/filter criteria'
              : 'No accounts stored in this vault'}
          </h3>
          <p className="text-xs text-muted-foreground max-w-sm mt-1 mb-5">
            {effectiveFavoriteOnly
              ? 'Mark accounts as favorite with the star icon to see them here.'
              : searchQuery.trim() || selectedPlatformId !== 'all' || selectedTagId !== 'all'
              ? 'Try adjusting your search query or selecting a different platform or tag.'
              : 'Add platforms and accounts to organize your passwords securely.'}
          </p>

          {searchQuery.trim() || selectedPlatformId !== 'all' || selectedTagId !== 'all' ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSearchQuery('');
                setSelectedPlatformId('all');
                setSelectedTagId('all');
                setLocalFavoriteOnly(false);
              }}
              className="text-xs h-8"
            >
              Reset Filters
            </Button>
          ) : platforms.length === 0 && onNavigateToPlatforms ? (
            <Button
              variant="outline"
              size="sm"
              onClick={onNavigateToPlatforms}
              className="text-xs h-8 gap-1.5"
            >
              <Globe className="h-3.5 w-3.5" />
              Manage Platforms
            </Button>
          ) : null}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {accounts.map((acc) => (
            <div
              key={acc.id}
              onClick={() => setSelectedAccountId(acc.id)}
              className="group relative bg-card hover:bg-card/90 border border-border hover:border-primary/40 rounded-xl p-4 transition-all duration-150 shadow-xs flex flex-col justify-between cursor-pointer"
            >
              {/* Header: Title / Display Name & Star */}
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <PlatformLogo
                      logoId={acc.logo_id || platforms.find((p) => p.id === acc.platform_id)?.logo_id}
                      platformName={acc.platform_name}
                      size="sm"
                    />
                    <div className="space-y-0.5 min-w-0">
                      <h3 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate">
                        {acc.display_name || acc.username || acc.email || 'Untitled Account'}
                      </h3>
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground truncate">
                        <span>{acc.platform_name}</span>
                      </div>
                    </div>
                  </div>

                  {/* Favorite Star Badge per docs/ui-ux-spec.md §6 */}
                  <div
                    className={`h-7 w-7 rounded-lg flex items-center justify-center shrink-0 ${
                      acc.is_favorite
                        ? 'text-amber-500 bg-amber-500/10'
                        : 'text-muted-foreground/30'
                    }`}
                    title={acc.is_favorite ? 'Favorite account' : 'Not marked as favorite'}
                  >
                    <Star
                      className={`h-4 w-4 ${acc.is_favorite ? 'fill-amber-500' : ''}`}
                    />
                  </div>
                </div>

                {/* Identity info: Username / Email */}
                <div className="space-y-1.5 mt-3 pt-3 border-t border-border/60 text-xs">
                  {acc.username && (
                    <div className="flex items-center gap-2 text-muted-foreground font-mono">
                      <User className="h-3 w-3 shrink-0 text-muted-foreground/70" />
                      <span className="truncate">{acc.username}</span>
                    </div>
                  )}

                  {acc.email && (
                    <div className="flex items-center gap-2 text-muted-foreground font-mono">
                      <Mail className="h-3 w-3 shrink-0 text-muted-foreground/70" />
                      <span className="truncate">{acc.email}</span>
                    </div>
                  )}

                  {!acc.username && !acc.email && (
                    <div className="text-xs text-muted-foreground/60 italic">
                      No username or email specified
                    </div>
                  )}
                </div>
              </div>

              {/* Card Footer: Metadata and Security Note */}
              <div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between text-[11px] text-muted-foreground font-mono">
                <span className="flex items-center gap-1">
                  <Calendar className="h-3 w-3" />
                  {formatDate(acc.updated_at)}
                </span>
                <span className="text-[10px] uppercase tracking-wider text-primary bg-primary/10 px-1.5 py-0.5 rounded font-sans font-medium">
                  View Detail →
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Account Detail Modal per docs/ui-ux-spec.md §8 (Phase 6 Step 5) */}
      <AccountDetailModal
        accountId={selectedAccountId}
        onClose={() => setSelectedAccountId(null)}
        onEdit={(accDetail) => {
          setSelectedAccountId(null);
          setEditingAccount(accDetail);
          setIsFormModalOpen(true);
        }}
        onDelete={(accSummary) => {
          setSelectedAccountId(null);
          setDeletingAccount(accSummary);
        }}
      />

      {/* Account Form Modal (Add / Edit) per docs/ui-ux-spec.md §9 (Phase 6 Step 6) */}
      <AccountFormModal
        isOpen={isFormModalOpen}
        onClose={() => {
          setIsFormModalOpen(false);
          setEditingAccount(null);
        }}
        onSubmitCreate={handleCreateAccount}
        onSubmitUpdate={handleUpdateAccount}
        initialAccount={editingAccount}
        defaultPlatformId={selectedPlatformId !== 'all' ? selectedPlatformId : null}
        platforms={platforms}
        loading={actionLoading}
      />

      {/* Delete Confirmation Modal (Phase 6 Step 6) */}
      <DeleteAccountModal
        account={deletingAccount}
        isOpen={Boolean(deletingAccount)}
        onClose={() => setDeletingAccount(null)}
        onConfirm={handleDeleteAccount}
        loading={actionLoading}
      />

      {/* Tag Manager Modal (Phase 7 Step 1) */}
      <TagManagerModal
        isOpen={isTagModalOpen}
        onClose={() => setIsTagModalOpen(false)}
        onTagsUpdated={() => {
          loadTagsList();
          fetchAccounts();
        }}
      />
    </div>
  );
};


