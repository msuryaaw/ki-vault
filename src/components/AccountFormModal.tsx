import React, { useState, useEffect, useCallback } from 'react';
import type {
  PlatformSummary,
  AccountDetail,
  CreateAccountInput,
  UpdateAccountInput,
  CreateCustomFieldInput,
  Tag,
} from '../types/domain';
import { listTags, createTag, assignTag, removeTag } from '../services/domain';
import { Button } from './Button';
import { Input } from './Input';
import { TagSelector } from './TagSelector';
import { LogoManagerModal } from './LogoManagerModal';
import { PlatformLogo } from './PlatformLogo';
import { Dropdown } from './Dropdown';
import {
  User,
  Globe,
  Star,
  Plus,
  Trash2,
  X,
  FileText,
  AlertCircle,
  Layers,
  Lock,
  Image as ImageIcon,
} from 'lucide-react';


interface AccountFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmitCreate: (data: CreateAccountInput) => Promise<void>;
  onSubmitUpdate: (accountId: string, data: UpdateAccountInput) => Promise<void>;
  initialAccount?: AccountDetail | null;
  defaultPlatformId?: string | null;
  platforms: PlatformSummary[];
  loading?: boolean;
}

export const AccountFormModal: React.FC<AccountFormModalProps> = ({
  isOpen,
  onClose,
  onSubmitCreate,
  onSubmitUpdate,
  initialAccount,
  defaultPlatformId,
  platforms,
  loading = false,
}) => {
  // Identity fields
  const [platformId, setPlatformId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [url, setUrl] = useState('');

  // Credential field (never prefilled from backend on edit for zero-knowledge security)
  const [password, setPassword] = useState('');

  // Organization & Notes
  const [favorite, setFavorite] = useState(false);
  const [notes, setNotes] = useState('');
  const [logoId, setLogoId] = useState<string | null>(null);
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);

  // Tags State
  const [availableTags, setAvailableTags] = useState<Tag[]>([]);
  const [selectedTagIds, setSelectedTagIds] = useState<string[]>([]);

  // Custom Fields (for creation)
  const [customFields, setCustomFields] = useState<CreateCustomFieldInput[]>([]);

  // Client validation / submission error
  const [clientError, setClientError] = useState<string | null>(null);

  const isEditing = Boolean(initialAccount);

  const loadTags = useCallback(async () => {
    try {
      const tags = await listTags();
      setAvailableTags(tags);
    } catch {
      // Non-critical background fetch failure
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      loadTags();
    }
  }, [isOpen, loadTags]);

  useEffect(() => {
    if (initialAccount) {
      setPlatformId(initialAccount.account.platform_id || '');
      setDisplayName(initialAccount.account.display_name || '');
      setUsername(initialAccount.account.username || '');
      setEmail(initialAccount.account.email || '');
      setUrl(initialAccount.account.url || '');
      setPassword(''); // Password must not be pre-filled; only provided if changing
      setFavorite(initialAccount.account.is_favorite);
      setNotes(initialAccount.account.notes || '');
      setLogoId(initialAccount.account.logo_id || null);
      setSelectedTagIds(initialAccount.tags ? initialAccount.tags.map((t) => t.id) : []);
      setCustomFields([]); // Custom fields in edit mode are read-only from Step 5
    } else {
      setPlatformId(defaultPlatformId || (platforms.length > 0 ? platforms[0].id : ''));
      setDisplayName('');
      setUsername('');
      setEmail('');
      setUrl('');
      setPassword('');
      setFavorite(false);
      setNotes('');
      setLogoId(null);
      setSelectedTagIds([]);
      setCustomFields([]);
    }
    setClientError(null);
  }, [initialAccount, defaultPlatformId, platforms, isOpen]);

  const handleCreateNewTag = async (name: string): Promise<Tag | null> => {
    try {
      const created = await createTag(name);
      setAvailableTags((prev) => [...prev, created]);
      return created;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create tag.';
      setClientError(msg);
      return null;
    }
  };

  if (!isOpen) return null;

  const handleAddCustomField = () => {
    setCustomFields([
      ...customFields,
      { field_name: '', field_value: '', field_type: 'text', is_sensitive: true },
    ]);
  };

  const handleRemoveCustomField = (index: number) => {
    setCustomFields(customFields.filter((_, i) => i !== index));
  };

  const handleCustomFieldChange = (
    index: number,
    field: keyof CreateCustomFieldInput,
    value: string | boolean
  ) => {
    const updated = [...customFields];
    updated[index] = { ...updated[index], [field]: value };
    setCustomFields(updated);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setClientError(null);

    if (!platformId.trim()) {
      setClientError('Platform is required.');
      return;
    }

    // Validate that at least one identity field or password is provided
    if (
      !displayName.trim() &&
      !username.trim() &&
      !email.trim() &&
      !password.trim() &&
      !isEditing
    ) {
      setClientError('Please provide at least a display name, username, email, or password.');
      return;
    }

    // Validate custom fields
    for (const cf of customFields) {
      if (!cf.field_name.trim()) {
        setClientError('Custom field name cannot be empty.');
        return;
      }
    }

    try {
      if (isEditing && initialAccount) {
        const updatePayload: UpdateAccountInput = {
          platform_id: platformId !== initialAccount.account.platform_id ? platformId : undefined,
          display_name: displayName.trim() || null,
          username: username.trim() || null,
          email: email.trim() || null,
          url: url.trim() || null,
          notes: notes.trim() || null,
          logo_id: logoId,
          is_favorite: favorite,
        };

        // Only include password if user typed a new one
        if (password.length > 0) {
          updatePayload.password = password;
        }

        await onSubmitUpdate(initialAccount.account.id, updatePayload);

        // Reconcile tag assignments
        const prevTagIds = initialAccount.tags ? initialAccount.tags.map((t) => t.id) : [];
        const addedTags = selectedTagIds.filter((id) => !prevTagIds.includes(id));
        const removedTags = prevTagIds.filter((id) => !selectedTagIds.includes(id));

        for (const tagId of addedTags) {
          await assignTag(initialAccount.account.id, tagId).catch(() => {});
        }
        for (const tagId of removedTags) {
          await removeTag(initialAccount.account.id, tagId).catch(() => {});
        }
      } else {
        const createPayload: CreateAccountInput = {
          platform_id: platformId,
          display_name: displayName.trim() || null,
          username: username.trim() || null,
          email: email.trim() || null,
          password: password.length > 0 ? password : null,
          url: url.trim() || null,
          notes: notes.trim() || null,
          logo_id: logoId,
          favorite,
          tags: selectedTagIds.length > 0 ? selectedTagIds : null,
          custom_fields: customFields.length > 0 ? customFields : null,
        };

        await onSubmitCreate(createPayload);
      }

      // Memory sanitization
      setPassword('');
      onClose();
    } catch (err: unknown) {
      const maybeErr = err as { message?: string };
      setClientError(maybeErr.message || 'Operation failed.');
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget && !loading) {
          setPassword('');
          onClose();
        }
      }}
    >
      <div className="w-full max-w-2xl rounded-2xl border border-border bg-card shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-6 py-4 bg-card/60 shrink-0">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20">
              <User className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground">
                {isEditing ? 'Edit Account' : 'Add New Account'}
              </h2>
              <p className="text-xs text-muted-foreground">
                {isEditing
                  ? 'Update account credentials and organization details'
                  : 'Store credentials securely inside your active encrypted vault'}
              </p>
            </div>
          </div>

          <button
            onClick={() => {
              setPassword('');
              onClose();
            }}
            disabled={loading}
            className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="overflow-y-auto p-6 space-y-6">
          {clientError && (
            <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-3.5 flex items-start gap-3">
              <AlertCircle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
              <div className="text-xs text-destructive">
                <span className="font-semibold">Validation Error</span>
                <p className="mt-0.5">{clientError}</p>
              </div>
            </div>
          )}

          {/* Section: Platform Selection */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Globe className="h-3.5 w-3.5 text-primary" />
              Platform <span className="text-destructive">*</span>
            </label>
            {platforms.length === 0 ? (
              <p className="text-xs text-amber-500 bg-amber-500/10 border border-amber-500/20 p-2.5 rounded-lg">
                No platforms available. Please create a platform first before adding accounts.
              </p>
            ) : (
              <Dropdown
                value={platformId}
                onChange={(val) => setPlatformId(val)}
                disabled={loading}
                placeholder="Select platform..."
                ariaLabel="Select platform"
                options={platforms.map((p) => ({
                  value: p.id,
                  label: `${p.name}${p.category ? ` (${p.category})` : ''}`,
                }))}
              />
            )}
          </div>

          {/* Section: Identity Details */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Identity Information
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Input
                label="Account Name / Title"
                placeholder="Google, GitHub, BPK RI"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                onClear={() => setDisplayName('')}
                helperText="Account name or display label."
                exampleText="e.g. Personal Account, Work Profile."
                maxLength={64}
                showCharCount
                isValid={displayName.trim().length >= 3}
                error={displayName.length > 0 && displayName.trim().length < 3 ? 'Account title must be at least 3 characters.' : undefined}
                disabled={loading}
              />

              <Input
                label="Username / ID"
                placeholder="user123, myusername"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onClear={() => setUsername('')}
                helperText="User identifier for login."
                exampleText="e.g. user123, myusername."
                maxLength={256}
                showCharCount
                disabled={loading}
              />

              <Input
                label="Email"
                type="email"
                placeholder="user@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onClear={() => setEmail('')}
                helperText="Associated email address."
                exampleText="e.g. user@gmail.com or user@example.com."
                maxLength={256}
                showCharCount
                isValid={email.length > 0 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())}
                error={email.length > 0 && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ? 'Please enter a valid email address.' : undefined}
                disabled={loading}
              />

              <Input
                label="Website URL"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onClear={() => setUrl('')}
                helperText="Service login URL."
                exampleText="e.g. https://google.com or https://github.com."
                maxLength={2048}
                showCharCount
                isValid={url.length > 0 && /^https?:\/\/.+/i.test(url.trim())}
                error={url.length > 0 && !/^https?:\/\/.+/i.test(url.trim()) ? 'Enter a valid URL starting with http:// or https://' : undefined}
                disabled={loading}
              />
            </div>
          </div>

          {/* Section: Password Credential */}
          <div className="space-y-2 bg-background/50 border border-border p-4 rounded-xl">
            <label className="text-xs font-semibold text-foreground flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-primary" />
                Password
              </span>
              {isEditing && (
                <span className="text-[11px] text-muted-foreground font-normal italic">
                  Leave blank to keep current password
                </span>
              )}
            </label>
            <Input
              type="password"
              placeholder={isEditing ? 'Enter new password to change...' : 'Enter account password...'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onClear={() => setPassword('')}
              helperText="Password for this account."
              exampleText="e.g. Use a combination of letters, numbers, and symbols."
              disabled={loading}
            />
          </div>

          {/* Section: Organization & Favorites */}
          <div className="space-y-2">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={favorite}
                onChange={(e) => setFavorite(e.target.checked)}
                disabled={loading}
                className="h-4 w-4 rounded border-input text-primary focus:ring-primary cursor-pointer"
              />
              <span className="text-xs font-medium text-foreground flex items-center gap-1">
                <Star className={`h-3.5 w-3.5 ${favorite ? 'text-amber-500 fill-amber-500' : 'text-muted-foreground'}`} />
                Mark as Favorite (starred for quick access)
              </span>
            </label>
          </div>

          {/* Section: Custom Fields (Creation only) */}
          {!isEditing && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Layers className="h-3.5 w-3.5" />
                  Custom Fields ({customFields.length})
                </h3>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleAddCustomField}
                  className="h-7 text-xs px-2 gap-1"
                >
                  <Plus className="h-3 w-3" /> Add Field
                </Button>
              </div>

              {customFields.length > 0 && (
                <div className="space-y-2">
                  {customFields.map((cf, idx) => (
                    <div
                      key={idx}
                      className="grid grid-cols-12 gap-2 bg-background border border-border p-2.5 rounded-lg items-center"
                    >
                      <div className="col-span-4">
                        <input
                          type="text"
                          placeholder="Field Name (e.g. PIN)"
                          value={cf.field_name}
                          onChange={(e) =>
                            handleCustomFieldChange(idx, 'field_name', e.target.value)
                          }
                          className="w-full bg-card border border-input rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                          required
                        />
                      </div>
                      <div className="col-span-4">
                        <input
                          type={cf.is_sensitive ? 'password' : 'text'}
                          placeholder="Field Value"
                          value={cf.field_value}
                          onChange={(e) =>
                            handleCustomFieldChange(idx, 'field_value', e.target.value)
                          }
                          className="w-full bg-card border border-input rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                          required
                        />
                      </div>
                      <div className="col-span-3 flex items-center gap-1.5">
                        <label className="text-[11px] text-muted-foreground flex items-center gap-1 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={Boolean(cf.is_sensitive)}
                            onChange={(e) =>
                              handleCustomFieldChange(idx, 'is_sensitive', e.target.checked)
                            }
                            className="rounded border-input text-primary"
                          />
                          Sensitive
                        </label>
                      </div>
                      <div className="col-span-1 flex justify-end">
                        <button
                          type="button"
                          onClick={() => handleRemoveCustomField(idx)}
                          className="text-muted-foreground hover:text-destructive p-1 rounded"
                          title="Remove field"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Section: Tags */}
          <div className="pt-1">
            <TagSelector
              availableTags={availableTags}
              selectedTagIds={selectedTagIds}
              onChange={setSelectedTagIds}
              onCreateTag={handleCreateNewTag}
              disabled={loading}
            />
          </div>

          {/* Section: Notes */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <FileText className="h-3.5 w-3.5 text-muted-foreground" />
              Private Notes
            </label>
            <textarea
              rows={3}
              placeholder="Additional confidential notes, security answers, or hints..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={loading}
              className="w-full bg-background border border-input rounded-lg px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
            />
          </div>

          {/* Section: Logo Selection */}
          <div className="space-y-1.5 pt-1">
            <label className="text-xs font-semibold text-foreground flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <ImageIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Account Logo (Optional)
              </span>
              <button
                type="button"
                onClick={() => setIsLogoModalOpen(true)}
                className="text-[11px] text-primary hover:underline cursor-pointer font-medium"
              >
                {logoId ? 'Change Logo' : 'Choose Logo...'}
              </button>
            </label>
            <div className="flex items-center justify-between p-2.5 rounded-lg border border-input bg-background/50">
              <div className="flex items-center gap-2.5 min-w-0">
                {logoId ? (
                  <PlatformLogo
                    logoId={logoId}
                    platformName={displayName || 'Account'}
                    size="sm"
                  />
                ) : (
                  <div className="h-6 w-6 rounded-lg bg-muted flex items-center justify-center text-muted-foreground shrink-0">
                    <ImageIcon className="h-3.5 w-3.5" />
                  </div>
                )}
                <span className="text-xs text-muted-foreground truncate">
                  {logoId ? 'Custom account logo selected' : 'Using platform logo / default'}
                </span>
              </div>
              {logoId ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setLogoId(null)}
                  className="h-6 px-2 text-[10px] shrink-0"
                >
                  Remove
                </Button>
              ) : (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setIsLogoModalOpen(true)}
                  className="h-6 px-2 text-[10px] shrink-0"
                >
                  Browse...
                </Button>
              )}
            </div>
          </div>

          {/* Footer Submit Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-border">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                setPassword('');
                onClose();
              }}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              loading={loading}
              disabled={platforms.length === 0}
            >
              {isEditing ? 'Save Changes' : 'Create Account'}
            </Button>
          </div>
        </form>
      </div>

      {/* Logo Manager Modal */}
      <LogoManagerModal
        isOpen={isLogoModalOpen}
        onClose={() => setIsLogoModalOpen(false)}
        selectedLogoId={logoId}
        onSelectLogo={(newLogoId) => {
          setLogoId(newLogoId);
          setIsLogoModalOpen(false);
        }}
      />
    </div>
  );
};
