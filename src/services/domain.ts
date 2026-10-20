import { invoke } from '@tauri-apps/api/core';
import type {
  AccountSummary,
  AccountDetail,
  Account,
  CreateAccountInput,
  UpdateAccountInput,
  Platform,
  PlatformSummary,
  CreatePlatformInput,
  UpdatePlatformInput,
  SecurityStatus,
  PasswordHealth,
  DashboardStats,
  SearchFilters,
  SortOrder,
  SecuritySettings,
  PasswordGeneratorSettings,
  VaultSettings,
  Tag,
  Logo,
  LogoSummary,
  ActivityNotificationResponse,
} from '../types/domain';

import { normalizeError } from './vault';


/**
 * Retrieves the list of account summaries matching optional filters.
 */
export async function listAccounts(
  platformId?: string | null,
  favoriteOnly?: boolean | null,
  tagId?: string | null
): Promise<AccountSummary[]> {
  try {
    return await invoke<AccountSummary[]>('list_accounts', {
      platformId: platformId || null,
      favoriteOnly: favoriteOnly !== undefined ? favoriteOnly : null,
      tagId: tagId || null,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Searches accounts matching query string, optional filters, and sort order.
 */
export async function searchAccounts(
  query: string,
  filters?: SearchFilters | null,
  sort?: SortOrder | null
): Promise<AccountSummary[]> {
  try {
    return await invoke<AccountSummary[]>('search_accounts', {
      query,
      filters: filters || null,
      sort: sort || null,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}


/**
 * Retrieves full account details (including tags and custom fields, with password omitted).
 */
export async function getAccountDetail(accountId: string): Promise<AccountDetail> {
  try {
    return await invoke<AccountDetail>('get_account_detail', {
      accountId,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Creates a new account in the active vault.
 */
export async function createAccount(input: CreateAccountInput): Promise<AccountDetail> {
  try {
    return await invoke<AccountDetail>('create_account', {
      platformId: input.platform_id,
      displayName: input.display_name || null,
      username: input.username || null,
      email: input.email || null,
      password: input.password || null,
      url: input.url || null,
      notes: input.notes || null,
      favorite: input.favorite,
      tags: input.tags || null,
      customFields: input.custom_fields || null,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Updates an existing account in the active vault.
 */
export async function updateAccount(
  accountId: string,
  input: UpdateAccountInput
): Promise<Account> {
  try {
    return await invoke<Account>('update_account', {
      accountId,
      fields: {
        platform_id: input.platform_id || null,
        display_name: input.display_name !== undefined ? input.display_name : null,
        username: input.username !== undefined ? input.username : null,
        email: input.email !== undefined ? input.email : null,
        password: input.password !== undefined ? input.password : null,
        url: input.url !== undefined ? input.url : null,
        notes: input.notes !== undefined ? input.notes : null,
        is_favorite: input.is_favorite !== undefined ? input.is_favorite : null,
      },
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Deletes an account and its associated custom fields and tag relationships.
 */
export async function deleteAccount(accountId: string): Promise<void> {
  try {
    await invoke<void>('delete_account', {
      accountId,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}


/**
 * Reveals a secret value across IPC on-demand.
 * Must NOT be persisted to storage or written to logs.
 */
export async function revealSecret(accountId: string, field: string): Promise<string> {
  try {
    return await invoke<string>('reveal_secret', {
      accountId,
      field,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Copies a secret directly to the OS clipboard from Rust and configures auto-clear.
 * Note: Secret value is never returned across IPC to React.
 */
export async function copySecret(
  accountId: string,
  field: string,
  timeoutSeconds?: number
): Promise<void> {
  try {
    await invoke<void>('copy_secret', {
      accountId,
      field,
      timeoutSeconds: timeoutSeconds || null,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Retrieves the list of platform summaries.
 */

export async function listPlatforms(): Promise<PlatformSummary[]> {
  try {
    return await invoke<PlatformSummary[]>('list_platforms');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Creates a new platform in the active vault.
 */
export async function createPlatform(input: CreatePlatformInput): Promise<Platform> {
  try {
    return await invoke<Platform>('create_platform', {
      name: input.name,
      category: input.category || null,
      website: input.website || null,
      logoId: input.logo_id || null,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Retrieves a single platform by ID.
 */
export async function getPlatform(platformId: string): Promise<Platform> {
  try {
    return await invoke<Platform>('get_platform', {
      platformId,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Updates an existing platform.
 */
export async function updatePlatform(
  platformId: string,
  input: UpdatePlatformInput
): Promise<Platform> {
  try {
    return await invoke<Platform>('update_platform', {
      platformId,
      name: input.name || null,
      category: input.category !== undefined ? (input.category ? input.category : null) : null,
      website: input.website !== undefined ? (input.website ? input.website : null) : null,
      logoId: input.logo_id !== undefined ? (input.logo_id ? input.logo_id : null) : null,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Deletes a platform by ID.
 * Requires confirmationToken to match platformId for cascading account deletion safety.
 */
export async function deletePlatform(
  platformId: string,
  confirmationToken: string
): Promise<void> {
  try {
    await invoke<void>('delete_platform', {
      platformId,
      confirmationToken,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Retrieves cryptographic and vault integrity status from Rust Security module.
 */
export async function getSecurityStatus(): Promise<SecurityStatus> {
  try {
    return await invoke<SecurityStatus>('get_security_status');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Retrieves aggregate password health counts (weak and reused count).
 * Guaranteed to never return passwords or account lists.
 */
export async function getPasswordHealth(): Promise<PasswordHealth> {
  try {
    return await invoke<PasswordHealth>('get_password_health');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Pings Rust backend to record user activity and refresh the auto-lock deadline.
 * Never logs or exposes passwords or sensitive data.
 */
export async function notifyActivity(): Promise<ActivityNotificationResponse> {
  try {
    return await invoke<ActivityNotificationResponse>('notify_activity');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Fetches and aggregates all 4 Dashboard overview datasets concurrently.
 */
export async function fetchDashboardStats(): Promise<DashboardStats> {
  const [accounts, platforms, security, passwordHealth] = await Promise.all([
    listAccounts(),
    listPlatforms(),
    getSecurityStatus(),
    getPasswordHealth(),
  ]);

  const totalAccounts = accounts.length;
  const totalFavorites = accounts.filter((acc) => acc.is_favorite).length;
  const totalPlatforms = platforms.length;

  return {
    totalAccounts,
    totalFavorites,
    totalPlatforms,
    security,
    passwordHealth,
  };
}

/**
 * Retrieves all vault settings (security timeouts and generator defaults).
 */
export async function getSettings(): Promise<VaultSettings> {
  try {
    return await invoke<VaultSettings>('get_settings');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Updates security settings (auto_lock and clipboard_timeout).
 */
export async function updateSecuritySettings(
  settings: SecuritySettings
): Promise<SecuritySettings> {
  try {
    return await invoke<SecuritySettings>('update_security_settings', {
      settings,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Updates password generator default settings.
 */
export async function updatePasswordGeneratorSettings(
  settings: PasswordGeneratorSettings
): Promise<PasswordGeneratorSettings> {
  try {
    return await invoke<PasswordGeneratorSettings>('update_password_generator_settings', {
      settings,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

// ─── Tag Commands (docs/api-contract.md §8) ───────────────────────────────────

/**
 * Creates a new tag.
 */
export async function createTag(name: string): Promise<Tag> {
  try {
    return await invoke<Tag>('create_tag', { name });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Lists all tags in the vault.
 */
export async function listTags(): Promise<Tag[]> {
  try {
    return await invoke<Tag[]>('list_tags');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Renames an existing tag.
 */
export async function renameTag(tagId: string, name: string): Promise<Tag> {
  try {
    return await invoke<Tag>('rename_tag', { tagId, name });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Deletes a tag and cascades removal of tag assignments.
 */
export async function deleteTag(tagId: string): Promise<void> {
  try {
    await invoke<void>('delete_tag', { tagId });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Assigns a tag to an account.
 */
export async function assignTag(accountId: string, tagId: string): Promise<void> {
  try {
    await invoke<void>('assign_tag', { accountId, tagId });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Removes a tag assignment from an account.
 */
export async function removeTag(accountId: string, tagId: string): Promise<void> {
  try {
    await invoke<void>('remove_tag', { accountId, tagId });
  } catch (err) {
    throw normalizeError(err);
  }
}

// ─── Logo Commands (docs/api-contract.md §9) ──────────────────────────────────

/**
 * Imports a new logo into the vault database.
 * Size limit is <= 2 MiB. Supported: image/png, image/jpeg, image/webp, image/svg+xml.
 */
export async function importLogo(
  name: string,
  mimeType: string,
  imageData: number[]
): Promise<Logo> {
  try {
    return await invoke<Logo>('import_logo', {
      name,
      mimeType,
      imageData,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Lists lightweight logo summaries (metadata only, without raw image bytes).
 */
export async function listLogos(): Promise<LogoSummary[]> {
  try {
    return await invoke<LogoSummary[]>('list_logos');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Retrieves full logo entity including sanitized image bytes.
 */
export async function getLogo(logoId: string): Promise<Logo> {
  try {
    return await invoke<Logo>('get_logo', { logoId });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Renames an existing logo.
 */
export async function renameLogo(logoId: string, newName: string): Promise<Logo> {
  try {
    return await invoke<Logo>('rename_logo', { logoId, newName });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Replaces the image content and MIME type of an existing logo.
 */
export async function replaceLogo(
  logoId: string,
  newMimeType: string,
  newImageData: number[]
): Promise<Logo> {
  try {
    return await invoke<Logo>('replace_logo', {
      logoId,
      newMimeType,
      newImageData,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Deletes a logo from the vault and nullifies any platform reference.
 */
export async function deleteLogo(logoId: string): Promise<void> {
  try {
    await invoke<void>('delete_logo', { logoId });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Assigns or unassigns a logo to/from a platform.
 */
export async function assignLogo(
  platformId: string,
  logoId: string | null
): Promise<void> {
  try {
    await invoke<void>('assign_logo', { platformId, logoId: logoId || null });
  } catch (err) {
    throw normalizeError(err);
  }
}

