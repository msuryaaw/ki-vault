/**
 * Summary representation of an account (used in lists and aggregates).
 * Mirrors Rust `crate::accounts::AccountSummary`.
 */
export interface AccountSummary {
  id: string;
  platform_id: string;
  platform_name: string;
  display_name: string | null;
  username: string | null;
  email: string | null;
  logo_id: string | null;
  is_favorite: boolean;
  updated_at: number;
}

/**
 * Account entity stored in the SQLite database.
 * Note: password is never serialized by default in general responses.
 */
export interface Account {
  id: string;
  platform_id: string;
  display_name: string | null;
  username: string | null;
  email: string | null;
  password?: string | null;
  url: string | null;
  notes: string | null;
  logo_id: string | null;
  is_favorite: boolean;
  created_at: number;
  updated_at: number;
}

/**
 * Tag associated with accounts.
 */
export interface Tag {
  id: string;
  name: string;
  created_at: number;
}

/**
 * Custom field attached to an account.
 */
export interface CustomField {
  id: string;
  account_id: string;
  field_name: string;
  field_value: string;
  field_type: string;
  is_sensitive: boolean;
  created_at: number;
  updated_at: number;
}

/**
 * Detailed account representation returned by `get_account_detail`.
 */
export interface AccountDetail {
  account: Account;
  tags: Tag[];
  custom_fields: CustomField[];
}

/**
 * Filter parameters for `list_accounts`.
 */
export interface ListAccountsFilter {
  platform_id?: string | null;
  favorite_only?: boolean | null;
  tag_id?: string | null;
}

/**
 * Custom field parameter for account creation.
 * Mirrors Rust `crate::accounts::CreateCustomFieldParamsInput`.
 */
export interface CreateCustomFieldInput {
  field_name: string;
  field_value: string;
  field_type?: string | null;
  is_sensitive?: boolean | null;
}

/**
 * Parameters for creating an account.
 * Mirrors Rust `crate::accounts::CreateAccountParams` and IPC args.
 */
export interface CreateAccountInput {
  platform_id: string;
  display_name?: string | null;
  username?: string | null;
  email?: string | null;
  password?: string | null;
  url?: string | null;
  notes?: string | null;
  logo_id?: string | null;
  favorite: boolean;
  tags?: string[] | null;
  custom_fields?: CreateCustomFieldInput[] | null;
}

/**
 * Parameters for updating an existing account.
 * Mirrors Rust `crate::accounts::UpdateAccountParams`.
 */
export interface UpdateAccountInput {
  platform_id?: string | null;
  display_name?: string | null;
  username?: string | null;
  email?: string | null;
  password?: string | null;
  url?: string | null;
  notes?: string | null;
  logo_id?: string | null;
  is_favorite?: boolean | null;
}



/**
 * Platform entity stored in the SQLite database.
 * Mirrors Rust `crate::platforms::Platform`.
 */
export interface Platform {
  id: string;
  name: string;
  category: string | null;
  website: string | null;
  logo_id: string | null;
  created_at: number;
  updated_at: number;
}

/**
 * Parameters for creating a platform.
 * Mirrors Rust `crate::platforms::CreatePlatformParams`.
 */
export interface CreatePlatformInput {
  name: string;
  category?: string | null;
  website?: string | null;
  logo_id?: string | null;
}

/**
 * Parameters for updating a platform.
 * Mirrors Rust `crate::platforms::UpdatePlatformParams`.
 */
export interface UpdatePlatformInput {
  name?: string;
  category?: string | null;
  website?: string | null;
  logo_id?: string | null;
}

/**
 * Summary representation of a platform.
 * Mirrors Rust `crate::platforms::PlatformSummary`.
 */
export interface PlatformSummary {
  id: string;
  name: string;
  category: string | null;
  website: string | null;
  logo_id: string | null;
  account_count: number;
}

/**
 * Security status report returned by `get_security_status`.
 * Mirrors Rust `crate::security::SecurityStatusResponse`.
 */
export interface SecurityStatus {
  encryption: string;
  kdf: string;
  vault_state: string;
  auto_lock: string;
  clipboard_timeout: number;
  vault_integrity: string;
}

/**
 * Password health summary returned by `get_password_health`.
 * Mirrors Rust `crate::security::PasswordHealthResponse`.
 */
export interface PasswordHealth {
  weak_count: number;
  reused_count: number;
}

/**
 * Optional filters for searching accounts (`api-contract.md` §5).
 */
export interface SearchFilters {
  platform_id?: string | null;
  tag_id?: string | null;
  category?: string | null;
  favorite_only?: boolean | null;
}

/**
 * Sorting criteria for account queries.
 */
export type SortOrder =
  | 'updated_at_desc'
  | 'updated_at_asc'
  | 'title_asc'
  | 'title_desc'
  | 'created_at_desc'
  | 'created_at_asc';

/**
 * Aggregated overview stats consumed by the Dashboard.
 */
export interface DashboardStats {
  totalAccounts: number;
  totalFavorites: number;
  totalPlatforms: number;
  security: SecurityStatus;
  passwordHealth: PasswordHealth;
}

/**
 * Security timeout configurations in settings table.
 * Mirrors Rust `crate::settings::SecuritySettings`.
 */
export interface SecuritySettings {
  auto_lock: string;
  clipboard_timeout: number;
}

/**
 * Password generator default preferences in settings table.
 * Mirrors Rust `crate::settings::PasswordGeneratorSettings`.
 */
export interface PasswordGeneratorSettings {
  length: number;
  use_uppercase: boolean;
  use_lowercase: boolean;
  use_numbers: boolean;
  use_symbols: boolean;
}

/**
 * Combined vault settings returned by `get_settings`.
 * Mirrors Rust `crate::settings::VaultSettings`.
 */
export interface VaultSettings {
  security: SecuritySettings;
  password_generator: PasswordGeneratorSettings;
}

/**
 * Full Logo entity stored in the SQLite database.
 * Mirrors Rust `crate::logos::Logo`.
 */
export interface Logo {
  id: string;
  name: string;
  mime_type: string;
  image_data: number[];
  created_at: number;
  updated_at: number;
}

export interface LogoSummary {
  id: string;
  name: string;
  mime_type: string;
  size_bytes: number;
  created_at: number;
  updated_at: number;
}

/**
 * Activity notification response returned by `notify_activity`.
 * Mirrors Rust `crate::security::ActivityNotificationResponse`.
 */
export interface ActivityNotificationResponse {
  acknowledged: boolean;
  auto_lock_enforced: boolean;
}


