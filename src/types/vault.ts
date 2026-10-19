/**
 * Vault status returned by `get_vault_status`
 */
export type VaultStatus = 'Uninitialised' | 'Locked' | 'Unlocked';

/**
 * Vault summary metadata returned by `get_vault_summary`
 */
export interface VaultSummary {
  vault_id: string;
  vault_name: string;
  created_at: number;
  updated_at: number;
}

/**
 * Structured error returned by Tauri commands
 */
export interface CommandError {
  code: string;
  message: string;
}

/**
 * Result of evaluating password strength
 */
export type PasswordStrengthLevel = 'weak' | 'fair' | 'good' | 'strong';

export interface PasswordStrength {
  level: PasswordStrengthLevel;
  score: number; // 0 to 4
  feedback: string;
}
