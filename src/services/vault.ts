import { invoke } from '@tauri-apps/api/core';
import type { VaultStatus, VaultSummary, CommandError } from '../types/vault';

/**
 * Normalizes unknown errors from Tauri IPC into a structured CommandError
 */
export function normalizeError(err: unknown): CommandError {
  if (err && typeof err === 'object') {
    const maybeCommandError = err as Record<string, unknown>;
    if (typeof maybeCommandError.code === 'string' && typeof maybeCommandError.message === 'string') {
      return {
        code: maybeCommandError.code,
        message: maybeCommandError.message,
      };
    }
  }
  if (typeof err === 'string') {
    return {
      code: 'Internal',
      message: err,
    };
  }
  return {
    code: 'Internal',
    message: 'An unexpected error occurred.',
  };
}

/**
 * Checks the current lifecycle state of the vault.
 */
export async function getVaultStatus(): Promise<VaultStatus> {
  try {
    return await invoke<VaultStatus>('get_vault_status');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Retrieves non-sensitive vault metadata (name, IDs, timestamps).
 * Only succeeds if vault is Unlocked.
 */
export async function getVaultSummary(): Promise<VaultSummary> {
  try {
    return await invoke<VaultSummary>('get_vault_summary');
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Creates a new .kivault file atomically and transitions to Locked.
 */
export async function createVault(
  vaultPath: string,
  vaultName: string,
  masterPassword: string
): Promise<void> {
  try {
    await invoke<void>('create_vault', {
      vaultPath,
      vaultName,
      masterPassword,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Unlocks the active vault (or initialises from vaultPath if provided).
 */
export async function unlockVault(
  masterPassword: string,
  vaultPath?: string
): Promise<void> {
  try {
    await invoke<void>('unlock_vault', {
      masterPassword,
      vaultPath: vaultPath || null,
    });
  } catch (err) {
    throw normalizeError(err);
  }
}

/**
 * Flushes in-memory SQLite state to disk, zeroizes memory, and locks the vault.
 */
export async function lockVault(): Promise<void> {
  try {
    await invoke<void>('lock_vault');
  } catch (err) {
    throw normalizeError(err);
  }
}
