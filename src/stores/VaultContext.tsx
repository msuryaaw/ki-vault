import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import type { VaultStatus, VaultSummary, CommandError } from '../types/vault';
import {
  getVaultStatus,
  getVaultSummary,
  createVault as apiCreateVault,
  unlockVault as apiUnlockVault,
  lockVault as apiLockVault,
} from '../services/vault';

interface VaultContextType {
  status: VaultStatus;
  summary: VaultSummary | null;
  loading: boolean;
  error: CommandError | null;
  refreshStatus: () => Promise<void>;
  createVault: (path: string, name: string, password: string) => Promise<void>;
  unlockVault: (password: string, path?: string) => Promise<void>;
  lockVault: () => Promise<void>;
  clearError: () => void;
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

export const VaultProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<VaultStatus>('Uninitialised');
  const [summary, setSummary] = useState<VaultSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CommandError | null>(null);

  const isCheckingRef = useRef<boolean>(false);

  const refreshStatus = useCallback(async (showLoading: boolean = true) => {
    if (isCheckingRef.current) {
      return;
    }
    isCheckingRef.current = true;
    if (showLoading) {
      setLoading(true);
    }
    try {
      const currentStatus = await getVaultStatus();
      setStatus(currentStatus);

      if (currentStatus === 'Unlocked') {
        const currentSummary = await getVaultSummary();
        setSummary(currentSummary);
      } else {
        setSummary(null);
      }
      setError(null);
    } catch (err) {
      setError(err as CommandError);
    } finally {
      if (showLoading) {
        setLoading(false);
      }
      isCheckingRef.current = false;
    }
  }, []);

  useEffect(() => {
    refreshStatus(true);
  }, [refreshStatus]);

  // Polling synchronization: only active when vault is Unlocked
  useEffect(() => {
    if (status !== 'Unlocked') {
      return;
    }

    const intervalId = window.setInterval(() => {
      void refreshStatus(false);
    }, 2000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [status, refreshStatus]);

  const handleCreateVault = async (path: string, name: string, password: string) => {
    setLoading(true);
    setError(null);
    try {
      await apiCreateVault(path, name, password);
      // create_vault transitions state to Locked in backend
      await refreshStatus();
    } catch (err) {
      setError(err as CommandError);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const handleUnlockVault = async (password: string, path?: string) => {
    setLoading(true);
    setError(null);
    try {
      await apiUnlockVault(password, path);
      // unlock_vault transitions state to Unlocked in backend
      await refreshStatus();
    } catch (err) {
      setError(err as CommandError);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const handleLockVault = async () => {
    setLoading(true);
    setError(null);
    try {
      await apiLockVault();
      // lock_vault transitions state to Locked in backend
      await refreshStatus();
    } catch (err) {
      setError(err as CommandError);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const clearError = () => setError(null);

  return (
    <VaultContext.Provider
      value={{
        status,
        summary,
        loading,
        error,
        refreshStatus,
        createVault: handleCreateVault,
        unlockVault: handleUnlockVault,
        lockVault: handleLockVault,
        clearError,
      }}
    >
      {children}
    </VaultContext.Provider>
  );
};

export const useVault = (): VaultContextType => {
  const context = useContext(VaultContext);
  if (!context) {
    throw new Error('useVault must be used within a VaultProvider');
  }
  return context;
};
