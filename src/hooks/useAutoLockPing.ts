import { useEffect, useRef, useCallback } from 'react';
import { notifyActivity } from '../services/domain';
import type { VaultStatus } from '../types/vault';

export interface UseAutoLockPingOptions {
  /**
   * The current vault status. Ping events are only active when status === 'Unlocked'.
   */
  vaultStatus: VaultStatus;
  /**
   * Minimum time in milliseconds between successive `notify_activity` IPC calls.
   * Defaults to 15,000 ms (15 seconds).
   */
  throttleMs?: number;
  /**
   * Optional callback triggered on auto-lock ping failure or when vault becomes locked.
   */
  onLockDetected?: () => void;
}

/**
 * Global user activity events monitored for auto-lock heartbeat.
 * Note: Key events capture user interaction; key values or input contents are NEVER inspected or logged.
 */
const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = [
  'mousemove',
  'mousedown',
  'keydown',
  'touchstart',
  'wheel',
  'scroll',
];

/**
 * React hook that attaches throttled activity listeners to window while vault is Unlocked.
 * Dispatches `notify_activity` to the Rust backend to keep the auto-lock deadline fresh.
 *
 * Security & Reliability guarantees:
 * - Completely inactive when vault is not 'Unlocked'.
 * - Cleanly removes all window listeners upon unmount or when vault locks.
 * - Enforces client-side throttle to avoid IPC flooding.
 * - Never captures or logs keystrokes, event values, or sensitive payload data.
 */
export function useAutoLockPing({
  vaultStatus,
  throttleMs = 15000,
  onLockDetected,
}: UseAutoLockPingOptions): void {
  const lastPingTimeRef = useRef<number>(0);
  const pendingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onLockDetectedRef = useRef(onLockDetected);

  useEffect(() => {
    onLockDetectedRef.current = onLockDetected;
  }, [onLockDetected]);

  const sendPing = useCallback(async () => {
    try {
      lastPingTimeRef.current = Date.now();
      await notifyActivity();
    } catch (err: unknown) {
      // If the backend returns VaultLocked, the vault has locked.
      const errorObj = err as { code?: string } | undefined;
      if (errorObj?.code === 'VaultLocked') {
        onLockDetectedRef.current?.();
      }
    }
  }, []);

  const handleActivity = useCallback(() => {
    if (vaultStatus !== 'Unlocked') {
      return;
    }

    const now = Date.now();
    const elapsed = now - lastPingTimeRef.current;

    if (elapsed >= throttleMs) {
      // Clear any pending deferred trailing ping
      if (pendingTimerRef.current !== null) {
        clearTimeout(pendingTimerRef.current);
        pendingTimerRef.current = null;
      }
      void sendPing();
    } else if (pendingTimerRef.current === null) {
      // Schedule trailing ping so late activity within throttle window is not lost
      const delay = Math.max(0, throttleMs - elapsed);
      pendingTimerRef.current = setTimeout(() => {
        pendingTimerRef.current = null;
        if (vaultStatus === 'Unlocked') {
          void sendPing();
        }
      }, delay);
    }
  }, [vaultStatus, throttleMs, sendPing]);

  useEffect(() => {
    if (vaultStatus !== 'Unlocked') {
      // Clear any pending timer when not unlocked
      if (pendingTimerRef.current !== null) {
        clearTimeout(pendingTimerRef.current);
        pendingTimerRef.current = null;
      }
      return;
    }

    // Send an initial ping upon entering Unlocked status to establish baseline
    void sendPing();

    const options: AddEventListenerOptions = { passive: true, capture: true };

    for (const eventName of ACTIVITY_EVENTS) {
      window.addEventListener(eventName, handleActivity, options);
    }

    return () => {
      for (const eventName of ACTIVITY_EVENTS) {
        window.removeEventListener(eventName, handleActivity, options);
      }
      if (pendingTimerRef.current !== null) {
        clearTimeout(pendingTimerRef.current);
        pendingTimerRef.current = null;
      }
    };
  }, [vaultStatus, handleActivity, sendPing]);
}
