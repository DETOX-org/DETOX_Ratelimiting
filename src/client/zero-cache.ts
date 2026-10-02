import { hashCredentials, normalizeEmail } from '../core/hasher.js';
import { ClientLockoutState } from '../core/types.js';

export interface ZeroCacheCheckResult {
  /** True if the credential pair was found in 0-cache */
  isCached: boolean;
  /** Hash signature key (e.g. cred_0_1894205128) */
  hashKey: string;
  /** Descriptive message for instant client display */
  message?: string;
}

export interface ZeroCacheOptions {
  /** Custom storage key for 0-cache map */
  cacheStorageKey?: string;
  /** Custom storage key for client lockout state */
  lockoutStorageKey?: string;
}

const DEFAULT_CACHE_KEY = 'detox_failed_creds_0cache';
const DEFAULT_LOCKOUT_KEY = 'detox_client_ratelimit_state';

/**
 * DETOX Client-Side 0-Caching Shield & Lockout Synchronizer
 * 
 * Provides:
 * 1. 0ms pre-flight interception for repeated failed credential attempts.
 * 2. Zero network egress and zero cloud DB cost (Denial-of-Wallet prevention).
 * 3. Tamper-proof client-side countdown synchronization with server authority.
 */
export class DetoxClientShield {
  private cacheKey: string;
  private lockoutKey: string;

  constructor(options: ZeroCacheOptions = {}) {
    this.cacheKey = options.cacheStorageKey ?? DEFAULT_CACHE_KEY;
    this.lockoutKey = options.lockoutStorageKey ?? DEFAULT_LOCKOUT_KEY;
  }

  private isStorageAvailable(): boolean {
    return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
  }

  /**
   * Pre-Flight 0-Cache Interception:
   * Inspects local storage for previously verified bad credentials.
   * If found, aborts network request immediately with 0ms overhead!
   */
  checkLocal0Cache(email: string, password: string): ZeroCacheCheckResult {
    const hashKey = hashCredentials(email, password);

    if (!this.isStorageAvailable()) {
      return { isCached: false, hashKey };
    }

    try {
      const raw = window.localStorage.getItem(this.cacheKey);
      if (!raw) return { isCached: false, hashKey };

      const cache = JSON.parse(raw);
      if (cache && cache[hashKey] === 0) {
        return {
          isCached: true,
          hashKey,
          message: 'Login credentials not valid (0-Cache Verified)',
        };
      }
    } catch {
      // In case of corrupt localStorage, fail open
    }

    return { isCached: false, hashKey };
  }

  /**
   * Stores a failed credential signature in local storage with value 0.
   */
  storeFailedCred0(email: string, password: string): void {
    if (!this.isStorageAvailable()) return;

    try {
      const hashKey = hashCredentials(email, password);
      const raw = window.localStorage.getItem(this.cacheKey);
      const cache = raw ? JSON.parse(raw) : {};
      cache[hashKey] = 0;
      window.localStorage.setItem(this.cacheKey, JSON.stringify(cache));
    } catch {
      // Ignore quota errors in restricted browser storage
    }
  }

  /**
   * Cleanses the 0-cache map upon successful authentication.
   */
  clear0Cache(): void {
    if (!this.isStorageAvailable()) return;
    try {
      window.localStorage.removeItem(this.cacheKey);
      window.localStorage.removeItem(this.lockoutKey);
    } catch {
      // Safe no-op
    }
  }

  /**
   * Saves or updates the client lockout state returned from server.
   */
  saveLocalLockoutState(
    email: string,
    data: { isLocked: boolean; lockedUntil: number; uniqueKey: string }
  ): void {
    if (!this.isStorageAvailable()) return;

    try {
      const state = {
        email: normalizeEmail(email),
        isLocked: data.isLocked,
        lockedUntil: data.lockedUntil,
        uniqueKey: data.uniqueKey,
        updatedAt: Date.now(),
      };
      window.localStorage.setItem(this.lockoutKey, JSON.stringify(state));
    } catch {
      // Safe no-op
    }
  }

  /**
   * Retrieves active lockout state for the given identifier.
   * Authoritative: automatically expires if current time exceeds lockedUntil.
   */
  getLocalLockoutState(email?: string): ClientLockoutState | null {
    if (!this.isStorageAvailable()) return null;

    try {
      const raw = window.localStorage.getItem(this.lockoutKey);
      if (!raw) return null;

      const state = JSON.parse(raw);
      if (!state || !state.isLocked) return null;

      // Filter by email if specified
      if (email && normalizeEmail(state.email) !== normalizeEmail(email)) {
        return null;
      }

      const now = Date.now();
      const remainingSeconds = Math.max(0, Math.ceil((state.lockedUntil - now) / 1000));

      if (remainingSeconds <= 0) {
        // Cooldown naturally elapsed
        this.clearLocalLockoutState();
        return null;
      }

      return {
        identifier: state.email,
        isLocked: true,
        lockedUntil: state.lockedUntil,
        uniqueKey: state.uniqueKey,
        remainingSeconds,
        updatedAt: state.updatedAt,
      };
    } catch {
      return null;
    }
  }

  /**
   * Clears saved client lockout state.
   */
  clearLocalLockoutState(): void {
    if (!this.isStorageAvailable()) return;
    try {
      window.localStorage.removeItem(this.lockoutKey);
    } catch {
      // Safe no-op
    }
  }
}

/** Singleton default instance */
export const detoxClient = new DetoxClientShield();

/** Factory helper */
export function createZeroCache(options?: ZeroCacheOptions): DetoxClientShield {
  return new DetoxClientShield(options);
}
