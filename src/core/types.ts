/**
 * DETOX Rate Limiting & Anti-Tamper Security Core Types
 * Based on DETOX System Design Specification v1.0
 */

export interface RateLimitRecord {
  /** Consecutive failed attempts counter */
  count: number;
  /** Active lockout flag */
  isLocked: boolean;
  /** Epoch timestamp in milliseconds when lockout expires */
  lockedUntil: number;
  /** Ephemeral binary security key token (SEC-BIN-...) */
  uniqueKey: string;
  /** Last update timestamp in epoch milliseconds */
  updatedAt: number;
}

export interface RateLimitResult {
  /** True if the user or IP is currently locked out */
  isLocked: boolean;
  /** Number of failed attempts remaining before 5-min lockout */
  remainingAttempts: number;
  /** Seconds remaining in the lockout cooldown (0 if not locked) */
  remainingSeconds: number;
  /** Exact epoch timestamp in ms when lockout expires */
  lockedUntil: number;
  /** Official cryptographic binary security token */
  uniqueKey: string;
  /** True if an actor probed while locked and triggered a 300s penalty reset */
  antiTamperTriggered: boolean;
  /** Retry-After header value in seconds (only when isLocked = true) */
  retryAfter: number;
  /** Maximum attempts allowed before lockout (e.g. 5) */
  limit: number;
}

export interface IRateLimitStore {
  /** Inspect current rate limit state for an identifier without incrementing */
  check(key: string, now: number): Promise<RateLimitRecord | null>;

  /**
   * Atomically records a failed attempt, checks threshold, enforces lockout,
   * and applies anti-tamper penalty extension if probed while locked.
   */
  recordFailure(
    key: string,
    maxAttempts: number,
    lockoutDurationMs: number,
    now: number,
    token: string,
    antiTamperPenalty: boolean
  ): Promise<RateLimitResult>;

  /** Clears all rate-limiting counters upon valid authentication */
  reset(key: string): Promise<void>;

  /** Optional cleanup / disconnect */
  close?(): Promise<void>;
}

export interface DetoxRateLimiterOptions {
  /**
   * Maximum failed attempts allowed before triggering lockout.
   * @default 5
   */
  maxAttempts?: number;

  /**
   * Lockout cooldown duration in milliseconds.
   * @default 300000 (5 minutes = 300 seconds)
   */
  lockoutDurationMs?: number;

  /**
   * Duration in ms to retain failed attempt counters before automatic expiration.
   * @default 900000 (15 minutes)
   */
  windowDurationMs?: number;

  /**
   * If true, attempting requests while already locked resets the cooldown back to the full 300s.
   * @default true
   */
  antiTamperPenalty?: boolean;

  /**
   * Custom storage engine. Defaults to High-Performance in-memory store.
   */
  store?: IRateLimitStore;

  /**
   * Key prefix for namespacing in shared stores (e.g. Redis).
   * @default 'detox:ratelimit:'
   */
  prefix?: string;

  /**
   * Custom identifier extractor from request or payload.
   */
  keyGenerator?: (reqOrId: any) => string;

  /**
   * Security audit event hook when a lockout is triggered.
   */
  onLockout?: (event: SecurityAuditEvent) => void | Promise<void>;

  /**
   * Security audit event hook when anti-tamper cooldown reset is triggered.
   */
  onAntiTamper?: (event: SecurityAuditEvent) => void | Promise<void>;
}

export interface SecurityAuditEvent {
  action: 'RATE_LIMIT_LOCKOUT_TRIGGERED' | 'ANTI_TAMPER_PENALTY_TRIGGERED' | 'RATE_LIMIT_RESET';
  identifier: string;
  lockedUntil: number;
  uniqueKey: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

export interface ClientLockoutState {
  identifier: string;
  isLocked: boolean;
  lockedUntil: number;
  uniqueKey: string;
  remainingSeconds: number;
  updatedAt: number;
}
