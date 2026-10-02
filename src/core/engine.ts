import { DetoxRateLimiterOptions, IRateLimitStore, RateLimitResult } from './types.js';
import { MemoryStore } from '../stores/memory.js';
import { generateBinarySecurityToken } from './token.js';

/**
 * DETOX Rate Limiter & Anti-Tamper Cooldown Engine
 * Orchestrates threshold tracking, tamper-proof cooldowns, and cryptographic session tokens.
 */
export class DetoxRateLimiter {
  private readonly store: IRateLimitStore;
  private readonly maxAttempts: number;
  private readonly lockoutDurationMs: number;
  private readonly antiTamperPenalty: boolean;
  private readonly prefix: string;
  private readonly onLockout?: DetoxRateLimiterOptions['onLockout'];
  private readonly onAntiTamper?: DetoxRateLimiterOptions['onAntiTamper'];

  constructor(options: DetoxRateLimiterOptions = {}) {
    this.maxAttempts = options.maxAttempts ?? 5;
    this.lockoutDurationMs = options.lockoutDurationMs ?? 300_000; // 5 minutes (300s)
    this.antiTamperPenalty = options.antiTamperPenalty ?? true;
    this.prefix = options.prefix ?? 'detox:ratelimit:';
    this.store = options.store ?? new MemoryStore({ defaultTtlMs: options.windowDurationMs });
    this.onLockout = options.onLockout;
    this.onAntiTamper = options.onAntiTamper;
  }

  /**
   * Pre-flight inspection: Checks if an identifier is actively locked
   * Call this BEFORE evaluating passwords or querying databases!
   */
  async check(identifier: string): Promise<RateLimitResult> {
    const key = `${this.prefix}${identifier.trim().toLowerCase()}`;
    const now = Date.now();
    const record = await this.store.check(key, now);

    if (record && record.isLocked && now < record.lockedUntil) {
      const remainingSeconds = Math.ceil((record.lockedUntil - now) / 1000);
      return {
        isLocked: true,
        remainingAttempts: 0,
        remainingSeconds,
        lockedUntil: record.lockedUntil,
        uniqueKey: record.uniqueKey,
        antiTamperTriggered: false,
        retryAfter: remainingSeconds,
        limit: this.maxAttempts,
      };
    }

    const currentCount = record ? record.count : 0;
    return {
      isLocked: false,
      remainingAttempts: Math.max(0, this.maxAttempts - currentCount),
      remainingSeconds: 0,
      lockedUntil: 0,
      uniqueKey: '',
      antiTamperTriggered: false,
      retryAfter: 0,
      limit: this.maxAttempts,
    };
  }

  /**
   * Records a failed attempt for an identity or IP address.
   * If 5 attempts are exceeded, initiates a 5-minute lockout.
   * If already locked, enforces punitive anti-tamper penalty extension.
   */
  async recordFailure(identifier: string, metadata?: Record<string, any>): Promise<RateLimitResult> {
    const key = `${this.prefix}${identifier.trim().toLowerCase()}`;
    const now = Date.now();
    const token = generateBinarySecurityToken();

    const result = await this.store.recordFailure(
      key,
      this.maxAttempts,
      this.lockoutDurationMs,
      now,
      token,
      this.antiTamperPenalty
    );

    // Trigger security audit callbacks
    if (result.isLocked) {
      if (result.antiTamperTriggered && this.onAntiTamper) {
        try {
          await this.onAntiTamper({
            action: 'ANTI_TAMPER_PENALTY_TRIGGERED',
            identifier,
            lockedUntil: result.lockedUntil,
            uniqueKey: result.uniqueKey,
            timestamp: now,
            metadata,
          });
        } catch (err) {
          console.error('[DETOX Audit] Error in onAntiTamper callback:', err);
        }
      } else if (!result.antiTamperTriggered && this.onLockout) {
        try {
          await this.onLockout({
            action: 'RATE_LIMIT_LOCKOUT_TRIGGERED',
            identifier,
            lockedUntil: result.lockedUntil,
            uniqueKey: result.uniqueKey,
            timestamp: now,
            metadata,
          });
        } catch (err) {
          console.error('[DETOX Audit] Error in onLockout callback:', err);
        }
      }
    }

    return result;
  }

  /**
   * Resets all rate-limiting and lockout records for an identity.
   * Call upon successful user authentication.
   */
  async recordSuccess(identifier: string): Promise<void> {
    return this.reset(identifier);
  }

  /**
   * Clears rate limit state for the given identifier.
   */
  async reset(identifier: string): Promise<void> {
    const key = `${this.prefix}${identifier.trim().toLowerCase()}`;
    await this.store.reset(key);
  }

  /**
   * Produces standard HTTP response headers for rate-limited requests.
   */
  getHeaders(result: RateLimitResult): Record<string, string> {
    const headers: Record<string, string> = {
      'X-RateLimit-Limit': String(result.limit),
      'X-RateLimit-Remaining': String(result.remainingAttempts),
    };

    if (result.isLocked) {
      headers['Retry-After'] = String(result.retryAfter);
      headers['X-RateLimit-Reset'] = String(Math.ceil(result.lockedUntil / 1000));
      headers['X-DETOX-Security-Token'] = result.uniqueKey;
      if (result.antiTamperTriggered) {
        headers['X-DETOX-Anti-Tamper'] = 'penalty-extended';
      }
    }

    return headers;
  }

  /**
   * Closes internal store resources
   */
  async close(): Promise<void> {
    if (typeof this.store.close === 'function') {
      await this.store.close();
    }
  }
}
