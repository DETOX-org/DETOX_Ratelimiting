import { IRateLimitStore, RateLimitRecord, RateLimitResult } from '../core/types.js';

/**
 * Atomic Redis Lua script for distributed lockout & anti-tamper enforcement
 * Direct implementation from DETOX System Design Section 7.1
 */
const ATOMIC_RECORD_FAILURE_LUA = `
local key = KEYS[1]
local max_attempts = tonumber(ARGV[1])
local lockout_ms = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local security_token = ARGV[4]
local anti_tamper_flag = tonumber(ARGV[5]) or 1

local record = redis.call("HMGET", key, "count", "isLocked", "lockedUntil", "uniqueKey")
local count = tonumber(record[1]) or 0
local isLocked = record[2] == "true"
local lockedUntil = tonumber(record[3]) or 0
local uniqueKey = record[4] or ""

-- Case 1: Account is actively locked
if isLocked then
    if now < lockedUntil then
        if anti_tamper_flag == 1 then
            -- Anti-tamper violation: Probed while locked. Extend penalty by lockout_ms!
            local newLockedUntil = now + lockout_ms
            redis.call("HMSET", key, "lockedUntil", newLockedUntil, "uniqueKey", security_token)
            redis.call("PEXPIREAT", key, newLockedUntil + 60000)
            local remainingSec = math.ceil((newLockedUntil - now) / 1000)
            return { 1, remainingSec, security_token, 1, newLockedUntil }
        else
            local remainingSec = math.ceil((lockedUntil - now) / 1000)
            return { 1, remainingSec, uniqueKey, 0, lockedUntil }
        end
    else
        -- Cooldown naturally expired
        count = 0
        isLocked = false
        lockedUntil = 0
        uniqueKey = ""
    end
end

-- Case 2: Increment failure counter
count = count + 1

if count >= max_attempts then
    -- Lockout triggered
    local newLockedUntil = now + lockout_ms
    redis.call("HMSET", key, "count", count, "isLocked", "true", "lockedUntil", newLockedUntil, "uniqueKey", security_token)
    redis.call("PEXPIREAT", key, newLockedUntil + 60000)
    local remainingSec = math.ceil(lockout_ms / 1000)
    return { 1, remainingSec, security_token, 0, newLockedUntil }
else
    -- Still within allowed attempts
    redis.call("HMSET", key, "count", count, "isLocked", "false", "lockedUntil", 0)
    redis.call("PEXPIRE", key, 900000) -- Retain attempt state for 15 minutes
    return { 0, max_attempts - count, "", 0, 0 }
end
`;

export interface RedisClientLike {
  eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<any>;
  hmget(key: string, ...fields: string[]): Promise<(string | null)[]>;
  del(key: string): Promise<number>;
  quit?(): Promise<string>;
}

export interface RedisStoreOptions {
  /** Existing ioredis client instance */
  client: RedisClientLike;
}

/**
 * Distributed Redis Store executing atomic Lua script transactions
 * Guarantees zero race conditions across multi-node / multi-region clusters.
 */
export class RedisStore implements IRateLimitStore {
  private client: RedisClientLike;

  constructor(options: RedisStoreOptions) {
    if (!options?.client) {
      throw new Error('[DETOX] RedisStore requires an active redis client instance (e.g. ioredis)');
    }
    this.client = options.client;
  }

  async check(key: string, now: number): Promise<RateLimitRecord | null> {
    const record = await this.client.hmget(key, 'count', 'isLocked', 'lockedUntil', 'uniqueKey');
    if (!record || record.every((f) => f === null)) {
      return null;
    }

    const count = parseInt(record[0] || '0', 10);
    const isLocked = record[1] === 'true';
    const lockedUntil = parseInt(record[2] || '0', 10);
    const uniqueKey = record[3] || '';

    // If locked but timer expired, return null
    if (isLocked && now >= lockedUntil) {
      return null;
    }

    return {
      count,
      isLocked,
      lockedUntil,
      uniqueKey,
      updatedAt: now,
    };
  }

  async recordFailure(
    key: string,
    maxAttempts: number,
    lockoutDurationMs: number,
    now: number,
    token: string,
    antiTamperPenalty: boolean
  ): Promise<RateLimitResult> {
    const rawResult = await this.client.eval(
      ATOMIC_RECORD_FAILURE_LUA,
      1,
      key,
      maxAttempts,
      lockoutDurationMs,
      now,
      token,
      antiTamperPenalty ? 1 : 0
    );

    // rawResult: [ isLockedNum, remainingAttemptsOrSec, token, antiTamperNum, lockedUntilEpoch ]
    const isLocked = Number(rawResult[0]) === 1;
    const secondParam = Number(rawResult[1]);
    const uniqueKey = String(rawResult[2] || '');
    const antiTamperTriggered = Number(rawResult[3]) === 1;
    const lockedUntil = Number(rawResult[4] || 0);

    return {
      isLocked,
      remainingAttempts: isLocked ? 0 : secondParam,
      remainingSeconds: isLocked ? secondParam : 0,
      lockedUntil,
      uniqueKey,
      antiTamperTriggered,
      retryAfter: isLocked ? secondParam : 0,
      limit: maxAttempts,
    };
  }

  async reset(key: string): Promise<void> {
    await this.client.del(key);
  }

  async close(): Promise<void> {
    if (typeof this.client.quit === 'function') {
      await this.client.quit();
    }
  }
}
