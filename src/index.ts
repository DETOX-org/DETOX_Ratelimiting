/**
 * DETOX Rate Limiting & Anti-Tamper Security Framework
 * 
 * An open-source, production-grade security framework providing:
 * - Layer 1: Client-Side 0-Cache Shield (Zero cloud DB egress)
 * - Layer 2: Tamper-proof 5-Minute Cooldown & Anti-Tamper penalty extensions
 * - Layer 3: Cryptographic Binary Security Key generation (SEC-BIN-...)
 * - Layer 4: Atomic Redis Lua scripts & in-memory sliding store
 * - Layer 5: First-class Express, Next.js, and Browser integration
 * 
 * @license MIT
 */

// Core Engine & Store
export { DetoxRateLimiter } from './core/engine.js';
export { MemoryStore } from './stores/memory.js';
export { RedisStore } from './stores/redis.js';

// Security & Hashing Utilities
export { generateBinarySecurityToken, isValidBinarySecurityToken } from './core/token.js';
export { hashCredentials, normalizeEmail, hashString32 } from './core/hasher.js';

// Client 0-Cache Shield
export { DetoxClientShield, detoxClient, createZeroCache } from './client/zero-cache.js';

// Middlewares & Framework Integrations
export { detoxExpress } from './middleware/express.js';
export { createNextDetox } from './middleware/nextjs.js';

// Type definitions
export type {
  RateLimitRecord,
  RateLimitResult,
  IRateLimitStore,
  DetoxRateLimiterOptions,
  SecurityAuditEvent,
  ClientLockoutState,
} from './core/types.js';
export type { ZeroCacheCheckResult, ZeroCacheOptions } from './client/zero-cache.js';
export type { ExpressMiddlewareOptions, ExpressRequestWithDetox } from './middleware/express.js';
export type { NextDetoxHelper } from './middleware/nextjs.js';
export type { RedisClientLike, RedisStoreOptions } from './stores/redis.js';
