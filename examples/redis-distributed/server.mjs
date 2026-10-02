/**
 * DETOX Redis Distributed Store Example
 * 
 * For production-scale deployments across multiple server nodes.
 * Uses atomic Lua scripts for zero race conditions.
 */

import Redis from 'ioredis';
import { DetoxRateLimiter, RedisStore } from 'detox-ratelimit';

// Connect to Redis
const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: Number(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  maxRetriesPerRequest: 3,
  retryDelayOnFailover: 100,
});

// Create RedisStore-backed limiter
const limiter = new DetoxRateLimiter({
  maxAttempts: 5,
  lockoutDurationMs: 300_000, // 5 minutes
  antiTamperPenalty: true,
  prefix: 'detox:ratelimit:',
  store: new RedisStore({ client: redis }),
  onLockout: (event) => {
    console.log(`[REDIS AUDIT] Lockout: ${event.identifier} | Token: ${event.uniqueKey}`);
  },
  onAntiTamper: (event) => {
    console.log(`[REDIS AUDIT] Anti-Tamper: ${event.identifier} | Token: ${event.uniqueKey}`);
  },
});

// Usage in your authentication flow
async function loginHandler(email, password) {
  // Pre-flight check
  const check = await limiter.check(email);
  if (check.isLocked) {
    return {
      status: 429,
      body: { error: 'Account locked', remainingSeconds: check.remainingSeconds, uniqueKey: check.uniqueKey },
    };
  }

  // Verify against database
  const isValid = email === 'user@detox.org' && password === 'supersecret123';

  if (!isValid) {
    const result = await limiter.recordFailure(email);
    return {
      status: result.isLocked ? 429 : 401,
      body: result,
    };
  }

  await limiter.recordSuccess(email);
  return { status: 200, body: { success: true } };
}

// Demo
(async () => {
  console.log('--- DETOX Redis Rate Limiter Demo ---\n');
  
  for (let i = 1; i <= 6; i++) {
    const result = await loginHandler('attacker@evil.com', 'wrong-password');
    console.log(`Attempt ${i}:`, JSON.stringify(result.body, null, 2));
  }

  // Anti-tamper probe
  console.log('\n--- Anti-Tamper Probe (while locked) ---');
  const tamper = await loginHandler('attacker@evil.com', 'still-wrong');
  console.log('Tamper result:', JSON.stringify(tamper.body, null, 2));

  await limiter.close();
  process.exit(0);
})();
