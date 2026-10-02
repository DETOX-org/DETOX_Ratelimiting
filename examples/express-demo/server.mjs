/**
 * DETOX Express.js Plug-and-Play Example
 * Run: node examples/express-demo/server.mjs
 */

import express from 'express';
import { detoxExpress, DetoxRateLimiter } from '../../dist/index.mjs';

const app = express();
app.use(express.json());

// Initialize Rate Limiter with 5 attempts & 5-minute lockout (or 30s for demo)
const limiter = new DetoxRateLimiter({
  maxAttempts: 5,
  lockoutDurationMs: 30_000, // 30 seconds for quick local testing
  antiTamperPenalty: true, // Probing while locked adds another 30 seconds!
  onLockout: (event) => {
    console.log(`\n🚨 [SECURITY AUDIT] LOCKOUT TRIGGERED for: ${event.identifier}`);
    console.log(`   Binary Token : ${event.uniqueKey}`);
    console.log(`   Locked Until : ${new Date(event.lockedUntil).toLocaleTimeString()}`);
  },
  onAntiTamper: (event) => {
    console.log(`\n⚠️  [SECURITY AUDIT] ANTI-TAMPER PROBE PENALTY APPLIED to: ${event.identifier}`);
    console.log(`   New Binary Token : ${event.uniqueKey}`);
    console.log(`   Extended Until   : ${new Date(event.lockedUntil).toLocaleTimeString()}`);
  },
});

// Middleware applied to authentication route
app.post('/api/auth/login', detoxExpress({ maxAttempts: 5, lockoutDurationMs: 30_000 }), async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  // Demo Mock Credentials: user@detox.org / supersecret123
  const isValid = email === 'user@detox.org' && password === 'supersecret123';

  if (!isValid) {
    // Record failed attempt in DETOX Engine
    const status = await req.detox.recordFailedAttempt({ ip: req.ip });

    if (status.isLocked) {
      return res.status(429).json({
        success: false,
        isLocked: true,
        remainingSeconds: status.remainingSeconds,
        uniqueKey: status.uniqueKey,
        antiTamper: status.antiTamperTriggered,
        error: `Security Lockout Triggered: 5 failed attempts reached. Cooldown initiated for ${status.remainingSeconds}s.`,
      });
    }

    return res.status(401).json({
      success: false,
      isLocked: false,
      remainingAttempts: status.remainingAttempts,
      error: `Invalid credentials. ${status.remainingAttempts} attempts remaining before security lockout.`,
    });
  }

  // Valid credentials: Purge all failed attempt history
  await req.detox.resetRateLimit();

  return res.json({
    success: true,
    message: 'Welcome to the DETOX Protected Workspace!',
    user: { email },
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛡️  DETOX Rate Limiting Express Server running at http://localhost:${PORT}`);
  console.log(`👉 Test endpoint: POST /api/auth/login`);
  console.log(`   Valid login: email="user@detox.org", password="supersecret123"\n`);
});
