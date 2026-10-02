/**
 * DETOX Next.js App Router Example
 * 
 * File: app/api/auth/login/route.ts
 * 
 * This shows a complete Next.js 14+ App Router integration
 * with DETOX Rate Limiting & Anti-Tamper security.
 */

import { createNextDetox } from 'detox-ratelimit/next';

// Initialize the DETOX engine (module-level singleton)
const detox = createNextDetox({
  maxAttempts: 5,
  lockoutDurationMs: 300_000, // 5 minutes
  antiTamperPenalty: true,
  onLockout: (event) => {
    console.log(`[DETOX AUDIT] Lockout triggered for ${event.identifier} — Token: ${event.uniqueKey}`);
  },
  onAntiTamper: (event) => {
    console.log(`[DETOX AUDIT] Anti-tamper penalty for ${event.identifier} — Token: ${event.uniqueKey}`);
  },
});

export async function POST(req: Request) {
  const { email, password } = await req.json();

  if (!email || !password) {
    return Response.json({ error: 'Email and password required' }, { status: 400 });
  }

  // Step 1: Pre-flight lockout check (BEFORE touching your database!)
  const check = await detox.check(email);
  if (check.isLocked) {
    // Already locked — triggers anti-tamper penalty automatically on recordFailure
    const tamper = await detox.recordFailure(email, { source: 'nextjs-api' });
    return detox.json(tamper);
  }

  // Step 2: Verify credentials against your database
  const user = await authenticateUser(email, password);

  if (!user) {
    // Invalid credentials — record the failed attempt
    const result = await detox.recordFailure(email, { source: 'nextjs-api' });
    return detox.json(result, { status: result.isLocked ? 429 : 401 });
  }

  // Step 3: Valid login — purge all rate-limit state
  await detox.reset(email);

  return Response.json({
    success: true,
    message: 'Welcome to the DETOX Protected Workspace!',
    user: { email: user.email, name: user.name },
  });
}

// --- Demo Mock Database ---
async function authenticateUser(email: string, password: string) {
  // Replace with your real database lookup
  if (email === 'user@detox.org' && password === 'supersecret123') {
    return { email, name: 'DETOX Member' };
  }
  return null;
}
