<div align="center">

# 🛡️ DETOX Rate Limiting

### Production-Grade Anti-Tamper Rate Limiting Framework

**Stop brute-force attacks. Prevent denial-of-wallet billing. Ship tamper-proof authentication.**

[![npm version](https://img.shields.io/npm/v/detox-ratelimit?color=%23cc3534&style=for-the-badge)](https://www.npmjs.com/package/detox-ratelimit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-5%2F5_Passing-brightgreen?style=for-the-badge)](#-run-tests)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-success?style=for-the-badge)](#)

<br />

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  🔒  5 failed attempts?  →  Account locked for 5 minutes.          │
 │  🔄  Tried to bypass the lockout?  →  Timer resets to full 5 min.  │
 │  ⚡  Same bad password twice?  →  Blocked in 0ms. Zero server IO.  │
 │  🔑  Every lockout gets a unique cryptographic security token.      │
 └──────────────────────────────────────────────────────────────────────┘
```

</div>

---

## 🎯 Why DETOX?

Most rate limiters count requests and return `429`. **DETOX does much more:**

| Feature | Other Rate Limiters | DETOX |
|:---|:---:|:---:|
| Basic request counting | ✅ | ✅ |
| Client-side 0-Cache (blocks repeat bad passwords in 0ms) | ❌ | ✅ |
| Anti-Tamper penalty (reset timer if user probes while locked) | ❌ | ✅ |
| Cryptographic binary security tokens per lockout | ❌ | ✅ |
| Tamper-proof server-side countdown (immune to clock/devtools tricks) | ❌ | ✅ |
| Built-in security audit event hooks | ❌ | ✅ |
| Express, Next.js, and vanilla JS support out of the box | Partial | ✅ |
| In-memory AND distributed Redis (atomic Lua scripts) | Partial | ✅ |
| Zero runtime dependencies | ❌ | ✅ |

---

## 📦 Install

```bash
npm install detox-ratelimit
```

> **Redis users**: Also install `ioredis` as a peer dependency:
> ```bash
> npm install detox-ratelimit ioredis
> ```

---

## 🚀 Quick Start

### Express.js — 3 Lines to Protect Your Login

```typescript
import express from 'express';
import { detoxExpress } from 'detox-ratelimit/express';

const app = express();
app.use(express.json());

// 🛡️ Protect your login endpoint
app.post('/api/auth/login', detoxExpress(), async (req, res) => {
  const { email, password } = req.body;
  const user = await verifyCredentials(email, password); // Your auth logic

  if (!user) {
    // Record the failed attempt — DETOX handles lockout automatically
    const status = await req.detox.recordFailedAttempt();

    if (status.isLocked) {
      return res.status(429).json({
        error: 'Account locked',
        remainingSeconds: status.remainingSeconds,
        uniqueKey: status.uniqueKey,         // SEC-BIN-01101001...-M2K918A
        antiTamper: status.antiTamperTriggered,
      });
    }

    return res.status(401).json({
      error: 'Invalid credentials',
      remainingAttempts: status.remainingAttempts,
    });
  }

  // ✅ Valid login — purge all rate-limit state
  await req.detox.resetRateLimit();
  res.json({ success: true, token: generateJWT(user) });
});

app.listen(3000);
```

### Next.js App Router — Equally Simple

```typescript
// app/api/auth/login/route.ts
import { createNextDetox } from 'detox-ratelimit/next';

const detox = createNextDetox();

export async function POST(req: Request) {
  const { email, password } = await req.json();

  // Pre-flight lockout check (before touching your database!)
  const check = await detox.check(email);
  if (check.isLocked) {
    const tamper = await detox.recordFailure(email);
    return detox.json(tamper); // Returns proper 429 with all headers
  }

  const user = await authenticate(email, password);
  if (!user) {
    const fail = await detox.recordFailure(email);
    return detox.json(fail, { status: fail.isLocked ? 429 : 401 });
  }

  await detox.reset(email);
  return Response.json({ success: true });
}
```

### Browser — 0-Cache Shield (Blocks Repeat Bad Passwords Instantly)

```javascript
import { DetoxClientShield } from 'detox-ratelimit/client';

const shield = new DetoxClientShield();

async function handleLogin(email, password) {
  // ⚡ Check 0-cache FIRST — blocks in 0ms if same bad password was tried before
  const cache = shield.checkLocal0Cache(email, password);
  if (cache.isCached) {
    showError(cache.message); // "Login credentials not valid (0-Cache Verified)"
    return; // Zero network traffic!
  }

  // Check local lockout state
  const lockout = shield.getLocalLockoutState(email);
  if (lockout) {
    showLockoutBanner(lockout.remainingSeconds, lockout.uniqueKey);
    return;
  }

  // Send to server
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  const data = await res.json();

  if (data.success) {
    shield.clear0Cache();          // Purge all security state
    window.location.href = '/dashboard';
  } else if (data.isLocked) {
    shield.saveLocalLockoutState(email, data); // Sync server state locally
    showLockoutBanner(data.remainingSeconds, data.uniqueKey);
  } else {
    shield.storeFailedCred0(email, password);  // Cache this bad pair as "0"
    showError(`Invalid. ${data.remainingAttempts} attempts left.`);
  }
}
```

---

## 🏗️ Architecture — The 5-Layer Defense Matrix

```
+────────────────────────────────────────────────────────────────────+
│                  DETOX MULTI-LAYER DEFENSE MATRIX                  │
+────────────────────────────────────────────────────────────────────+
                                │
     [ Layer 1: Client 0-Cache Shield (Browser localStorage) ]
     - Hashes credential pairs → cred_0_<hash>
     - Intercepts repeated failed attempts in 0ms (ZERO server IO)
                                │ (Cache Miss)
                                ▼
     [ Layer 2: Edge / CDN & Network Gatekeeper ]
     - IP reputation & geo-fencing
     - Volumetric DDoS throttling
                                │
                                ▼
     [ Layer 3: Application Middleware Layer ]
     - Trusted IP resolution (X-Forwarded-For sanitization)
     - Request fingerprinting
                                │
                                ▼
     [ Layer 4: DETOX Rate Limiting Engine ]
     - Sliding window atomic attempt tracking
     - 5-attempt threshold → Binary Security Token issuance
     - Anti-tamper penalty: probing resets to full 300s
                                │
                                ▼
     [ Layer 5: Persistent Store & Audit Log ]
     - Atomic DB persistence of lockedUntil timestamps
     - Immutable audit logging (SEC-BIN-... tokens)
     - In-memory OR distributed Redis (Lua scripts)
```

---

## 🔧 Configuration

```typescript
import { DetoxRateLimiter } from 'detox-ratelimit';

const limiter = new DetoxRateLimiter({
  // Maximum failed attempts before lockout (default: 5)
  maxAttempts: 5,

  // Lockout duration in milliseconds (default: 300000 = 5 minutes)
  lockoutDurationMs: 300_000,

  // How long to retain failed attempt counters (default: 15 minutes)
  windowDurationMs: 900_000,

  // Reset timer when user probes while locked (default: true)
  antiTamperPenalty: true,

  // Key prefix for namespacing (useful for Redis)
  prefix: 'detox:ratelimit:',

  // Security audit hooks
  onLockout: (event) => {
    console.log('LOCKOUT:', event.identifier, event.uniqueKey);
    // Send to Datadog, Sentry, PagerDuty, Slack, etc.
  },
  onAntiTamper: (event) => {
    console.log('ANTI-TAMPER:', event.identifier, event.uniqueKey);
  },
});
```

---

## 🗄️ Storage Backends

### In-Memory (Default — Zero Dependencies)

```typescript
import { DetoxRateLimiter, MemoryStore } from 'detox-ratelimit';

const limiter = new DetoxRateLimiter({
  store: new MemoryStore({
    cleanupIntervalMs: 60_000,  // Garbage collect every 60s
    defaultTtlMs: 900_000,      // Expire idle records after 15 min
  }),
});
```

### Redis (Distributed — Atomic Lua Scripts)

```typescript
import Redis from 'ioredis';
import { DetoxRateLimiter, RedisStore } from 'detox-ratelimit';

const redis = new Redis({ host: '127.0.0.1', port: 6379 });

const limiter = new DetoxRateLimiter({
  store: new RedisStore({ client: redis }),
  prefix: 'myapp:auth:',
});
```

> The Redis store uses an **atomic Lua script** that executes the entire check-increment-lockout-penalty flow in a single `EVAL` call. Zero race conditions under any concurrency level.

### Custom Store

Implement the `IRateLimitStore` interface to plug in **any** backend (DynamoDB, PostgreSQL, Firestore, etc.):

```typescript
import { IRateLimitStore, RateLimitRecord, RateLimitResult } from 'detox-ratelimit';

class MyCustomStore implements IRateLimitStore {
  async check(key: string, now: number): Promise<RateLimitRecord | null> { /* ... */ }
  async recordFailure(key, max, duration, now, token, penalty): Promise<RateLimitResult> { /* ... */ }
  async reset(key: string): Promise<void> { /* ... */ }
}
```

---

## 📡 HTTP Response Format

### 401 — Failed Attempt (Still Under Threshold)

```http
HTTP/1.1 401 Unauthorized
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 2

{ "success": false, "remainingAttempts": 2, "error": "Invalid credentials" }
```

### 429 — Lockout Triggered

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 300
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1774982400
X-DETOX-Security-Token: SEC-BIN-11010010101110000010011111010100-M1X8PQ9

{
  "success": false,
  "isLocked": true,
  "remainingSeconds": 300,
  "lockedUntil": 1774982400000,
  "uniqueKey": "SEC-BIN-11010010101110000010011111010100-M1X8PQ9",
  "antiTamperTriggered": false
}
```

### 429 — Anti-Tamper Penalty Extended

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 300
X-DETOX-Anti-Tamper: penalty-extended
X-DETOX-Security-Token: SEC-BIN-01101001110010100111100010100101-M2K918A

{ "antiTamperTriggered": true, "remainingSeconds": 300 }
```

---

## 🔐 Security Token Format

Every lockout generates a unique binary security token:

```
SEC-BIN-11010010101110000010011111010100-M1X8PQ9
│       │                                │
│       │                                └── Base36 timestamp
│       └── 32-bit random binary string (4 × 8-bit octets)
└── Fixed prefix
```

```typescript
import { generateBinarySecurityToken, isValidBinarySecurityToken } from 'detox-ratelimit';

const token = generateBinarySecurityToken();
// → "SEC-BIN-11010010101110000010011111010100-M1X8PQ9"

isValidBinarySecurityToken(token); // → true
```

---

## 🧪 Run Tests

```bash
npm test
```

```
✔ Binary Security Token Generator (1.0ms)
✔ Deterministic Credential Hasher (Layer 1 0-Cache) (0.3ms)
✔ DetoxRateLimiter: 5-Attempt Threshold & Lockout State (1.7ms)
✔ DetoxClientShield (Browser 0-Cache Simulation) (0.5ms)
✔ Next.js Helper (createNextDetox) (24.1ms)

tests 5 | pass 5 | fail 0
```

---

## 📁 Project Structure

```
detox-ratelimit/
├── src/
│   ├── core/
│   │   ├── engine.ts       # DetoxRateLimiter — Main orchestrator
│   │   ├── types.ts        # TypeScript interfaces & types
│   │   ├── token.ts        # Binary Security Key generator (SEC-BIN-...)
│   │   └── hasher.ts       # FNV-1a deterministic credential hasher
│   ├── stores/
│   │   ├── memory.ts       # In-memory store (zero deps, auto-GC)
│   │   └── redis.ts        # Redis store (atomic Lua scripts)
│   ├── client/
│   │   ├── zero-cache.ts   # Browser 0-Cache Shield + lockout sync
│   │   └── index.ts        # Client exports
│   ├── middleware/
│   │   ├── express.ts      # Express/Connect middleware
│   │   └── nextjs.ts       # Next.js App Router helper
│   └── index.ts            # Main entry point
├── examples/
│   ├── express-demo/       # Complete Express.js server example
│   ├── nextjs-app-router/  # Next.js 14+ App Router example
│   ├── browser-client/     # Frontend 0-Cache integration
│   └── redis-distributed/  # Multi-node Redis deployment example
├── tests/
│   └── detox.test.mjs      # Full test suite
├── system design.md        # Complete system design document (560 lines)
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── LICENSE                  # MIT
├── CONTRIBUTING.md
└── README.md               # You are here
```

---

## 🛡️ Threat Model Coverage

| Attack Vector | How DETOX Stops It |
|:---|:---|
| **Brute-force (same IP)** | 5-attempt threshold with 5-minute lockout |
| **Distributed brute-force (rotating IPs)** | Identity-first rate limiting keyed to email, not just IP |
| **Password spraying** | Dual-dimensional: per-identity + per-IP subnet limiting |
| **Client storage erasure** | Server-side `lockedUntil` is the single source of truth |
| **Clock manipulation** | Server timestamps only; client time is never trusted |
| **Page refresh bypass** | Client rehydrates from `localStorage`, server re-validates |
| **DevTools manipulation** | Anti-tamper penalty resets timer to full 300s |
| **Denial-of-wallet** | 0-Cache blocks repeat bad passwords with zero server IO |
| **Automated scripting** | Binary security tokens trace every lockout to audit logs |

---

## 📖 Full System Design

For the complete 560-line system design document covering architecture philosophy, algorithmic comparisons (Token Bucket, Leaky Bucket, Sliding Window), data schemas, Redis Lua scripts, threat modeling, and monitoring KPIs — see:

📄 **[system design.md](./system%20design.md)**

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## 📜 License

[MIT](./LICENSE) — Use freely in personal and commercial projects.

---

<div align="center">

**Built with 🔒 by the [DETOX Engineering Collective](https://github.com/detox-engineering)**

*If this helped you, consider giving it a ⭐ on GitHub!*

</div>
