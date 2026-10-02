import test from 'node:test';
import assert from 'node:assert/strict';

import {
  DetoxRateLimiter,
  MemoryStore,
  generateBinarySecurityToken,
  isValidBinarySecurityToken,
  hashCredentials,
  detoxExpress,
  createNextDetox,
  DetoxClientShield,
} from '../dist/index.mjs';

test('Binary Security Token Generator', () => {
  const token = generateBinarySecurityToken();
  assert.ok(typeof token === 'string', 'Token must be a string');
  assert.ok(isValidBinarySecurityToken(token), `Token ${token} should match valid SEC-BIN format`);
  assert.match(token, /^SEC-BIN-[01]{32}-[0-9A-Z]+$/);

  // Entropy check: two consecutive tokens must differ
  const token2 = generateBinarySecurityToken();
  assert.notEqual(token, token2);
});

test('Deterministic Credential Hasher (Layer 1 0-Cache)', () => {
  const hash1 = hashCredentials('User@Example.COM', 'Password123!');
  const hash2 = hashCredentials('user@example.com', 'Password123!');
  const hash3 = hashCredentials('user@example.com', 'DifferentPassword');

  assert.match(hash1, /^cred_0_\d+$/, 'Hash must follow cred_0_<number> pattern');
  assert.equal(hash1, hash2, 'Email normalization should yield identical hashes');
  assert.notEqual(hash1, hash3, 'Different passwords must yield different hashes');
});

test('DetoxRateLimiter: 5-Attempt Threshold & Lockout State', async () => {
  const limiter = new DetoxRateLimiter({
    maxAttempts: 5,
    lockoutDurationMs: 300_000, // 5 min
    prefix: 'test:auth:',
  });

  const email = 'victim@detox.org';

  // Initial check
  const initCheck = await limiter.check(email);
  assert.equal(initCheck.isLocked, false);
  assert.equal(initCheck.remainingAttempts, 5);

  // 1st failed attempt
  const r1 = await limiter.recordFailure(email);
  assert.equal(r1.isLocked, false);
  assert.equal(r1.remainingAttempts, 4);

  // 2nd, 3rd, 4th attempts
  await limiter.recordFailure(email);
  await limiter.recordFailure(email);
  const r4 = await limiter.recordFailure(email);
  assert.equal(r4.isLocked, false);
  assert.equal(r4.remainingAttempts, 1);

  // 5th failed attempt: Lockout must trigger
  const r5 = await limiter.recordFailure(email);
  assert.equal(r5.isLocked, true);
  assert.equal(r5.remainingAttempts, 0);
  assert.equal(r5.remainingSeconds, 300);
  assert.ok(isValidBinarySecurityToken(r5.uniqueKey));
  assert.equal(r5.antiTamperTriggered, false);

  // Pre-flight check should now report locked
  const preCheck = await limiter.check(email);
  assert.equal(preCheck.isLocked, true);
  assert.equal(preCheck.uniqueKey, r5.uniqueKey);
  assert.equal(preCheck.remainingAttempts, 0);

  // HTTP Headers check
  const headers = limiter.getHeaders(r5);
  assert.equal(headers['X-RateLimit-Limit'], '5');
  assert.equal(headers['X-RateLimit-Remaining'], '0');
  assert.equal(headers['Retry-After'], '300');
  assert.equal(headers['X-DETOX-Security-Token'], r5.uniqueKey);

  // Anti-Tamper Test: Probe while locked
  const tamperResult = await limiter.recordFailure(email);
  assert.equal(tamperResult.isLocked, true);
  assert.equal(tamperResult.antiTamperTriggered, true);
  assert.equal(tamperResult.remainingSeconds, 300, 'Cooldown must reset back to full 300s');
  assert.notEqual(tamperResult.uniqueKey, r5.uniqueKey, 'Must generate fresh binary security token on tamper violation');

  const tamperHeaders = limiter.getHeaders(tamperResult);
  assert.equal(tamperHeaders['X-DETOX-Anti-Tamper'], 'penalty-extended');

  // Successful authentication cleanses state
  await limiter.recordSuccess(email);
  const postReset = await limiter.check(email);
  assert.equal(postReset.isLocked, false);
  assert.equal(postReset.remainingAttempts, 5);

  await limiter.close();
});

test('DetoxClientShield (Browser 0-Cache Simulation)', () => {
  // Mock localStorage in Node.js
  const mockStorage = new Map();
  globalThis.window = {
    localStorage: {
      getItem: (key) => mockStorage.get(key) || null,
      setItem: (key, val) => mockStorage.set(key, String(val)),
      removeItem: (key) => mockStorage.delete(key),
    },
  };

  const client = new DetoxClientShield();
  const email = 'user@detox.org';
  const badPass = 'WrongPass123';

  // 1. Initial 0-cache check: miss
  const initialCheck = client.checkLocal0Cache(email, badPass);
  assert.equal(initialCheck.isCached, false);

  // 2. Store failed credential pair as 0
  client.storeFailedCred0(email, badPass);

  // 3. Second 0-cache check: immediate hit in 0ms!
  const secondCheck = client.checkLocal0Cache(email, badPass);
  assert.equal(secondCheck.isCached, true);
  assert.ok(secondCheck.message.includes('0-Cache Verified'));

  // 4. Save lockout state
  const lockedUntil = Date.now() + 300_000;
  client.saveLocalLockoutState(email, {
    isLocked: true,
    lockedUntil,
    uniqueKey: 'SEC-BIN-01010101-TEST',
  });

  const lockoutState = client.getLocalLockoutState(email);
  assert.ok(lockoutState !== null);
  assert.equal(lockoutState.isLocked, true);
  assert.equal(lockoutState.uniqueKey, 'SEC-BIN-01010101-TEST');
  assert.ok(lockoutState.remainingSeconds > 290);

  // 5. Successful login clears cache
  client.clear0Cache();
  const finalCheck = client.checkLocal0Cache(email, badPass);
  assert.equal(finalCheck.isCached, false);
  assert.equal(client.getLocalLockoutState(email), null);

  // Clean mock
  delete globalThis.window;
});

test('Next.js Helper (createNextDetox)', async () => {
  const detox = createNextDetox({ maxAttempts: 3, lockoutDurationMs: 60_000 });
  const email = 'nextjs-user@detox.org';

  // Record 3 failures to trigger lockout
  await detox.recordFailure(email);
  await detox.recordFailure(email);
  const lockedResult = await detox.recordFailure(email);

  assert.equal(lockedResult.isLocked, true);

  // Generate Response object
  const response = detox.json(lockedResult);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('Retry-After'), '60');
  assert.equal(response.headers.get('X-RateLimit-Limit'), '3');
  assert.equal(response.headers.get('X-RateLimit-Remaining'), '0');
  assert.equal(response.headers.get('X-DETOX-Security-Token'), lockedResult.uniqueKey);

  const body = await response.json();
  assert.equal(body.isLocked, true);
  assert.equal(body.uniqueKey, lockedResult.uniqueKey);

  await detox.reset(email);
});
