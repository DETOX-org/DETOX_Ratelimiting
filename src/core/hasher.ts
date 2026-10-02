/**
 * Deterministic Credential Hasher for Layer 1 0-Cache Interception
 * Generates uniform local cache keys: cred_0_<hash>
 */

/**
 * Normalizes email address (lowercase and trimmed).
 */
export function normalizeEmail(email: string): string {
  return (email || '').trim().toLowerCase();
}

/**
 * Fast, deterministic 32-bit hash algorithm (FNV-1a variant)
 * Cross-platform compatible: executes in Browser, Node.js, Cloudflare Workers, Deno, Bun.
 * Produces an unsigned 32-bit integer string.
 */
export function hashString32(input: string): string {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    // Multiply by 32-bit FNV prime 16777619 with 32-bit integer wrap
    hash = Math.imul(hash, 16777619);
  }
  // Convert to unsigned 32-bit integer
  return (hash >>> 0).toString(10);
}

/**
 * Hashes a credential pair (normalized email + password) into a 0-cache key: cred_0_<hash>
 * 
 * @param email - User's email or identity identifier
 * @param password - Plaintext password attempt
 * @returns Discrete 0-cache key string, e.g. "cred_0_1894205128"
 */
export function hashCredentials(email: string, password: string): string {
  const normalized = `${normalizeEmail(email)}:auth_salt_0:${password}`;
  const digest = hashString32(normalized);
  return `cred_0_${digest}`;
}
