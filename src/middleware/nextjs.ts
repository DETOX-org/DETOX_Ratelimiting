import { DetoxRateLimiter } from '../core/engine.js';
import { DetoxRateLimiterOptions, RateLimitResult } from '../core/types.js';

export interface NextDetoxHelper {
  limiter: DetoxRateLimiter;
  check: (identifier: string) => Promise<RateLimitResult>;
  recordFailure: (identifier: string, metadata?: Record<string, any>) => Promise<RateLimitResult>;
  reset: (identifier: string) => Promise<void>;
  /**
   * Helper that produces a standard Next.js Response object with headers and JSON body
   */
  json: (
    result: RateLimitResult,
    options?: { status?: number; customBody?: Record<string, any> }
  ) => Response;
}

/**
 * Creates a Next.js helper for App Router and API Routes
 * 
 * Usage:
 * ```ts
 * // app/api/auth/login/route.ts
 * import { createNextDetox } from 'detox-ratelimit/next';
 * 
 * const detox = createNextDetox();
 * 
 * export async function POST(req: Request) {
 *   const { email, password } = await req.json();
 * 
 *   const check = await detox.check(email);
 *   if (check.isLocked) {
 *     return detox.json(check);
 *   }
 * 
 *   const user = await authenticate(email, password);
 *   if (!user) {
 *     const fail = await detox.recordFailure(email);
 *     return detox.json(fail, { status: fail.isLocked ? 429 : 401 });
 *   }
 * 
 *   await detox.reset(email);
 *   return Response.json({ success: true });
 * }
 * ```
 */
export function createNextDetox(options: DetoxRateLimiterOptions = {}): NextDetoxHelper {
  const limiter = new DetoxRateLimiter(options);

  return {
    limiter,
    check: (id: string) => limiter.check(id),
    recordFailure: (id: string, meta?: Record<string, any>) => limiter.recordFailure(id, meta),
    reset: (id: string) => limiter.reset(id),
    json: (result: RateLimitResult, opts: { status?: number; customBody?: Record<string, any> } = {}) => {
      const headers = new Headers();
      const rawHeaders = limiter.getHeaders(result);
      for (const [key, value] of Object.entries(rawHeaders)) {
        headers.set(key, value);
      }
      headers.set('Content-Type', 'application/json');

      const status = opts.status ?? (result.isLocked ? 429 : 200);

      const body = opts.customBody ?? {
        success: !result.isLocked,
        isLocked: result.isLocked,
        remainingAttempts: result.remainingAttempts,
        remainingSeconds: result.remainingSeconds,
        lockedUntil: result.lockedUntil,
        uniqueKey: result.uniqueKey,
        antiTamperTriggered: result.antiTamperTriggered,
        error: result.isLocked
          ? `Security Lockout Triggered: 5 failed attempts reached. Cooldown initiated for ${result.remainingSeconds} seconds.`
          : undefined,
      };

      return new Response(JSON.stringify(body), {
        status,
        headers,
      });
    },
  };
}
