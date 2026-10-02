import { DetoxRateLimiter } from '../core/engine.js';
import { DetoxRateLimiterOptions, RateLimitResult } from '../core/types.js';

export interface ExpressRequestWithDetox {
  body?: any;
  ip?: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  detox?: {
    limiter: DetoxRateLimiter;
    identifier: string;
    checkRateLimit: () => Promise<RateLimitResult>;
    recordFailedAttempt: (metadata?: Record<string, any>) => Promise<RateLimitResult>;
    resetRateLimit: () => Promise<void>;
  };
}

export interface ExpressMiddlewareOptions extends DetoxRateLimiterOptions {
  /**
   * Custom function to extract identifier (email, username, IP) from incoming request.
   */
  keyGenerator?: (req: any) => string;

  /**
   * Custom response handler when a request is blocked (HTTP 429).
   */
  handler?: (req: any, res: any, result: RateLimitResult) => void;
}

/**
 * Express / Connect Rate Limiting & Anti-Tamper Middleware
 * 
 * Usage:
 * ```ts
 * import express from 'express';
 * import { detoxExpress } from 'detox-ratelimit/express';
 * 
 * const app = express();
 * app.use(express.json());
 * 
 * app.post('/api/auth/login', detoxExpress(), async (req, res) => {
 *   const { email, password } = req.body;
 *   const user = await verifyCredentials(email, password);
 * 
 *   if (!user) {
 *     const status = await req.detox.recordFailedAttempt();
 *     return res.status(status.isLocked ? 429 : 401).json({
 *       error: 'Invalid credentials',
 *       remainingAttempts: status.remainingAttempts,
 *     });
 *   }
 * 
 *   await req.detox.resetRateLimit();
 *   return res.json({ token: 'jwt-...' });
 * });
 * ```
 */
export function detoxExpress(options: ExpressMiddlewareOptions = {}) {
  const limiter = new DetoxRateLimiter(options);

  const defaultKeyGen = (req: any): string => {
    if (req.body && typeof req.body.email === 'string') {
      return req.body.email;
    }
    if (req.body && typeof req.body.identifier === 'string') {
      return req.body.identifier;
    }
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0].trim();
    }
    return req.ip || req.socket?.remoteAddress || 'unknown-client';
  };

  const keyGen = options.keyGenerator ?? defaultKeyGen;

  return async function detoxMiddleware(req: any, res: any, next: (err?: any) => void) {
    try {
      const identifier = keyGen(req);

      // Attach convenient helper to req
      req.detox = {
        limiter,
        identifier,
        checkRateLimit: () => limiter.check(identifier),
        recordFailedAttempt: (meta?: Record<string, any>) => limiter.recordFailure(identifier, meta),
        resetRateLimit: () => limiter.reset(identifier),
      };

      // Pre-flight check before touching database
      const check = await limiter.check(identifier);

      // Apply standard headers
      const headers = limiter.getHeaders(check);
      for (const [headerName, headerValue] of Object.entries(headers)) {
        res.setHeader(headerName, headerValue);
      }

      // If already actively locked, reject immediately
      if (check.isLocked) {
        if (options.handler) {
          return options.handler(req, res, check);
        }

        return res.status(429).json({
          success: false,
          isLocked: true,
          remainingSeconds: check.remainingSeconds,
          lockedUntil: check.lockedUntil,
          uniqueKey: check.uniqueKey,
          error: `Security Lockout Triggered: 5 failed attempts reached. Cooldown initiated for ${check.remainingSeconds} seconds.`,
        });
      }

      return next();
    } catch (error) {
      return next(error);
    }
  };
}
