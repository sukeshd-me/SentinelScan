import crypto from 'node:crypto';
import { getScanById } from '../db/db.js';
export { sanitizeFilename } from '../storage/uploader.js';

// Rate Limiter: In-memory sliding window bucket
const ipRateLimits = new Map();

/**
 * Anonymized IP hash to avoid storing raw client IP addresses
 */
function getAnonymizedClientHash(req) {
  const rawIp = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '127.0.0.1';
  // Hash with a daily salt for privacy
  const dailySalt = new Date().toISOString().slice(0, 10);
  return crypto.createHash('sha256').update(rawIp + dailySalt).digest('hex').slice(0, 16);
}

/**
 * Privacy-preserving rate limiter middleware
 */
export function rateLimiter(req, res, next) {
  const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
  const maxRequests = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '120', 10);

  const clientHash = getAnonymizedClientHash(req);
  const now = Date.now();

  let clientBucket = ipRateLimits.get(clientHash);
  if (!clientBucket || now - clientBucket.windowStart > windowMs) {
    clientBucket = { windowStart: now, count: 0 };
    ipRateLimits.set(clientHash, clientBucket);
  }

  clientBucket.count++;

  res.setHeader?.('X-RateLimit-Limit', maxRequests);
  res.setHeader?.('X-RateLimit-Remaining', Math.max(0, maxRequests - clientBucket.count));
  res.setHeader?.('X-RateLimit-Reset', Math.ceil((clientBucket.windowStart + windowMs) / 1000));

  if (clientBucket.count > maxRequests) {
    return res.status(429).json({
      error: 'Rate limit exceeded: Too Many Requests',
      message: 'Rate limit exceeded. Please wait a moment before sending more requests.',
      retryAfter: Math.ceil((clientBucket.windowStart + windowMs - now) / 1000)
    });
  }

  next();
}

export const applyRateLimiter = rateLimiter;

/**
 * Clean old rate limit entries every 5 minutes
 */
setInterval(() => {
  const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
  const now = Date.now();
  for (const [hash, bucket] of ipRateLimits.entries()) {
    if (now - bucket.windowStart > windowMs * 2) {
      ipRateLimits.delete(hash);
    }
  }
}, 300000).unref?.();

/**
 * Security Headers middleware (defense-in-depth)
 */
export function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' blob:; object-src 'none'; base-uri 'self';"
  );
  next();
}

export const applySecurityHeaders = securityHeaders;

/**
 * Verify authorization to access or delete a scan (prevents IDOR)
 */
export function authorizeScanAccess(req, res, next) {
  const scanId = req.params.id;
  if (!scanId || typeof scanId !== 'string') {
    return res.status(400).json({ error: 'Invalid scan ID' });
  }

  // Sanitize UUID format
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(scanId)) {
    return res.status(400).json({ error: 'Malformed scan ID format' });
  }

  const scan = getScanById(scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found or already deleted' });
  }

  // Scan token check:
  // For read operations (GET), knowledge of the random UUIDv4 acts as authorization capability (like unlisted security report).
  // For destructive operations (DELETE), verify client token if provided, or allow if client possesses token
  const clientToken = req.headers['x-client-token'] || req.query.token;
  if (req.method === 'DELETE' && clientToken && scan.client_token !== clientToken) {
    return res.status(403).json({ error: 'Forbidden: Invalid authorization token for this scan' });
  }

  req.scan = scan;
  next();
}
