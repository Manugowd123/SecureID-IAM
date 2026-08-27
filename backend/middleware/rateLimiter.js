const rateLimitsStore = new Map();

/**
 * Basic in-memory rate limiter middleware to protect sensitive endpoints.
 * Configurable via environment variables.
 */
function rateLimiter({ 
  windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10), 
  max = parseInt(process.env.RATE_LIMIT_MAX || '200', 10), 
  message = 'Too many requests, please try again later.' 
} = {}) {
  return (req, res, next) => {
    // For test runs we might disable rate limiting or use high values
    if (process.env.NODE_ENV === 'test') {
      return next();
    }

    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const key = `${req.path}:${ip}`;
    const now = Date.now();

    if (!rateLimitsStore.has(key)) {
      rateLimitsStore.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }

    const rateLimit = rateLimitsStore.get(key);
    if (now > rateLimit.resetTime) {
      rateLimit.count = 1;
      rateLimit.resetTime = now + windowMs;
      return next();
    }

    rateLimit.count++;
    if (rateLimit.count > max) {
      return res.status(429).json({
        success: false,
        code: 'TOO_MANY_REQUESTS',
        message
      });
    }

    next();
  };
}

// Clean up stale entries every 10 minutes to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitsStore.entries()) {
    if (now > val.resetTime) {
      rateLimitsStore.delete(key);
    }
  }
}, 10 * 60 * 1000).unref();

module.exports = rateLimiter;
