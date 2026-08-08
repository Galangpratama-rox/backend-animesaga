// In-memory rate limiter (tidak perlu express-rate-limit)
const requestStore = {};

function getClientKey(req) {
  return req.ip || req.connection?.remoteAddress || "unknown";
}

function countRequests(key, windowMs) {
  const now = Date.now();
  if (!requestStore[key]) requestStore[key] = [];

  // Buang request di luar window
  requestStore[key] = requestStore[key].filter((t) => now - t < windowMs);
  return requestStore[key];
}

// Bersihkan store setiap 10 menit untuk cegah memory leak
setInterval(() => {
  const now = Date.now();
  for (const key of Object.keys(requestStore)) {
    requestStore[key] = requestStore[key].filter((t) => now - t < 3600000);
    if (requestStore[key].length === 0) delete requestStore[key];
  }
}, 10 * 60 * 1000);

/**
 * Rate limiter umum untuk semua request
 */
export function rateLimiter(req, res, next) {
  const windowMs = parseInt(process.env.API_RATE_LIMIT_WINDOW_MS) || 3600000;
  const maxRequests = parseInt(process.env.API_RATE_LIMIT_MAX_REQUESTS) || 200;

  const key = getClientKey(req);
  const requests = countRequests(key, windowMs);

  if (requests.length >= maxRequests) {
    return res.status(429).json({
      success: false,
      error: "Too many requests",
      message: "Terlalu banyak request, coba lagi nanti."
    });
  }

  requests.push(Date.now());
  next();
}

/**
 * Rate limiter khusus untuk XP events (lebih ketat)
 */
export function xpEventLimiter(req, res, next) {
  const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 3600000;
  const max = parseInt(process.env.RATE_LIMIT_MAX_EVENTS) || 5;

  const key = `xp_${getClientKey(req)}`;
  const requests = countRequests(key, windowMs);

  if (requests.length >= max) {
    return res.status(429).json({
      success: false,
      error: "Rate limit exceeded",
      message: "Terlalu banyak XP event, coba lagi nanti."
    });
  }

  requests.push(Date.now());
  next();
}
