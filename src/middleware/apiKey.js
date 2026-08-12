/**
 * apiKey.js — middleware validasi API key
 *
 * Semua request ke /api/* harus menyertakan header:
 *   X-API-Key: <nilai dari env API_SECRET_KEY>
 *
 * Pengecualian:
 *   - GET /health  — tidak perlu key (untuk monitoring uptime)
 *   - GET /uploads/* — tidak perlu key (static file publik)
 */
export function requireApiKey(req, res, next) {
  // Skip untuk health check, static uploads, dan video proxy (browser tidak bisa kirim custom header)
  if (
    req.path === "/health" ||
    req.path.startsWith("/uploads/") ||
    req.path.startsWith("/api/proxy/video")
  ) {
    return next();
  }

  const secret = process.env.API_SECRET_KEY;

  // Kalau env belum diset (development tanpa key), lewati validasi
  if (!secret) {
    return next();
  }

  const provided = req.headers["x-api-key"];

  if (!provided || provided !== secret) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized",
      message: "API key tidak valid atau tidak disertakan.",
    });
  }

  next();
}
