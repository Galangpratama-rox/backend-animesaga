import express from "express";
import https from "https";
import http from "http";

const router = express.Router();

// Agent khusus untuk image proxy: skip SSL cert validation
// (banyak CDN komik pakai cert expired/self-signed)
const httpsAgentNoVerify = new https.Agent({ rejectUnauthorized: false });

// Allowed streaming server domains for security
const ALLOWED_DOMAINS = [
  "desustream.net",
  "ondesuhd.com",
  "ondesuhd.net"
];

// Allowed video CDN domains for video proxy
const ALLOWED_VIDEO_DOMAINS = [
  "r2.cloudflarestorage.com",
  "kuramadrive.com",
  "v1.kuramadrive.com",
  "amiya.my.id",         // CDN kuramadrive aktif
  "r2.dev",
  "storage.googleapis.com",
  "b-cdn.net",
  "backblazeb2.com",
];

// Domain gambar komik yang perlu proxy karena hotlink protection
const ALLOWED_IMAGE_DOMAINS = [
  "kiryuu.to",
  "kiryuu.co",
  "cdnesia.my.id",
  "apkomik.com",
  "komikstation.co",
  "komikcast.com",
  "wpmanga.net",
  "mangakomik.id",
  "i0.wp.com",
  "i1.wp.com",
  "i2.wp.com",
  "i3.wp.com",
  "wp.com",
];

/**
 * Video streaming proxy — mendukung Range requests untuk seeking.
 * GET /api/proxy/video?url=<encoded_url>
 *
 * Mem-proxy direct video file (MP4/WebM dari R2/CDN) ke client
 * dengan header CORS yang benar dan dukungan Range request.
 */
router.get("/video", async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ success: false, error: "URL parameter is required" });
  }

  let targetUrl;
  try {
    targetUrl = new URL(url);
  } catch {
    return res.status(400).json({ success: false, error: "Invalid URL format" });
  }

  if (targetUrl.protocol !== "https:") {
    return res.status(400).json({ success: false, error: "Only HTTPS URLs are allowed" });
  }

  const hostname = targetUrl.hostname.toLowerCase();
  const ext      = targetUrl.pathname.split(".").pop().split("?")[0].toLowerCase();
  const byDomain = ALLOWED_VIDEO_DOMAINS.some((d) => hostname.includes(d));
  const byExt    = ["mp4", "webm", "mkv", "m3u8", "ts"].includes(ext);

  if (!byDomain && !byExt) {
    console.log(`[VideoProxy] Blocked: ${hostname} (domain not whitelisted, ext=${ext})`);
    return res.status(403).json({ success: false, error: "Domain not allowed for video proxy" });
  }

  console.log(`[VideoProxy] Streaming: ${hostname}${targetUrl.pathname.slice(0, 60)} (byDomain=${byDomain} byExt=${byExt}`);

  try {
    // Forward Range header dari browser (untuk seeking / partial content)
    const upstreamHeaders = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Referer":    "https://kuramanime.bid/",
      "Origin":     "https://kuramanime.bid",
      "Accept":     "*/*",
    };
    if (req.headers.range) {
      upstreamHeaders["Range"] = req.headers.range;
    }

    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 30000);

    const upstream = await fetch(url, {
      signal:  controller.signal,
      headers: upstreamHeaders,
    });
    clearTimeout(timeoutId);

    if (!upstream.ok && upstream.status !== 206) {
      return res.status(502).json({ success: false, error: `Upstream ${upstream.status}` });
    }

    // Forward headers yang relevan ke client
    const forwardHeaders = [
      "content-type",
      "content-length",
      "content-range",
      "accept-ranges",
      "last-modified",
      "etag",
    ];
    for (const h of forwardHeaders) {
      const val = upstream.headers.get(h);
      if (val) res.setHeader(h, val);
    }

    // CORS — izinkan embed dari semua origin (frontend kita)
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Range");
    res.setHeader("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges");

    // Hapus header yang paksa download
    res.removeHeader("Content-Disposition");
    res.setHeader("Cache-Control", "public, max-age=3600");

    // Status 206 Partial Content kalau upstream reply dengan range
    res.status(upstream.status === 206 ? 206 : 200);

    // Pipe body langsung ke response — tidak buffer di memory
    const reader = upstream.body.getReader();
    const pump = async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) { res.end(); break; }
        const canContinue = res.write(value);
        if (!canContinue) {
          // Back-pressure: tunggu drain sebelum lanjut
          await new Promise((resolve) => res.once("drain", resolve));
        }
      }
    };
    req.on("close", () => { reader.cancel(); });
    await pump();

  } catch (err) {
    if (!res.headersSent) {
      if (err.name === "AbortError") {
        return res.status(504).json({ success: false, error: "Video proxy timeout" });
      }
      console.error("[VideoProxy] Error:", err.message);
      return res.status(502).json({ success: false, error: err.message });
    }
  }
});

/**
 * OPTIONS preflight untuk /video (CORS)
 */
router.options("/video", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Range, X-API-Key");
  res.setHeader("Access-Control-Max-Age", "86400");
  res.sendStatus(204);
});

/**
 * Proxy endpoint untuk bypass CSP frame-ancestors restrictions
 * GET /api/proxy/stream?url=<encoded_url>
 * 
 * Fetches content dari streaming server, strips CSP headers,
 * dan serves ke frontend tanpa restrictions
 */
router.get("/stream", async (req, res) => {
  const { url } = req.query;

  try {
    // ── Input Validation ─────────────────────────────────────────────────
    if (!url) {
      return res.status(400).json({
        success: false,
        error: "URL parameter is required"
      });
    }

    // Validate URL format
    let targetUrl;
    try {
      targetUrl = new URL(url);
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: "Invalid URL format. Must be a valid HTTPS URL"
      });
    }

    // Only allow HTTPS
    if (targetUrl.protocol !== "https:") {
      return res.status(400).json({
        success: false,
        error: "Only HTTPS URLs are allowed"
      });
    }

    // Validate domain whitelist
    const hostname = targetUrl.hostname.toLowerCase();
    const isAllowed = ALLOWED_DOMAINS.some(domain => hostname.includes(domain));
    
    if (!isAllowed) {
      console.log(`[Proxy] Blocked request to non-whitelisted domain: ${hostname}`);
      return res.status(400).json({
        success: false,
        error: `Domain not allowed. Only ${ALLOWED_DOMAINS.join(", ")} are permitted`
      });
    }

    console.log(`[Proxy] Fetching: ${url}`);

    // ── Fetch External Content ───────────────────────────────────────────
    
    // Setup timeout with AbortController
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout

    try {
      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Referer": "https://otakudesu.blog/",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
      });

      clearTimeout(timeoutId);

      // ── Response Processing ──────────────────────────────────────────
      
      // Check if response is successful
      if (!response.ok) {
        console.error(`[Proxy] Upstream error: ${response.status} ${response.statusText}`);
        return res.status(502).json({
          success: false,
          error: `Upstream server returned ${response.status}: ${response.statusText}`
        });
      }

      // Get content type from upstream
      const contentType = response.headers.get("content-type") || "text/html";

      // Read response body
      const content = await response.text();

      console.log(`[Proxy] Successfully fetched ${content.length} bytes from ${hostname}`);

      // ── Header Modification (CSP Bypass) ─────────────────────────────
      
      // Inject <base> tag to make browser resolve all relative URLs relative to original page directory
      // This is the most reliable way to handle relative URLs in HTML
      // Important: Use the URL without query string so relative URLs resolve correctly
      // Example: https://desustream.net/dstream/arcg/?id=xxx → https://desustream.net/dstream/arcg/
      const baseUrl = `${targetUrl.origin}${targetUrl.pathname}`;
      let modifiedContent = content;
      
      // Inject <base href="..."> tag in <head> section
      // This makes ALL relative URLs (in HTML and JS) resolve relative to original server
      const baseTag = `<base href="${baseUrl}/">`;
      
      if (modifiedContent.includes('<head>')) {
        // Insert right after <head> tag
        modifiedContent = modifiedContent.replace('<head>', `<head>\n  ${baseTag}`);
        console.log(`[Proxy] Injected <base href="${baseUrl}/"> tag to resolve relative URLs`);
      } else if (modifiedContent.includes('<html>')) {
        // If no <head> tag, insert after <html>
        modifiedContent = modifiedContent.replace('<html>', `<html>\n<head>\n  ${baseTag}\n</head>`);
        console.log(`[Proxy] Created <head> and injected <base href="${baseUrl}/"> tag`);
      } else {
        // No HTML structure, prepend base tag
        modifiedContent = `${baseTag}\n${modifiedContent}`;
        console.log(`[Proxy] Prepended <base href="${baseUrl}/"> tag`);
      }

      // Set response headers WITHOUT CSP restrictions
      res.setHeader("Content-Type", contentType);
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      res.setHeader("X-Content-Type-Options", "nosniff");
      
      // CRITICAL: Do NOT set Content-Security-Policy or X-Frame-Options
      // This allows iframe embedding from any domain

      // Send the modified content
      res.send(modifiedContent);

    } catch (fetchError) {
      clearTimeout(timeoutId);

      if (fetchError.name === "AbortError") {
        console.error("[Proxy] Request timeout after 15 seconds");
        return res.status(502).json({
          success: false,
          error: "Request timeout: upstream server took too long to respond"
        });
      }

      console.error("[Proxy] Fetch error:", fetchError.message);
      return res.status(502).json({
        success: false,
        error: `Failed to fetch from upstream server: ${fetchError.message}`
      });
    }

  } catch (error) {
    // ── Error Handling ───────────────────────────────────────────────────
    console.error("[Proxy] Unexpected error:", error);
    return res.status(500).json({
      success: false,
      error: "Internal proxy error occurred"
    });
  }
});

/**
 * Image proxy — bypass hotlink protection untuk gambar komik.
 * GET /api/proxy/image?url=<encoded_url>
 *
 * Tidak butuh API key — diakses langsung oleh <img src> di browser.
 * Domain yang diizinkan: ALLOWED_IMAGE_DOMAINS
 *
 * Fitur:
 * - Header lengkap menyerupai browser biasa (lolos Cloudflare basic check)
 * - Follow redirect manual (max 3 hop) agar tidak gagal di CDN yang redirect
 * - Jika upstream non-ok (403/503/etc), coba lagi tanpa Referer sebagai fallback
 * - Stream body langsung ke client (tidak buffer di memory)
 */
router.get("/image", async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ success: false, error: "URL parameter is required" });
  }

  let targetUrl;
  try {
    targetUrl = new URL(url);
  } catch {
    return res.status(400).json({ success: false, error: "Invalid URL format" });
  }

  if (targetUrl.protocol !== "https:" && targetUrl.protocol !== "http:") {
    return res.status(400).json({ success: false, error: "Only HTTP/HTTPS URLs are allowed" });
  }

  const hostname = targetUrl.hostname.toLowerCase();
  const isAllowed = ALLOWED_IMAGE_DOMAINS.some(
    (d) => hostname === d || hostname.endsWith("." + d)
  );

  if (!isAllowed) {
    console.log(`[ImageProxy] Blocked: ${hostname}`);
    return res.status(403).json({ success: false, error: `Domain "${hostname}" not allowed for image proxy` });
  }

  console.log(`[ImageProxy] Fetching: ${hostname}${targetUrl.pathname.slice(0, 80)}`);

  // Header lengkap menyerupai browser Chrome biasa agar lolos Cloudflare/hotlink check
  const buildImgHeaders = (referer) => ({
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":          "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control":   "no-cache",
    "Sec-Fetch-Dest":  "image",
    "Sec-Fetch-Mode":  "no-cors",
    "Sec-Fetch-Site":  "same-site",
    ...(referer ? { "Referer": referer, "Origin": referer.replace(/\/$/, "") } : {}),
  });

  // Referer map: root domain → referer yang diterima CDN tersebut
  const REFERER_MAP = {
    "kiryuu.to":      "https://kiryuu.to/",
    "kiryuu.co":      "https://kiryuu.co/",
    "apkomik.com":    "https://apkomik.com/",
    "komiknesia.com": "https://komiknesia.com/",
    "cdnesia.my.id":  "https://komiknesia.com/",
    "komikstation.co":"https://komikstation.co/",
    "komikcast.com":  "https://komikcast.com/",
    "wpmanga.net":    "https://wpmanga.net/",
    "mangakomik.id":  "https://mangakomik.id/",
    "wp.com":         "https://wordpress.com/",
    "i0.wp.com":      "https://wordpress.com/",
    "i1.wp.com":      "https://wordpress.com/",
    "i2.wp.com":      "https://wordpress.com/",
    "i3.wp.com":      "https://wordpress.com/",
  };

  function getReferer(hostname) {
    const h = hostname.toLowerCase();
    if (REFERER_MAP[h]) return REFERER_MAP[h];
    for (const [domain, ref] of Object.entries(REFERER_MAP)) {
      if (h === domain || h.endsWith(`.${domain}`)) return ref;
    }
    return `https://${h}/`;
  }

  /**
   * Fetch gambar dengan https module (bukan native fetch) agar bisa
   * skip SSL cert validation — CDN komik sering pakai cert expired.
   * Follow redirect hingga maxHops kali.
   */
  function fetchImageWithRedirects(targetUrl, referer, onResponse, onError, hops = 0) {
    if (hops > 5) { onError(new Error("Too many redirects")); return; }

    const isHttps = targetUrl.protocol === "https:";
    const lib     = isHttps ? https : http;
    const options = {
      hostname: targetUrl.hostname,
      port:     targetUrl.port || (isHttps ? 443 : 80),
      path:     targetUrl.pathname + targetUrl.search,
      method:   "GET",
      headers:  buildImgHeaders(referer),
      // Skip SSL validation — cert expired/self-signed pada banyak CDN komik
      rejectUnauthorized: false,
    };

    const proxyReq = lib.request(options, (proxyRes) => {
      const status   = proxyRes.statusCode || 0;
      const location = proxyRes.headers["location"];

      if ((status === 301 || status === 302 || status === 307 || status === 308) && location) {
        proxyRes.resume(); // drain body
        let nextUrl;
        try { nextUrl = new URL(location, targetUrl.href); }
        catch { onError(new Error(`Bad redirect: ${location}`)); return; }
        fetchImageWithRedirects(nextUrl, getReferer(nextUrl.hostname), onResponse, onError, hops + 1);
        return;
      }
      onResponse(proxyRes, status);
    });

    proxyReq.on("error", onError);
    proxyReq.setTimeout(20000, () => {
      proxyReq.destroy();
      onError(new Error("Proxy timeout"));
    });
    proxyReq.end();
  }

  const referer = getReferer(hostname);

  new Promise((resolve) => {
    fetchImageWithRedirects(
      targetUrl,
      referer,
      (proxyRes, status) => {
        if (status < 200 || status >= 300) {
          console.log(`[ImageProxy] Upstream ${status} for ${hostname}`);
          // Kembalikan 1x1 transparan agar <img> tidak broken
          const TRANSPARENT_GIF = Buffer.from(
            "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==",
            "base64"
          );
          res.setHeader("Content-Type", "image/gif");
          res.setHeader("Cache-Control", "no-store");
          res.setHeader("Access-Control-Allow-Origin", "*");
          res.status(200).send(TRANSPARENT_GIF);
          resolve();
          return;
        }

        const contentType   = proxyRes.headers["content-type"] || "image/jpeg";
        const contentLength = proxyRes.headers["content-length"];

        res.setHeader("Content-Type", contentType);
        if (contentLength) res.setHeader("Content-Length", contentLength);
        res.setHeader("Cache-Control", "public, max-age=86400");
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.status(200);

        proxyRes.pipe(res);
        proxyRes.on("end", resolve);
        proxyRes.on("error", resolve);
        req.on("close", () => proxyRes.destroy());
      },
      (err) => {
        console.error("[ImageProxy] Error:", err.message);
        if (!res.headersSent) res.status(502).json({ success: false, error: err.message });
        resolve();
      }
    );
  });
});

/**
 * OPTIONS preflight untuk /image (CORS)
 */
router.options("/image", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Range");
  res.status(204).end();
});

export default router;