import express from "express";
import https from "https";
import http from "http";
import { URL } from "url";

const router = express.Router();

// Agent khusus untuk image proxy: skip SSL cert validation
// (banyak CDN komik pakai cert expired/self-signed)
const httpsAgentNoVerify = new https.Agent({ rejectUnauthorized: false });

// ── HTTP/HTTPS Agent dengan Connection Pooling & Keep-Alive ──
// Mengurangi latensi range request dari ~300ms ke ~20ms
// Referensi: implement.md Bagian 2 (Bottleneck #1 & #2)
const httpsKeepAliveAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 100,
  maxFreeSockets: 20,
  timeout: 60000,
  keepAliveMsecs: 30000,
});

const httpKeepAliveAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 100,
  maxFreeSockets: 20,
  timeout: 60000,
  keepAliveMsecs: 30000,
});

// Allowed streaming server domains for security
const ALLOWED_DOMAINS = ["desustream.net", "ondesuhd.com", "ondesuhd.net"];

// Allowed video CDN domains for video proxy
// Jika byDomain TIDAK lolos, backend MASIH mengijinkan byExt (mp4/webm/mkv/m3u8/ts).
// List ini adalah WHITELIST EXTRA untuk domain yang URL-nya TIDAK berakhir dengan
// ext standard (contoh: redirect m3u8 tanpa ext, atau URL aneh dari admin page).
const ALLOWED_VIDEO_DOMAINS = [
  "r2.cloudflarestorage.com",
  "kuramadrive.com",
  "v1.kuramadrive.com",
  "amiya.my.id", // CDN kuramadrive aktif
  "chisato.my.id", // kDrive Kuramanime (dari implement.md)
  "asuna.my.id", // +++ domain Kuramanime baru (contoh user)
  "anisphia.my.id", // +++ domain Kuramanime baru (contoh user)
  "r2.dev",
  "storage.googleapis.com",
  "b-cdn.net",
  "backblazeb2.com",
  // === URL CUSTOM ADMIN PAGE (user menambahkan episode baru bukan dari kuramanime/otakudesu) ===
  // Contoh user: https://cdn-203.lancartech.co.id/_UPLOAD_BARU_/.../....mp4
  "lancartech.co.id",
  // === Generic CDN populer yang sering user pakai upload video manual ===
  "cloudflare.net",
  "workers.dev",
  "cdn.discordapp.com",
  "media.discordapp.net",
  "dropbox.com",
  "dl.dropboxusercontent.com",
  "mega.nz",
  "pixeldrain.com",
  "streamtape.com",
  "streamcherry.com",
  "filemoon.sx",
  "luluvdo.com",
  // === HLS Custom Domain ===
  "xtwap.top",
];

// ── Referer/Origin Spoofing Map per domain group ──
// Referensi: implement.md Bagian 4 (Header yang WAJIB diteruskan ke upstream)
// - Kuramanime/kDrive (chisato.my.id, kuramadrive) butuh Referer v17.kuramanime.ink
// - Otakudesu (archive.org, googlevideo) butuh Referer otakudesu.blog / kuramanime.bid
//
// CATATAN: Tambahkan suffix ".my.id" agar SEMUA subdomain (*.my.id) milik
// Kuramanime otomatis dikenali (seperti anisphia, asuna, amiya, chisato, dll.)
// Tanpa perlu menambahkan satu-per-satu setiap domain baru.
const KURAMANIME_VIDEO_DOMAINS = new Set([
  "chisato.my.id",
  "amiya.my.id",
  "asuna.my.id", // +++
  "anisphia.my.id", // +++
  "my.id", // +++ catch-all: SEMUA domain *.my.id = Kuramanime group
  "kuramadrive.com",
  "v1.kuramadrive.com",
]);

function getSpoofedHeadersForVideo(hostname) {
  const h = hostname.toLowerCase();
  // Cek apakah domain termasuk Kuramanime/kDrive group
  const isKuramanime = [...KURAMANIME_VIDEO_DOMAINS].some(
    (d) => h === d || h.endsWith("." + d),
  );

  if (isKuramanime) {
    // Spesifik untuk sumber Kuramanime / kDrive (implement.md #4)
    return {
      Referer: "https://v17.kuramanime.ink/",
      Origin: "https://v17.kuramanime.ink",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
      Accept: "*/*",
    };
  }

  // Default: untuk sumber Otakudesu / Googlevideo / Archive.org
  return {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    Referer: "https://kuramanime.bid/",
    Origin: "https://kuramanime.bid",
    Accept: "*/*",
  };
}

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * HLS SESSION TRACKER (In-Memory, no dependency)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * MASALAH: Browser `strict-origin-when-cross-origin` memblokir Referer
 *          header full URL pada cross-origin request (localhost:5173 → 3001).
 *          Safety net sebelumnya bergantung Referer full URL untuk
 *          mereconstruct base directory m3u8 → GAGAL.
 *
 * SOLUSI: Track mapping (clientIP → last m3u8 baseDir) di memory.
 *         Setiap kali m3u8 di-request via /video, SIMPAN mapping ini.
 *         Safety net pertama-tama coba lookup dari session tracker ini
 *         (TIDAK bergantung Referer). Baru fallback ke Referer + manual parse.
 *
 * CLEANUP: Max 200 entry (LRU sederhana via Map insertion order). Entri >30 menit
 *          otomatis dihapus tiap ada request baru untuk hemat memory.
 */
const HLSSessionMap = new Map(); // key = clientIP, value = { baseDirHref, ts }
const HLS_SESSION_TTL_MS = 30 * 60 * 1000; // 30 menit

function _cleanupHLSSessions() {
  const now = Date.now();
  for (const [ip, entry] of HLSSessionMap.entries()) {
    if (now - entry.ts > HLS_SESSION_TTL_MS) HLSSessionMap.delete(ip);
  }
  // LRU: batasi 200 entry (hapus paling tua = Map insertion order terawal)
  if (HLSSessionMap.size > 200) {
    const toDelete = HLSSessionMap.size - 200;
    let i = 0;
    for (const ip of HLSSessionMap.keys()) {
      if (i >= toDelete) break;
      HLSSessionMap.delete(ip);
      i++;
    }
  }
}

function saveHLSSession(clientIP, baseDirHref) {
  if (!clientIP || !baseDirHref) return;
  _cleanupHLSSessions();
  // Delete dulu agar insertion order jadi terbaru (LRU sederhana)
  HLSSessionMap.delete(clientIP);
  HLSSessionMap.set(clientIP, { baseDirHref, ts: Date.now() });
}

function getHLSSession(clientIP) {
  _cleanupHLSSessions();
  const entry = HLSSessionMap.get(clientIP);
  if (!entry) return null;
  if (Date.now() - entry.ts > HLS_SESSION_TTL_MS) {
    HLSSessionMap.delete(clientIP);
    return null;
  }
  return entry.baseDirHref;
}

/**
 * Helper extract client real IP dari Express request (handle proxy / x-forwarded)
 */
function getClientIP(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) {
    const first = String(xf).split(",")[0].trim();
    if (first) return first;
  }
  return (
    req.ip ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "unknown"
  );
}

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
 * Mem-proxy direct video file (MP4/WebM dari R2/CDN / kDrive Kuramanime) ke client
 * dengan header CORS yang benar, dukungan Range request, dan Keep-Alive connection pooling.
 *
 * Optimasi (dari implement.md Bagian 2 Bottleneck Fixes):
 *  - Menggunakan httpsAgent keepAlive: true untuk menghindari TLS handshake berulang
 *  - Spoof Referer/Origin per domain group (Kuramanime vs Otakudesu)
 *  - Dukungan 206 Partial Content untuk seeking lancar
 */
router.get("/video", (req, res) => {
  const { url } = req.query;
  const clientIP = getClientIP(req);

  // ═══════════════════════════════════════════════════════════════════════
  // VERBOSE DEBUG LOG (wajib agar user tahu apakah route ini terpanggil)
  // ═══════════════════════════════════════════════════════════════════════
  const _dbgShortUrl = url
    ? String(url).slice(0, 80) + (String(url).length > 80 ? "..." : "")
    : "(MISSING)";
  console.log(
    "[VideoProxy] ➡️  INCOMING /video | ip=" +
      clientIP +
      " | url=" +
      _dbgShortUrl,
  );

  if (!url) {
    return res
      .status(400)
      .json({ success: false, error: "URL parameter is required" });
  }

  let targetUrl;
  try {
    targetUrl = new URL(String(url));
  } catch {
    return res
      .status(400)
      .json({ success: false, error: "Invalid URL format" });
  }

  if (targetUrl.protocol !== "https:" && targetUrl.protocol !== "http:") {
    return res
      .status(400)
      .json({ success: false, error: "Only HTTP/HTTPS URLs are allowed" });
  }

  const hostname = targetUrl.hostname.toLowerCase();
  const ext = targetUrl.pathname.split(".").pop().split("?")[0].toLowerCase();
  const byDomain = ALLOWED_VIDEO_DOMAINS.some((d) => hostname.includes(d));
  const byExt = ["mp4", "webm", "mkv", "m3u8", "ts"].includes(ext);

  if (!byDomain && !byExt) {
    console.log(
      `[VideoProxy] ❌ BLOCKED: ${hostname} (domain not whitelisted, ext=${ext})`,
    );
    return res
      .status(403)
      .json({ success: false, error: "Domain not allowed for video proxy" });
  }

  // ── PRE-LOG: Apakah ini m3u8? Harusnya rewrite jalan ────────────────
  const isM3u8Before = ext === "m3u8";
  console.log(
    "[VideoProxy] 🧪 CLASSIFY: hostname=" +
      hostname +
      " | ext=" +
      ext +
      " | byDomain=" +
      byDomain +
      " | byExt=" +
      byExt +
      " | isM3u8=" +
      isM3u8Before,
  );
  if (isM3u8Before) {
    // Simpan session SEGERA sebelum fetch upstream, agar request .ts
    // dari IP yang sama bisa di-track walaupun upstream fail
    const origHref = targetUrl.href;
    const baseDirHref = origHref.substring(0, origHref.lastIndexOf("/") + 1);
    saveHLSSession(clientIP, baseDirHref);
    console.log(
      "[VideoProxy] 📝 HLS session saved: ip=" +
        clientIP +
        " → baseDir=" +
        baseDirHref.slice(0, 100),
    );
  }

  // === LOG DETAIL KURAMANIME / VIDEO PROXY ===
  // Cek apakah hostname ini milik Kuramanime group (untuk logging detail)
  const isKuramanimeGroup = [...KURAMANIME_VIDEO_DOMAINS].some(
    (d) => hostname === d || hostname.endsWith("." + d),
  );

  const shortPath = targetUrl.pathname.slice(0, 80);
  const fullPath = targetUrl.pathname + targetUrl.search;
  // Parse parameter query khusus Kuramanime
  const params = Object.fromEntries(targetUrl.searchParams.entries());
  const lud = params.lud || "-";
  const pid = params.pid || "-";
  const sid = params.sid || "-";
  const cce = params.cce ?? "-";

  if (isKuramanimeGroup) {
    // Hitung semua nilai terlebih dahulu ke variabel → menghindari
    // syntax error parser Node.js pada expression kompleks di dalam template literal
    const fileName = targetUrl.pathname.split("/").pop() || "-";
    // Detect kualitas video (1080p / 720p / 540p / 480p / 360p / 240p)
    const qualityMatch = targetUrl.pathname.match(
      /(1080p|720p|540p|480p|360p|240p)/i,
    );
    const qualityText = qualityMatch ? qualityMatch[0] : "tidak terdeteksi";
    // Short path + query (truncated)
    let shortPathWithQs = shortPath;
    if (targetUrl.search) {
      shortPathWithQs += "?" + targetUrl.search.slice(1, 60);
    }
    // Range request info
    const rangeHeader = req.headers["range"];
    const rangeText = rangeHeader
      ? "YES — " + String(rangeHeader).slice(0, 60)
      : "NO (full request)";
    // Full URL truncated
    const fullPathText =
      fullPath.length < 140 ? fullPath : fullPath.slice(0, 140) + "...";

    // Log spesifik untuk Kuramanime (detailed)
    console.log("═══════════════════════════════════════════════════════════");
    console.log("[VideoProxy] 🔴 KURAMANIME STREAM REQUEST");
    console.log("  Hostname   : " + hostname);
    console.log("  File       : " + fileName);
    console.log("  Short Path : " + shortPathWithQs);
    console.log("  Kualitas   : " + qualityText);
    console.log(
      "  Query Params (Kuramanime): lud=" +
        lud +
        " | pid=" +
        pid +
        " | sid=" +
        sid +
        " | cce=" +
        cce,
    );
    console.log(
      "  Spoof Ref  : https://v17.kuramanime.ink/ (Kuramanime group)",
    );
    console.log("  Range Req  : " + rangeText);
    console.log("  Full URL   : " + hostname + fullPathText);
    console.log("═══════════════════════════════════════════════════════════");
  } else {
    // Non-Kuramanime: log ringkas
    const rangeText = req.headers["range"] ? "YES" : "NO";
    console.log(
      "[VideoProxy] 🟢 Streaming (non-Kuramanime): " +
        hostname +
        shortPath +
        " (byDomain=" +
        byDomain +
        " byExt=" +
        byExt +
        ") Range=" +
        rangeText,
    );
  }

  // ── Build upstream request ──
  const spoofedHeaders = getSpoofedHeadersForVideo(hostname);
  if (req.headers["range"]) {
    spoofedHeaders["Range"] = req.headers["range"];
  }
  // Tambahkan Accept-Encoding agar upstream tidak gzip mp4 (jarang tapi aman)
  spoofedHeaders["Accept-Encoding"] = "identity";

  const isHttps = targetUrl.protocol === "https:";
  const lib = isHttps ? https : http;
  const agent = isHttps ? httpsKeepAliveAgent : httpKeepAliveAgent;

  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.port || (isHttps ? 443 : 80),
    path: targetUrl.pathname + targetUrl.search,
    method: "GET",
    headers: spoofedHeaders,
    agent, // ← Keep-alive agent untuk connection pooling
    timeout: 30000, // timeout 30 detik
  };

  let proxyReq;
  try {
    proxyReq = lib.request(options, (proxyRes) => {
      const status = proxyRes.statusCode || 0;

      // Follow redirect (301/302/307/308) — 1 hop saja
      if (
        (status === 301 ||
          status === 302 ||
          status === 307 ||
          status === 308) &&
        proxyRes.headers["location"]
      ) {
        proxyRes.resume();
        let nextUrl;
        try {
          nextUrl = new URL(proxyRes.headers["location"], targetUrl.href);
        } catch {
          return res
            .status(502)
            .json({ success: false, error: "Bad redirect" });
        }

        // Log redirect untuk Kuramanime group
        if (isKuramanimeGroup) {
          console.log(
            "[VideoProxy] 🔴 KURAMANIME REDIRECT " +
              status +
              ": " +
              hostname +
              " → " +
              nextUrl.hostname +
              nextUrl.pathname.slice(0, 60),
          );
        } else {
          console.log(
            "[VideoProxy] Redirect " +
              status +
              ": " +
              hostname +
              " → " +
              nextUrl.hostname,
          );
        }

        // Rekursif call ulang dengan URL baru (simplifikasi: hanya follow 1 hop)
        const nextReq = { ...req, query: { ...req.query, url: nextUrl.href } };
        const myHandler = router.stack.find(
          (l) => l.route && l.route.path === "/video" && l.route.methods.get,
        );
        if (myHandler) return myHandler.handle(nextReq, res, () => {});
        return res
          .status(502)
          .json({ success: false, error: "Redirect handler error" });
      }

      if (status < 200 || (status >= 300 && status !== 206)) {
        if (isKuramanimeGroup) {
          console.error(
            "[VideoProxy] ❌ KURAMANIME FAIL — status=" +
              status +
              " | host=" +
              hostname +
              " | path=" +
              shortPath +
              " | lud=" +
              lud +
              " pid=" +
              pid +
              " sid=" +
              sid,
          );
        } else {
          console.error(
            "[VideoProxy] Upstream " + status + " for " + hostname + shortPath,
          );
        }
        if (!res.headersSent) {
          return res
            .status(502)
            .json({ success: false, error: "Upstream " + status });
        }
        proxyRes.resume();
        return;
      }

      // ── LOG SUKSES UPSTREAM (untuk Kuramanime: log detail) ─────────────
      const contentLen = proxyRes.headers["content-length"] || "chunked";
      const contentRange = proxyRes.headers["content-range"] || "-";
      if (isKuramanimeGroup) {
        // Hitung filename terpisah agar tidak complex di string
        const logFileName = targetUrl.pathname.split("/").pop() || "-";
        console.log(
          "[VideoProxy] ✅ KURAMANIME OK — status=" +
            status +
            " | File=" +
            logFileName +
            " | Size=" +
            contentLen +
            " bytes | Range=" +
            contentRange,
        );
      } else {
        console.log(
          "[VideoProxy] Upstream OK " +
            status +
            " (" +
            contentLen +
            " bytes) for " +
            hostname,
        );
      }

      // ── Forward response headers ke client ──
      const forwardHeaders = [
        "content-type",
        "content-length",
        "content-range",
        "accept-ranges",
        "last-modified",
        "etag",
        "cache-control",
      ];
      for (const h of forwardHeaders) {
        const v = proxyRes.headers[h];
        if (v !== undefined) res.setHeader(h, v);
      }

      // CORS headers (sesuai implement.md Bagian 4)
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Range, Origin, Content-Type, Accept",
      );
      res.setHeader(
        "Access-Control-Expose-Headers",
        "Content-Range, Content-Length, Accept-Ranges",
      );
      res.setHeader("Accept-Ranges", "bytes");

      // Hapus header yang paksa download
      res.removeHeader("Content-Disposition");

      // Status: 206 Partial Content jika upstream reply range, else 200
      res.status(status === 206 ? 206 : 200);

      // ═════════════════════════════════════════════════════════════════════════
      // HLS M3U8 REWRITE v2 (AGRESIF): Khusus file .m3u8 — SELALU rewrite
      // tanpa peduli status code upstream.
      //
      // Kenapa v2? Native <video> Safari/Chrome KADANG resolve relative URI
      // terhadap PATHNAME SAJA (abaikan query ?url=...), jadi player request:
      //     http://localhost:5173/api/proxy/seg_0.ts
      // Padahal yang benar seharusnya lewat /api/proxy/video?url=...
      //
      // Solusi: Rewrite SEMUA segment URI ke absolute PROXY URL.
      // ⚠️  HANYA berlaku untuk .m3u8 — ts/mp4/webm/mkv TETAP PIPE LANGSUNG.
      // ═════════════════════════════════════════════════════════════════════════
      const isM3u8 = ext === "m3u8";

      if (isM3u8) {
        const chunks = [];
        proxyRes.on("data", (chunk) => chunks.push(chunk));
        proxyRes.on("end", () => {
          try {
            const raw = Buffer.concat(chunks).toString("utf8");
            // Base directory dari m3u8 upstream (untuk resolve relative seg)
            const origHref = targetUrl.href;
            const baseDirHref = origHref.substring(
              0,
              origHref.lastIndexOf("/") + 1,
            );
            // ── Detect BACKEND host yang BENAR ────────────────────────────
            // KALAU request datang dari Vite dev proxy (host = localhost:5173),
            // JANGAN pakai host 5173! Nanti segment .ts dilempar ke Vite yang
            // gak punya route → 404 "Endpoint not found".
            // Force ke localhost:3001 (atau VITE_BACKEND_URL yang sesungguhan).
            const reqHost =
              req.headers["x-forwarded-host"] ||
              req.headers.host ||
              "localhost:3001";
            const isViteProxy =
              String(reqHost).includes("5173") ||
              String(req.headers["via"] || "")
                .toLowerCase()
                .includes("vite");
            // Gunakan ENV BACKEND_URL jika tersedia (lebih akurat untuk production)
            const envBackend = (process.env.BACKEND_PUBLIC_URL || "").trim();
            let realBackend;
            if (envBackend) {
              realBackend = envBackend.replace(/\/$/, "");
            } else if (isViteProxy) {
              realBackend = "http://localhost:3001";
            } else {
              const proto =
                req.headers["x-forwarded-proto"] ||
                (req.protocol ? req.protocol : "") ||
                (req.socket && req.socket.encrypted ? "https" : "http") ||
                "http";
              realBackend = `${proto}://${reqHost}`;
            }
            const proxyPrefix = `${realBackend}/api/proxy/video?url=`;

            // ── Rewrite segment URI ───────────────────────────────────────
            const lines = raw.split(/\r?\n/);
            let rewroteCount = 0;
            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];
              if (!line || line.startsWith("#")) continue;
              let segmentAbsUrl;
              try {
                segmentAbsUrl = new URL(line).href; // sudah absolute
              } catch {
                try {
                  segmentAbsUrl = new URL(line, baseDirHref).href; // relative
                } catch {
                  continue;
                }
              }
              lines[i] = proxyPrefix + encodeURIComponent(segmentAbsUrl);
              rewroteCount++;
            }

            const rewritten = lines.join("\n");
            res.setHeader(
              "Content-Length",
              Buffer.byteLength(rewritten, "utf8"),
            );
            res.setHeader(
              "Content-Type",
              "application/vnd.apple.mpegurl; charset=utf-8",
            );
            console.log(
              "[VideoProxy] 🎞️  M3U8 v2: " +
                hostname +
                " | segRewrote=" +
                rewroteCount +
                " | reqHost=" +
                reqHost +
                " → realBackend=" +
                realBackend,
            );
            res.end(rewritten);
          } catch (rewriteErr) {
            console.error(
              "[VideoProxy] M3U8 Rewrite FAIL, fallback:",
              rewriteErr.message,
            );
            if (!res.headersSent) {
              res.setHeader("Content-Type", "application/vnd.apple.mpegurl");
            }
            res.end(Buffer.concat(chunks));
          }
        });
        proxyRes.on("error", () => {
          if (!res.headersSent) res.status(502).end();
          else res.end();
        });
        return;
      }

      // ── Default: NON m3u8 (mp4 / webm / mkv / ts / range seek) →
      //    PIPE streaming LANGSUNG — SAMA PERSIS TIDAK DIUBAH ──
      proxyRes.pipe(res);

      // Cleanup jika client disconnect sebelum upstream selesai
      req.on("close", () => {
        proxyRes.destroy();
      });
      proxyRes.on("error", () => {
        if (!res.headersSent) res.status(502).end();
        else res.end();
      });
    });
  } catch (err) {
    console.error("[VideoProxy] Request error:", err.message);
    if (!res.headersSent)
      return res.status(500).json({ success: false, error: err.message });
    return;
  }

  proxyReq.on("error", (err) => {
    if (res.headersSent) return res.end();
    if (err.code === "ETIMEDOUT") {
      return res
        .status(504)
        .json({ success: false, error: "Video proxy timeout" });
    }
    console.error("[VideoProxy] Network error:", err.message);
    return res.status(502).json({ success: false, error: err.message });
  });

  proxyReq.on("timeout", () => proxyReq.destroy(new Error("ETIMEDOUT")));

  // Batalkan upstream request jika client menutup koneksi / seek sebelum selesai
  req.on("close", () => {
    if (!proxyReq.destroyed) proxyReq.destroy();
  });

  proxyReq.end();
});

/**
 * OPTIONS preflight untuk /video (CORS)
 */
router.options("/video", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Range, Origin, Content-Type, Accept, X-API-Key",
  );
  res.setHeader(
    "Access-Control-Expose-Headers",
    "Content-Range, Content-Length, Accept-Ranges",
  );
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
        error: "URL parameter is required",
      });
    }

    // Validate URL format
    let targetUrl;
    try {
      targetUrl = new URL(url);
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: "Invalid URL format. Must be a valid HTTPS URL",
      });
    }

    // Only allow HTTPS
    if (targetUrl.protocol !== "https:") {
      return res.status(400).json({
        success: false,
        error: "Only HTTPS URLs are allowed",
      });
    }

    // Validate domain whitelist
    const hostname = targetUrl.hostname.toLowerCase();
    const isAllowed = ALLOWED_DOMAINS.some((domain) =>
      hostname.includes(domain),
    );

    if (!isAllowed) {
      console.log(
        `[Proxy] Blocked request to non-whitelisted domain: ${hostname}`,
      );
      return res.status(400).json({
        success: false,
        error: `Domain not allowed. Only ${ALLOWED_DOMAINS.join(", ")} are permitted`,
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
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          Referer: "https://otakudesu.blog/",
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });

      clearTimeout(timeoutId);

      // ── Response Processing ──────────────────────────────────────────

      // Check if response is successful
      if (!response.ok) {
        console.error(
          `[Proxy] Upstream error: ${response.status} ${response.statusText}`,
        );
        return res.status(502).json({
          success: false,
          error: `Upstream server returned ${response.status}: ${response.statusText}`,
        });
      }

      // Get content type from upstream
      const contentType = response.headers.get("content-type") || "text/html";

      // Read response body
      const content = await response.text();

      console.log(
        `[Proxy] Successfully fetched ${content.length} bytes from ${hostname}`,
      );

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

      if (modifiedContent.includes("<head>")) {
        // Insert right after <head> tag
        modifiedContent = modifiedContent.replace(
          "<head>",
          `<head>\n  ${baseTag}`,
        );
        console.log(
          `[Proxy] Injected <base href="${baseUrl}/"> tag to resolve relative URLs`,
        );
      } else if (modifiedContent.includes("<html>")) {
        // If no <head> tag, insert after <html>
        modifiedContent = modifiedContent.replace(
          "<html>",
          `<html>\n<head>\n  ${baseTag}\n</head>`,
        );
        console.log(
          `[Proxy] Created <head> and injected <base href="${baseUrl}/"> tag`,
        );
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
          error: "Request timeout: upstream server took too long to respond",
        });
      }

      console.error("[Proxy] Fetch error:", fetchError.message);
      return res.status(502).json({
        success: false,
        error: `Failed to fetch from upstream server: ${fetchError.message}`,
      });
    }
  } catch (error) {
    // ── Error Handling ───────────────────────────────────────────────────
    console.error("[Proxy] Unexpected error:", error);
    return res.status(500).json({
      success: false,
      error: "Internal proxy error occurred",
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
    return res
      .status(400)
      .json({ success: false, error: "URL parameter is required" });
  }

  let targetUrl;
  try {
    targetUrl = new URL(url);
  } catch {
    return res
      .status(400)
      .json({ success: false, error: "Invalid URL format" });
  }

  if (targetUrl.protocol !== "https:" && targetUrl.protocol !== "http:") {
    return res
      .status(400)
      .json({ success: false, error: "Only HTTP/HTTPS URLs are allowed" });
  }

  const hostname = targetUrl.hostname.toLowerCase();
  const isAllowed = ALLOWED_IMAGE_DOMAINS.some(
    (d) => hostname === d || hostname.endsWith("." + d),
  );

  if (!isAllowed) {
    console.log(`[ImageProxy] Blocked: ${hostname}`);
    return res.status(403).json({
      success: false,
      error: `Domain "${hostname}" not allowed for image proxy`,
    });
  }

  console.log(
    `[ImageProxy] Fetching: ${hostname}${targetUrl.pathname.slice(0, 80)}`,
  );

  // Header lengkap menyerupai browser Chrome biasa agar lolos Cloudflare/hotlink check
  const buildImgHeaders = (referer) => ({
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    Accept: "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Sec-Fetch-Dest": "image",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-site",
    ...(referer
      ? { Referer: referer, Origin: referer.replace(/\/$/, "") }
      : {}),
  });

  // Referer map: root domain → referer yang diterima CDN tersebut
  const REFERER_MAP = {
    "kiryuu.to": "https://kiryuu.to/",
    "kiryuu.co": "https://kiryuu.co/",
    "apkomik.com": "https://apkomik.com/",
    "komiknesia.com": "https://komiknesia.com/",
    "cdnesia.my.id": "https://komiknesia.com/",
    "komikstation.co": "https://komikstation.co/",
    "komikcast.com": "https://komikcast.com/",
    "wpmanga.net": "https://wpmanga.net/",
    "mangakomik.id": "https://mangakomik.id/",
    "wp.com": "https://wordpress.com/",
    "i0.wp.com": "https://wordpress.com/",
    "i1.wp.com": "https://wordpress.com/",
    "i2.wp.com": "https://wordpress.com/",
    "i3.wp.com": "https://wordpress.com/",
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
  function fetchImageWithRedirects(
    targetUrl,
    referer,
    onResponse,
    onError,
    hops = 0,
  ) {
    if (hops > 5) {
      onError(new Error("Too many redirects"));
      return;
    }

    const isHttps = targetUrl.protocol === "https:";
    const lib = isHttps ? https : http;
    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: "GET",
      headers: buildImgHeaders(referer),
      // Skip SSL validation — cert expired/self-signed pada banyak CDN komik
      rejectUnauthorized: false,
    };

    const proxyReq = lib.request(options, (proxyRes) => {
      const status = proxyRes.statusCode || 0;
      const location = proxyRes.headers["location"];

      if (
        (status === 301 ||
          status === 302 ||
          status === 307 ||
          status === 308) &&
        location
      ) {
        proxyRes.resume(); // drain body
        let nextUrl;
        try {
          nextUrl = new URL(location, targetUrl.href);
        } catch {
          onError(new Error(`Bad redirect: ${location}`));
          return;
        }
        fetchImageWithRedirects(
          nextUrl,
          getReferer(nextUrl.hostname),
          onResponse,
          onError,
          hops + 1,
        );
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
            "base64",
          );
          res.setHeader("Content-Type", "image/gif");
          res.setHeader("Cache-Control", "no-store");
          res.setHeader("Access-Control-Allow-Origin", "*");
          res.status(200).send(TRANSPARENT_GIF);
          resolve();
          return;
        }

        const contentType = proxyRes.headers["content-type"] || "image/jpeg";
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
        if (!res.headersSent)
          res.status(502).json({ success: false, error: err.message });
        resolve();
      },
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

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  FALLBACK ROUTE: HLS Relative Path Safety Net                           ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║  MASALAH: Native <video> kadang resolve relative segment URI            ║
 * ║           terhadap PATHNAME tanpa query string →                        ║
 * ║           GET /api/proxy/seg_0.ts (bukan /api/proxy/video?url=...)      ║
 * ║           → 404 Endpoint not found di index.js.                         ║
 * ║                                                                          ║
 * ║  SOLUSI: Route ini TANGKAP SEMUA request /api/proxy/<apapun> yang       ║
 * ║          tidak match route spesifik (video/stream/image).               ║
 * ║          Jika path ber-ekstensi video/hls (.ts, .m3u8, .mp4, dll),      ║
 * ║          reconstruct URL xtwap FULL dari Referer header request m3u8,   ║
 *          lalu forward ke handler /video normal via internal redirect.    ║
 * ║                                                                          ║
 * ║  INI SAFETY NET TERAKHIR — hanya jalan kalau rewrite m3u8 gagal.        ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */
router.get("*", (req, res, next) => {
  const rawPath = req.path; // misal: /seg_0.ts
  const trimmed = rawPath.replace(/^\/+/, ""); // hilangkan leading slashes
  const clientIP = getClientIP(req);
  if (!trimmed) return next(); // root proxy path, skip

  console.log(
    "[VideoProxy] 🛟 SAFETY NET TRIGGERED: ip=" +
      clientIP +
      " | path=" +
      rawPath +
      " | query=" +
      JSON.stringify(req.query).slice(0, 100),
  );

  // Hanya tangani ekstensi yang jelas-jelas media (jangan tangani random path)
  const extMatch = trimmed.match(/\.([a-z0-9]{2,5})(?:\?|$)/i);
  const ext = extMatch ? extMatch[1].toLowerCase() : "";
  const isMediaExt = [
    "ts",
    "m3u8",
    "m4s",
    "mp4",
    "webm",
    "mkv",
    "mov",
    "aac",
    "mp3",
  ].includes(ext);
  if (!isMediaExt) {
    return next();
  }

  // ── PRIORITAS #1: Cek HLS session tracker (BERBASIS CLIENT IP) ─────────
  //    Inilah yang menyelamatkan dari Referer header diblokir CORS!
  let baseDirHref = getHLSSession(clientIP);
  let fromSession = !!baseDirHref;

  // ── PRIORITAS #2: Referer header (hanya sebagai fallback) ──────────────
  if (!baseDirHref) {
    const referer = req.headers.referer || req.headers.referrer || "";
    try {
      const refUrl = new URL(referer);
      const encodedOrig = refUrl.searchParams.get("url");
      if (encodedOrig) {
        const origM3u8 = new URL(decodeURIComponent(encodedOrig));
        baseDirHref = origM3u8.href.substring(
          0,
          origM3u8.href.lastIndexOf("/") + 1,
        );
      }
    } catch {
      /* abaikan */
    }
  }

  if (baseDirHref) {
    try {
      const segFullUrl = new URL(trimmed, baseDirHref).href;
      console.log(
        "[VideoProxy] 🛟 SAFETY NET RESOLVED: fromSession=" +
          fromSession +
          " | " +
          rawPath +
          " → " +
          segFullUrl.substring(0, 120),
      );
      const nextReq = {
        ...req,
        query: { ...req.query, url: segFullUrl },
      };
      const videoHandler = router.stack.find(
        (l) =>
          l.route &&
          l.route.path === "/video" &&
          l.route.methods &&
          l.route.methods.get,
      );
      if (videoHandler) return videoHandler.handle(nextReq, res, () => {});
    } catch (e) {
      console.error("[VideoProxy] Safety net reconstruct fail:", e.message);
    }
  }

  // Fallback: tidak bisa reconstruct
  const sessMapSize = HLSSessionMap.size;
  res.status(400).json({
    success: false,
    error:
      "[HLS Safety Net] Tidak bisa menemukan session HLS. " +
      "src=" +
      rawPath +
      " | clientIP=" +
      clientIP +
      " | sessionMapSize=" +
      sessMapSize +
      " | fromSessionTried=" +
      fromSession +
      ". PASTIKAN request m3u8 via /api/proxy/video?url=... DIJALANKAN DULU sebelum request segment!",
  });
});

export default router;
