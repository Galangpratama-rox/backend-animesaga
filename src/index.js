import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import { fileURLToPath } from "url";
import path from "path";

import levelingRoutes from "./routes/leveling.js";
import uploadRoutes from "./routes/upload.js";
import proxyRoutes from "./routes/proxy.js";
import { rateLimiter } from "./middleware/rateLimit.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requireApiKey } from "./middleware/apiKey.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// ── Resolve paths ─────────────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const UPLOADS_DIR = path.join(__dirname, "..", "uploads");

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }, // izinkan load gambar dari frontend
  contentSecurityPolicy: false, // disable CSP dari helmet (kita handle manual di proxy)
  frameguard: false, // disable X-Frame-Options untuk allow iframe embedding
}));
app.use(cors({
  origin: (origin, callback) => {
    const allowed = (process.env.ALLOWED_ORIGINS || "http://localhost:5173")
      .split(",")
      .map((o) => o.trim());
    // Izinkan request tanpa origin (server-to-server, curl, dsb)
    if (!origin || allowed.includes(origin) || allowed.includes("*")) {
      return callback(null, true);
    }
    return callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));
app.use(express.json({ limit: "10kb" }));
app.use(rateLimiter);

// ── Public routes (tidak perlu API key) ───────────────────────────────────
// Proxy image/video diakses langsung oleh browser via <img src> dan <video src>
// sehingga tidak bisa menyertakan header X-API-Key
app.use("/api/proxy", proxyRoutes);

app.use(requireApiKey); // blok request tanpa API key yang valid

// ── Static file serving untuk uploads ─────────────────────────────────────
app.use("/uploads", express.static(UPLOADS_DIR));

// Routes
app.use("/api/leveling", levelingRoutes);
app.use("/api/upload", uploadRoutes);

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// 404
app.use((_req, res) => {
  res.status(404).json({ success: false, error: "Endpoint not found" });
});

// Error handling
app.use(errorHandler);

// Start server
const server = app.listen(PORT, () => {
  console.log(`Anime Saga Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

export default app;
