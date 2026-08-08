/**
 * upload.js — Route untuk upload foto profil & banner
 *
 * POST /api/upload/profile-image
 *   field : profile_image (multipart/form-data)
 *   Format: JPEG, PNG, WebP, GIF
 *   Limit : 5MB
 *   Returns: { success: true, url: "https://..." }
 *
 * Validasi berlapis:
 *   1. MIME type dari header (frontend check)
 *   2. Ekstensi file — hanya .jpg/.jpeg/.png/.webp/.gif yang diizinkan
 *   3. Magic bytes — baca byte pertama file untuk verifikasi format asli
 *      Ini yang paling penting: tidak bisa dipalsukan
 */

import { Router } from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";

const router = Router();

// ── Resolve uploads directory ───────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const UPLOADS_DIR = path.join(__dirname, "..", "..", "uploads");

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// ── Whitelist ───────────────────────────────────────────────────────────────
const ALLOWED_MIME = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
]);

// Ekstensi yang diizinkan — peta dari MIME ke ekstensi yang dipakai untuk simpan
const MIME_TO_EXT = {
  "image/jpeg": ".jpg",
  "image/png":  ".png",
  "image/webp": ".webp",
  "image/gif":  ".gif",
};

const MAX_SIZE_BYTES = 5 * 1024 * 1024; // 5MB

// ── Magic bytes signatures ───────────────────────────────────────────────────
// Setiap format gambar punya urutan byte unik di awal file yang tidak bisa dipalsukan
const MAGIC_BYTES = [
  // JPEG: FF D8 FF
  { mime: "image/jpeg", offset: 0, bytes: [0xFF, 0xD8, 0xFF] },
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  { mime: "image/png",  offset: 0, bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
  // GIF: 47 49 46 38 (GIF8)
  { mime: "image/gif",  offset: 0, bytes: [0x47, 0x49, 0x46, 0x38] },
  // WebP: 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 (RIFF....WEBP)
  { mime: "image/webp", offset: 0, bytes: [0x52, 0x49, 0x46, 0x46], secondCheck: { offset: 8, bytes: [0x57, 0x45, 0x42, 0x50] } },
];

/**
 * Baca magic bytes dari file yang sudah tersimpan di disk
 * dan cocokkan dengan signature yang dikenal.
 * @returns {string|null} MIME type yang terdeteksi, atau null kalau tidak cocok
 */
function detectMimeFromMagicBytes(filePath) {
  // Baca 12 byte pertama — cukup untuk semua format yang kita support
  const fd = fs.openSync(filePath, "r");
  const buf = Buffer.alloc(12);
  fs.readSync(fd, buf, 0, 12, 0);
  fs.closeSync(fd);

  for (const sig of MAGIC_BYTES) {
    const chunk = buf.slice(sig.offset, sig.offset + sig.bytes.length);
    if (chunk.equals(Buffer.from(sig.bytes))) {
      // WebP butuh pengecekan kedua (byte 8-11 harus "WEBP")
      if (sig.secondCheck) {
        const chunk2 = buf.slice(sig.secondCheck.offset, sig.secondCheck.offset + sig.secondCheck.bytes.length);
        if (!chunk2.equals(Buffer.from(sig.secondCheck.bytes))) continue;
      }
      return sig.mime;
    }
  }
  return null; // tidak dikenal
}

// ── Multer config — simpan ke memori dulu, baru validasi, baru tulis ke disk ─
// Pakai memoryStorage supaya bisa validasi magic bytes sebelum file menyentuh disk
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_SIZE_BYTES },
  fileFilter: (_req, file, cb) => {
    // Layer 1: cek MIME dari header
    if (!ALLOWED_MIME.has(file.mimetype)) {
      return cb(new Error("Format tidak didukung. Gunakan JPG, PNG, WebP, atau GIF."), false);
    }

    // Layer 2: cek ekstensi dari nama file original
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExts = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif"]);
    if (ext && !allowedExts.has(ext)) {
      return cb(new Error("Ekstensi file tidak diizinkan."), false);
    }

    cb(null, true);
  },
});

// ── Helper: build public URL ─────────────────────────────────────────────────
function buildFileUrl(req, filename) {
  const base =
    process.env.BACKEND_PUBLIC_URL ||
    `${req.protocol}://${req.get("host")}`;
  return `${base}/uploads/${filename}`;
}

// ── POST /api/upload/profile-image ──────────────────────────────────────────
router.post(
  "/profile-image",
  // Step 1: multer parse + layer 1 & 2 validasi
  (req, res, next) => {
    upload.single("profile_image")(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(413).json({
            success: false,
            message: "Ukuran file terlalu besar. Maksimal 5MB.",
          });
        }
        return res.status(400).json({ success: false, message: err.message });
      }
      if (err) {
        return res.status(400).json({ success: false, message: err.message });
      }
      next();
    });
  },
  // Step 2: validasi magic bytes (layer 3) + tulis ke disk
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Tidak ada file yang diunggah.",
      });
    }

    // Layer 3: validasi magic bytes dari buffer di memori
    const buf = req.file.buffer;
    const header = buf.slice(0, 12);
    let detectedMime = null;

    for (const sig of MAGIC_BYTES) {
      const chunk = header.slice(sig.offset, sig.offset + sig.bytes.length);
      if (chunk.equals(Buffer.from(sig.bytes))) {
        if (sig.secondCheck) {
          const chunk2 = header.slice(sig.secondCheck.offset, sig.secondCheck.offset + sig.secondCheck.bytes.length);
          if (!chunk2.equals(Buffer.from(sig.secondCheck.bytes))) continue;
        }
        detectedMime = sig.mime;
        break;
      }
    }

    if (!detectedMime) {
      console.warn(`[Upload] BLOCKED — magic bytes tidak cocok. MIME klaim: ${req.file.mimetype}, size: ${req.file.size}`);
      return res.status(400).json({
        success: false,
        message: "File ditolak. Konten file tidak sesuai format gambar yang diizinkan.",
      });
    }

    // Pastikan MIME dari magic bytes cocok dengan yang diklaim
    if (detectedMime !== req.file.mimetype) {
      console.warn(`[Upload] BLOCKED — MIME mismatch. Klaim: ${req.file.mimetype}, Aktual: ${detectedMime}`);
      return res.status(400).json({
        success: false,
        message: "File ditolak. Tipe file tidak sesuai dengan isinya.",
      });
    }

    // Semua validasi lolos — tulis ke disk dengan ekstensi yang aman (dari MIME, bukan dari nama file)
    const safeExt  = MIME_TO_EXT[detectedMime];
    const filename = `${uuidv4()}${safeExt}`;
    const destPath = path.join(UPLOADS_DIR, filename);

    try {
      fs.writeFileSync(destPath, buf);
    } catch (writeErr) {
      console.error("[Upload] Gagal menulis file:", writeErr);
      return res.status(500).json({ success: false, message: "Gagal menyimpan file." });
    }

    const url = buildFileUrl(req, filename);
    console.log(`[Upload] OK — ${filename} (${req.file.size} bytes, ${detectedMime})`);

    return res.json({ success: true, url });
  }
);

export default router;
