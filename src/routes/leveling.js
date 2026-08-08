import { Router } from "express";
import { getFirebaseDB } from "../utils/database.js";
import { xpEventLimiter } from "../middleware/rateLimit.js";
import {
  calculateLevel,
  calculateXPEarned,
  getXPProgress,
  getLevelBadge,
  xpToNextLevel,
  ANTI_SPAM_COOLDOWN_HOURS
} from "../utils/leveling.js";

const router = Router();

// ─────────────────────────────────────────────
// POST /api/leveling/add-xp
// Tambah XP user saat menonton anime/donghua
// ─────────────────────────────────────────────
router.post("/add-xp", xpEventLimiter, async (req, res) => {
  try {
    const {
      uid,
      xpAmount,
      animeId,
      animeTitle,
      thumbnail,
      episodeTitle,
      watchDuration,
      totalDuration
    } = req.body;

    if (!uid || !xpAmount || xpAmount <= 0) {
      return res.status(400).json({ success: false, error: "uid dan xpAmount wajib diisi" });
    }

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    const userRef = db.doc(`users/${uid}`);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      await userRef.set({
        xp: 0,
        level: 1,
        is_history_public: true,
        created_at: new Date(),
        updated_at: new Date()
      });
    }

    const userData = userSnap.exists ? userSnap.data() : { xp: 0, level: 1 };
    const now = new Date();

    // Anti-spam: anime yang sama dalam cooldown window tidak dapat XP
    if (userData.last_watch_anime_id === animeId && userData.last_watch_date) {
      const lastDate = userData.last_watch_date.toDate
        ? userData.last_watch_date.toDate()
        : new Date(userData.last_watch_date);
      const hoursDiff = (now - lastDate) / (1000 * 60 * 60);
      if (hoursDiff < ANTI_SPAM_COOLDOWN_HOURS) {
        return res.json({
          success: true,
          earned: 0,
          reason: "cooldown",
          xpProgress: getXPProgress(userData.xp || 0, calculateLevel(userData.xp || 0))
        });
      }
    }

    // Hitung XP berdasarkan persentase tonton jika durasi tersedia
    const actualXPEarned = totalDuration && totalDuration > 0
      ? calculateXPEarned(watchDuration / totalDuration)
      : xpAmount;

    const newXP = (userData.xp || 0) + actualXPEarned;
    const newLevel = calculateLevel(newXP);

    // Update XP user
    await userRef.update({
      xp: newXP,
      level: newLevel,
      last_watch_anime_id: animeId,
      last_watch_date: now,
      updated_at: now
    });

    // Log XP event (non-blocking)
    db.collection(`xp_events/${uid}/events`).add({
      xp_amount: actualXPEarned,
      anime_id: animeId,
      created_at: now
    }).catch((e) => console.warn("[Leveling] xp_events write failed:", e.message));

    // Simpan ke watch history
    const historyRef = db.doc(`users/${uid}/watch_history/${animeId || String(Date.now())}`);
    await historyRef.set({
      anime_id: animeId || null,
      title: animeTitle || "",
      thumbnail: thumbnail || "",
      episode_title: episodeTitle || "",
      watched_at: now,
      xp_earned: actualXPEarned
    }, { merge: true });

    res.json({
      success: true,
      earned: actualXPEarned,
      newXP,
      newLevel,
      badge: getLevelBadge(newLevel),
      xpProgress: getXPProgress(newXP, newLevel)
    });

  } catch (error) {
    console.error("[Leveling] Add XP error:", error);
    res.status(500).json({ success: false, error: "Gagal menambahkan XP" });
  }
});

// ─────────────────────────────────────────────
// GET /api/leveling/user/:uid
// Ambil data level user
// ─────────────────────────────────────────────
router.get("/user/:uid", async (req, res) => {
  try {
    const { uid } = req.params;

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    const userSnap = await db.doc(`users/${uid}`).get();

    if (!userSnap.exists) {
      return res.json({
        success: true,
        uid,
        xp: 0,
        level: 1,
        badge: getLevelBadge(1),
        is_history_public: true,
        xpProgress: getXPProgress(0, 1)
      });
    }

    const userData = userSnap.data();
    // Prioritaskan field level dari Firestore, fallback ke kalkulasi dari XP
    const level = userData.level || calculateLevel(userData.xp || 0);

    res.json({
      success: true,
      uid,
      xp: userData.xp || 0,
      level,
      badge: getLevelBadge(level),
      is_history_public: userData.is_history_public ?? true,
      last_watch_date: userData.last_watch_date || null,
      xpProgress: getXPProgress(userData.xp || 0, level)
    });

  } catch (error) {
    console.error("[Leveling] Get user error:", error);
    res.status(500).json({ success: false, error: "Gagal mengambil data user" });
  }
});

// ─────────────────────────────────────────────
// GET /api/leveling/user/:uid/full-profile
// Ambil profil lengkap: info user + level + history
// Dipakai di UserProfile page & mini popup chat
// Query: ?viewer_uid=xxx&history_limit=10
// ─────────────────────────────────────────────
router.get("/user/:uid/full-profile", async (req, res) => {
  try {
    const { uid } = req.params;
    const { viewer_uid, history_limit = "10" } = req.query;
    const limit = Math.min(parseInt(history_limit) || 10, 20);

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    const userSnap = await db.doc(`users/${uid}`).get();

    if (!userSnap.exists) {
      return res.status(404).json({ success: false, error: "User tidak ditemukan" });
    }

    const userData = userSnap.data();
    const xp    = userData.xp || 0;
    const level = userData.level || calculateLevel(xp);
    const isPublic = userData.is_history_public ?? true;

    // Ambil history hanya kalau publik atau dilihat oleh diri sendiri
    let history = [];
    const canSeeHistory = isPublic || viewer_uid === uid;
    if (canSeeHistory) {
      const histSnap = await db
        .collection(`users/${uid}/watch_history`)
        .orderBy("watched_at", "desc")
        .limit(limit)
        .get();
      history = histSnap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    }

    res.json({
      success: true,
      uid,
      displayName:      userData.displayName || "User",
      photoURL:         userData.photoURL    || "",
      bannerURL:        userData.bannerURL   || "",
      email:            userData.email       || "",
      xp,
      level,
      badge:            getLevelBadge(level),
      is_history_public: isPublic,
      last_watch_date:  userData.last_watch_date || null,
      created_at:       userData.created_at || null,
      xpProgress:       getXPProgress(xp, level),
      history_visible:  canSeeHistory,
      history
    });

  } catch (error) {
    console.error("[Leveling] Full profile error:", error);
    res.status(500).json({ success: false, error: "Gagal mengambil profil" });
  }
});

// ─────────────────────────────────────────────
// GET /api/leveling/user/:uid/history
// Ambil watch history user
// Query: ?viewer_uid=xxx
// ─────────────────────────────────────────────
router.get("/user/:uid/history", async (req, res) => {
  try {
    const { uid } = req.params;
    const { viewer_uid } = req.query;

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    const userSnap = await db.doc(`users/${uid}`).get();

    if (!userSnap.exists) {
      return res.json({ success: true, is_public: true, history: [] });
    }

    const userData = userSnap.data();

    // Cek privasi — kalau private dan bukan diri sendiri, tolak
    if (!userData.is_history_public && viewer_uid !== uid) {
      return res.json({
        success: true,
        is_public: false,
        message: "History bersifat private",
        history: []
      });
    }

    const historySnap = await db
      .collection(`users/${uid}/watch_history`)
      .orderBy("watched_at", "desc")
      .limit(20)
      .get();

    const history = historySnap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    res.json({
      success: true,
      is_public: userData.is_history_public ?? true,
      history
    });

  } catch (error) {
    console.error("[Leveling] Get history error:", error);
    res.status(500).json({ success: false, error: "Gagal mengambil history" });
  }
});

// ─────────────────────────────────────────────
// PUT /api/leveling/user/:uid/privacy
// Update setting privasi history user
// Body: { is_public: boolean }
// ─────────────────────────────────────────────
router.put("/user/:uid/privacy", async (req, res) => {
  try {
    const { uid } = req.params;
    const { is_public } = req.body;

    if (typeof is_public !== "boolean") {
      return res.status(400).json({ success: false, error: "is_public harus boolean" });
    }

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    const now = new Date();
    await Promise.all([
      db.doc(`users/${uid}`).set({ is_history_public: is_public, updated_at: now }, { merge: true }),
      db.doc(`users/${uid}/settings/privacy`).set({ is_history_public: is_public, updated_at: now }, { merge: true })
    ]);

    res.json({ success: true, is_public });

  } catch (error) {
    console.error("[Leveling] Update privacy error:", error);
    res.status(500).json({ success: false, error: "Gagal update privasi" });
  }
});

// ─────────────────────────────────────────────
// GET /api/leveling/leaderboard
// Leaderboard top users berdasarkan XP
// Query: ?limit=50
// ─────────────────────────────────────────────
router.get("/leaderboard", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    // Ambil semua user tanpa orderBy — sort di memory untuk hindari butuh Firestore index
    const snapshot = await db.collection("users").get();

    const users = snapshot.docs
      .map((doc) => {
        const data = doc.data();
        const xp = data.xp || 0;
        // Prioritaskan field level dari Firestore, fallback ke kalkulasi dari XP
        const level = data.level || calculateLevel(xp);
        return {
          uid: doc.id,
          displayName: data.displayName || "Anonymous",
          photoURL: data.photoURL || "",
          xp,
          level,
          badge: getLevelBadge(level)
        };
      })
      .sort((a, b) => b.xp - a.xp)
      .slice(0, limit);

    res.json({ success: true, users });

  } catch (error) {
    console.error("[Leveling] Leaderboard error:", error);
    res.status(500).json({ success: false, error: "Gagal mengambil leaderboard" });
  }
});

// ─────────────────────────────────────────────
// PUT /api/leveling/admin/user/:uid
// Admin: override XP & level user secara manual
// Body: { xp: number, level: number }
// ─────────────────────────────────────────────
router.put("/admin/user/:uid", async (req, res) => {
  try {
    const { uid } = req.params;
    const { xp, level } = req.body;

    if (typeof xp !== "number" || typeof level !== "number" || xp < 0 || level < 1) {
      return res.status(400).json({ success: false, error: "xp dan level harus number yang valid" });
    }

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    await db.doc(`users/${uid}`).set({
      xp,
      level,
      updated_at: new Date()
    }, { merge: true });

    res.json({
      success: true,
      uid,
      xp,
      level,
      badge: getLevelBadge(level),
      xpProgress: getXPProgress(xp, level)
    });

  } catch (error) {
    console.error("[Leveling] Admin update user error:", error);
    res.status(500).json({ success: false, error: "Gagal update data user" });
  }
});

// ─────────────────────────────────────────────
// GET /api/leveling/admin/users
// Admin: list semua user dengan data leveling
// Query: ?limit=50&startAfter=<uid>
// ─────────────────────────────────────────────
router.get("/admin/users", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const { startAfter } = req.query;

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    // Ambil SEMUA user tanpa orderBy — tidak butuh Firestore index
    const snapshot = await db.collection("users").get();

    let allUsers = snapshot.docs.map((doc) => {
      const data = doc.data();
      const xp = data.xp || 0;
      // Prioritaskan field level dari Firestore, fallback ke kalkulasi dari XP
      const level = data.level || calculateLevel(xp);
      return {
        uid: doc.id,
        displayName: data.displayName || "",
        email: data.email || "",
        photoURL: data.photoURL || "",
        xp,
        level,
        badge: getLevelBadge(level),
        is_history_public: data.is_history_public ?? true,
        last_watch_date: data.last_watch_date || null,
        created_at: data.created_at || null
      };
    });

    // Sort XP desc di memory
    allUsers.sort((a, b) => b.xp - a.xp);

    // Pagination offset berdasarkan startAfter uid
    let startIdx = 0;
    if (startAfter) {
      const idx = allUsers.findIndex((u) => u.uid === startAfter);
      if (idx !== -1) startIdx = idx + 1;
    }

    const paged = allUsers.slice(startIdx, startIdx + limit);
    const nextStartAfter = startIdx + limit < allUsers.length ? paged[paged.length - 1]?.uid : null;

    res.json({
      success: true,
      users: paged,
      total: allUsers.length,
      nextStartAfter
    });

  } catch (error) {
    console.error("[Leveling] Admin get users error:", error);
    res.status(500).json({ success: false, error: "Gagal mengambil data users" });
  }
});

// ─────────────────────────────────────────────
// DELETE /api/leveling/admin/user/:uid/history
// Admin: hapus seluruh watch history user
// ─────────────────────────────────────────────
router.delete("/admin/user/:uid/history", async (req, res) => {
  try {
    const { uid } = req.params;

    const db = getFirebaseDB();
    if (!db) {
      return res.status(503).json({ success: false, error: "Database tidak terkonfigurasi" });
    }

    const historySnap = await db.collection(`users/${uid}/watch_history`).get();
    const batch = db.batch();
    historySnap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    res.json({ success: true, deleted: historySnap.size });

  } catch (error) {
    console.error("[Leveling] Delete history error:", error);
    res.status(500).json({ success: false, error: "Gagal menghapus history" });
  }
});

export default router;
