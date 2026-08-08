/**
 * ════════════════════════════════════════════════
 *  LEVELING SYSTEM — Anime Saga
 * ════════════════════════════════════════════════
 *
 * Skema biaya XP (linear scaling):
 *   Level N → N+1  :  N × 100 EXP
 *
 * Total akumulasi XP untuk mencapai Level N:
 *   Σ(k=1 to N-1) k×100  =  N×(N-1)/2 × 100
 *
 * Contoh:
 *   Level 1  → 2  : 100 EXP   | Akumulasi: 100 EXP
 *   Level 2  → 3  : 200 EXP   | Akumulasi: 300 EXP
 *   Level 3  → 4  : 300 EXP   | Akumulasi: 600 EXP
 *   Level 10 → 11 : 1,000 EXP | Akumulasi: 4,500 EXP
 *   Level 50 → 51 : 5,000 EXP | Akumulasi: 122,500 EXP
 *   Level 100→ 101: 10,000 EXP| Akumulasi: 495,000 EXP
 */

export const XP_COST_MULTIPLIER   = 100;  // Level N → N+1 costs N×100 XP
export const BASE_XP_PER_EPISODE  = 50;
export const MIN_XP_PERCENTAGE    = 0.3;
export const ANTI_SPAM_COOLDOWN_HOURS = 24;
export const MAX_LEVEL            = 999;

/**
 * XP total akumulasi yang dibutuhkan untuk MENCAPAI level N (mulai dari level 1)
 * Formula: N×(N-1)/2 × 100
 */
export function xpRequiredForLevel(level) {
  const n = Math.max(1, level);
  return (n * (n - 1) / 2) * XP_COST_MULTIPLIER;
}

/**
 * Hitung level dari total XP akumulasi.
 * Balik dari formula akumulasi: solve N×(N-1)/2×100 ≤ xp
 * → N² - N - 2×xp/100 ≤ 0
 * → N = floor((1 + sqrt(1 + 8×xp/100)) / 2)
 */
export function calculateLevel(xp) {
  if (xp <= 0) return 1;
  const n = Math.floor((1 + Math.sqrt(1 + 8 * xp / XP_COST_MULTIPLIER)) / 2);
  return Math.min(Math.max(1, n), MAX_LEVEL);
}

/**
 * XP yang dibutuhkan untuk naik dari level N ke level N+1
 * = N × 100
 */
export function xpToNextLevel(level) {
  return level * XP_COST_MULTIPLIER;
}

/**
 * Hitung XP earned berdasarkan persentase tonton episode
 */
export function calculateXPEarned(watchPercentage) {
  return Math.round(
    BASE_XP_PER_EPISODE * (MIN_XP_PERCENTAGE + (1 - MIN_XP_PERCENTAGE) * Math.min(watchPercentage, 1))
  );
}

/**
 * XP progress untuk progress bar menuju level berikutnya
 * Returns: { passed, total, percentage }
 *   passed  = XP yang sudah dikumpulkan di level sekarang
 *   total   = XP yang dibutuhkan untuk naik 1 level dari level sekarang
 */
export function getXPProgress(xp, level) {
  const currentLevelBase = xpRequiredForLevel(level);     // akumulasi untuk mencapai level ini
  const nextLevelBase    = xpRequiredForLevel(level + 1); // akumulasi untuk level berikutnya
  const total            = nextLevelBase - currentLevelBase; // = level × 100
  const passed           = Math.max(0, xp - currentLevelBase);

  return {
    passed,
    total,
    percentage: Math.min((passed / total) * 100, 100)
  };
}

/**
 * Badge tier berdasarkan level
 */
export function getLevelBadge(level) {
  if (level >= 500) return "Mythic";
  if (level >= 200) return "Transcendent";
  if (level >= 100) return "Legendary";
  if (level >= 50)  return "Legend";
  if (level >= 30)  return "Master";
  if (level >= 20)  return "Expert";
  if (level >= 10)  return "Advanced";
  if (level >= 5)   return "Intermediate";
  return "Beginner";
}
