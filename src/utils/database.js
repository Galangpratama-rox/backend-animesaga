import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

let db = null;

const initializeFirebase = () => {
  // Cegah double init
  if (getApps().length > 0) {
    db = getFirestore(getApps()[0]);
    return getApps()[0];
  }

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n");

  if (!projectId || !clientEmail || !privateKey) {
    console.warn("[Firebase] Credentials not configured — Firebase features disabled");
    return null;
  }

  try {
    const app = initializeApp({
      credential: cert({ projectId, clientEmail, privateKey })
    });
    db = getFirestore(app);
    console.log("[Firebase] Connected to Firestore project:", projectId);
    return app;
  } catch (err) {
    console.error("[Firebase] Init failed:", err.message);
    return null;
  }
};

export const getFirebaseDB = () => {
  if (!db) {
    initializeFirebase();
  }
  return db;
};

export { initializeFirebase };
