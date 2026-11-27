import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import {
  getAuth,
  setPersistence,
  browserLocalPersistence,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";
import { FIREBASE_CONFIG } from "./firebase-config.js";

export const firebaseConfigured = !Object.values(FIREBASE_CONFIG)
  .some((value) => value.startsWith("REPLACE_WITH_"));

export let auth = null;
if (firebaseConfigured) {
  const firebaseApp = initializeApp(FIREBASE_CONFIG);
  auth = getAuth(firebaseApp);
  await setPersistence(auth, browserLocalPersistence);
} else {
  console.warn("Firebase login is disabled until js/firebase-config.js is configured.");
}

export { signInWithEmailAndPassword, signOut, onAuthStateChanged };
