// Firebase web configuration is public client configuration, not a service-account key.
// Replace these values from Firebase Console > Project settings > Your apps.
export const FIREBASE_CONFIG = {
  apiKey: "AIzaSyAj9XA07gw_r4lCWgn8W3MsH30XYcFwj3M",
  authDomain: "tieuluanchuyennganh-551bf.firebaseapp.com",
  projectId: "tieuluanchuyennganh-551bf",
  appId: "1:684301415007:web:3bbeb061f6f709150ae1ea",
};

export const API_BASE_URL = window.APP_CONFIG?.API_BASE_URL || "http://127.0.0.1:8000";
export const EVM_CHAIN_ID = window.APP_CONFIG?.CHAIN_ID || "0x7a69";
export const EVM_CHAIN_NAME = window.APP_CONFIG?.CHAIN_NAME || "Hardhat Local";
export const EVM_RPC_URL = window.APP_CONFIG?.CHAIN_RPC_URL || "http://127.0.0.1:8546";
