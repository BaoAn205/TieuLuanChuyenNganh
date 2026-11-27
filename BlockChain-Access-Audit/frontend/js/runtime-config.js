// Public runtime settings for local development and hosted deployment.
// Set apiBaseUrl to the deployed FastAPI URL before publishing to Firebase Hosting.
window.BANCOLLECT_CONFIG = Object.freeze({
  apiBaseUrl: "http://127.0.0.1:8000",
  chainId: "0x7a69",
  chainName: "Ganache Local",
  rpcUrl: "http://127.0.0.1:8546",
});
