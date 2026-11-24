// FabAI seal check: JavaScript wrapper for the WASM build.
//
// The kiosk loads the bundle from a local copy and pins its SHA-256. Load
// wasm_exec.js from the same Go toolchain first; it defines globalThis.Go.
//
//   import { loadSeal } from "./seal.mjs";
//   const seal = await loadSeal(wasmBytes, PINNED_SHA256);
//   const result = await seal.check({ baseURL, enclave });
//   if (result.permitted) { /* seal one request body to result.hpkeKey with ehbp */ }
//
// result: { ticks: {hardware, software, gpu}, permitted, message, entryId?,
//           detail, hpkeKey? }. hpkeKey is present only when all three ticks
// pass. Run a new check before every send; never reuse a key.

const hex = (buffer) =>
  Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Instantiates the seal check after checking the bundle against its pinned
 * digest. Throws, and so leaves the Protected pane unable to send, if the
 * digest differs.
 * @param {ArrayBuffer|Uint8Array} wasmBytes the bundle
 * @param {string} pinnedSha256 the bundle's published SHA-256, lowercase hex
 */
export async function loadSeal(wasmBytes, pinnedSha256) {
  const digest = hex(await globalThis.crypto.subtle.digest("SHA-256", wasmBytes));
  if (digest !== pinnedSha256) {
    throw new Error(`seal bundle digest ${digest} isn't the pinned ${pinnedSha256}`);
  }
  if (typeof globalThis.Go !== "function") {
    throw new Error("load wasm_exec.js from the bundle's Go toolchain first");
  }
  const go = new globalThis.Go();
  const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
  go.run(instance);
  const api = globalThis.fabaiSeal;
  if (!api || typeof api.check !== "function") {
    throw new Error("the seal bundle didn't register fabaiSeal.check");
  }
  return {
    /**
     * Runs one seal check with a fresh nonce.
     * @param {{baseURL: string, enclave?: string}} target
     */
    check: ({ baseURL, enclave = "" }) => api.check(baseURL, enclave),
  };
}
