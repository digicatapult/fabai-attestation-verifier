// Runs every conformance vector through the sealtest WASM build, via the JS
// wrapper, under Node.js, and compares each outcome with the vector's
// expectation, which the Go suite checks too.
//
//   node js/test/run-vectors.mjs <wasm_exec.js> <fabai-seal-test.wasm> <vectors dir>

import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { loadSeal } from "../seal.mjs";

const [wasmExec, wasmPath, vectorsDir] = process.argv.slice(2);
if (!wasmExec || !wasmPath || !vectorsDir) {
  console.error("usage: run-vectors.mjs <wasm_exec.js> <wasm> <vectors dir>");
  process.exit(2);
}

await import(pathToFileURL(wasmExec).href);
const wasm = await readFile(wasmPath);
const digest = createHash("sha256").update(wasm).digest("hex");

let failures = 0;
const fail = (message) => {
  failures++;
  console.error(`FAIL ${message}`);
};

try {
  await loadSeal(wasm, "0".repeat(64));
  fail("loadSeal accepted a bundle whose digest isn't the pinned one");
} catch {
  // Expected: seal-check "Bundle digest mismatch".
}

await loadSeal(wasm, digest);
const exports = Object.keys(globalThis.fabaiSeal).sort();
if (!isDeepStrictEqual(exports, ["check"])) {
  fail(`fabaiSeal exports ${exports}, want only check (seal-check "No root override")`);
}

const files = (await readdir(vectorsDir)).filter((f) => f.endsWith(".json")).sort();
for (const file of files) {
  const text = await readFile(join(vectorsDir, file), "utf8");
  const vector = JSON.parse(text);
  try {
    const got = JSON.parse(await globalThis.fabaiSealTest.runVector(text));
    if (!isDeepStrictEqual(got, vector.expect)) {
      fail(`${vector.name}: got ${JSON.stringify(got)}, want ${JSON.stringify(vector.expect)}`);
    }
  } catch (err) {
    fail(`${vector.name}: ${err}`);
  }
}

console.log(`${files.length - failures} of ${files.length} vectors passed under Node.js ${process.version}`);
process.exit(failures === 0 ? 0 : 1);
