// Runs every conformance vector through the sealtest WASM build, via the JS
// wrapper, under Node.js, and compares each outcome with the vector's
// expectation, which the Go suite checks too.
//
//   node js/test/run-vectors.mjs <wasm_exec.js> <fabai-seal-test.wasm> <vectors dir>

import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { isAbsolute, join, relative } from "node:path";
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
  // Expected: a bundle digest mismatch is refused.
}

await loadSeal(wasm, digest);
const exports = Object.keys(globalThis.fabaiSeal).sort();
if (!isDeepStrictEqual(exports, ["check"])) {
  fail(`fabaiSeal exports ${exports}, want only check, so nothing can override a root`);
}

// Inlines a vector's allowlistFile, as the Go loader does, because the WASM
// hook only sees the one vector's text.
const resolveAllowlist = async (vector) => {
  if (vector.allowlistFile === undefined) {
    if (vector.allowlist === undefined) throw new Error("vector has neither allowlist nor allowlistFile");
    return;
  }
  if (vector.allowlist !== undefined) throw new Error("vector has both allowlist and allowlistFile");
  const path = join(vectorsDir, ...vector.allowlistFile.split("/"));
  const rel = relative(vectorsDir, path);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`allowlistFile ${JSON.stringify(vector.allowlistFile)} isn't a local path`);
  }
  vector.allowlist = JSON.parse(await readFile(path, "utf8"));
  delete vector.allowlistFile;
};

const files = (await readdir(vectorsDir)).filter((f) => f.endsWith(".json")).sort();
for (const file of files) {
  const vector = JSON.parse(await readFile(join(vectorsDir, file), "utf8"));
  try {
    await resolveAllowlist(vector);
    const got = JSON.parse(await globalThis.fabaiSealTest.runVector(JSON.stringify(vector)));
    if (!isDeepStrictEqual(got, vector.expect)) {
      fail(`${vector.name}: got ${JSON.stringify(got)}, want ${JSON.stringify(vector.expect)}`);
    }
  } catch (err) {
    fail(`${vector.name}: ${err}`);
  }
}

console.log(`${files.length - failures} of ${files.length} vectors passed under Node.js ${process.version}`);
process.exit(failures === 0 ? 0 : 1);
