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

// Reads the JSON fixture a vector names, relative to the vectors directory.
const readFixture = async (member, name) => {
  const path = join(vectorsDir, ...name.split("/"));
  const rel = relative(vectorsDir, path);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`${member} ${JSON.stringify(name)} isn't a local path`);
  }
  return JSON.parse(await readFile(path, "utf8"));
};

// Inlines a vector's allowlistFile and rootsFile, as the Go loader does,
// because the WASM hook only sees the one vector's text. A vector without
// roots uses the pinned AMD roots.
const resolveFiles = async (vector) => {
  if (vector.allowlistFile === undefined) {
    if (vector.allowlist === undefined) throw new Error("vector has neither allowlist nor allowlistFile");
  } else {
    if (vector.allowlist !== undefined) throw new Error("vector has both allowlist and allowlistFile");
    vector.allowlist = await readFixture("allowlistFile", vector.allowlistFile);
    delete vector.allowlistFile;
  }
  if (vector.rootsFile !== undefined) {
    if (vector.roots !== undefined) throw new Error("vector has both roots and rootsFile");
    vector.roots = await readFixture("rootsFile", vector.rootsFile);
    if (Object.keys(vector.roots).length === 0) {
      throw new Error(`rootsFile ${JSON.stringify(vector.rootsFile)} has no roots`);
    }
    delete vector.rootsFile;
  }
};

const files = (await readdir(vectorsDir)).filter((f) => f.endsWith(".json")).sort();
for (const file of files) {
  const vector = JSON.parse(await readFile(join(vectorsDir, file), "utf8"));
  try {
    await resolveFiles(vector);
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
