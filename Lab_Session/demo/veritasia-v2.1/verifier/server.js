#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║  CineVault - Age-Restricted Content Verifier             ║
 * ║  Port 9090 · Express + snarkjs                           ║
 * ║                                                          ║
 * ║  Verifies ZK proofs without learning anything about      ║
 * ║  the citizen except: "age ≥ 18".                         ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * Security model:
 *   1. Issue fresh nonce per session (anti-replay)
 *   2. Before snarkjs.verify, validate ALL public signals:
 *      - verification_nonce matches issued nonce
 *      - current_year matches server clock
 *      - age_threshold matches server policy (18)
 *      - merkle_root matches VIDAA's published root
 *   3. Only then run cryptographic verification
 *   4. Mark nonce as used (one-time)
 */

const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { execSync } = require("child_process");

const app = express();
const PORT = 9090;
const PROJECT_ROOT = path.resolve(__dirname, "..");

// ── Server Policy ──
const AGE_THRESHOLD = 18;
const CURRENT_YEAR = new Date().getFullYear();
const NONCE_TTL_MS = 5 * 60 * 1000;   // 5 minutes
const VIDAA_ROOT_URL = "http://localhost:8080/api/root";

// ── Nonce Store (in-memory for demo) ──
// Map<nonceValue, { created: timestamp, used: boolean }>
const nonceStore = new Map();

function issueNonce() {
  // Generate 6-digit numeric nonce (easy to copy-paste)
  const value = crypto.randomInt(100000, 999999);
  nonceStore.set(value, { created: Date.now(), used: false });

  // Cleanup expired nonces
  const now = Date.now();
  for (const [k, v] of nonceStore) {
    if (now - v.created > NONCE_TTL_MS * 2) nonceStore.delete(k);
  }

  return value;
}

function validateNonce(value) {
  const entry = nonceStore.get(value);
  if (!entry) return { valid: false, reason: "Unknown nonce - not issued by this server" };
  if (entry.used) return { valid: false, reason: "Nonce already used - replay attempt blocked" };
  if (Date.now() - entry.created > NONCE_TTL_MS) return { valid: false, reason: `Nonce expired (TTL: ${NONCE_TTL_MS / 1000}s)` };
  return { valid: true };
}

function markNonceUsed(value) {
  const entry = nonceStore.get(value);
  if (entry) entry.used = true;
}

// ── Fetch VIDAA root ──
async function fetchVIDAARoot() {
  try {
    // Use dynamic import for fetch (Node 18+) or http module
    const http = require("http");
    return new Promise((resolve, reject) => {
      http.get(VIDAA_ROOT_URL, { timeout: 5000 }, (res) => {
        let data = "";
        res.on("data", c => data += c);
        res.on("end", () => {
          try {
            const json = JSON.parse(data);
            resolve(json.merkle_root || null);
          } catch { resolve(null); }
        });
      }).on("error", () => resolve(null));
    });
  } catch { return null; }
}

// ── Hex→bits for root comparison ──
function hexToBits256(hexStr) {
  const bits = [];
  const buf = Buffer.from(hexStr, "hex");
  for (const byte of buf) {
    for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
  }
  return bits;
}

function bitsToHex256(bits) {
  let hex = "";
  for (let i = 0; i < 256; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | (parseInt(bits[i + j]) || 0);
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

// ── Middleware ──
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

// ══════════════════════════════════════════════════
//  API ENDPOINTS
// ══════════════════════════════════════════════════

// Issue a fresh verification nonce
app.get("/api/nonce", (req, res) => {
  const nonce = issueNonce();
  res.json({
    verification_nonce: nonce,
    current_year: CURRENT_YEAR,
    age_threshold: AGE_THRESHOLD,
    ttl_seconds: NONCE_TTL_MS / 1000,
    instructions: "Paste this nonce into your Prover app, then upload the resulting proof here.",
  });
});

// Verify a proof - the 4-check gauntlet
app.post("/api/verify", upload.fields([
  { name: "proof", maxCount: 1 },
  { name: "public_signals", maxCount: 1 },
]), async (req, res) => {
  const startTime = Date.now();
  const checks = [];

  try {
    // ── Parse uploaded files ──
    if (!req.files?.proof?.[0] || !req.files?.public_signals?.[0]) {
      return res.status(400).json({ error: "Upload both proof.json and public.json" });
    }

    let proof, publicSignals;
    try {
      proof = JSON.parse(req.files.proof[0].buffer.toString("utf-8"));
      publicSignals = JSON.parse(req.files.public_signals[0].buffer.toString("utf-8"));
    } catch {
      return res.status(400).json({ error: "Invalid JSON in uploaded files" });
    }

    if (!Array.isArray(publicSignals) || publicSignals.length < 259) {
      return res.status(400).json({ error: `Expected 259 public signals, got ${publicSignals.length}` });
    }

    // ── Extract public signals ──
    // Layout: [merkle_root[0..255], current_year[256], age_threshold[257], verification_nonce[258]]
    const proofRootBits = publicSignals.slice(0, 256);
    const proofRootHex = bitsToHex256(proofRootBits);
    const proofYear = parseInt(publicSignals[256]);
    const proofThreshold = parseInt(publicSignals[257]);
    const proofNonce = parseInt(publicSignals[258]);

    // ══════════════════════════════════════════
    //  CHECK 1: Verification nonce
    // ══════════════════════════════════════════
    const nonceCheck = validateNonce(proofNonce);
    checks.push({
      name: "Verification Nonce",
      expected: "Issued by this server, unused, not expired",
      received: String(proofNonce),
      pass: nonceCheck.valid,
      detail: nonceCheck.valid ? "Valid session nonce" : nonceCheck.reason,
    });

    if (!nonceCheck.valid) {
      return res.json({
        verified: false,
        checks,
        reason: `Nonce check failed: ${nonceCheck.reason}`,
        elapsed_ms: Date.now() - startTime,
      });
    }

    // ══════════════════════════════════════════
    //  CHECK 2: Current year
    // ══════════════════════════════════════════
    const yearPass = proofYear === CURRENT_YEAR;
    checks.push({
      name: "Current Year",
      expected: String(CURRENT_YEAR),
      received: String(proofYear),
      pass: yearPass,
      detail: yearPass ? "Matches server clock" : "Year mismatch - possible tampering",
    });

    if (!yearPass) {
      markNonceUsed(proofNonce);
      return res.json({
        verified: false,
        checks,
        reason: `Year mismatch: proof says ${proofYear}, server says ${CURRENT_YEAR}`,
        elapsed_ms: Date.now() - startTime,
      });
    }

    // ══════════════════════════════════════════
    //  CHECK 3: Age threshold
    // ══════════════════════════════════════════
    const threshPass = proofThreshold === AGE_THRESHOLD;
    checks.push({
      name: "Age Threshold",
      expected: String(AGE_THRESHOLD),
      received: String(proofThreshold),
      pass: threshPass,
      detail: threshPass ? "Matches server policy" : "Threshold mismatch - possible downgrade attack",
    });

    if (!threshPass) {
      markNonceUsed(proofNonce);
      return res.json({
        verified: false,
        checks,
        reason: `Threshold mismatch: proof says ≥${proofThreshold}, policy requires ≥${AGE_THRESHOLD}`,
        elapsed_ms: Date.now() - startTime,
      });
    }

    // ══════════════════════════════════════════
    //  CHECK 4: Merkle root matches VIDAA
    // ══════════════════════════════════════════
    const vidaaRoot = await fetchVIDAARoot();
    let rootPass = false;
    let rootDetail = "";

    if (!vidaaRoot) {
      rootDetail = "Could not reach VIDAA /api/root - is it running on :8080?";
    } else if (vidaaRoot === proofRootHex) {
      rootPass = true;
      rootDetail = "Matches VIDAA published root";
    } else {
      rootDetail = `Root mismatch - proof root doesn't match VIDAA's current tree`;
    }

    checks.push({
      name: "Merkle Root",
      expected: vidaaRoot ? `0x${vidaaRoot.slice(0, 20)}...` : "VIDAA unavailable",
      received: `0x${proofRootHex.slice(0, 20)}...`,
      pass: rootPass,
      detail: rootDetail,
    });

    if (!rootPass) {
      markNonceUsed(proofNonce);
      return res.json({
        verified: false,
        checks,
        reason: rootDetail,
        elapsed_ms: Date.now() - startTime,
      });
    }

    // ══════════════════════════════════════════
    //  CHECK 5: Groth16 cryptographic verification
    // ══════════════════════════════════════════
    const vkPath = path.join(PROJECT_ROOT, "circuits", "verification_key.json");
    if (!fs.existsSync(vkPath)) {
      return res.status(500).json({ error: "verification_key.json not found. Run: node circuits/build.js" });
    }

    // Write temp files for snarkjs CLI
    const sessionId = crypto.randomBytes(8).toString("hex");
    const tempDir = path.join(__dirname, "temp", sessionId);
    fs.mkdirSync(tempDir, { recursive: true });

    const proofPath = path.join(tempDir, "proof.json");
    const publicPath = path.join(tempDir, "public.json");
    fs.writeFileSync(proofPath, JSON.stringify(proof));
    fs.writeFileSync(publicPath, JSON.stringify(publicSignals));

    let groth16Pass = false;
    let groth16Detail = "";

    try {
      const result = execSync(
        `npx snarkjs groth16 verify circuits/verification_key.json "${publicPath}" "${proofPath}"`,
        { cwd: PROJECT_ROOT, stdio: ["pipe", "pipe", "pipe"], timeout: 30000 }
      ).toString().trim();

      groth16Pass = result.toLowerCase().includes("ok");
      groth16Detail = groth16Pass ? "snarkJS: OK!" : result;
    } catch (err) {
      const output = err.stdout?.toString() || err.stderr?.toString() || "verification failed";
      groth16Detail = output.trim().slice(0, 200);
    }

    // Clean temp
    fs.rmSync(tempDir, { recursive: true, force: true });

    checks.push({
      name: "Groth16 Proof",
      expected: "Valid cryptographic proof",
      received: groth16Pass ? "OK" : "INVALID",
      pass: groth16Pass,
      detail: groth16Detail,
    });

    // ── Mark nonce as used (regardless of groth16 result) ──
    markNonceUsed(proofNonce);

    const verified = groth16Pass;
    const elapsed = Date.now() - startTime;

    res.json({
      verified,
      checks,
      reason: verified
        ? "All checks passed - citizen is verified as age ≥ 18"
        : "Groth16 proof verification failed",
      elapsed_ms: elapsed,
      transparency: {
        what_cinevault_learned: [
          "Citizen is at least 18 years old",
          `Citizen is registered in VIDAA Merkle tree (root: 0x${proofRootHex.slice(0, 16)}...)`,
        ],
        what_cinevault_did_NOT_learn: [
          "Citizen's name",
          "Citizen's birth year or exact age",
          "Citizen's ID or leaf index",
          "Citizen's secret or nonce",
          "Which leaf in the tree belongs to this citizen",
        ],
      },
    });

  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).json({ error: "Internal verification error", detail: err.message });
  }
});

// Server status
app.get("/api/status", async (req, res) => {
  const vidaaRoot = await fetchVIDAARoot();
  const vkExists = fs.existsSync(path.join(PROJECT_ROOT, "circuits", "verification_key.json"));
  res.json({
    server: "CineVault Verifier",
    port: PORT,
    policy: { age_threshold: AGE_THRESHOLD, current_year: CURRENT_YEAR },
    vidaa_connected: !!vidaaRoot,
    vidaa_root: vidaaRoot ? `0x${vidaaRoot.slice(0, 24)}...` : null,
    verification_key_loaded: vkExists,
    active_nonces: [...nonceStore.entries()].filter(([, v]) => !v.used && Date.now() - v.created < NONCE_TTL_MS).length,
  });
});

// ── Start ──
app.listen(PORT, () => {
  console.log("");
  console.log("══════════════════════════════════════════════════");
  console.log("  🎬 CineVault - Age-Restricted Content Verifier");
  console.log(`  🌐 Portal: http://localhost:${PORT}`);
  console.log(`  📋 Policy: age ≥ ${AGE_THRESHOLD} (year ${CURRENT_YEAR})`);
  console.log(`  🔗 VIDAA:  ${VIDAA_ROOT_URL}`);
  console.log("══════════════════════════════════════════════════");
  console.log("");
});
