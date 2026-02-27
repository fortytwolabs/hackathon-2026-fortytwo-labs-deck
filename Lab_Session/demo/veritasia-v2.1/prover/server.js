#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║  Alex's Prover - Personal Proof Generation Device        ║
 * ║  Port 7070 · Express + snarkjs                           ║
 * ║                                                          ║
 * ║  In production this runs on the citizen's own device.    ║
 * ║  Private data (wallet) NEVER leaves this server.         ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * Endpoints:
 *   GET  /              → Prover UI
 *   POST /generate      → Upload wallet + nonce → returns proof + public signals
 *   GET  /download/:file → Download proof.json or public.json
 */

const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { execSync } = require("child_process");
const crypto = require("crypto");

const app = express();
const PORT = 7070;
const PROJECT_ROOT = path.resolve(__dirname, "..");

// Multer: store uploaded wallet in memory
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });

// Serve static UI
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

// ── hex→bits conversion (must match circuit expectations) ──
function hexToBits(hexStr, numBits) {
  const buf = Buffer.from(hexStr, "hex");
  const bits = [];
  for (const byte of buf) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  if (numBits && bits.length !== numBits) {
    throw new Error(`Expected ${numBits} bits, got ${bits.length}`);
  }
  return bits;
}

// ── Proof generation endpoint ──
app.post("/generate", upload.single("wallet"), async (req, res) => {
  const startTime = Date.now();

  try {
    // 1. Parse wallet
    if (!req.file) return res.status(400).json({ error: "No wallet file uploaded" });

    let wallet;
    try {
      wallet = JSON.parse(req.file.buffer.toString("utf-8"));
    } catch {
      return res.status(400).json({ error: "Invalid wallet JSON" });
    }

    // Validate wallet shape
    const required = ["birth_year", "citizen_secret_hex", "nonce_issuance_hex",
                      "path_siblings_hex", "path_indices", "merkle_root_hex"];
    for (const key of required) {
      if (!(key in wallet)) {
        return res.status(400).json({ error: `Wallet missing field: ${key}` });
      }
    }

    // 2. Parse verifier params
    const verificationNonce = parseInt(req.body.verification_nonce);
    const currentYear = parseInt(req.body.current_year || "2026");
    const ageThreshold = parseInt(req.body.age_threshold || "18");

    if (isNaN(verificationNonce) || verificationNonce <= 0) {
      return res.status(400).json({ error: "Invalid verification nonce - get one from CineVault" });
    }

    // 3. Age pre-check
    const sum = wallet.birth_year + ageThreshold;
    if (sum > currentYear) {
      return res.status(400).json({
        error: `Age check will fail: ${wallet.birth_year} + ${ageThreshold} = ${sum} > ${currentYear}. Citizen is underage.`,
        underage: true,
      });
    }

    // 4. Build circuit input (hex → bits conversion)
    const input = {
      birth_year: String(wallet.birth_year),
      citizen_secret: hexToBits(wallet.citizen_secret_hex, 256).map(String),
      nonce_issuance: hexToBits(wallet.nonce_issuance_hex, 128).map(String),
      path_siblings: wallet.path_siblings_hex.map(h => hexToBits(h, 256).map(String)),
      path_indices: wallet.path_indices.map(String),
      merkle_root: hexToBits(wallet.merkle_root_hex, 256).map(String),
      current_year: String(currentYear),
      age_threshold: String(ageThreshold),
      verification_nonce: String(verificationNonce),
    };

    // 5. Write input to temp file
    const sessionId = crypto.randomBytes(8).toString("hex");
    const tempDir = path.join(__dirname, "temp", sessionId);
    fs.mkdirSync(tempDir, { recursive: true });

    const inputPath = path.join(tempDir, "input.json");
    fs.writeFileSync(inputPath, JSON.stringify(input));

    // 6. Check circuit artifacts exist
    const wasmPath = path.join(PROJECT_ROOT, "circuits", "veritasia_age_proof_js", "veritasia_age_proof.wasm");
    const zkeyPath = path.join(PROJECT_ROOT, "circuits", "veritasia_age_proof_final.zkey");
    const genWitPath = path.join(PROJECT_ROOT, "circuits", "veritasia_age_proof_js", "generate_witness.js");

    if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
      return res.status(500).json({ error: "Circuit artifacts not found. Run: node circuits/build.js" });
    }

    // 7. Generate witness
    const witnessPath = path.join(tempDir, "witness.wtns");
    try {
      execSync(`node "${genWitPath}" "${wasmPath}" "${inputPath}" "${witnessPath}"`, {
        cwd: PROJECT_ROOT,
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 120000,
      });
    } catch (err) {
      const stderr = err.stderr ? err.stderr.toString() : "unknown error";
      // Check for common circuit failures
      if (stderr.includes("Assert Failed")) {
        return res.status(400).json({
          error: "Circuit rejected the inputs - proof cannot be generated.",
          detail: "This typically means the citizen doesn't meet the age requirement, or the Merkle proof is invalid.",
          circuit_error: true,
        });
      }
      return res.status(500).json({ error: "Witness generation failed", detail: stderr.slice(0, 300) });
    }

    // 8. Generate Groth16 proof
    const proofPath = path.join(tempDir, "proof.json");
    const publicPath = path.join(tempDir, "public.json");
    try {
      execSync(
        `npx snarkjs groth16 prove "${zkeyPath}" "${witnessPath}" "${proofPath}" "${publicPath}"`,
        { cwd: PROJECT_ROOT, stdio: ["pipe", "pipe", "pipe"], timeout: 120000 }
      );
    } catch (err) {
      return res.status(500).json({ error: "Proof generation failed", detail: err.stderr?.toString().slice(0, 300) });
    }

    // 9. Read results
    const proof = JSON.parse(fs.readFileSync(proofPath, "utf-8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf-8"));

    // 10. Copy to downloads folder
    const dlDir = path.join(__dirname, "downloads");
    fs.mkdirSync(dlDir, { recursive: true });
    fs.copyFileSync(proofPath, path.join(dlDir, "proof.json"));
    fs.copyFileSync(publicPath, path.join(dlDir, "public.json"));

    // 11. Clean up temp
    fs.rmSync(tempDir, { recursive: true, force: true });

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    res.json({
      success: true,
      elapsed_seconds: parseFloat(elapsed),
      citizen_id: wallet._meta?.citizen_id || "unknown",
      citizen_name: wallet._meta?.full_name || "unknown",
      proof_size: JSON.stringify(proof).length,
      public_signals_count: publicSignals.length,
      summary: {
        merkle_root_prefix: wallet.merkle_root_hex.slice(0, 24) + "...",
        current_year: currentYear,
        age_threshold: ageThreshold,
        verification_nonce: verificationNonce,
      },
      download_proof: "/download/proof.json",
      download_public: "/download/public.json",
    });

  } catch (err) {
    console.error("Proof generation error:", err);
    res.status(500).json({ error: "Internal error", detail: err.message });
  }
});

// ── Download endpoint ──
app.get("/download/:file", (req, res) => {
  const allowed = ["proof.json", "public.json"];
  const file = req.params.file;
  if (!allowed.includes(file)) return res.status(404).json({ error: "Not found" });
  const filePath = path.join(__dirname, "downloads", file);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "No proof generated yet" });
  res.download(filePath, file);
});

// ── Start ──
app.listen(PORT, () => {
  console.log("");
  console.log("══════════════════════════════════════════════════");
  console.log("  📱 Alex's Prover - Personal Proof Device");
  console.log(`  🌐 Portal: http://localhost:${PORT}`);
  console.log("  🔐 Private data never leaves this server.");
  console.log("══════════════════════════════════════════════════");
  console.log("");
});
