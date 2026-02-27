#!/usr/bin/env node
/**
 * Veritasia - Circuit Build & Trusted Setup (Cross-Platform)
 * Works on Windows, Linux, macOS
 *
 * Usage:  node circuits/build.js
 * Run from project root (where package.json / node_modules live)
 *
 * All commands use RELATIVE paths (cwd = project root).
 * Absolute paths used only for fs.existsSync() checks.
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");

// Absolute paths - only for fs.existsSync / fs.statSync / download dest
const PROJECT_ROOT = path.resolve(__dirname, "..");
const ABS_CIRCUITS = path.resolve(__dirname);

// Relative paths - used in ALL shell commands (resolved from PROJECT_ROOT cwd)
const C = "circuits";                                     // circuit directory
const N = "veritasia_age_proof";                          // circuit name
const REL = {
  src:      `${C}/${N}.circom`,
  r1cs:     `${C}/${N}.r1cs`,
  wasm:     `${C}/${N}_js/${N}.wasm`,
  sym:      `${C}/${N}.sym`,
  ptau:     `${C}/pot18_final.ptau`,
  zkey0:    `${C}/${N}_0000.zkey`,
  zkeyFin:  `${C}/${N}_final.zkey`,
  vk:       `${C}/verification_key.json`,
};

const PTAU_URL = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau";

// ── Helpers ──

function abs(relPath) {
  return path.resolve(PROJECT_ROOT, relPath);
}

function run(cmd, label) {
  console.log(`\n  ⏳ ${label}...`);
  try {
    const out = execSync(cmd, {
      cwd: PROJECT_ROOT,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 50 * 1024 * 1024,
      timeout: 600000,
    });
    const text = out.toString().trim();
    if (text) console.log("  " + text.split("\n").join("\n  "));
    return text;
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString() : "";
    const stdout = err.stdout ? err.stdout.toString() : "";
    console.error(`\n  ❌ Command failed: ${cmd}`);
    if (stderr) console.error("  STDERR:", stderr.slice(0, 500));
    if (stdout) console.error("  STDOUT:", stdout.slice(0, 500));
    process.exit(1);
  }
}

function commandExists(cmd) {
  try {
    execSync(process.platform === "win32" ? `where ${cmd}` : `which ${cmd}`, { stdio: "pipe" });
    return true;
  } catch { return false; }
}

function download(url, destAbs) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destAbs);
    const get = url.startsWith("https") ? https.get : http.get;
    function doGet(u) {
      get(u, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          doGet(res.headers.location); return;
        }
        if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode}`)); return; }
        const total = parseInt(res.headers["content-length"] || "0");
        let downloaded = 0;
        res.on("data", (chunk) => {
          downloaded += chunk.length;
          if (total > 0) {
            const pct = ((downloaded / total) * 100).toFixed(1);
            process.stdout.write(`\r  ⬇️  ${pct}% (${(downloaded / 1048576).toFixed(1)} MB)`);
          }
        });
        res.pipe(file);
        file.on("finish", () => { file.close(); console.log(""); resolve(); });
      }).on("error", reject);
    }
    doGet(url);
  });
}

function sj(args) { return `npx snarkjs ${args}`; }

// ── Main ──

async function main() {
  console.log("");
  console.log("══════════════════════════════════════════════════");
  console.log("  🏗️  Veritasia Circuit Build (Cross-Platform)");
  console.log(`  📂 Platform: ${process.platform} / ${process.arch}`);
  console.log("══════════════════════════════════════════════════");

  // ── Step 0: Dependencies ──
  console.log("\n  [0/6] Checking dependencies...");

  if (!commandExists("circom")) {
    console.error("\n  ❌ circom not found!\n");
    if (process.platform === "win32") {
      console.log("  WINDOWS INSTALL:");
      console.log("    Option A: https://github.com/iden3/circom/releases");
      console.log("              Download .exe → rename circom.exe → add to PATH");
      console.log("    Option B: Install Rust (https://rustup.rs) then:");
      console.log("              cargo install --git https://github.com/iden3/circom.git");
    } else if (process.platform === "darwin") {
      console.log("  macOS: brew install rust && cargo install --git https://github.com/iden3/circom.git");
    } else {
      console.log("  Linux: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
      console.log("         source ~/.cargo/env");
      console.log("         cargo install --git https://github.com/iden3/circom.git");
    }
    console.log("\n  Then re-run:  node circuits/build.js\n");
    process.exit(1);
  }

  const circomVer = run("circom --version", "circom version").trim();
  console.log(`  ✅ circom: ${circomVer}`);
  console.log(`  ✅ node: ${process.version}`);

  if (!fs.existsSync(path.join(PROJECT_ROOT, "node_modules", "circomlib"))) {
    console.log("  📦 Installing circomlib...");
    run("npm install circomlib", "npm install");
  }
  console.log("  ✅ circomlib installed");

  // ── Step 1: Compile ──
  console.log("\n  [1/6] Compiling circuit (may take 30–90 seconds)...");

  if (!fs.existsSync(abs(REL.src))) {
    console.error(`  ❌ Not found: ${REL.src}`);
    process.exit(1);
  }

  run(
    `circom ${REL.src} --r1cs --wasm --sym --output ${C} -l node_modules`,
    "Compiling"
  );
  console.log("  ✅ Compiled");

  run(sj(`r1cs info ${REL.r1cs}`), "R1CS info");

  // ── Step 2: Powers of Tau ──
  console.log("\n  [2/6] Powers of Tau (pot18)...");
  if (fs.existsSync(abs(REL.ptau))) {
    const sz = fs.statSync(abs(REL.ptau)).size;
    console.log(`  ✅ Already downloaded: ${(sz / 1048576).toFixed(1)} MB`);
  } else {
    console.log("  ⬇️  Downloading pot18 (~144 MB)...");
    await download(PTAU_URL, abs(REL.ptau));
    console.log("  ✅ Downloaded");
  }

  // ── Step 3: Groth16 setup ──
  console.log("\n  [3/6] Groth16 setup...");
  run(
    sj(`groth16 setup ${REL.r1cs} ${REL.ptau} ${REL.zkey0}`),
    "Groth16 setup"
  );
  console.log("  ✅ Initial zkey created");

  // ── Step 4: Contribute randomness ──
  console.log("\n  [4/6] Contributing randomness...");
  const entropy = require("crypto").randomBytes(32).toString("hex");
  run(
    sj(`zkey contribute ${REL.zkey0} ${REL.zkeyFin} --name="Veritasia Hackathon 2026" -v -e="${entropy}"`),
    "Contribute randomness"
  );
  console.log("  ✅ Final zkey created");

  // Clean intermediate
  const zkey0Abs = abs(REL.zkey0);
  if (fs.existsSync(zkey0Abs)) fs.unlinkSync(zkey0Abs);

  // ── Step 5: Export verification key ──
  console.log("\n  [5/6] Exporting verification key...");
  run(
    sj(`zkey export verificationkey ${REL.zkeyFin} ${REL.vk}`),
    "Export verification key"
  );
  console.log("  ✅ verification_key.json exported");

  // ── Step 6: Summary ──
  console.log("\n══════════════════════════════════════════════════");
  console.log("  ✅ BUILD COMPLETE");
  console.log("══════════════════════════════════════════════════\n");

  console.log("  Generated files:");
  for (const key of ["r1cs", "zkeyFin", "vk", "wasm"]) {
    const f = abs(REL[key]);
    if (fs.existsSync(f)) {
      const sz = (fs.statSync(f).size / 1024).toFixed(0);
      console.log(`    ${REL[key]}: ${sz} KB`);
    }
  }

  console.log("\n  Next steps:");
  console.log("    1. node circuits/generate_input.js wallets/wallet_XXX.json 42");
  console.log("    2. node circuits/prove.js");
  console.log("    3. node circuits/verify.js\n");
}

main().catch(err => { console.error("Fatal:", err); process.exit(1); });
