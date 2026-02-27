#!/usr/bin/env node
/**
 * Veritasia - Proof Generation (Cross-Platform)
 * Usage:  node circuits/prove.js
 * Run from project root. Requires circuits/input.json
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const C = "circuits";
const N = "veritasia_age_proof";

// Relative paths for commands (cwd = PROJECT_ROOT)
const REL = {
  wasm:     `${C}/${N}_js/${N}.wasm`,
  genWit:   `${C}/${N}_js/generate_witness.js`,
  zkey:     `${C}/${N}_final.zkey`,
  input:    `${C}/input.json`,
  witness:  `${C}/witness.wtns`,
  proof:    `${C}/proof.json`,
  public:   `${C}/public.json`,
};

function abs(rel) { return path.resolve(PROJECT_ROOT, rel); }

function run(cmd, label) {
  console.log(`\n  ⏳ ${label}...`);
  try {
    const out = execSync(cmd, {
      cwd: PROJECT_ROOT,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 50 * 1024 * 1024,
      timeout: 300000,
    });
    const text = out.toString().trim();
    if (text) console.log("  " + text.split("\n").join("\n  "));
    return text;
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString() : "";
    const stdout = err.stdout ? err.stdout.toString() : "";
    console.error(`\n  ❌ Command failed: ${cmd}`);
    if (stderr) console.error("  STDERR:", stderr.slice(0, 1000));
    if (stdout) console.error("  STDOUT:", stdout.slice(0, 1000));
    process.exit(1);
  }
}

function main() {
  console.log("");
  console.log("══════════════════════════════════════════════════");
  console.log("  🔐 Veritasia Proof Generation");
  console.log("══════════════════════════════════════════════════");

  // Check required files
  for (const [label, rel] of [["WASM", "wasm"], ["zkey", "zkey"], ["input.json", "input"], ["generate_witness.js", "genWit"]]) {
    if (!fs.existsSync(abs(REL[rel]))) {
      console.error(`\n  ❌ Missing: ${REL[rel]}`);
      if (rel === "input") {
        console.error("     Run first: node circuits/generate_input.js wallets/wallet_XXX.json 42");
      } else {
        console.error("     Run first: node circuits/build.js");
      }
      process.exit(1);
    }
  }
  console.log("  ✅ All required files found");

  // Step 1: Generate witness
  run(
    `node ${REL.genWit} ${REL.wasm} ${REL.input} ${REL.witness}`,
    "Generating witness"
  );
  console.log("  ✅ Witness generated");

  // Step 2: Generate proof
  run(
    `npx snarkjs groth16 prove ${REL.zkey} ${REL.witness} ${REL.proof} ${REL.public}`,
    "Generating Groth16 proof"
  );
  console.log("  ✅ Proof generated");

  // Summary
  const proofSize = fs.statSync(abs(REL.proof)).size;
  const pubSize = fs.statSync(abs(REL.public)).size;
  console.log(`\n  📄 proof.json:  ${proofSize} bytes`);
  console.log(`  📄 public.json: ${pubSize} bytes`);

  try {
    const pub = JSON.parse(fs.readFileSync(abs(REL.public), "utf-8"));
    console.log(`\n  Public signals (${pub.length} total):`);
    console.log(`    merkle_root:       [256 bits]`);
    if (pub.length > 256) console.log(`    current_year:      ${pub[256]}`);
    if (pub.length > 257) console.log(`    age_threshold:     ${pub[257]}`);
    if (pub.length > 258) console.log(`    verif_nonce:       ${pub[258]}`);
  } catch {}

  console.log("\n  Next: node circuits/verify.js\n");
}

main();
