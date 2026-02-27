#!/usr/bin/env node
/**
 * Veritasia - Proof Verification (Cross-Platform)
 * Usage:  node circuits/verify.js
 * Run from project root.
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const C = "circuits";

const REL = {
  vk:     `${C}/verification_key.json`,
  proof:  `${C}/proof.json`,
  public: `${C}/public.json`,
};

function abs(rel) { return path.resolve(PROJECT_ROOT, rel); }

function main() {
  console.log("");
  console.log("══════════════════════════════════════════════════");
  console.log("  🛡️  Veritasia Proof Verification");
  console.log("══════════════════════════════════════════════════");

  for (const [label, key] of [["verification_key.json", "vk"], ["proof.json", "proof"], ["public.json", "public"]]) {
    if (!fs.existsSync(abs(REL[key]))) {
      console.error(`\n  ❌ Missing: ${REL[key]}`);
      process.exit(1);
    }
  }

  console.log("\n  Verifying Groth16 proof...\n");

  try {
    const result = execSync(
      `npx snarkjs groth16 verify ${REL.vk} ${REL.public} ${REL.proof}`,
      { cwd: PROJECT_ROOT, stdio: ["pipe", "pipe", "pipe"], timeout: 60000 }
    ).toString().trim();

    console.log(`  ${result}`);

    if (result.toLowerCase().includes("ok")) {
      console.log("\n  ✅ PROOF VALID - Citizen meets the age requirement");
      console.log("     CineVault would grant access.\n");
    } else {
      console.log("\n  ⚠️  Unexpected output - check manually.\n");
    }
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString().trim() : "";
    const stdout = err.stdout ? err.stdout.toString().trim() : "";
    const output = stderr || stdout || "unknown error";
    console.log(`  ${output}`);

    if (output.toLowerCase().includes("invalid") || output.toLowerCase().includes("not valid")) {
      console.log("\n  ❌ PROOF INVALID - Verification failed");
      console.log("     CineVault would deny access.\n");
    } else {
      console.log("\n  ❌ Verification error. Check output above.\n");
    }
    process.exit(1);
  }
}

main();
