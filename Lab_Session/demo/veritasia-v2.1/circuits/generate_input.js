#!/usr/bin/env node
/**
 * Veritasia - Prover Input Generator
 *
 * Reads a VIDAA credential wallet (hex-only format v2.1)
 * and produces input.json for the Circom witness generator.
 *
 * Usage:
 *   node circuits/generate_input.js <wallet.json> [verification_nonce] [current_year] [age_threshold]
 *
 * Example:
 *   node circuits/generate_input.js wallets/wallet_VR-20010715-AM1234.json 42 2026 18
 *
 * The hex→bits conversion lives HERE (not in Python), so there's
 * exactly one place where bit ordering is defined.
 */

const fs = require("fs");
const path = require("path");

// ── Bit conversion (MSB first per byte, bytes left-to-right) ──

function hexToBits(hexStr, numBits) {
  const buf = Buffer.from(hexStr, "hex");
  const bits = [];
  for (const byte of buf) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  if (numBits && bits.length !== numBits) {
    throw new Error(`Expected ${numBits} bits from hex "${hexStr.slice(0,16)}...", got ${bits.length}`);
  }
  return bits;
}

// ── Main ──

function main() {
  const args = process.argv.slice(2);

  if (args.length < 1) {
    console.error("Usage: node generate_input.js <wallet.json> [verification_nonce] [current_year] [age_threshold]");
    console.error("\nExample:");
    console.error("  node generate_input.js wallet_VR-20010715-AM1234.json 42 2026 18");
    process.exit(1);
  }

  const walletPath = args[0];
  const verificationNonce = parseInt(args[1] || "42");
  const currentYear = parseInt(args[2] || "2026");
  const ageThreshold = parseInt(args[3] || "18");

  // Read wallet
  if (!fs.existsSync(walletPath)) {
    console.error(`Error: wallet file not found: ${walletPath}`);
    process.exit(1);
  }
  const wallet = JSON.parse(fs.readFileSync(walletPath, "utf-8"));

  console.log(`\n  📁 Wallet:  ${wallet._meta.citizen_id} (${wallet._meta.full_name})`);
  console.log(`  🗓️  Year:    ${currentYear}`);
  console.log(`  🎂 Born:    ${wallet.birth_year}`);
  console.log(`  📏 Thresh:  ${ageThreshold}`);
  console.log(`  🎲 Nonce:   ${verificationNonce}`);
  console.log(`  🌳 Root:    0x${wallet.merkle_root_hex.slice(0, 24)}...`);

  // Age check (matches circuit: birth_year + age_threshold <= current_year)
  const sum = wallet.birth_year + ageThreshold;
  if (sum > currentYear) {
    console.error(`\n  ❌ Age check will FAIL: ${wallet.birth_year} + ${ageThreshold} = ${sum} > ${currentYear}`);
    console.error(`     This citizen is too young. Circuit will reject.`);
  } else {
    console.log(`  ✅ Age OK:  ${wallet.birth_year} + ${ageThreshold} = ${sum} ≤ ${currentYear}`);
  }

  // Convert to circuit input
  const input = {
    // Private
    birth_year: String(wallet.birth_year),
    citizen_secret: hexToBits(wallet.citizen_secret_hex, 256).map(String),
    nonce_issuance: hexToBits(wallet.nonce_issuance_hex, 128).map(String),
    path_siblings: wallet.path_siblings_hex.map(h => hexToBits(h, 256).map(String)),
    path_indices: wallet.path_indices.map(String),

    // Public (set by verifier)
    merkle_root: hexToBits(wallet.merkle_root_hex, 256).map(String),
    current_year: String(currentYear),
    age_threshold: String(ageThreshold),
    verification_nonce: String(verificationNonce),
  };

  // Write output
  // Write to circuits/input.json (same directory as this script)
  const outPath = path.join(__dirname, "input.json");

  fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
  console.log(`\n  💾 Written: ${outPath}`);
  console.log(`     (${Object.keys(input).length} signals, ready for witness generation)\n`);
}

main();
