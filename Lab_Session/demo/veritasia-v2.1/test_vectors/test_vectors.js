#!/usr/bin/env node
/**
 * Veritasia - Encoding Contract Test Vectors (Node.js)
 * Run: node test_vectors/test_vectors.js
 * Output must be IDENTICAL to: python test_vectors/test_vectors.py
 *
 * This file also serves as the reference for hex→bits conversion
 * that the prover script will use.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const TREE_DEPTH = 3;
const EMPTY_LEAF = "0".repeat(64);

// ── FIXED TEST DATA (same as Python - DO NOT CHANGE) ──

const CITIZENS = [
  { name: "Alex Miranov", birth_year: 2001,
    secret: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    nonce:  "1111111111111111aaaaaaaaaaaaaaaa" },
  { name: "Priya Nair", birth_year: 1998,
    secret: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    nonce:  "2222222222222222bbbbbbbbbbbbbbbb" },
  { name: "Ravi Chen", birth_year: 2010,
    secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    nonce:  "3333333333333333cccccccccccccccc" },
  { name: "Mei Tanaka", birth_year: 1996,
    secret: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce:  "4444444444444444dddddddddddddddd" },
];

// ── CORE FUNCTIONS ──

function sha256hex(hexData) {
  return crypto.createHash("sha256").update(Buffer.from(hexData, "hex")).digest("hex");
}

function computeLeaf(birthYear, secretHex, nonceHex) {
  // birth_year: 2 bytes big-endian
  const byBuf = Buffer.alloc(2);
  byBuf.writeUInt16BE(birthYear, 0);
  const byHex = byBuf.toString("hex");
  const preimageHex = byHex + secretHex + nonceHex;
  // Verify: 2 + 32 + 16 = 50 bytes = 100 hex chars
  if (preimageHex.length !== 100) throw new Error(`Expected 100 hex chars, got ${preimageHex.length}`);
  return sha256hex(preimageHex);
}

function hashPair(leftHex, rightHex) {
  const combined = leftHex + rightHex;
  if (combined.length !== 128) throw new Error(`Expected 128 hex chars, got ${combined.length}`);
  return sha256hex(combined);
}

function buildTree(leaves) {
  const padded = [...leaves];
  while (padded.length < 8) padded.push(EMPTY_LEAF);
  const layers = [padded.slice()];
  let current = padded;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(hashPair(current[i], current[i + 1]));
    }
    layers.push(next);
    current = next;
  }
  return { root: current[0], layers };
}

function getPath(tree, index) {
  const siblings = [], indices = [];
  let idx = index;
  for (let level = 0; level < TREE_DEPTH; level++) {
    const layer = tree.layers[level];
    if (idx % 2 === 0) {
      siblings.push(layer[idx + 1]); indices.push(0);
    } else {
      siblings.push(layer[idx - 1]); indices.push(1);
    }
    idx = Math.floor(idx / 2);
  }
  return { siblings, indices };
}

/**
 * Convert hex string to bit array: MSB first per byte, bytes left-to-right.
 * This is the circomlib SHA-256 convention.
 * Example: 0xAB = 10101011 → [1,0,1,0,1,0,1,1]
 */
function hexToBits(hexStr) {
  const bits = [];
  const buf = Buffer.from(hexStr, "hex");
  for (const byte of buf) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  return bits;
}

/** Convert integer to big-endian bit array */
function intToBitsBE(value, numBits) {
  const bits = [];
  for (let i = numBits - 1; i >= 0; i--) {
    bits.push((value >> i) & 1);
  }
  return bits;
}

// ── GENERATE ──

console.log("=".repeat(70));
console.log("  VERITASIA ENCODING CONTRACT - NODE.JS TEST VECTORS");
console.log("=".repeat(70));

// 1) Individual leaf hashes
const leaves = [];
for (let i = 0; i < CITIZENS.length; i++) {
  const c = CITIZENS[i];
  const leaf = computeLeaf(c.birth_year, c.secret, c.nonce);
  leaves.push(leaf);
  console.log(`\nCitizen ${i}: ${c.name} (born ${c.birth_year})`);
  console.log(`  secret:  ${c.secret}`);
  console.log(`  nonce:   ${c.nonce}`);
  console.log(`  leaf:    ${leaf}`);
}

// 2) Merkle tree
const tree = buildTree(leaves);
console.log(`\n${"─".repeat(70)}`);
console.log(`MERKLE TREE (depth=${TREE_DEPTH}, ${leaves.length} real + ${8 - leaves.length} empty)`);
for (let lvl = 0; lvl < tree.layers.length; lvl++) {
  const layer = tree.layers[lvl].map(h => h.slice(0, 16) + "...");
  console.log(`  Level ${lvl}: ${JSON.stringify(layer)}`);
}
console.log(`\n  ROOT: ${tree.root}`);

// 3) Merkle path for Alex
const alexPath = getPath(tree, 0);
console.log(`\n${"─".repeat(70)}`);
console.log(`MERKLE PATH for Alex (index 0):`);
console.log(`  siblings: ${JSON.stringify(alexPath.siblings.map(s => s.slice(0, 16) + "..."))}`);
console.log(`  indices:  ${JSON.stringify(alexPath.indices)}`);

// 4) Bit encoding
const sampleLeaf = leaves[0];
const bits = hexToBits(sampleLeaf);
console.log(`\n${"─".repeat(70)}`);
console.log(`BIT ENCODING (Alex leaf, first 32 bits):`);
console.log(`  hex:  ${sampleLeaf.slice(0, 8)}`);
console.log(`  bits: [${bits.slice(0, 32).join(",")}]`);

// 5) Age check
const currentYear = 2026, threshold = 18;
console.log(`\n${"─".repeat(70)}`);
console.log(`AGE CHECK (current_year=${currentYear}, threshold=${threshold}):`);
for (const c of CITIZENS) {
  const diff = currentYear - c.birth_year - threshold;
  console.log(`  ${c.name}: ${currentYear} - ${c.birth_year} - ${threshold} = ${diff} → ${diff >= 0 ? "PASS ✓" : "FAIL ✗"}`);
}

// 6) Cross-check against Python vectors if available
const vectorsPath = path.join(__dirname, "vectors.json");
if (fs.existsSync(vectorsPath)) {
  console.log(`\n${"─".repeat(70)}`);
  console.log("CROSS-CHECK against Python vectors.json:");
  const pyVectors = JSON.parse(fs.readFileSync(vectorsPath, "utf-8"));

  let allMatch = true;
  for (let i = 0; i < CITIZENS.length; i++) {
    const expected = pyVectors.citizens[i].expected_leaf;
    const got = leaves[i];
    const match = expected === got;
    if (!match) allMatch = false;
    console.log(`  Citizen ${i} leaf: ${match ? "✅ MATCH" : "❌ MISMATCH"}`);
    if (!match) {
      console.log(`    Python: ${expected}`);
      console.log(`    Node:   ${got}`);
    }
  }
  const rootMatch = pyVectors.tree_root === tree.root;
  if (!rootMatch) allMatch = false;
  console.log(`  Tree root:     ${rootMatch ? "✅ MATCH" : "❌ MISMATCH"}`);

  console.log(`\n${allMatch ? "✅ ALL VECTORS MATCH - ENCODING CONTRACT FROZEN" : "❌ MISMATCH DETECTED - DO NOT PROCEED"}`);
} else {
  console.log(`\n⚠️  Run Python first to generate vectors.json, then re-run this for cross-check.`);
}
console.log("=".repeat(70));

// Export functions for prover script
module.exports = { hexToBits, intToBitsBE, computeLeaf, hashPair, buildTree, getPath, sha256hex };
