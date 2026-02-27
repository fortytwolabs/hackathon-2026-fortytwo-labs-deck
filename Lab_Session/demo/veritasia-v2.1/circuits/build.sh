#!/usr/bin/env bash
set -euo pipefail

# ═════════════════════════════════════════════════════════
#  Veritasia - Circuit Build & Trusted Setup
#  Run from project root: bash circuits/build.sh
# ═════════════════════════════════════════════════════════

CIRCUIT_DIR="circuits"
CIRCUIT_NAME="veritasia_age_proof"
PTAU_FILE="$CIRCUIT_DIR/pot18_final.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau"

echo ""
echo "══════════════════════════════════════════════════"
echo "  🏗️  Veritasia Circuit Build"
echo "══════════════════════════════════════════════════"

# ── Step 0: Check dependencies ──
echo ""
echo "  [0/6] Checking dependencies..."
command -v circom >/dev/null 2>&1 || { echo "  ❌ circom not found. Install: https://docs.circom.io/getting-started/installation/"; exit 1; }
command -v node   >/dev/null 2>&1 || { echo "  ❌ node not found."; exit 1; }
echo "  ✅ circom $(circom --version 2>&1 | head -1)"
echo "  ✅ node $(node --version)"

# Check snarkjs
if ! npx snarkjs --version >/dev/null 2>&1; then
    echo "  📦 Installing snarkjs..."
    npm install -g snarkjs
fi
echo "  ✅ snarkjs $(npx snarkjs --version 2>&1 | head -1)"

# Check circomlib
if [ ! -d "node_modules/circomlib" ]; then
    echo "  📦 Installing circomlib..."
    npm install circomlib
fi
echo "  ✅ circomlib installed"

# ── Step 1: Compile circuit ──
echo ""
echo "  [1/6] Compiling circuit..."
echo "        This may take 30–90 seconds for SHA256..."
time circom "$CIRCUIT_DIR/$CIRCUIT_NAME.circom" \
    --r1cs \
    --wasm \
    --sym \
    --output "$CIRCUIT_DIR" \
    -l "node_modules" \
    2>&1

echo "  ✅ Compiled"
echo "  📊 R1CS info:"
npx snarkjs r1cs info "$CIRCUIT_DIR/$CIRCUIT_NAME.r1cs"

# ── Step 2: Download Powers of Tau ──
echo ""
echo "  [2/6] Powers of Tau (pot18)..."
if [ -f "$PTAU_FILE" ]; then
    echo "  ✅ Already downloaded: $PTAU_FILE"
else
    echo "  ⬇️  Downloading pot18 (~144MB)..."
    curl -L -o "$PTAU_FILE" "$PTAU_URL"
    echo "  ✅ Downloaded"
fi

# ── Step 3: Groth16 setup ──
echo ""
echo "  [3/6] Groth16 setup (generating zkey)..."
npx snarkjs groth16 setup \
    "$CIRCUIT_DIR/$CIRCUIT_NAME.r1cs" \
    "$PTAU_FILE" \
    "$CIRCUIT_DIR/${CIRCUIT_NAME}_0000.zkey"
echo "  ✅ Initial zkey created"

# ── Step 4: Contribute randomness ──
echo ""
echo "  [4/6] Contributing randomness..."
npx snarkjs zkey contribute \
    "$CIRCUIT_DIR/${CIRCUIT_NAME}_0000.zkey" \
    "$CIRCUIT_DIR/${CIRCUIT_NAME}_final.zkey" \
    --name="Veritasia Hackathon 2026" \
    -v -e="$(head -c 32 /dev/urandom | xxd -p)"
echo "  ✅ Final zkey created"

# Clean up intermediate
rm -f "$CIRCUIT_DIR/${CIRCUIT_NAME}_0000.zkey"

# ── Step 5: Export verification key ──
echo ""
echo "  [5/6] Exporting verification key..."
npx snarkjs zkey export verificationkey \
    "$CIRCUIT_DIR/${CIRCUIT_NAME}_final.zkey" \
    "$CIRCUIT_DIR/verification_key.json"
echo "  ✅ verification_key.json exported"

# ── Step 6: Summary ──
echo ""
echo "══════════════════════════════════════════════════"
echo "  ✅ BUILD COMPLETE"
echo "══════════════════════════════════════════════════"
echo ""
echo "  Generated files:"
ls -lh "$CIRCUIT_DIR/$CIRCUIT_NAME.r1cs" \
       "$CIRCUIT_DIR/${CIRCUIT_NAME}_final.zkey" \
       "$CIRCUIT_DIR/verification_key.json" \
       "$CIRCUIT_DIR/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" 2>/dev/null || true
echo ""
echo "  Next steps:"
echo "    1. Generate input:  node circuits/generate_input.js wallets/wallet_XXX.json 42"
echo "    2. Generate proof:  bash circuits/prove.sh"
echo "    3. Verify proof:    bash circuits/verify.sh"
echo ""
