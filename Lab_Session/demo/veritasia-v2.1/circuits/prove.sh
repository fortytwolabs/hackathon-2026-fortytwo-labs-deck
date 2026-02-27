#!/usr/bin/env bash
set -euo pipefail

# ═════════════════════════════════════════════════════════
#  Veritasia - Proof Generation
#  Run from project root: bash circuits/prove.sh
#  Requires: circuits/input.json (from generate_input.js)
# ═════════════════════════════════════════════════════════

CIRCUIT_DIR="circuits"
CIRCUIT_NAME="veritasia_age_proof"
WASM="$CIRCUIT_DIR/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"
ZKEY="$CIRCUIT_DIR/${CIRCUIT_NAME}_final.zkey"
INPUT="$CIRCUIT_DIR/input.json"

echo ""
echo "══════════════════════════════════════════════════"
echo "  🔐 Veritasia Proof Generation"
echo "══════════════════════════════════════════════════"

# Check files exist
for f in "$WASM" "$ZKEY" "$INPUT"; do
    if [ ! -f "$f" ]; then
        echo "  ❌ Missing: $f"
        exit 1
    fi
done

# ── Step 1: Generate witness ──
echo ""
echo "  [1/2] Generating witness..."
time node "$CIRCUIT_DIR/${CIRCUIT_NAME}_js/generate_witness.js" \
    "$WASM" "$INPUT" "$CIRCUIT_DIR/witness.wtns"
echo "  ✅ Witness generated"

# ── Step 2: Generate proof ──
echo ""
echo "  [2/2] Generating Groth16 proof..."
time npx snarkjs groth16 prove \
    "$ZKEY" \
    "$CIRCUIT_DIR/witness.wtns" \
    "$CIRCUIT_DIR/proof.json" \
    "$CIRCUIT_DIR/public.json"
echo "  ✅ Proof generated"

echo ""
echo "  📄 proof.json:  $(wc -c < "$CIRCUIT_DIR/proof.json") bytes"
echo "  📄 public.json: $(wc -c < "$CIRCUIT_DIR/public.json") bytes"
echo ""
echo "  Public signals:"
cat "$CIRCUIT_DIR/public.json" | node -e "
const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
console.log('    Total signals: ' + d.length);
console.log('    merkle_root:   [256 bits]');
console.log('    current_year:  ' + d[256]);
console.log('    age_threshold: ' + d[257]);
console.log('    verif_nonce:   ' + d[258]);
"
echo ""
echo "  Next: bash circuits/verify.sh"
echo ""
