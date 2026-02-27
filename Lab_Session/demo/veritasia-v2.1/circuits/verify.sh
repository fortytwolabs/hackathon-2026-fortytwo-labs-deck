#!/usr/bin/env bash
set -euo pipefail

# ═════════════════════════════════════════════════════════
#  Veritasia - Proof Verification
#  Run from project root: bash circuits/verify.sh
# ═════════════════════════════════════════════════════════

CIRCUIT_DIR="circuits"
VK="$CIRCUIT_DIR/verification_key.json"
PROOF="$CIRCUIT_DIR/proof.json"
PUBLIC="$CIRCUIT_DIR/public.json"

echo ""
echo "══════════════════════════════════════════════════"
echo "  🛡️  Veritasia Proof Verification"
echo "══════════════════════════════════════════════════"

for f in "$VK" "$PROOF" "$PUBLIC"; do
    if [ ! -f "$f" ]; then
        echo "  ❌ Missing: $f"
        exit 1
    fi
done

echo ""
echo "  Verifying Groth16 proof..."
echo ""

RESULT=$(npx snarkjs groth16 verify "$VK" "$PUBLIC" "$PROOF" 2>&1)
echo "  $RESULT"

if echo "$RESULT" | grep -qi "OK"; then
    echo ""
    echo "  ✅ PROOF VALID - Citizen is ≥ age threshold"
    echo "     CineVault would grant access."
else
    echo ""
    echo "  ❌ PROOF INVALID - Verification failed"
    echo "     CineVault would deny access."
fi

echo ""
