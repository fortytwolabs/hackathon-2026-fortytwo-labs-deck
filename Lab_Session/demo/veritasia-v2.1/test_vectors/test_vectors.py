#!/usr/bin/env python3
"""
Veritasia - Encoding Contract Test Vectors (Python)
Run: python test_vectors/test_vectors.py
Then: node test_vectors/test_vectors.js
Both must produce IDENTICAL output. If they do, encoding is frozen.
"""

import hashlib, struct, json

TREE_DEPTH = 3
EMPTY_LEAF = "0" * 64

# ── FIXED TEST DATA (this IS the contract - do NOT change) ──

CITIZENS = [
    {"name": "Alex Miranov",  "birth_year": 2001,
     "secret": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
     "nonce":  "1111111111111111aaaaaaaaaaaaaaaa"},
    {"name": "Priya Nair",    "birth_year": 1998,
     "secret": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
     "nonce":  "2222222222222222bbbbbbbbbbbbbbbb"},
    {"name": "Ravi Chen",     "birth_year": 2010,
     "secret": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
     "nonce":  "3333333333333333cccccccccccccccc"},
    {"name": "Mei Tanaka",    "birth_year": 1996,
     "secret": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "nonce":  "4444444444444444dddddddddddddddd"},
]

# ── CORE FUNCTIONS (must match app.py + circuit) ──

def compute_leaf(birth_year, secret_hex, nonce_hex):
    by_bytes = struct.pack(">H", birth_year)        # 2 bytes BE
    preimage = by_bytes + bytes.fromhex(secret_hex) + bytes.fromhex(nonce_hex)
    assert len(preimage) == 50, f"Expected 50 bytes, got {len(preimage)}"
    return hashlib.sha256(preimage).hexdigest()

def hash_pair(left_hex, right_hex):
    data = bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    assert len(data) == 64
    return hashlib.sha256(data).hexdigest()

def build_tree(leaves):
    padded = list(leaves) + [EMPTY_LEAF] * (8 - len(leaves))
    layers = [padded[:]]
    current = padded
    for _ in range(TREE_DEPTH):
        nxt = [hash_pair(current[i], current[i+1]) for i in range(0, len(current), 2)]
        layers.append(nxt)
        current = nxt
    return {"root": current[0], "layers": layers}

def get_path(tree, index):
    siblings, indices = [], []
    idx = index
    for level in range(TREE_DEPTH):
        layer = tree["layers"][level]
        if idx % 2 == 0:
            siblings.append(layer[idx + 1]); indices.append(0)
        else:
            siblings.append(layer[idx - 1]); indices.append(1)
        idx //= 2
    return {"siblings": siblings, "indices": indices}

def hex_to_bits(hex_str):
    """MSB first per byte, bytes left-to-right (Circom convention)."""
    bits = []
    for byte in bytes.fromhex(hex_str):
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

# ── GENERATE ──

def main():
    print("=" * 70)
    print("  VERITASIA ENCODING CONTRACT - PYTHON TEST VECTORS")
    print("=" * 70)

    # 1) Individual leaf hashes
    leaves = []
    for i, c in enumerate(CITIZENS):
        leaf = compute_leaf(c["birth_year"], c["secret"], c["nonce"])
        leaves.append(leaf)
        print(f"\nCitizen {i}: {c['name']} (born {c['birth_year']})")
        print(f"  secret:  {c['secret']}")
        print(f"  nonce:   {c['nonce']}")
        print(f"  leaf:    {leaf}")

    # 2) Merkle tree
    tree = build_tree(leaves)
    print(f"\n{'─' * 70}")
    print(f"MERKLE TREE (depth={TREE_DEPTH}, {len(leaves)} real + {8-len(leaves)} empty)")
    for lvl, layer in enumerate(tree["layers"]):
        print(f"  Level {lvl}: {[h[:16]+'...' for h in layer]}")
    print(f"\n  ROOT: {tree['root']}")

    # 3) Merkle paths (for Alex = index 0)
    path = get_path(tree, 0)
    print(f"\n{'─' * 70}")
    print(f"MERKLE PATH for Alex (index 0):")
    print(f"  siblings: {[s[:16]+'...' for s in path['siblings']]}")
    print(f"  indices:  {path['indices']}")

    # 4) Bit encoding sample (for Circom cross-check)
    sample_leaf = leaves[0]
    bits = hex_to_bits(sample_leaf)
    print(f"\n{'─' * 70}")
    print(f"BIT ENCODING (Alex leaf, first 32 bits):")
    print(f"  hex:  {sample_leaf[:8]}")
    print(f"  bits: {bits[:32]}")

    # 5) Age check
    current_year = 2026
    threshold = 18
    print(f"\n{'─' * 70}")
    print(f"AGE CHECK (current_year={current_year}, threshold={threshold}):")
    for i, c in enumerate(CITIZENS):
        diff = current_year - c["birth_year"] - threshold
        print(f"  {c['name']}: {current_year} - {c['birth_year']} - {threshold} = {diff} → {'PASS ✓' if diff >= 0 else 'FAIL ✗'}")

    # 6) Export JSON for cross-check
    vectors = {
        "encoding_contract": {
            "birth_year_encoding": "uint16 big-endian (2 bytes)",
            "citizen_secret_encoding": "raw bytes (32 bytes)",
            "nonce_issuance_encoding": "raw bytes (16 bytes)",
            "leaf_preimage_total": "50 bytes = 400 bits",
            "merkle_parent_preimage": "64 bytes = 512 bits",
            "bit_order": "MSB first per byte, bytes left-to-right",
        },
        "citizens": [],
        "tree_root": tree["root"],
        "tree_layers": tree["layers"],
        "alex_path": path,
    }
    for i, c in enumerate(CITIZENS):
        vectors["citizens"].append({
            "name": c["name"],
            "birth_year": c["birth_year"],
            "secret_hex": c["secret"],
            "nonce_hex": c["nonce"],
            "expected_leaf": leaves[i],
        })

    out_path = "test_vectors/vectors.json"
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"\n✅ Vectors written to {out_path}")
    print("=" * 70)

if __name__ == "__main__":
    main()
