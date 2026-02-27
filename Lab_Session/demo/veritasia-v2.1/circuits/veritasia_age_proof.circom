pragma circom 2.0.0;

/*
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║  VERITASIA - Zero-Knowledge Age Verification Circuit          ║
 * ║  Proves: "I am a citizen in the Merkle tree AND age >= 18"    ║
 * ║  Without revealing: name, birth year, leaf index, or identity ║
 * ╚═══════════════════════════════════════════════════════════════╝
 *
 * Encoding contract (frozen by test_vectors):
 *   leaf = SHA256( BE16(birth_year) || citizen_secret[256] || nonce_issuance[128] )
 *   parent = SHA256( left_child[256] || right_child[256] )
 *   Bit order: MSB first per byte, bytes left-to-right
 *
 * Private inputs (witness):
 *   - birth_year                    (field element)
 *   - citizen_secret[256]           (bit array)
 *   - nonce_issuance[128]           (bit array)
 *   - path_siblings[depth][256]     (bit arrays)
 *   - path_indices[depth]           (0 or 1)
 *
 * Public inputs (set by verifier):
 *   - merkle_root[256]              (bit array - from VIDAA /api/root)
 *   - current_year                  (field element - server clock)
 *   - age_threshold                 (field element - e.g. 18)
 *   - verification_nonce            (field element - fresh per session)
 *
 * Estimated constraints: ~221K  (4× SHA256 ≈ 116K + comparators + switchers)
 *
 * Age check: uses circomlib LessEqThan comparator instead of manual
 * range check. All year values constrained to 16 bits - prevents
 * field-wraparound exploits where negative values survive as huge
 * field elements.
 */

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";


// ═════════════════════════════════════════════════
//  HELPER: one Merkle-tree level
//  Orders (current, sibling) by path_index, then
//  hashes SHA256(left[256] || right[256]).
// ═════════════════════════════════════════════════
template MerkleHashLevel() {
    signal input current_hash[256];
    signal input sibling_hash[256];
    signal input path_index;           // 0 → I'm left child, 1 → I'm right

    signal output next_hash[256];

    // Binary guard
    path_index * (path_index - 1) === 0;

    // Conditional swap via arithmetic:
    //   left[i]  = current*(1-s) + sibling*s
    //   right[i] = sibling*(1-s) + current*s
    signal sel_x_curr[256];
    signal sel_x_sib[256];
    signal left[256];
    signal right[256];

    for (var i = 0; i < 256; i++) {
        sel_x_curr[i] <== path_index * current_hash[i];
        sel_x_sib[i]  <== path_index * sibling_hash[i];
        left[i]  <== current_hash[i] - sel_x_curr[i] + sel_x_sib[i];
        right[i] <== sibling_hash[i] - sel_x_sib[i]  + sel_x_curr[i];
    }

    // parent = SHA256(left[256] || right[256])  → 512-bit input
    component hasher = Sha256(512);
    for (var i = 0; i < 256; i++) {
        hasher.in[i]       <== left[i];
        hasher.in[256 + i] <== right[i];
    }
    for (var i = 0; i < 256; i++) {
        next_hash[i] <== hasher.out[i];
    }
}


// ═════════════════════════════════════════════════
//  MAIN CIRCUIT
// ═════════════════════════════════════════════════
template VeritasiaAgeProof(depth) {

    // ── Private inputs ──
    signal input birth_year;
    signal input citizen_secret[256];
    signal input nonce_issuance[128];
    signal input path_siblings[depth][256];
    signal input path_indices[depth];

    // ── Public inputs ──
    signal input merkle_root[256];
    signal input current_year;
    signal input age_threshold;
    signal input verification_nonce;


    // ═══════════════════════════════════════════
    //  PART 1 - Recompute leaf
    //  SHA256( BE16(birth_year) || secret[256] || nonce[128] )
    //  Input width: 16 + 256 + 128 = 400 bits
    // ═══════════════════════════════════════════

    component by_bits = Num2Bits(16);
    by_bits.in <== birth_year;
    // Num2Bits: out[0]=LSB … out[15]=MSB
    // We need big-endian (MSB first), so reverse.

    component leaf_sha = Sha256(400);

    for (var i = 0; i < 16; i++) {
        leaf_sha.in[i] <== by_bits.out[15 - i];     // MSB first
    }
    for (var i = 0; i < 256; i++) {
        leaf_sha.in[16 + i] <== citizen_secret[i];   // already MSB-first
    }
    for (var i = 0; i < 128; i++) {
        leaf_sha.in[16 + 256 + i] <== nonce_issuance[i];
    }


    // ═══════════════════════════════════════════
    //  PART 2 - Merkle tree walk  (depth levels)
    //  Each level: ~29K constraints (SHA256-512)
    // ═══════════════════════════════════════════

    component merkle_level[depth];

    for (var level = 0; level < depth; level++) {
        merkle_level[level] = MerkleHashLevel();
        merkle_level[level].path_index <== path_indices[level];

        for (var i = 0; i < 256; i++) {
            merkle_level[level].sibling_hash[i] <== path_siblings[level][i];
        }
    }

    // Wire the chain: leaf → level 0 → level 1 → … → root
    for (var i = 0; i < 256; i++) {
        merkle_level[0].current_hash[i] <== leaf_sha.out[i];
    }
    for (var level = 1; level < depth; level++) {
        for (var i = 0; i < 256; i++) {
            merkle_level[level].current_hash[i] <== merkle_level[level - 1].next_hash[i];
        }
    }

    // Constraint: computed root == declared public root
    for (var i = 0; i < 256; i++) {
        merkle_level[depth - 1].next_hash[i] === merkle_root[i];
    }


    // ═══════════════════════════════════════════
    //  PART 3 - Age predicate (comparator-based)
    //
    //  Enforce: birth_year + age_threshold ≤ current_year
    //
    //  Security: all values range-checked to 16 bits.
    //  This prevents field-wraparound exploits where a
    //  negative age_diff wraps to a huge field element
    //  that could pass a naive bit-decomposition check.
    //
    //  birth_year: already 16-bit constrained by Num2Bits in Part 1
    //  current_year: constrained here to 16 bits
    //  age_threshold: constrained here to 16 bits
    //  sum (birth_year + age_threshold): max 17 bits → LessEqThan(17)
    // ═══════════════════════════════════════════

    // Range-check current_year to 16 bits (0..65535)
    component cy_range = Num2Bits(16);
    cy_range.in <== current_year;

    // Range-check age_threshold to 16 bits
    component at_range = Num2Bits(16);
    at_range.in <== age_threshold;

    // Core predicate: birth_year + age_threshold ≤ current_year
    // LessEqThan(n): out = 1 if in[0] ≤ in[1], else 0
    // Using 17 bits because sum can be up to 2^16 + 2^16 - 2
    component age_check = LessEqThan(17);
    age_check.in[0] <== birth_year + age_threshold;
    age_check.in[1] <== current_year;
    age_check.out === 1;  // fails if underage


    // ═══════════════════════════════════════════
    //  PART 4 - Session-nonce binding
    //  verification_nonce is a public input;
    //  Groth16 verification equation binds it.
    //  Quadratic constraint forces the prover to
    //  commit to the nonce value.
    // ═══════════════════════════════════════════

    signal nonce_sq;
    nonce_sq <== verification_nonce * verification_nonce;
}


// ── Instantiate: depth = 3 → 8-citizen tree ──
component main {public [merkle_root, current_year, age_threshold, verification_nonce]}
    = VeritasiaAgeProof(3);
