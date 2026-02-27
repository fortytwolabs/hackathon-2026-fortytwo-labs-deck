# Veritasia - Zero-Knowledge Age Verification System

## Architecture (3 Servers)

```
┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
│   VIDAA             │    │  Alex's Prover     │    │   CineVault        │
│   (Issuer)          │    │  (Citizen Device)   │    │   (Verifier)       │
│   :8080             │    │  :7070              │    │   :9090            │
├───────────────────┤    ├───────────────────┤    ├───────────────────┤
│ Register citizens   │    │ Upload wallet      │    │ Issue nonce        │
│ Build Merkle tree   │───►│ Paste nonce  ◄─────│────│ Display nonce      │
│ Issue wallets       │    │ Generate proof     │    │ Receive proof      │
│ Publish root  ──────│────│───────────────────│───►│ 4-check gauntlet   │
│ /api/root           │    │ Download proof ────│───►│ snarkjs verify     │
│ /api/wallet         │    │ [ALL PRIVATE]      │    │ ✅ or ❌           │
└───────────────────┘    └───────────────────┘    └───────────────────┘
```

## Demo Flow

1. **VIDAA** → Register citizens, download wallet JSON files
2. **CineVault** → Citizen clicks "Verify Age", gets a session nonce
3. **Prover** → Citizen uploads wallet + pastes nonce → generates ZK proof
4. **CineVault** → Citizen uploads proof → verified → ✅ ACCESS GRANTED

## Quick Start

### 1. Install dependencies

```bash
pip install flask pillow              # VIDAA portal
npm install circomlib snarkjs         # Circuit tools
npm install express multer            # Prover portal
```

### 2. Install circom (one-time)

**Windows:**
```
# Option A: https://github.com/iden3/circom/releases → download .exe → rename circom.exe → add to PATH
# Option B: Install Rust (https://rustup.rs) then: cargo install --git https://github.com/iden3/circom.git
```

**macOS:** `brew install rust && cargo install --git https://github.com/iden3/circom.git`

**Linux:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && cargo install --git https://github.com/iden3/circom.git`

### 3. Build circuit (one-time, ~3 minutes)

```bash
node circuits/build.js
```

### 4. Run the demo (3 terminals)

```bash
# Terminal 1 - VIDAA (Issuer)
python app.py --reset
# → http://localhost:8080

# Terminal 2 - Alex's Prover (Citizen Device)
node prover/server.js
# → http://localhost:7070

# Terminal 3 - CineVault (Verifier)  [TODO: Step 3]
node verifier/server.js
# → http://localhost:9090
```

### 5. Test the flow

1. Open VIDAA → Register citizens → Download wallets
2. Open CineVault → Click "Verify Age" → Copy nonce
3. Open Prover → Upload wallet → Paste nonce → Generate Proof → Download proof
4. Back to CineVault → Upload proof → See result

## CLI Alternative (still works)

```bash
node circuits/generate_input.js wallets/wallet_VR-XXXXX.json 42 2026 18
node circuits/prove.js
node circuits/verify.js
```

## File Structure

```
├── app.py                              # VIDAA portal (Flask, :8080)
├── templates/                          # VIDAA Jinja2 templates
├── prover/
│   ├── server.js                       # Prover portal (Express, :7070)
│   └── public/index.html               # Prover UI
├── verifier/                           # CineVault [TODO]
│   ├── server.js
│   └── public/index.html
├── circuits/
│   ├── veritasia_age_proof.circom      # THE circuit
│   ├── generate_input.js               # Wallet → circuit input
│   ├── build.js                        # Compile + trusted setup
│   ├── prove.js                        # CLI proof generation
│   └── verify.js                       # CLI verification
├── test_vectors/
│   ├── test_vectors.py                 # Python encoding contract
│   ├── test_vectors.js                 # Node cross-check
│   └── vectors.json                    # Reference vectors
├── data/                               # SQLite DB
├── uploads/ cards/ wallets/            # Generated files
└── assets/fonts/                       # Bundled fonts
```

## Wallet Format (v2.1 - hex only)

```json
{
  "_meta": { "version": "2.1", "citizen_id": "...", "full_name": "..." },
  "birth_year": 2001,
  "citizen_secret_hex": "a1b2c3d4...",
  "nonce_issuance_hex": "11111111...",
  "leaf_hash_hex": "b2bd59f5...",
  "leaf_index": 0,
  "path_indices": [0, 0, 0],
  "path_siblings_hex": ["973d...", "4bf5...", "db56..."],
  "merkle_root_hex": "7b5a7fa1..."
}
```

## Encoding Contract

| Field | Encoding | Size |
|---|---|---|
| birth_year | uint16 big-endian | 2 bytes |
| citizen_secret | raw bytes | 32 bytes |
| nonce_issuance | raw bytes | 16 bytes |
| **Leaf preimage** | concat above | **50 bytes (400 bits)** |
| Merkle parent | SHA256(left ∥ right) | 64 bytes in |
| Bit order | MSB first per byte, bytes L→R | circomlib convention |

## API Endpoints (VIDAA)

| Endpoint | Method | Description |
|---|---|---|
| `/api/root` | GET | Current Merkle root |
| `/api/wallet/<id>` | GET | Download credential wallet |
| `/api/tree` | GET | Full tree structure |
| `/api/citizens` | GET | All citizens (public fields) |

## Districts

Aethon-7, TrueByte, Merkle Heights, Cipher Coast, Hash Harbor,
Proofgate, Circuit Row, Witness Quarter, Rootvale, Ledgerfall,
Nonce Basin, Verifier Ridge

## Reset

```bash
python app.py --reset    # or: VIDAA_RESET=1 python app.py
```
Wipes: DB + uploads + cards + wallets
