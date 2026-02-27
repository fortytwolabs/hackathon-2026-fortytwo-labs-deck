"""
VIDAA - Veritasian Identity Assurance Authority Portal
Merkle-Tree Identity · ZK-Proof Ready · Credential Wallet (v2.1)

leaf = SHA-256( birth_year_bytes || citizen_secret || nonce_issuance )
Binary SHA-256 Merkle tree over all citizen leaves
Credential wallet export for Circom/SnarkJS proof generation
Tree depth = 3 (supports up to 8 citizens for demo)

Reset modes:
  --reset         CLI flag: wipe DB + generated files on startup
  VIDAA_RESET=1   env var: same effect
  Normal startup: keeps existing data
"""

import os, sys, json, hashlib, secrets, sqlite3, struct, random, shutil, argparse
import hmac as hmac_mod
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, send_file, send_from_directory, Response
)
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

# ── App Setup ──
app = Flask(__name__, static_folder="static", template_folder="templates")
BASE_DIR = Path(__file__).resolve().parent
app.config["UPLOAD_FOLDER"] = str(BASE_DIR / "uploads")
app.config["CARDS_FOLDER"]  = str(BASE_DIR / "cards")
app.config["WALLETS_FOLDER"] = str(BASE_DIR / "wallets")
app.config["DB_PATH"]       = str(BASE_DIR / "data" / "vidaa.db")

for d in [app.config["UPLOAD_FOLDER"], app.config["CARDS_FOLDER"],
          app.config["WALLETS_FOLDER"], str(BASE_DIR / "data")]:
    os.makedirs(d, exist_ok=True)

# ── Constants ──
TREE_DEPTH = 3
MAX_CITIZENS = 2 ** TREE_DEPTH  # 8
VIDAA_SECRET_KEY = "VIDAA_SK_2026_VERITASIA_MASTER_KEY"
EMPTY_LEAF = "0" * 64

DISTRICTS = [
    "Aethon-7",
    "TrueByte",
    "Merkle Heights",
    "Cipher Coast",
    "Hash Harbor",
    "Proofgate",
    "Circuit Row",
    "Witness Quarter",
    "Rootvale",
    "Ledgerfall",
    "Nonce Basin",
    "Verifier Ridge",
]


# ══════════════════════════════════════════════════════════════
#  RESET & DATABASE
# ══════════════════════════════════════════════════════════════

def reset_demo_state():
    """Wipe DB + all generated files. Called via --reset flag or VIDAA_RESET=1."""
    db_path = app.config["DB_PATH"]
    if os.path.exists(db_path):
        os.remove(db_path)

    for folder_key in ["UPLOAD_FOLDER", "CARDS_FOLDER", "WALLETS_FOLDER"]:
        folder = app.config[folder_key]
        if not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            if name.startswith("."):        # keep .gitkeep etc.
                continue
            p = os.path.join(folder, name)
            try:
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            except Exception:
                pass

    print("  🗑️  Demo state reset: DB + uploads + cards + wallets cleared")

def get_db():
    db = sqlite3.connect(app.config["DB_PATH"])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS citizens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            citizen_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            date_of_birth TEXT NOT NULL,
            birth_year INTEGER NOT NULL,
            district TEXT NOT NULL,
            blood_group TEXT DEFAULT '',
            gender TEXT DEFAULT '',
            photo_path TEXT DEFAULT '',
            nonce TEXT NOT NULL,
            credential_hash TEXT NOT NULL,
            issuer_signature TEXT NOT NULL,
            citizen_secret TEXT NOT NULL DEFAULT '',
            nonce_issuance TEXT NOT NULL DEFAULT '',
            leaf_hash TEXT NOT NULL DEFAULT '',
            leaf_index INTEGER NOT NULL DEFAULT 0,
            issued_at TEXT NOT NULL,
            card_path TEXT DEFAULT '',
            wallet_downloaded INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS merkle_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            merkle_root TEXT NOT NULL DEFAULT '',
            tree_json TEXT NOT NULL DEFAULT '{}',
            total_leaves INTEGER NOT NULL DEFAULT 0,
            tree_depth INTEGER NOT NULL DEFAULT 3,
            updated_at TEXT NOT NULL DEFAULT ''
        )
    """)
    db.execute("""
        INSERT OR IGNORE INTO merkle_state (id, merkle_root, tree_json, total_leaves, tree_depth, updated_at)
        VALUES (1, '', '{}', 0, ?, ?)
    """, (TREE_DEPTH, datetime.now().isoformat()))
    db.commit()
    db.close()


# ── Startup reset logic ──
def _should_reset():
    # CLI: python app.py --reset
    if "--reset" in sys.argv:
        return True
    # Env: VIDAA_RESET=1 python app.py
    if os.getenv("VIDAA_RESET", "0") == "1":
        return True
    return False

if _should_reset():
    reset_demo_state()

init_db()


# ══════════════════════════════════════════════════════════════
#  CRYPTOGRAPHIC FUNCTIONS
# ══════════════════════════════════════════════════════════════

def sha256_hex(data_hex):
    """SHA-256 of hex-encoded data → hex digest."""
    return hashlib.sha256(bytes.fromhex(data_hex)).hexdigest()

def generate_citizen_id(name, dob):
    dob_clean = dob.replace("-", "")
    suffix = secrets.token_hex(2).upper()
    initials = "".join([w[0] for w in name.split()[:2]]).upper()
    return f"VR-{dob_clean}-{initials}{suffix}"

def generate_citizen_secret():
    return secrets.token_hex(32)

def generate_nonce_issuance():
    return secrets.token_hex(16)

def generate_nonce():
    return secrets.token_hex(16)

def int_to_hex_padded(value, byte_length):
    return value.to_bytes(byte_length, byteorder='big').hex()

def compute_leaf_hash(birth_year, citizen_secret, nonce_issuance):
    """
    leaf = SHA-256( BE16(birth_year) || citizen_secret || nonce_issuance )
    Preimage: 2 + 32 + 16 = 50 bytes = 400 bits → Circom Sha256(400)
    """
    by_hex = int_to_hex_padded(birth_year, 2)
    preimage_hex = by_hex + citizen_secret + nonce_issuance
    return sha256_hex(preimage_hex)

def compute_credential_hash(citizen_id, name, birth_year, district, blood_group, gender, nonce):
    preimage = f"{citizen_id}||{name}||{birth_year}||{district}||{blood_group}||{gender}||{nonce}"
    return hashlib.sha256(preimage.encode()).hexdigest()

def sign_credential(credential_hash):
    return hmac_mod.new(
        VIDAA_SECRET_KEY.encode(), credential_hash.encode(), hashlib.sha256
    ).hexdigest()


# ══════════════════════════════════════════════════════════════
#  MERKLE TREE ENGINE
# ══════════════════════════════════════════════════════════════

def hash_pair(left, right):
    """parent = SHA-256(left_32B || right_32B) - 512-bit input → Circom Sha256(512)"""
    return sha256_hex(left + right)

def build_merkle_tree(leaves):
    num_real = len(leaves)
    padded = list(leaves) + [EMPTY_LEAF] * (MAX_CITIZENS - len(leaves))
    layers = [padded[:]]
    current = padded
    for _ in range(TREE_DEPTH):
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i+1] if i+1 < len(current) else EMPTY_LEAF
            next_level.append(hash_pair(left, right))
        layers.append(next_level)
        current = next_level
    return {
        'root': current[0] if current else EMPTY_LEAF,
        'depth': TREE_DEPTH, 'leaves': padded,
        'layers': layers, 'num_real': num_real,
    }

def get_merkle_path(tree, leaf_index):
    siblings, indices = [], []
    idx = leaf_index
    for level in range(tree['depth']):
        layer = tree['layers'][level]
        if idx % 2 == 0:
            sibling_idx = idx + 1; indices.append(0)
        else:
            sibling_idx = idx - 1; indices.append(1)
        siblings.append(layer[sibling_idx] if sibling_idx < len(layer) else EMPTY_LEAF)
        idx //= 2
    return {'path_siblings': siblings, 'path_indices': indices}

def rebuild_tree_and_update_db():
    db = get_db()
    citizens = db.execute("SELECT citizen_id, leaf_hash, id FROM citizens ORDER BY id ASC").fetchall()
    leaves = [c['leaf_hash'] for c in citizens]
    if not leaves:
        db.execute("UPDATE merkle_state SET merkle_root='', tree_json='{}', total_leaves=0, updated_at=? WHERE id=1",
                   (datetime.now().isoformat(),))
        db.commit(); db.close()
        return {'root': '', 'depth': TREE_DEPTH, 'leaves': [], 'layers': [], 'num_real': 0}
    tree = build_merkle_tree(leaves)
    for i, c in enumerate(citizens):
        db.execute("UPDATE citizens SET leaf_index=? WHERE citizen_id=?", (i, c['citizen_id']))
    db.execute("UPDATE merkle_state SET merkle_root=?, tree_json=?, total_leaves=?, updated_at=? WHERE id=1",
               (tree['root'], json.dumps(tree), len(leaves), datetime.now().isoformat()))
    db.commit(); db.close()
    return tree

def get_current_tree():
    db = get_db()
    state = db.execute("SELECT tree_json FROM merkle_state WHERE id=1").fetchone()
    db.close()
    if state and state['tree_json'] and state['tree_json'] != '{}':
        return json.loads(state['tree_json'])
    return None

def get_current_root():
    db = get_db()
    state = db.execute("SELECT merkle_root FROM merkle_state WHERE id=1").fetchone()
    db.close()
    return state['merkle_root'] if state else ''


# ══════════════════════════════════════════════════════════════
#  CREDENTIAL WALLET (hex-only format per integration plan)
# ══════════════════════════════════════════════════════════════

def generate_credential_wallet(citizen, tree):
    """
    Flat hex-only wallet - bit conversion happens in the prover script (Node).
    This eliminates Python↔Circom bit-ordering mismatches.
    """
    path = get_merkle_path(tree, citizen['leaf_index'])
    return {
        "_meta": {
            "version": "2.1",
            "issuer": "VIDAA - Veritasian Identity Assurance Authority",
            "citizen_id": citizen['citizen_id'],
            "full_name": citizen['full_name'],
            "issued_at": citizen['issued_at'],
            "tree_depth": TREE_DEPTH,
            "WARNING": "PRIVATE - Never share with verifiers.",
        },
        "birth_year": citizen['birth_year'],
        "citizen_secret_hex": citizen['citizen_secret'],
        "nonce_issuance_hex": citizen['nonce_issuance'],
        "leaf_hash_hex": citizen['leaf_hash'],
        "leaf_index": citizen['leaf_index'],
        "path_indices": path['path_indices'],
        "path_siblings_hex": path['path_siblings'],
        "merkle_root_hex": tree['root'],
    }

def save_credential_wallet(citizen, tree):
    wallet = generate_credential_wallet(citizen, tree)
    filename = f"wallet_{citizen['citizen_id']}.json"
    filepath = os.path.join(app.config["WALLETS_FOLDER"], filename)
    with open(filepath, 'w') as f:
        json.dump(wallet, f, indent=2)
    return filepath, filename


# ══════════════════════════════════════════════════════════════
#  DERIVATION STEPS (UI)
# ══════════════════════════════════════════════════════════════

def get_derivation_steps(citizen, tree=None):
    by_hex = int_to_hex_padded(citizen['birth_year'], 2)
    steps = {
        "step1_birth_year": citizen['birth_year'],
        "step1_birth_year_hex": f"0x{by_hex}",
        "step1_birth_year_bits": f"{citizen['birth_year']:016b}",
        "step2_citizen_secret": f"0x{citizen['citizen_secret'][:16]}...{citizen['citizen_secret'][-8:]}",
        "step2_secret_length": "256 bits (32 bytes)",
        "step3_nonce_issuance": f"0x{citizen['nonce_issuance']}",
        "step3_nonce_length": "128 bits (16 bytes)",
        "step4_preimage_size": "50 bytes (400 bits)",
        "step5_leaf_hash": citizen['leaf_hash'],
        "step6_leaf_index": citizen['leaf_index'],
    }
    if tree:
        path = get_merkle_path(tree, citizen['leaf_index'])
        steps["step7_siblings"] = [f"0x{s[:16]}..." for s in path['path_siblings']]
        steps["step7_indices"] = path['path_indices']
        steps["step8_merkle_root"] = tree['root']
    steps["legacy_credential_hash"] = citizen['credential_hash']
    steps["legacy_issuer_signature"] = citizen['issuer_signature']
    return steps


# ══════════════════════════════════════════════════════════════
#  ID CARD GENERATOR
# ══════════════════════════════════════════════════════════════

def generate_id_card(citizen_data, merkle_root=""):
    W, H = 1050, 700
    DARK_BG, TEAL, TEAL_L, MINT = (10,22,40), (13,148,136), (20,184,166), (94,234,212)
    WHITE, LGRAY, GOLD, DIM = (255,255,255), (200,210,220), (245,158,11), (80,100,130)

    card = Image.new("RGBA", (W, H), (0,0,0,0))
    draw = ImageDraw.Draw(card)
    R = 24
    draw.rounded_rectangle([(0,0),(W-1,H-1)], radius=R, fill=DARK_BG, outline=TEAL, width=3)
    draw.rounded_rectangle([(0,0),(W-1,80)], radius=R, fill=TEAL)
    draw.rectangle([(0,50),(W,80)], fill=TEAL)

    # Fonts: try bundled NotoSans → fallback to system DejaVu → fallback to default
    font_dir = BASE_DIR / "assets" / "fonts"
    font_bold_path = font_dir / "NotoSans-Bold.ttf"
    font_regular_path = font_dir / "NotoSans-Regular.ttf"

    def _font(bold, size):
        for path in ([font_bold_path] if bold else [font_regular_path]):
            if path.exists():
                try: return ImageFont.truetype(str(path), size)
                except: pass
        # System fallback
        dv = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
        try: return ImageFont.truetype(f"/usr/share/fonts/truetype/dejavu/{dv}", size)
        except: return ImageFont.load_default()

    fb = lambda s: _font(True, s)
    fn = lambda s: _font(False, s)

    draw.text((30,14), "VERITASIA", fill=WHITE, font=fb(28))
    draw.text((30,50), "VIDAA - NATIONAL IDENTITY  ·  MERKLE-TREE v2", fill=MINT, font=fn(12))
    draw.text((W-300,22), f"ID: {citizen_data['citizen_id']}", fill=GOLD, font=fb(13))
    draw.text((W-300,48), f"Issued: {citizen_data['issued_at'][:10]}", fill=LGRAY, font=fn(10))

    px, py, pw, ph = 30, 100, 170, 210
    draw.rounded_rectangle([(px-2,py-2),(px+pw+2,py+ph+2)], radius=10, fill=TEAL, outline=TEAL_L, width=2)
    if citizen_data.get("photo_path") and os.path.exists(citizen_data["photo_path"]):
        try:
            photo = Image.open(citizen_data["photo_path"]).convert("RGB").resize((pw,ph), Image.LANCZOS)
            mask = Image.new("L", (pw,ph), 0); ImageDraw.Draw(mask).rounded_rectangle([(0,0),(pw-1,ph-1)], radius=8, fill=255)
            card.paste(photo, (px,py), mask)
        except: draw.rounded_rectangle([(px,py),(px+pw,py+ph)], radius=8, fill=(30,50,80)); draw.text((px+45,py+90), "PHOTO", fill=LGRAY, font=fn(12))
    else:
        draw.rounded_rectangle([(px,py),(px+pw,py+ph)], radius=8, fill=(30,50,80)); draw.text((px+45,py+90), "PHOTO", fill=LGRAY, font=fn(12))

    fx = 225
    for i, (lbl, val) in enumerate([("FULL NAME", citizen_data['full_name']),("DATE OF BIRTH", citizen_data['date_of_birth']),("DISTRICT", citizen_data['district']),("BLOOD GROUP", citizen_data.get('blood_group','')),("GENDER", citizen_data.get('gender',''))]):
        y = 100 + i * 40; draw.text((fx,y), lbl, fill=TEAL_L, font=fn(11)); draw.text((fx+130,y), str(val), fill=WHITE, font=fb(14))

    sy = 320
    draw.line([(30,sy),(W-30,sy)], fill=(30,60,90), width=1)
    draw.text((30,sy+10), "MERKLE LEAF HASH", fill=TEAL_L, font=fn(11))
    lh = citizen_data.get('leaf_hash','')
    draw.text((30,sy+26), f"0x{lh[:32]}", fill=MINT, font=fn(9))
    draw.text((30,sy+40), f"  {lh[32:]}", fill=MINT, font=fn(9))
    draw.text((30,sy+56), "= SHA256( birth_year || secret || nonce )", fill=DIM, font=fn(9))
    draw.text((550,sy+10), "LEAF INDEX", fill=TEAL_L, font=fn(11))
    draw.text((550,sy+26), f"#{citizen_data.get('leaf_index',0)} of {MAX_CITIZENS}", fill=WHITE, font=fb(14))
    draw.text((700,sy+10), "MERKLE ROOT (PUBLIC)", fill=GOLD, font=fn(11))
    if merkle_root: draw.text((700,sy+26), f"0x{merkle_root[:24]}...", fill=GOLD, font=fn(9))
    draw.text((30,sy+78), "CREDENTIAL HASH (LEGACY)", fill=DIM, font=fn(11))
    draw.text((250,sy+78), f"0x{citizen_data['credential_hash'][:32]}...", fill=DIM, font=fn(9))
    draw.text((30,sy+96), "ISSUER SIGNATURE", fill=DIM, font=fn(11))
    draw.text((250,sy+96), f"sig=0x{citizen_data['issuer_signature'][:24]}...", fill=DIM, font=fn(9))

    by2 = sy + 125
    draw.rounded_rectangle([(0,by2),(W,H-1)], radius=R, fill=(8,18,35))
    draw.rectangle([(0,by2),(W,by2+20)], fill=(8,18,35))
    qx, qy, qs = 30, by2+10, 85
    draw.rounded_rectangle([(qx,qy),(qx+qs,qy+qs)], radius=6, fill=WHITE)
    random.seed(lh or citizen_data['credential_hash'])
    for r in range(11):
        for c in range(11):
            if random.random() > 0.45: draw.rectangle([(qx+7+c*6, qy+7+r*6),(qx+12+c*6, qy+12+r*6)], fill=DARK_BG)
    draw.text((130,by2+10), "Merkle-tree registered credential. Verify via ZK proof.", fill=LGRAY, font=fn(10))
    draw.text((130,by2+26), "No personal data exposed to verifiers.", fill=LGRAY, font=fn(10))
    draw.text((130,by2+46), "CONFIDENTIAL - Do not share citizen_secret or nonce.", fill=GOLD, font=fn(10))
    ni = citizen_data.get('nonce_issuance','')
    draw.text((130,by2+66), f"Nonce: 0x{ni[:8]}...{ni[-8:]}  ·  Secret: [REDACTED]", fill=(60,80,110), font=fn(9))
    draw.text((W-200,by2+78), "VERITASIA × VIDAA v2.1", fill=(30,50,70), font=fn(10))

    os.makedirs(app.config["CARDS_FOLDER"], exist_ok=True)
    fname = f"VIDAA_ID_{citizen_data['citizen_id']}.png"
    fpath = os.path.join(app.config["CARDS_FOLDER"], fname)
    card.save(fpath, "PNG", quality=95)
    return fpath, fname


# ══════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    root = get_current_root()
    db = get_db()
    count = db.execute("SELECT COUNT(*) as c FROM citizens").fetchone()['c']
    db.close()
    return render_template("index.html", merkle_root=root, citizen_count=count)

@app.route("/register", methods=["GET"])
def register_page():
    db = get_db()
    count = db.execute("SELECT COUNT(*) as c FROM citizens").fetchone()['c']
    db.close()
    return render_template("register.html", citizen_count=count,
                           max_citizens=MAX_CITIZENS, districts=DISTRICTS)

@app.route("/register", methods=["POST"])
def register_citizen():
    full_name = request.form.get("full_name","").strip()
    dob = request.form.get("date_of_birth","").strip()
    district = request.form.get("district","").strip()
    blood_group = request.form.get("blood_group","").strip()
    gender = request.form.get("gender","").strip()

    if not all([full_name, dob, district]):
        return jsonify({"error": "Name, DOB, and District required"}), 400
    if district not in DISTRICTS:
        return jsonify({"error": "Invalid district selection"}), 400

    db = get_db()
    count = db.execute("SELECT COUNT(*) as c FROM citizens").fetchone()['c']
    db.close()
    if count >= MAX_CITIZENS:
        return jsonify({"error": f"Registry full ({MAX_CITIZENS} max for depth {TREE_DEPTH})."}), 400

    birth_year = int(dob.split("-")[0])
    photo_path = ""
    if "photo" in request.files:
        photo = request.files["photo"]
        if photo.filename:
            ext = photo.filename.rsplit(".",1)[-1].lower()
            photo_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{secrets.token_hex(8)}.{ext}")
            photo.save(photo_path)

    citizen_id = generate_citizen_id(full_name, dob)
    citizen_secret = generate_citizen_secret()
    nonce_issuance = generate_nonce_issuance()
    leaf_hash = compute_leaf_hash(birth_year, citizen_secret, nonce_issuance)
    nonce = generate_nonce()
    credential_hash = compute_credential_hash(citizen_id, full_name, birth_year, district, blood_group, gender, nonce)
    issuer_signature = sign_credential(credential_hash)
    issued_at = datetime.now().isoformat()

    db = get_db()
    try:
        db.execute("""INSERT INTO citizens
            (citizen_id, full_name, date_of_birth, birth_year, district, blood_group, gender,
             photo_path, nonce, credential_hash, issuer_signature, citizen_secret, nonce_issuance,
             leaf_hash, leaf_index, issued_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (citizen_id, full_name, dob, birth_year, district, blood_group, gender,
             photo_path, nonce, credential_hash, issuer_signature, citizen_secret, nonce_issuance,
             leaf_hash, count, issued_at))
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({"error": "ID collision - try again."}), 400
    db.close()

    tree = rebuild_tree_and_update_db()
    citizen_data = dict(citizen_id=citizen_id, full_name=full_name, date_of_birth=dob,
        birth_year=birth_year, district=district, blood_group=blood_group, gender=gender,
        photo_path=photo_path, nonce=nonce, credential_hash=credential_hash,
        issuer_signature=issuer_signature, citizen_secret=citizen_secret,
        nonce_issuance=nonce_issuance, leaf_hash=leaf_hash, leaf_index=count, issued_at=issued_at)

    card_path, card_filename = generate_id_card(citizen_data, tree['root'])
    db = get_db()
    db.execute("UPDATE citizens SET card_path=? WHERE citizen_id=?", (card_path, citizen_id))
    db.commit()
    citizen_row = db.execute("SELECT * FROM citizens WHERE citizen_id=?", (citizen_id,)).fetchone()
    db.close()

    save_credential_wallet(dict(citizen_row), tree)
    derivation = get_derivation_steps(dict(citizen_row), tree)
    path_info = get_merkle_path(tree, citizen_row['leaf_index'])

    return jsonify({
        "success": True, "citizen": citizen_data, "derivation": derivation,
        "card_url": f"/cards/{card_filename}",
        "wallet_url": f"/api/wallet/{citizen_id}",
        "merkle": {
            "root": tree['root'], "leaf_hash": leaf_hash,
            "leaf_index": citizen_row['leaf_index'],
            "path_siblings": [f"0x{s[:16]}..." for s in path_info['path_siblings']],
            "path_indices": path_info['path_indices'],
            "total_leaves": tree['num_real'], "tree_depth": TREE_DEPTH,
        },
    })

@app.route("/dashboard")
def dashboard():
    db = get_db()
    citizens = db.execute("SELECT * FROM citizens ORDER BY id ASC").fetchall()
    state = db.execute("SELECT * FROM merkle_state WHERE id=1").fetchone()
    db.close()
    tree = get_current_tree()
    return render_template("dashboard.html", citizens=citizens, state=state,
                           tree=tree, max_citizens=MAX_CITIZENS, tree_depth=TREE_DEPTH)

@app.route("/merkle")
def merkle_tree_page():
    tree = get_current_tree()
    db = get_db()
    citizens = db.execute("SELECT citizen_id, full_name, leaf_hash, leaf_index FROM citizens ORDER BY id ASC").fetchall()
    db.close()
    return render_template("merkle.html", tree=tree, citizens=citizens,
                           tree_depth=TREE_DEPTH, max_citizens=MAX_CITIZENS)

@app.route("/citizen/<citizen_id>")
def citizen_detail(citizen_id):
    db = get_db()
    citizen = db.execute("SELECT * FROM citizens WHERE citizen_id=?", (citizen_id,)).fetchone()
    db.close()
    if not citizen: return "Citizen not found", 404
    tree = get_current_tree()
    derivation = get_derivation_steps(dict(citizen), tree)
    path_info = get_merkle_path(tree, citizen['leaf_index']) if tree else None
    return render_template("citizen_detail.html", citizen=citizen, derivation=derivation,
                           tree=tree, path_info=path_info, merkle_root=get_current_root())

@app.route("/cards/<filename>")
def serve_card(filename): return send_from_directory(app.config["CARDS_FOLDER"], filename)

@app.route("/uploads/<filename>")
def serve_upload(filename): return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ── API ENDPOINTS ──

@app.route("/api/root")
def api_root():
    root = get_current_root()
    db = get_db()
    state = db.execute("SELECT * FROM merkle_state WHERE id=1").fetchone()
    db.close()
    return jsonify({"merkle_root": root, "tree_depth": TREE_DEPTH,
                     "total_citizens": state['total_leaves'] if state else 0,
                     "max_citizens": MAX_CITIZENS, "updated_at": state['updated_at'] if state else ''})

@app.route("/api/wallet/<citizen_id>")
def api_wallet(citizen_id):
    db = get_db()
    citizen = db.execute("SELECT * FROM citizens WHERE citizen_id=?", (citizen_id,)).fetchone()
    db.close()
    if not citizen: return jsonify({"error": "Not found"}), 404
    tree = get_current_tree()
    if not tree: return jsonify({"error": "Tree not built"}), 400
    wallet = generate_credential_wallet(dict(citizen), tree)
    return Response(json.dumps(wallet, indent=2), mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename=wallet_{citizen_id}.json'})

@app.route("/api/wallet/<citizen_id>/view")
def api_wallet_view(citizen_id):
    db = get_db()
    citizen = db.execute("SELECT * FROM citizens WHERE citizen_id=?", (citizen_id,)).fetchone()
    db.close()
    if not citizen: return jsonify({"error": "Not found"}), 404
    tree = get_current_tree()
    if not tree: return jsonify({"error": "Tree not built"}), 400
    return jsonify(generate_credential_wallet(dict(citizen), tree))

@app.route("/api/tree")
def api_tree():
    tree = get_current_tree()
    if not tree: return jsonify({"error": "No tree"}), 404
    return jsonify({"root": tree['root'], "depth": tree['depth'],
                     "num_real": tree['num_real'], "layers": tree['layers']})

@app.route("/api/citizens")
def api_citizens():
    db = get_db()
    citizens = db.execute("SELECT citizen_id, full_name, date_of_birth, district, leaf_hash, leaf_index, credential_hash, issued_at FROM citizens ORDER BY id ASC").fetchall()
    db.close()
    return jsonify([dict(c) for c in citizens])

@app.route("/api/derivation/<citizen_id>")
def api_derivation(citizen_id):
    db = get_db()
    c = db.execute("SELECT * FROM citizens WHERE citizen_id=?", (citizen_id,)).fetchone()
    db.close()
    if not c: return jsonify({"error": "Not found"}), 404
    return jsonify(get_derivation_steps(dict(c), get_current_tree()))


if __name__ == "__main__":
    # Strip our custom flags before Flask sees sys.argv
    clean_argv = [a for a in sys.argv if a != "--reset"]
    sys.argv = clean_argv

    print("\n" + "="*60)
    print("  🏛️  VIDAA - Veritasian Identity Assurance Authority")
    print("  🌳  Merkle-Tree v2.1 · ZK-Proof Ready")
    print("  🌐  Portal: http://localhost:8080")
    print("  💡  Reset: python app.py --reset")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=8080, debug=True)
