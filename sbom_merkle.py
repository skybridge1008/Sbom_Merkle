#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sbom_merkle.py — SBOM Merkle bundle with node-level encryption, stable-hash(purl), and bundle concatenation

Features
- Deterministic normalization
- Node-level encryption (preferred): encrypts entire component payload except bom-ref
- Optional per-field encryption/redaction (backward-compatible)
- Stable hashing: use only a chosen field's hash (e.g., purl) for leaf hashes -> roots stay stable regardless of encryption
- Merkle tree build, proof generation & verification
- Version chaining (prev_root) and bundle concatenation update
- Optional Ed25519 signing of roots

CLI
- build: SBOM -> bundle
- prove: produce Merkle proof for a bom-ref
- verify: verify proof (optional decryption)
- update: concat previous bundle leaves + new SBOM leaves => new bundle

Dependencies (optional):
    pip install cryptography pynacl
"""

from __future__ import annotations
import argparse
import base64
import json
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

# Optional crypto libs
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:
    AESGCM = None

try:
    from nacl.signing import SigningKey, VerifyKey  # type: ignore
    from nacl.exceptions import BadSignatureError  # type: ignore
except Exception:
    SigningKey = None
    VerifyKey = None
    BadSignatureError = Exception


# -------------------- Utils --------------------

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canonical_json(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

def h_domain(prefix: bytes, *chunks: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(prefix)
    for c in chunks:
        h.update(c)
    return h.digest()


# -------------------- Traversal --------------------

def iter_components(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = sbom.get('components') or []
    return comps if isinstance(comps, list) else []

def get_by_path(obj: Any, path: str):
    cur = obj
    parts = path.split('.')
    parent = None
    key = None
    for p in parts:
        parent = cur
        key = p
        if isinstance(cur, dict):
            if p not in cur:
                return (False, None, None, '')
            cur = cur[p]
        elif isinstance(cur, list):
            try:
                idx = int(p)
            except Exception:
                return (False, None, None, '')
            if idx < 0 or idx >= len(cur):
                return (False, None, None, '')
            cur = cur[idx]
        else:
            return (False, None, None, '')
    return (True, parent, cur, key if key is not None else '')

def set_by_path(obj: Any, path: str, val: Any) -> bool:
    ok, parent, _, last = get_by_path(obj, path)
    if not ok:
        return False
    if isinstance(parent, dict):
        parent[last] = val
        return True
    if isinstance(parent, list):
        try:
            idx = int(last)
        except Exception:
            return False
        parent[idx] = val
        return True
    return False


# -------------------- Crypto --------------------

def encrypt_value(value: Any, key: bytes, aad: str) -> Dict[str, Any]:
    if AESGCM is None:
        raise RuntimeError("AES-GCM needs 'cryptography'. pip install cryptography")
    pt = canonical_json(value).encode('utf-8')
    nonce = secrets.token_bytes(12)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, pt, aad.encode('utf-8'))
    return {"enc":"v1","alg":"AES-GCM","nonce_b64":b64e(nonce),"aad":aad,"ct_b64":b64e(ct)}

def decrypt_value(encobj: Dict[str, Any], key: bytes) -> Any:
    if AESGCM is None:
        raise RuntimeError("AES-GCM needs 'cryptography'. pip install cryptography")
    if not (isinstance(encobj, dict) and encobj.get("enc") == "v1" and encobj.get("alg") == "AES-GCM"):
        raise ValueError("unsupported enc object")
    nonce = b64d(encobj["nonce_b64"])
    ct = b64d(encobj["ct_b64"])
    aad = encobj.get("aad","")
    aead = AESGCM(key)
    pt = aead.decrypt(nonce, ct, aad.encode('utf-8'))
    return json.loads(pt.decode('utf-8'))

def redact_value(value: Any) -> Dict[str, Any]:
    nonce = secrets.token_bytes(32)
    commit = sha256(canonical_json(value).encode('utf-8') + nonce).hex()
    return {"redacted":"v1","commitment_hex":commit,"nonce_b64":b64e(nonce)}


# -------------------- Merkle --------------------

@dataclass
class LeafRecord:
    idx: int
    ref: str
    record: Dict[str, Any]
    leaf_hash: str

@dataclass
class MerkleBundle:
    leaves: List[LeafRecord]
    tree: List[List[str]]
    root: str
    meta: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[Dict[str, Any]] = None

def leaf_hash(record: Dict[str, Any]) -> bytes:
    cj = canonical_json(record).encode('utf-8')
    return h_domain(b'\x00', sha256(cj))

def leaf_hash_from_hashview(hashview: Dict[str, Any]) -> bytes:
    cj = canonical_json(hashview).encode('utf-8')
    return h_domain(b'\x00', sha256(cj))

def build_merkle(leaves: List[bytes]):
    if not leaves:
        empty = sha256(b'')
        return [[empty]], empty
    level = leaves[:]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i+1 == len(level):
                nxt.append(h_domain(b'\x01', level[i], level[i]))
            else:
                nxt.append(h_domain(b'\x01', level[i], level[i+1]))
        level = nxt
        levels.append(level)
    return levels, level[0]

def gen_proof(levels: List[List[bytes]], index: int):
    proof = []
    idx = index
    for lvl in range(0, len(levels)-1):
        nodes = levels[lvl]
        if idx % 2 == 0:
            sib_idx = idx + 1 if idx + 1 < len(nodes) else idx
            direction = "R"
        else:
            sib_idx = idx - 1
            direction = "L"
        proof.append((direction, nodes[sib_idx].hex()))
        idx //= 2
    return proof

def verify_proof(leaf: bytes, proof, expected_root_hex: str) -> bool:
    h = leaf
    for direction, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        if direction == "R":
            h = h_domain(b'\x01', h, sib)
        elif direction == "L":
            h = h_domain(b'\x01', sib, h)
        else:
            return False
    return h.hex() == expected_root_hex.lower()


# -------------------- Signing --------------------

def sign_root_ed25519(root_hex: str, meta: Dict[str, Any], sk_hex: Optional[str]):
    if sk_hex is None:
        return None
    if SigningKey is None:
        raise RuntimeError("Ed25519 needs 'pynacl'. pip install pynacl")
    sk = SigningKey(bytes.fromhex(sk_hex))
    msg = canonical_json({"root":root_hex.lower(), "meta":meta}).encode('utf-8')
    sig = sk.sign(msg)
    vk = sk.verify_key
    return {"alg":"ed25519","sig_b64":b64e(sig.signature),"pub_hex":vk.encode().hex()}

def verify_root_sig(signature: Dict[str, Any], root_hex: str, meta: Dict[str, Any]) -> bool:
    if VerifyKey is None:
        raise RuntimeError("Ed25519 needs 'pynacl'. pip install pynacl")
    if not signature or signature.get("alg") != "ed25519":
        return False
    sig = b64d(signature["sig_b64"])
    pub = bytes.fromhex(signature["pub_hex"])
    vk = VerifyKey(pub)
    msg = canonical_json({"root":root_hex.lower(), "meta":meta}).encode('utf-8')
    try:
        vk.verify(msg, sig)
        return True
    except BadSignatureError:
        return False


# -------------------- Build --------------------

def build_bundle(sbom: Dict[str, Any],
                 encrypt_paths: List[str],
                 redact_paths: List[str],
                 aead_key_hex: Optional[str],
                 prev_root_hex: Optional[str] = None,
                 sign_sk_hex: Optional[str] = None,
                 encrypt_node: bool = False,
                 stable_hash_field: Optional[str] = None) -> MerkleBundle:
    if (encrypt_paths or encrypt_node) and not aead_key_hex:
        # Encryption requested but no key; allow if encrypt_paths empty and encrypt_node False; otherwise raise
        if encrypt_node or (encrypt_paths and len(encrypt_paths) > 0):
            raise ValueError("encryption requested but no --key-hex provided")
    key = bytes.fromhex(aead_key_hex) if aead_key_hex else None

    sbom_clone = json.loads(canonical_json(sbom))
    leaves: List[LeafRecord] = []
    leaf_bytes: List[bytes] = []

    comps = iter_components(sbom_clone)
    for idx, comp in enumerate(comps):
        rec = json.loads(canonical_json(comp))

        # Build hashview (stable preimage) if requested
        hashview = None
        if stable_hash_field:
            def _get(obj, path):
                parts = path.split('.')
                cur = obj
                for pp in parts:
                    if isinstance(cur, dict) and pp in cur:
                        cur = cur[pp]
                    else:
                        return None
                return cur
            hv_val = _get(rec, stable_hash_field)
            if hv_val is None:
                hv_val = rec.get("purl") or rec.get("bom-ref") or rec.get("name")
            hv_bytes = canonical_json(hv_val).encode('utf-8')
            hashview = {"stable_field": stable_hash_field, "value_sha256": sha256(hv_bytes).hex()}

        # Node-level encryption
        if encrypt_node and key:
            ref = rec.get("bom-ref", f"component[{idx}]")
            if stable_hash_field:
                # Redacted-only form; include hash hint so consumers can correlate
                rec = {
                    "bom-ref": ref,
                    "__node_redacted": {
                        "v": 1,
                        "reason": "confidential",
                        "stable": hashview
                    }
                }
            else:
                # Default: ciphertext form
                payload = json.loads(canonical_json(rec))
                if isinstance(payload, dict) and "bom-ref" in payload:
                    payload_no_ref = {k:v for k,v in payload.items() if k != "bom-ref"}
                else:
                    payload_no_ref = payload
                enc = encrypt_value(payload_no_ref, key, aad=f"node:{ref}")
                rec = {"bom-ref": ref, "__node_enc": enc}
        else:
            # Per-field redaction
            for path in redact_paths:
                ok, parent, value, last = get_by_path(rec, path)
                if ok:
                    set_by_path(rec, path, redact_value(value))
            # Per-field encryption
            if key:
                for path in encrypt_paths:
                    ok, parent, value, last = get_by_path(rec, path)
                    if ok:
                        set_by_path(rec, path, encrypt_value(value, key, aad=path))

        # Compute leaf hash (prefer stable hashview if provided)
        if hashview is not None:
            lhash_hex = leaf_hash_from_hashview(hashview).hex()
        else:
            lhash_hex = leaf_hash(rec).hex()

        leaves.append(LeafRecord(idx=idx, ref=str(rec.get("bom-ref", f"component[{idx}]")), record=rec, leaf_hash=lhash_hex))
        leaf_bytes.append(bytes.fromhex(lhash_hex))

    levels, root = build_merkle(leaf_bytes)

    meta = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "leaf_count": len(leaves),
        "prev_root": prev_root_hex,
        "root_alg": "sha256",
        "leaf_alg": "sha256",
        "domain_sep": {"leaf":"0x00","inner":"0x01"},
        "encrypt_mode": "node" if encrypt_node else ("field" if key and encrypt_paths else "none"),
        "stable_hash_field": stable_hash_field
    }
    signature = sign_root_ed25519(root.hex(), meta, sign_sk_hex)

    return MerkleBundle(
        leaves=leaves,
        tree=[[h.hex() for h in level] for level in levels],
        root=root.hex(),
        meta=meta,
        signature=signature
    )


# -------------------- Concatenation Update --------------------

def combine_with_previous(prev_bundle: Dict[str, Any], new_bundle: MerkleBundle, sign_sk_hex: Optional[str] = None) -> MerkleBundle:
    prev_leaves = prev_bundle.get("leaves", [])
    prev_leaf_hash_bytes = [bytes.fromhex(l["leaf_hash"]) for l in prev_leaves]
    new_leaf_hash_bytes = [bytes.fromhex(l.leaf_hash) for l in new_bundle.leaves]
    all_leaf_hash_bytes = prev_leaf_hash_bytes + new_leaf_hash_bytes

    levels, root = build_merkle(all_leaf_hash_bytes)

    combined_leaves: List[LeafRecord] = []
    for i, l in enumerate(prev_leaves):
        combined_leaves.append(LeafRecord(idx=i, ref=l["ref"], record=l["record"], leaf_hash=l["leaf_hash"]))
    base = len(prev_leaves)
    for j, l in enumerate(new_bundle.leaves):
        combined_leaves.append(LeafRecord(idx=base+j, ref=l.ref, record=l.record, leaf_hash=l.leaf_hash))

    meta = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "leaf_count": len(combined_leaves),
        "prev_root": prev_bundle.get("root"),
        "append_mode": "concat",
        "prev_leaf_count": len(prev_leaves),
        "added_leaf_count": len(new_bundle.leaves),
        "root_alg": "sha256",
        "leaf_alg": "sha256",
        "domain_sep": {"leaf":"0x00","inner":"0x01"},
    }
    signature = sign_root_ed25519(root.hex(), meta, sign_sk_hex)

    return MerkleBundle(
        leaves=combined_leaves,
        tree=[[h.hex() for h in level] for level in levels],
        root=root.hex(),
        meta=meta,
        signature=signature
    )


# -------------------- CLI ops --------------------

def cmd_build(a):
    with open(a._in, 'r', encoding='utf-8') as f:
        sbom = json.load(f)
    bundle = build_bundle(
        sbom=sbom,
        encrypt_paths=a.encrypt or [],
        redact_paths=a.redact or [],
        aead_key_hex=a.key_hex,
        prev_root_hex=a.prev_root,
        sign_sk_hex=a.sign_root,
        encrypt_node=bool(a.encrypt_node),
        stable_hash_field=a.stable_hash,
    )
    outj = {
        "root": bundle.root,
        "meta": bundle.meta,
        "signature": bundle.signature,
        "leaves": [asdict(l) for l in bundle.leaves],
        "tree": bundle.tree,
    }
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(outj, f, ensure_ascii=False, indent=2)
    print(f"[ok] bundle written: {a.out}")
    print(f"     root={bundle.root}  leaves={bundle.meta['leaf_count']}  levels={len(bundle.tree)}")

def cmd_prove(a):
    with open(a.bundle, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    leaves = bundle["leaves"]
    target_idx = None
    for i, l in enumerate(leaves):
        if l["ref"] == a.ref or l["record"].get("bom-ref") == a.ref:
            target_idx = i
            break
    if target_idx is None:
        raise SystemExit(f"ref not found: {a.ref}")

    rec = leaves[target_idx]["record"]
    # Compute hash in both ways to be robust: by record and by possible stable hashview
    try:
        lh = leaf_hash(rec).hex()
    except Exception:
        lh = None
    # If bundle used stable-hash, proof contains a leaf_hash computed from hashview; trust that
    leaf_hash_in_bundle = leaves[target_idx]["leaf_hash"].lower()
    if lh and lh != leaf_hash_in_bundle:
        # allow; may be stable-hash mode
        pass

    levels_bytes = [[bytes.fromhex(h) for h in level] for level in bundle["tree"]]
    proof = gen_proof(levels_bytes, target_idx)

    proof_obj = {
        "root": bundle["root"],
        "meta": bundle["meta"],
        "signature": bundle.get("signature"),
        "ref": leaves[target_idx]["ref"],
        "leaf_hash": leaves[target_idx]["leaf_hash"],
        "proof": proof,
        "record": rec if a.include_record else None
    }
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(proof_obj, f, ensure_ascii=False, indent=2)
    print(f"[ok] proof written: {a.out}")

def cmd_verify(a):
    with open(a.bundle, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    with open(a.proof, 'r', encoding='utf-8') as f:
        proof = json.load(f)

    signature = bundle.get("signature")
    if signature:
        try:
            sig_ok = verify_root_sig(signature, bundle["root"], bundle["meta"])
        except Exception as e:
            print(f"[warn] signature check error: {e}")
            sig_ok = False
        print(f"[info] root signature valid: {sig_ok}")

    record = proof.get("record")
    if record is None:
        ref = proof["ref"]
        rec = None
        for l in bundle["leaves"]:
            if l["ref"] == ref:
                rec = l["record"]
                break
        if rec is None:
            raise SystemExit("record not found; re-run prove with --include-record")
        record = rec

    # Compute leaf by record (may differ in stable-hash mode)
    leaf_by_record = leaf_hash(record)
    ok = verify_proof(leaf_by_record, proof["proof"], bundle["root"])
    if not ok and bundle["meta"].get("stable_hash_field"):
        # Reconstruct hashview path if possible
        stable_field = bundle["meta"]["stable_hash_field"]
        def _get(obj, path):
            parts = path.split('.')
            cur = obj
            for pp in parts:
                if isinstance(cur, dict) and pp in cur:
                    cur = cur[pp]
                else:
                    return None
            return cur
        hv_val = _get(record, stable_field) or record.get("purl") or record.get("bom-ref") or record.get("name")
        hv_bytes = canonical_json(hv_val).encode('utf-8')
        hashview = {"stable_field": stable_field, "value_sha256": sha256(hv_bytes).hex()}
        leaf_by_hashview = leaf_hash_from_hashview(hashview)
        ok = verify_proof(leaf_by_hashview, proof["proof"], bundle["root"])

    print(f"[info] merkle proof valid: {ok}")
    if not ok:
        raise SystemExit(2)

    if a.key_hex and a.show_fields:
        key = bytes.fromhex(a.key_hex)
        for path in a.show_fields:
            if path == "__node_enc" and isinstance(record.get("__node_enc"), dict):
                try:
                    dec = decrypt_value(record["__node_enc"], key)
                    print(f"[decrypt] __node_enc = {json.dumps(dec, ensure_ascii=False)}")
                except Exception as e:
                    print(f"[decrypt] __node_enc error: {e}")
                continue

            okp, parent, value, last = get_by_path(record, path)
            if okp and isinstance(value, dict) and value.get("enc") == "v1":
                try:
                    dec = decrypt_value(value, key)
                    print(f"[decrypt] {path} = {json.dumps(dec, ensure_ascii=False)}")
                except Exception as e:
                    print(f"[decrypt] {path} error: {e}")
            elif okp and isinstance(value, dict) and value.get("redacted") == "v1":
                print(f"[redacted] {path} commitment={value.get('commitment_hex')}")
            elif okp:
                print(f"[plain]    {path} = {json.dumps(value, ensure_ascii=False)}")
            else:
                print(f"[miss]     {path} not found")

def cmd_update(a):
    with open(a.prev_bundle, 'r', encoding='utf-8') as f:
        prev_bundle = json.load(f)
    with open(a._in, 'r', encoding='utf-8') as f:
        sbom = json.load(f)

    new_part = build_bundle(
        sbom=sbom,
        encrypt_paths=([] if a.encrypt_node else (a.encrypt or [])),
        redact_paths=([] if a.encrypt_node else (a.redact or [])),
        aead_key_hex=a.key_hex,
        prev_root_hex=None,
        sign_sk_hex=None,
        encrypt_node=bool(a.encrypt_node),
        stable_hash_field=a.stable_hash,
    )

    combined = combine_with_previous(prev_bundle, new_part, sign_sk_hex=a.sign_root)
    outj = {
        "root": combined.root,
        "meta": combined.meta,
        "signature": combined.signature,
        "leaves": [asdict(l) for l in combined.leaves],
        "tree": combined.tree,
    }
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(outj, f, ensure_ascii=False, indent=2)
    print(f"[ok] combined bundle written: {a.out}")
    print(f"     prev_root={prev_bundle.get('root')}  new_root={combined.root}  total_leaves={combined.meta['leaf_count']}")


# -------------------- CLI --------------------

def build_argparser():
    p = argparse.ArgumentParser(description="SBOM → Merkle + Node/Field Encryption/Redaction + StableHash")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Build merkle bundle from SBOM JSON")
    b.add_argument("--in", dest="_in", required=True, help="Input SBOM JSON (CycloneDX)")
    b.add_argument("--out", required=True, help="Output bundle JSON")
    b.add_argument("--key-hex", dest="key_hex", help="AEAD key (hex, 32B=64 hex). Required if encryption used.")
    b.add_argument("--encrypt-node", action="store_true", help="Encrypt entire component node (except bom-ref)")
    b.add_argument("--encrypt", nargs="*", default=[], help="Per-field encryption (dot paths); ignored if --encrypt-node")
    b.add_argument("--redact", nargs="*", default=[], help="Per-field redaction (dot paths); ignored if --encrypt-node")
    b.add_argument("--prev-root", help="Previous bundle root hex (version chaining metadata)")
    b.add_argument("--sign-root", help="Ed25519 secret key hex to sign root (optional)")
    b.add_argument("--stable-hash", dest="stable_hash", help="Use only this field's SHA256 (e.g., purl) for leaf hashes")

    pr = sub.add_parser("prove", help="Generate Merkle proof for a bom-ref")
    pr.add_argument("--bundle", required=True, help="Bundle JSON from build/update step")
    pr.add_argument("--ref", required=True, help="bom-ref to prove")
    pr.add_argument("--out", required=True, help="Proof JSON output path")
    pr.add_argument("--include-record", action="store_true", help="Embed record in proof")

    v = sub.add_parser("verify", help="Verify a proof against a bundle; optionally decrypt fields")
    v.add_argument("--bundle", required=True, help="Bundle JSON")
    v.add_argument("--proof", required=True, help="Proof JSON")
    v.add_argument("--key-hex", dest="key_hex", help="AEAD key hex (for decryption)")
    v.add_argument("--show-fields", nargs="*", default=[], help="Paths to display/decrypt (tip: __node_enc)")

    up = sub.add_parser("update", help="Concatenate previous bundle + new SBOM into a new bundle")
    up.add_argument("--prev-bundle", required=True, help="Existing bundle JSON")
    up.add_argument("--in", dest="_in", required=True, help="New SBOM JSON (CycloneDX)")
    up.add_argument("--out", required=True, help="Output NEW combined bundle JSON")
    up.add_argument("--key-hex", dest="key_hex", help="AEAD key hex (required if encryption used)")
    up.add_argument("--encrypt-node", action="store_true", help="Encrypt entire component node (except bom-ref)")
    up.add_argument("--encrypt", nargs="*", default=[], help="Per-field encryption (ignored if --encrypt-node)")
    up.add_argument("--redact", nargs="*", default=[], help="Per-field redaction (ignored if --encrypt-node)")
    up.add_argument("--sign-root", help="Ed25519 secret key hex to sign NEW root (optional)")
    up.add_argument("--stable-hash", dest="stable_hash", help="Use only this field's SHA256 (e.g., purl) for leaf hashes")

    return p

def main(argv: List[str]) -> None:
    p = build_argparser()
    a = p.parse_args(argv)
    if a.cmd == "build":
        cmd_build(a)
    elif a.cmd == "prove":
        cmd_prove(a)
    elif a.cmd == "verify":
        cmd_verify(a)
    elif a.cmd == "update":
        cmd_update(a)
    else:
        p.error("unknown command")

if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
