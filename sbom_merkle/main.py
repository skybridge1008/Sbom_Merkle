import argparse, json
from dataclasses import asdict
from .bundle import build_bundle, combine_with_previous
from .merkle import gen_proof, verify_proof, leaf_hash, leaf_hash_from_hashview
from .crypto import decrypt_value, verify_root_sig
from .utils import get_by_path

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

    leaf_by_record = leaf_hash(record)
    ok = verify_proof(leaf_by_record, proof["proof"], bundle["root"])
    if not ok and bundle["meta"].get("stable_hash_field"):
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
        import hashlib, json as _json
        hv_bytes = _json.dumps(hv_val, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        hashview = {"stable_field": stable_field, "value_sha256": hashlib.sha256(hv_bytes).hexdigest()}
        leaf_by_hashview = leaf_hash_from_hashview(hashview)
        ok = verify_proof(leaf_by_hashview, proof["proof"], bundle["root"])

    print(f"[info] merkle proof valid: {ok}")
    if not ok:
        raise SystemExit(2)

    if a.key_hex and a.show_fields:
        key = bytes.fromhex(a.key_hex)
        for path in a.show_fields:
            okp, parent, value, last = get_by_path(record, path)
            if okp and isinstance(value, dict) and value.get("enc") == "v1":
                try:
                    dec = decrypt_value(value, key)
                    print(f"[decrypt] {path} = {_json.dumps(dec, ensure_ascii=False)}")
                except Exception as e:
                    print(f"[decrypt] {path} error: {e}")
            elif okp and isinstance(value, dict) and value.get("redacted") == "v1":
                print(f"[redacted] {path} commitment={value.get('commitment_hex')}")
            elif okp:
                print(f"[plain]    {path} = {_json.dumps(value, ensure_ascii=False)}")
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
    v.add_argument("--show-fields", nargs="*", default=[], help="Paths to display/decrypt")

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

def main(argv=None):
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
