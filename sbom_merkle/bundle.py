from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json

from .utils import canonical_json, iter_components, get_by_path, set_by_path
from .crypto import encrypt_value, redact_value, sign_root_ed25519
from .merkle import leaf_hash, leaf_hash_from_hashview, build_merkle

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

def build_bundle(sbom: Dict[str, Any],
                 encrypt_paths: List[str],
                 redact_paths: List[str],
                 aead_key_hex: Optional[str],
                 prev_root_hex: Optional[str] = None,
                 sign_sk_hex: Optional[str] = None,
                 encrypt_node: bool = False,
                 stable_hash_field: Optional[str] = None) -> MerkleBundle:
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
            import hashlib
            hashview = {"stable_field": stable_hash_field, "value_sha256": hashlib.sha256(hv_bytes).hexdigest()}

        # Node-level encryption
        if encrypt_node and key:
            ref = rec.get("bom-ref", f"component[{idx}]")
            if stable_hash_field:
                rec = {
                    "bom-ref": ref,
                    "__node_redacted": {
                        "v": 1,
                        "reason": "confidential",
                        "stable": hashview
                    }
                }
            else:
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
