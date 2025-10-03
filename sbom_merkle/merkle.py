from typing import Any, Dict, List
from .utils import canonical_json, sha256, h_domain

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
