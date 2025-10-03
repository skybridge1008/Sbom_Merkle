import json, hashlib, base64
from typing import Any, Dict, List

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
