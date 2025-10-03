from typing import Any, Dict, Optional
import secrets, json, hashlib
from .utils import canonical_json, b64e, b64d

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
    commit = hashlib.sha256(canonical_json(value).encode('utf-8') + nonce).hexdigest()
    return {"redacted":"v1","commitment_hex":commit,"nonce_b64":b64e(nonce)}

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
