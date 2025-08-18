# audit.py
import os, json, hmac, hashlib, time
from typing import Optional, Tuple

AUDIT_LOG = "audit.log"          # JSON Lines (one entry per line)
AUDIT_KEY_FILE = "audit.key"     # HMAC key (generated if missing)

# -- internal helpers --
def _load_key() -> bytes:
    if not os.path.exists(AUDIT_KEY_FILE):
        key = os.urandom(32)
        with open(AUDIT_KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(AUDIT_KEY_FILE, "rb") as f:
            key = f.read()
    return key

def _hmac_digest(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()

def _last_digest() -> Optional[str]:
    if not os.path.exists(AUDIT_LOG):
        return None
    last = None
    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                last = obj.get("digest")
            except Exception:
                continue
    return last

# -- public API --
def write_entry(event: str, details: str, user: str, role: str) -> str:
    """
    Append a tamper-evident audit entry.
    Returns the digest written for this entry.
    """
    key = _load_key()
    prev = _last_digest()
    entry = {
        "ts": int(time.time()),
        "user": user,
        "role": role,
        "event": event,
        "details": details,
        "prev": prev,              # previous digest (or None)
    }
    # compute digest over a stable, canonical payload
    payload = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = _hmac_digest(key, payload)
    entry["digest"] = digest

    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")

    return digest

def verify_log() -> Tuple[bool, int, Optional[int], Optional[str]]:
    """
    Verify the entire audit chain.
    Returns: (ok, total_entries, first_bad_index, reason_if_bad)
    """
    key = _load_key()
    if not os.path.exists(AUDIT_LOG):
        return True, 0, None, None

    prev = None
    total = 0
    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                return False, total, idx, "corrupt JSON line"

            digest = obj.get("digest")
            if not digest:
                return False, total, idx, "missing digest"

            # remove digest field to recompute
            check_obj = {k: v for k, v in obj.items() if k != "digest"}

            # prev pointer must match our running prev
            if check_obj.get("prev") != prev:
                return False, total, idx, "prev link mismatch"

            payload = json.dumps(check_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
            recomputed = _hmac_digest(key, payload)
            if recomputed != digest:
                return False, total, idx, "HMAC mismatch"

            prev = digest
            total += 1

    return True, total, None, None
