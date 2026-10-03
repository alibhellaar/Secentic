import hashlib


def compute_fingerprint(name: str, owner: str | None, environment: str) -> str:
    raw = f"{name.lower().strip()}|{(owner or '').lower().strip()}|{environment.lower().strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()