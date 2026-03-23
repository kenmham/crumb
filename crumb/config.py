import configparser
import json
import re
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

CRUMB_DIR = Path.home() / ".crumb"
DB_PATH = CRUMB_DIR / "crumb.db"
CONFIG_PATH = CRUMB_DIR / "config.ini"
IDENTIFIERS_PATH = CRUMB_DIR / "identifiers"

DATA_TYPES = [
    "email", "phone", "address", "payment",
    "name", "dob", "username", "location",
    "ip", "purchases", "gov_id",
]

STATUS_VALUES = ["active", "dormant", "deletion_requested", "deleted"]

STATUS_WEIGHTS = {
    "active": 1.0,
    "dormant": 1.3,
    "deletion_requested": 0.2,
    "deleted": 0.0,
}


# Argon2id with OWASP-minimum params. time_cost=2, memory_cost=19 MB, parallelism=1.
# These are embedded in each encoded hash string, so future param changes don't
# break existing stored hashes.
_ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


def _normalize(itype: str, value: str) -> str:
    if itype == "email":
        return value.strip().lower()
    if itype == "phone":
        return re.sub(r"\D", "", value)
    if itype == "gov_id":
        return value.strip().upper().replace(" ", "").replace("-", "")
    raise ValueError(f"Unknown identifier type: {itype}")


def load_identifiers() -> dict:
    """Return {type: [sha256_hex, ...]} — never contains plaintext."""
    if not IDENTIFIERS_PATH.exists():
        return {}
    try:
        with open(IDENTIFIERS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_identifiers(data: dict) -> None:
    CRUMB_DIR.mkdir(parents=True, exist_ok=True)
    with open(IDENTIFIERS_PATH, "w") as f:
        json.dump(data, f, indent=2)


def add_identifier(itype: str, value: str) -> bool:
    """Normalize, hash with Argon2id+random salt, and persist. Returns True if newly added.

    Each encoded string is of the form:
      $argon2id$v=19$m=...,t=...,p=...$<salt_b64>$<hash_b64>
    The salt is random and stored within the encoded string — plaintext is never written.
    """
    normalized = _normalize(itype, value)
    if not normalized:
        return False
    data = load_identifiers()
    bucket = data.get(itype, [])
    # Duplicate check: verify candidate against every stored hash (O(n), n is tiny).
    for encoded in bucket:
        try:
            _ph.verify(encoded, normalized)
            return False  # already stored
        except (VerifyMismatchError, VerificationError):
            continue
    data.setdefault(itype, []).append(_ph.hash(normalized))
    save_identifiers(data)
    return True


def get_extract_depth() -> int:
    """Return extract_depth from [scan] config section (default 1).

    Set in ~/.crumb/config.ini:
        [scan]
        extract_depth = 3
    """
    cfg = load_config()
    try:
        return max(1, cfg.getint("scan", "extract_depth"))
    except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
        return 1


def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        cfg.read(CONFIG_PATH)
    return cfg


def save_config(cfg: configparser.ConfigParser) -> None:
    CRUMB_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        cfg.write(f)
