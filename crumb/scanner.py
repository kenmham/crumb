"""IMAP connection, domain extraction, data-type detection, interactive review."""

import email
import getpass
import imaplib
import re
import sys
from email.utils import parseaddr
from typing import Callable, Dict, List, Optional, Set, Tuple

import tldextract
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from .config import CONFIG_PATH, DATA_TYPES, load_config, save_config

# PasswordHasher used only for verification — params are read from each encoded string.
_ph = PasswordHasher()

# ---------------------------------------------------------------------------
# Credentials / connection
# ---------------------------------------------------------------------------

def get_credentials() -> Tuple[str, str, str]:
    cfg = load_config()
    if cfg.has_section("imap"):
        h = cfg.get("imap", "host", fallback=None)
        u = cfg.get("imap", "user", fallback=None)
        p = cfg.get("imap", "password", fallback=None)
        if h and u and p:
            return h, u, p
    print("IMAP not configured. Use an app password, not your real account password.")
    host = input("IMAP host (e.g. imap.gmail.com): ").strip()
    user = input("Email address: ").strip()
    password = getpass.getpass("App password: ")
    if input("Save to ~/.crumb/config.ini? [y/N] ").strip().lower() == "y":
        if not cfg.has_section("imap"):
            cfg.add_section("imap")
        cfg.set("imap", "host", host)
        cfg.set("imap", "user", user)
        cfg.set("imap", "password", password)
        save_config(cfg)
        print(f"Saved to {CONFIG_PATH}")
    return host, user, password


def connect(host: str, user: str, password: str) -> imaplib.IMAP4_SSL:
    try:
        conn = imaplib.IMAP4_SSL(host)
        conn.login(user, password)
        return conn
    except imaplib.IMAP4.error as e:
        sys.exit(f"IMAP login failed: {e}")


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

_RELAY_RE = re.compile(r"^[a-z0-9]+@privaterelay\.icloud\.com$")


def _relay_addr(to_header: str) -> Optional[str]:
    """Return the relay address if the TO field is a Hide My Email relay, else None."""
    _, addr = parseaddr(to_header)
    addr = addr.lower()
    return addr if _RELAY_RE.match(addr) else None


def fetch_senders(imap: imaplib.IMAP4_SSL, folder: str = "INBOX",
                  limit: int = 0,
                  since_date: Optional[str] = None) -> List[Tuple[str, str, str, Optional[str]]]:
    """Return [(from_addr, date_str, uid, relay_or_None), ...] for messages in folder.

    since_date: IMAP SINCE criterion string, e.g. '21-Mar-2026'.  If given, only
    messages on or after that date are fetched.
    """
    status, _ = imap.select(folder, readonly=True)
    if status != "OK":
        sys.stderr.write(f"  Warning: folder {folder!r} not found, skipping.\n")
        return []
    criterion = f"SINCE {since_date}" if since_date else "ALL"
    _, data = imap.search(None, criterion)
    uids = data[0].split() if data[0] else []
    if limit:
        uids = uids[-limit:]
    total = len(uids)
    results = []
    for i, uid in enumerate(uids, 1):
        try:
            _, msg_data = imap.fetch(uid, "(BODY.PEEK[HEADER.FIELDS (FROM TO DATE)])")
            part = msg_data[0]
            if not isinstance(part, tuple):
                continue
            msg = email.message_from_bytes(part[1])
            _, addr = parseaddr(msg.get("From", ""))
            date_str = msg.get("Date", "")
            relay = _relay_addr(msg.get("To", ""))
            if addr and "@" in addr:
                results.append((addr.lower(), date_str, uid.decode(), relay))
            _progress(i, total, addr or "—")
        except Exception:
            _progress(i, total, "—")
            continue
    sys.stderr.write("\n")
    sys.stderr.flush()
    return results


def _progress(current: int, total: int, sender: str) -> None:
    counter = f"[{current}/{total}]"
    # Reserve space for counter + space + truncated sender
    available = max(0, 72 - len(counter) - 1)
    snippet = sender if len(sender) <= available else "…" + sender[-(available - 1):]
    sys.stderr.write(f"\r{counter} {snippet:<{available}}")
    sys.stderr.flush()


def fetch_body(imap: imaplib.IMAP4_SSL, uid: str, max_bytes: int = 4096) -> str:
    try:
        _, data = imap.fetch(uid, f"(BODY.PEEK[TEXT]<0.{max_bytes}>)")
        part = data[0] if data else None
        if isinstance(part, tuple):
            raw = part[1]
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="replace")
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

_PERSONAL = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "protonmail.com", "aol.com", "live.com", "googlemail.com", "me.com",
    "mac.com", "ymail.com", "zoho.com",
}

# Email sending infrastructure and shipping notification intermediaries.
# These domains appear as FROM senders on behalf of merchants/carriers but are
# not services the user signed up for directly.
SHIPPING_SENDERS = {
    # Shipping & tracking notifications
    "narvar.com", "aftership.com", "route.com", "easypost.com",
    "shipbob.com", "shipstation.com", "shippo.com", "returnly.com",
    "parcelpending.com", "17track.net", "parcellab.com",
    # Merchant email infrastructure
    "shopify.com", "klaviyo.com", "braze.com", "iterable.com",
    "sailthru.com", "exacttarget.com", "sparkpost.com",
    "postmarkapp.com", "mandrill.com", "mandrillapp.com",
    "mailgun.org", "amazonses.com",
}
_PHONE_RE = re.compile(r"\+?\d[\d\s\-\.\(\)]{7,}\d")
_ADDR_RE = re.compile(r"\d{1,5}\s[\w\s]{3,30},?\s[\w\s]{2,20},?\s[A-Z]{2}\s\d{5}", re.I)
_PAY_RE = re.compile(r"\b(card|payment|billing|invoice|receipt|order|purchase|subscription)\b", re.I)

# Canonical brand names keyed by the registered domain's SLD (lowercase).
# Covers brands where capitalisation is non-obvious or the name differs from the domain.
_CANONICAL: Dict[str, str] = {
    # All-caps / acronyms
    "aaa": "AAA", "aarp": "AARP", "amc": "AMC", "aol": "AOL", "att": "AT&T",
    "bbc": "BBC", "cbs": "CBS", "cnn": "CNN", "cvs": "CVS", "dhl": "DHL",
    "diy": "DIY", "ea": "EA", "espn": "ESPN", "fbi": "FBI", "fda": "FDA",
    "fedex": "FedEx", "fico": "FICO", "geico": "GEICO", "gmc": "GMC",
    "hbo": "HBO", "hsbc": "HSBC", "hulu": "Hulu", "ibm": "IBM",
    "irs": "IRS", "mtv": "MTV", "nbc": "NBC", "nfl": "NFL", "nhs": "NHS",
    "npr": "NPR", "nytimes": "NYT", "pbs": "PBS", "pnc": "PNC",
    "ups": "UPS", "usaa": "USAA", "usps": "USPS", "vw": "VW",
    # Mixed-case
    "airbnb": "Airbnb", "amazonaws": "AWS", "doordash": "DoorDash",
    "draftkings": "DraftKings", "dropbox": "Dropbox", "ebay": "eBay",
    "github": "GitHub", "gitlab": "GitLab", "godaddy": "GoDaddy",
    "grubhub": "Grubhub", "hubspot": "HubSpot", "imgur": "Imgur",
    "linkedin": "LinkedIn", "mailchimp": "Mailchimp", "mcdonalds": "McDonald's",
    "mongodb": "MongoDB", "myspace": "MySpace", "nerdwallet": "NerdWallet",
    "newrelic": "New Relic", "nordvpn": "NordVPN", "nowtv": "Now TV",
    "paypal": "PayPal", "pinterest": "Pinterest", "postmates": "Postmates",
    "redfin": "Redfin", "salesforce": "Salesforce", "sendgrid": "SendGrid",
    "shopify": "Shopify", "stackoverflow": "Stack Overflow",
    "taskrabbit": "TaskRabbit", "tripadvisor": "TripAdvisor",
    "turbotax": "TurboTax", "twitch": "Twitch", "twitter": "Twitter",
    "venmo": "Venmo", "whatsapp": "WhatsApp", "wordpress": "WordPress",
    "youtube": "YouTube", "zapier": "Zapier", "zillow": "Zillow",
    # Name ≠ domain
    "amex": "American Express", "americanexpress": "American Express",
    "bankofamerica": "Bank of America", "bestbuy": "Best Buy",
    "capitalone": "Capital One", "homedepot": "Home Depot",
    "kohls": "Kohl's", "lowes": "Lowe's", "macys": "Macy's",
    "oldnavy": "Old Navy", "tmobile": "T-Mobile", "wellsfargo": "Wells Fargo",
}


CANONICAL_NAMES = _CANONICAL


def normalize_domain(domain: str) -> str:
    """Return eTLD+1 (registered domain), stripping all subdomains."""
    ext = tldextract.extract(domain)
    return ext.registered_domain or domain


# Internal alias used by group_senders.
_normalize = normalize_domain


def guess_name(domain: str) -> str:
    """Return a human-readable service name for a domain."""
    ext = tldextract.extract(domain)
    core = ext.domain or (domain.split(".")[-2] if "." in domain else domain)
    if core in _CANONICAL:
        return _CANONICAL[core]
    return " ".join(w.capitalize() for w in re.split(r"[-_]", core))


def group_senders(senders: List[Tuple[str, str, str, Optional[str]]]) -> Dict[str, dict]:
    """Group (addr, date, uid, relay_or_None) by normalized domain."""
    groups: Dict[str, dict] = {}
    for addr, date_str, uid, relay in senders:
        domain = _normalize(addr.split("@")[-1].lower())
        if domain in _PERSONAL or domain in SHIPPING_SENDERS:
            continue
        if domain not in groups:
            groups[domain] = {"name": guess_name(domain), "email_count": 0,
                              "uids": [], "first_seen": date_str, "last_seen": date_str,
                              "relay_address": None}
        g = groups[domain]
        g["email_count"] += 1
        g["uids"].append(uid)
        if date_str:
            g["last_seen"] = date_str
        if relay:
            g["relay_address"] = relay
    return groups


_EMAIL_BODY_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")


def _verify_any(candidate: str, encoded_list: list) -> bool:
    """Return True if candidate matches any Argon2-encoded hash in encoded_list."""
    for encoded in encoded_list:
        try:
            _ph.verify(encoded, candidate)
            return True
        except (VerifyMismatchError, VerificationError):
            continue
    return False


def match_identifiers(text: str, hashes: dict) -> List[str]:
    """Return data type names whose hashed PII is found in text.

    Checks email addresses and phone numbers only — gov_id is manual-tag only.
    Each candidate is normalized and verified against stored Argon2id hashes.
    """
    if not hashes:
        return []
    matched = []
    if "email" in hashes:
        for m in _EMAIL_BODY_RE.finditer(text):
            if _verify_any(m.group(0).lower(), hashes["email"]):
                matched.append("email")
                break
    if "phone" in hashes:
        for m in _PHONE_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if digits and _verify_any(digits, hashes["phone"]):
                matched.append("phone")
                break
    return matched


def detect_data_types(text: str) -> List[str]:
    found = ["email"]
    if _PHONE_RE.search(text):
        found.append("phone")
    if _ADDR_RE.search(text):
        found.append("address")
    if _PAY_RE.search(text):
        found.append("payment")
    return found


# ---------------------------------------------------------------------------
# Interactive review
# ---------------------------------------------------------------------------

def review_candidates(candidates: List[dict], known: Set[str],
                      on_processed: Optional[Callable[[str], None]] = None) -> List[dict]:
    new = [c for c in candidates if c["domain"] not in known]
    if not new:
        print("No new domains to review.")
        return []
    print(f"\nFound {len(new)} new domain(s):\n")
    confirmed = []
    for i, c in enumerate(new, 1):
        print(f"[{i}/{len(new)}] {c['domain']}")
        print(f"  Name     : {c['name']}")
        print(f"  Emails   : {c['email_count']}")
        if c.get("hide_my_email"):
            print(f"  Relay    : {c['identifier']}  [Hide My Email]")
        print(f"  Detected : {', '.join(c['detected_data_types'])}")
        if c.get("source"):
            print(f"  Source   : {c['source']}")
        try:
            action = input("  [Y]es / [n]o / [e]dit name / [d]ata types / [s]top: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if action == "s":
            break
        # Domain has been given a decision (yes/no/edit) — mark as processed.
        if on_processed:
            on_processed(c["domain"])
        if action == "n":
            continue
        if action == "e":
            v = input(f"  Name [{c['name']}]: ").strip()
            if v:
                c["name"] = v
        elif action == "d":
            print(f"  Available: {', '.join(DATA_TYPES)}")
            v = input(f"  Types [{', '.join(c['detected_data_types'])}]: ").strip()
            if v:
                parsed = [t.strip() for t in v.split(",") if t.strip() in DATA_TYPES]
                if parsed:
                    c["detected_data_types"] = parsed
        v = input("  Source   (blank = signed up directly): ").strip()
        if v:
            c["source"] = v
        confirmed.append(c)
    return confirmed
