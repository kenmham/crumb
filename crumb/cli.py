import argparse
import sys
from datetime import date, datetime, timedelta

from . import db
from .config import (DATA_TYPES, IDENTIFIERS_PATH, STATUS_VALUES, STATUS_WEIGHTS,
                     add_identifier, get_extract_depth, load_identifiers)
from .scanner import (CANONICAL_NAMES, SHIPPING_SENDERS, connect,
                      fetch_bodies_concurrent, fetch_senders, get_credentials,
                      group_senders, guess_name, normalize_domain, review_candidates,
                      search_domain_uids)


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------

def cmd_add(args, conn):
    domain = args.domain.lower().strip()
    name = args.name or guess_name(domain)
    dtypes = list(dict.fromkeys(["email"] + (args.data or [])))
    invalid = [d for d in dtypes if d not in DATA_TYPES]
    if invalid:
        sys.exit(f"Unknown data types: {', '.join(invalid)}. Valid: {', '.join(DATA_TYPES)}")
    try:
        db.add_service(conn, name, domain, dtypes,
                       last_used=args.last_used, notes=args.notes or "",
                       source=args.source or None)
        parts = [f"({domain})", "—", ", ".join(dtypes)]
        if args.source:
            parts.append(f"via {args.source}")
        print(f"Added: {name} {' '.join(parts)}")
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            sys.exit(f"Domain already exists: {domain}")
        raise


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

def cmd_ls(args, conn):
    status = None if args.status == "all" else args.status
    services = db.get_services(conn, status=status, data_type=args.data,
                               source=args.source or None)
    if not services:
        print("No services found.")
        return
    fmt = "{:<4}  {:<25}  {:<28}  {:<18}  {:<18}  {:<20}  {}"
    print(fmt.format("ID", "Name", "Domain", "Data Types", "Source", "Status", "Last Used"))
    print("─" * 120)
    for s in services:
        name = (s.name + " [HME]" if s.hide_my_email else s.name)[:24]
        print(fmt.format(
            s.id, name, s.domain[:27],
            ", ".join(s.data_types)[:17] or "—",
            (s.source or "—")[:17],
            s.status,
            s.last_used[:10] if s.last_used else "—",
        ))
    print(f"\n{len(services)} service(s)")


# ---------------------------------------------------------------------------
# forget
# ---------------------------------------------------------------------------

def cmd_forget(args, conn):
    services = db.get_services(conn)
    for target in args.target:
        try:
            sid = int(target)
            svc = next((s for s in services if s.id == sid), None)
        except ValueError:
            svc = next((s for s in services if s.domain == target.lower()), None)
        if not svc:
            print(f"Not found: {target}", file=sys.stderr)
            continue

        if args.purge:
            conn.execute("DELETE FROM services WHERE id = ?", (svc.id,))
            conn.execute(
                "INSERT OR IGNORE INTO known_domains (domain, first_seen) VALUES (?,?)",
                (svc.domain, svc.added_at),
            )
            conn.commit()
            print(f"Purged: {svc.name} ({svc.domain})")
            continue

        if args.done:
            db.update_service_status(conn, svc.id, "deleted")
            print(f"Marked as deleted: {svc.name} ({svc.domain})")
            continue

        if svc.status == "deleted":
            print(f"{svc.name}: already marked deleted (use --done to confirm, --purge to remove)")
            continue
        db.update_service_status(conn, svc.id, "deletion_requested")
        print(f"Marked for deletion: {svc.name} ({svc.domain})")
        if svc.hide_my_email:
            relay = f" ({svc.identifier})" if svc.identifier else ""
            print(f"  → Hide My Email relay{relay}: deactivate it in iCloud Settings → [your name] → iCloud → Hide My Email.")
        else:
            print(f"  → Contact {svc.domain} directly to request data deletion.")
        downstream = db.get_downstream(conn, svc.name)
        downstream = [d for d in downstream if d.id != svc.id]
        if downstream:
            names = ", ".join(d.name for d in downstream)
            print(f"  ⚠ {len(downstream)} service(s) list {svc.name!r} as their source: {names}")
            print(f"    They may also hold your data — review and forget them separately.")
    if not args.done and not args.purge:
        print("\ncrumb doesn't send deletion requests for you.")


# ---------------------------------------------------------------------------
# edit
# ---------------------------------------------------------------------------

def cmd_edit(args, conn):
    import json
    services = db.get_services(conn)
    try:
        sid = int(args.target)
        svc = next((s for s in services if s.id == sid), None)
    except ValueError:
        svc = next((s for s in services if s.domain == args.target.lower()), None)
    if not svc:
        sys.exit(f"Not found: {args.target}")

    fields = {}
    if args.name is not None:
        fields["name"] = args.name
    if args.domain is not None:
        fields["domain"] = args.domain.lower().strip()
    if args.data is not None:
        invalid = [d for d in args.data if d not in DATA_TYPES]
        if invalid:
            sys.exit(f"Unknown data types: {', '.join(invalid)}. Valid: {', '.join(DATA_TYPES)}")
        fields["data_types"] = json.dumps(args.data)
    if args.last_used is not None:
        fields["last_used"] = args.last_used
    if args.status is not None:
        fields["status"] = args.status
    if args.notes is not None:
        fields["notes"] = args.notes
    if args.source is not None:
        fields["source"] = args.source or None

    if not fields:
        sys.exit("Nothing to edit. Pass at least one field flag.")

    try:
        db.update_service(conn, svc.id, **fields)
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            sys.exit(f"Domain already exists: {args.domain}")
        raise

    print(f"Updated {svc.name} ({svc.domain}):")
    for k, v in fields.items():
        label = k.replace("_", " ")
        display = json.loads(v) if k == "data_types" else v
        print(f"  {label}: {display}")


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def _parse_duration(value: str) -> int:
    """Parse a duration string like '6m', '1y', '30d' into days."""
    units = {"d": 1, "w": 7, "m": 30, "y": 365}
    value = value.strip().lower()
    if value[-1] not in units:
        sys.exit(f"Invalid duration '{value}'. Use e.g. 30d, 6m, 1y.")
    try:
        n = int(value[:-1])
    except ValueError:
        sys.exit(f"Invalid duration '{value}'. Use e.g. 30d, 6m, 1y.")
    return n * units[value[-1]]


def _fmt_age(added_at: str) -> str:
    try:
        days = (datetime.now() - datetime.fromisoformat(added_at)).days
    except Exception:
        return "?"
    years, rem = divmod(days, 365)
    months = rem // 30
    if years and months:
        return f"{years}y {months}m"
    if years:
        return f"{years}y"
    if months:
        return f"{months}m"
    return f"{days}d"


# ---------------------------------------------------------------------------
# risk
# ---------------------------------------------------------------------------


def cmd_risk(args, conn):
    services = [s for s in db.get_services(conn) if s.status != "deleted"]

    if args.stale:
        cutoff_days = _parse_duration(args.stale)
        cutoff = datetime.now() - timedelta(days=cutoff_days)
        services = [
            s for s in services
            if s.status == "active"
            and datetime.fromisoformat(s.added_at) < cutoff
        ]
        if not services:
            print(f"No active services older than {args.stale}.")
            return

    dist = db.downstream_counts(conn)
    scored = sorted(((s, _risk(s, dist.get(s.name, 0))) for s in services),
                    key=lambda x: x[1], reverse=True)
    limit = args.top or len(scored)
    fmt = "{:<4}  {:<6}  {:<25}  {:<28}  {:<18}  {:<18}  {}"
    print(fmt.format("ID", "Score", "Name", "Domain", "Data Types", "Source", "Status"))
    print("─" * 115)
    for svc, score in scored[:limit]:
        name = (svc.name + " [HME]" if svc.hide_my_email else svc.name)[:24]
        n_down = dist.get(svc.name, 0)
        name_col = f"{name} ({n_down}↓)" if n_down else name
        print(fmt.format(
            svc.id, f"{score:.1f}", name_col[:24], svc.domain[:27],
            ", ".join(svc.data_types)[:17] or "—",
            (svc.source or "—")[:17], svc.status,
        ))


def _risk(svc, downstream: int = 0) -> float:
    density = min(len(svc.data_types), 10) / 10
    ref = svc.last_used or svc.added_at
    try:
        days = (datetime.now() - datetime.fromisoformat(ref)).days
    except Exception:
        days = 0
    dormancy = min(days / 365, 3.0) / 3.0
    weight = STATUS_WEIGHTS.get(svc.status, 1.0)
    if svc.hide_my_email:
        weight *= 0.5
    base = (0.5 * density + 0.5 * dormancy) * weight * 10
    # Each downstream service adds 0.5: this service is a distribution point.
    return round(base + downstream * 0.5, 1)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def cmd_scan(args, conn):
    if args.reextract:
        return cmd_reextract(args, conn)

    folders = args.folder  # list of folder names
    # Stable key shared across all folders in this scan session.
    pending_key = "|".join(sorted(folders))

    # ------------------------------------------------------------------
    # Resume from a previous interrupted review if candidates are pending.
    # ------------------------------------------------------------------
    resumed = db.load_pending(conn, pending_key)
    if resumed:
        candidates, next_checkpoint = resumed
        print(f"Resuming review of {len(candidates)} pending domain(s) — skipping IMAP fetch.")
        domains_found = len(candidates)
    else:
        # --------------------------------------------------------------
        # Fresh fetch from IMAP — aggregate senders across all folders.
        # --------------------------------------------------------------
        host, user, password = get_credentials()
        print(f"Connecting to {host}...")
        imap = connect(host, user, password)

        all_senders = []
        for folder in folders:
            checkpoint = db.get_checkpoint(conn, folder)
            suffix = f" (since {checkpoint})" if checkpoint else ""
            print(f"Fetching {folder}{suffix}...")
            senders = fetch_senders(imap, folder=folder, limit=args.limit, since_date=checkpoint)
            print(f"  {len(senders)} messages")
            all_senders.extend(senders)

        groups = group_senders(all_senders)
        known = db.get_known_domains(conn) | {s.domain for s in db.get_services(conn)}
        new = {d: g for d, g in groups.items() if d not in known}
        domains_found = len(groups)
        print(f"  {domains_found} unique domains, {len(new)} new")

        try:
            imap.close()
        except Exception:
            pass
        imap.logout()

        id_hashes = load_identifiers()
        new_items = list(new.items())
        if not args.no_extract and new_items:
            detected_map = fetch_bodies_concurrent(
                new_items, host, user, password,
                folder=folders[-1],
                id_hashes=id_hashes,
                workers=4,
                depth=get_extract_depth(),
            )
        else:
            detected_map = {}

        candidates = []
        for domain, g in new_items:
            detected = detected_map.get(domain, {"email"})
            relay = g["relay_address"]
            candidates.append({
                "domain": domain,
                "name": g["name"],
                "email_count": g["email_count"],
                "detected_data_types": list(detected),
                "first_seen": g["first_seen"],
                "last_seen": g["last_seen"],
                "hide_my_email": relay is not None,
                "identifier": relay,
            })

        # Mark all fetched domains as seen immediately so future fetches skip them,
        # regardless of whether the review completes.
        db.add_known_domains(conn, {c["domain"]: (c["first_seen"] or "") for c in candidates})

        next_checkpoint = date.today().strftime("%d-%b-%Y")
        db.save_pending(conn, pending_key, candidates, next_checkpoint)

    # ------------------------------------------------------------------
    # Interactive review.
    # ------------------------------------------------------------------
    known = db.get_known_domains(conn) | {s.domain for s in db.get_services(conn)}

    def _on_processed(domain: str) -> None:
        db.remove_pending(conn, pending_key, domain)

    # Drain any pending candidates already in known_domains (added during a
    # previous run) so they don't block the pending queue indefinitely.
    for c in candidates:
        if c["domain"] in known:
            _on_processed(c["domain"])
    candidates = [c for c in candidates if c["domain"] not in known]

    if args.auto:
        confirmed = candidates
        for c in candidates:
            _on_processed(c["domain"])
    else:
        confirmed = review_candidates(candidates, known, on_processed=_on_processed)

    added = 0
    for c in confirmed:
        try:
            db.add_service(conn, c["name"], c["domain"], c["detected_data_types"],
                           last_used=c.get("last_seen"),
                           identifier=c.get("identifier"),
                           hide_my_email=c.get("hide_my_email", False),
                           source=c.get("source"))
            added += 1
        except Exception as e:
            if "UNIQUE constraint" not in str(e):
                print(f"Error adding {c['domain']}: {e}", file=sys.stderr)

    db.log_scan(conn, domains_found=domains_found, domains_added=added)

    # Advance per-folder checkpoints only once all pending candidates are reviewed.
    if not db.count_pending(conn, pending_key):
        for folder in folders:
            db.set_checkpoint(conn, folder, next_checkpoint)
        print(f"\nDone. {added} service(s) added.")
    else:
        remaining = db.count_pending(conn, pending_key)
        print(f"\nDone. {added} service(s) added. {remaining} domain(s) pending — run scan again to continue.")


# ---------------------------------------------------------------------------
# reextract (called via scan --reextract)
# ---------------------------------------------------------------------------

def cmd_reextract(args, conn):
    import json as _json
    services = [s for s in db.get_services(conn) if s.status != "deleted"]
    if not services:
        print("No services in ledger.")
        return

    host, user, password = get_credentials()
    folder = args.folder[-1]
    depth = get_extract_depth()

    print(f"Connecting to {host}...")
    imap = connect(host, user, password)
    quoted = f'"{folder}"' if any(c in folder for c in ' []()\\') else folder
    imap.select(quoted, readonly=True)

    print(f"Searching {folder} for {len(services)} service domain(s)...")
    items = []
    for s in services:
        uids = search_domain_uids(imap, s.domain, depth)
        if uids:
            items.append((s.domain, {"uids": uids}))
    try:
        imap.close()
    except Exception:
        pass
    imap.logout()

    if not items:
        print("No emails found for any service.")
        return

    print(f"  Re-extracting from {len(items)} service(s) ({depth} email(s) each)...")
    id_hashes = load_identifiers()
    detected_map = fetch_bodies_concurrent(
        items, host, user, password,
        folder=folder,
        id_hashes=id_hashes,
        workers=4,
        depth=depth,
    )

    domain_to_service = {s.domain: s for s in services}
    updated = 0
    for domain, detected in detected_map.items():
        s = domain_to_service.get(domain)
        if not s:
            continue
        new_types = detected - set(s.data_types)
        if new_types:
            merged = list(dict.fromkeys(s.data_types + sorted(new_types)))
            db.update_service(conn, s.id, data_types=_json.dumps(merged))
            updated += 1
            print(f"  {s.name} ({domain}): +{', '.join(sorted(new_types))}")

    print(f"\nDone. {updated} service(s) updated.")


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------

def cmd_merge(args, conn):
    import json
    services = db.get_services(conn)

    def _resolve(target):
        try:
            sid = int(target)
            return next((s for s in services if s.id == sid), None)
        except ValueError:
            return next((s for s in services if s.domain == target.lower()), None)

    src  = _resolve(args.source)
    dest = _resolve(args.dest)

    if not src:
        sys.exit(f"Not found: {args.source}")
    if not dest:
        sys.exit(f"Not found: {args.dest}")
    if src.id == dest.id:
        sys.exit("Source and destination are the same service.")

    merged_types = list(dict.fromkeys(dest.data_types + src.data_types))
    added_at     = min(dest.added_at, src.added_at)
    last_useds   = [x for x in [dest.last_used, src.last_used] if x]
    last_used    = max(last_useds) if last_useds else None
    notes        = dest.notes or src.notes
    identifier   = dest.identifier or src.identifier
    source       = dest.source or src.source

    print(f"Merge: {src.name} ({src.domain})  →  {dest.name} ({dest.domain})")
    if set(merged_types) != set(dest.data_types):
        gained = [t for t in merged_types if t not in dest.data_types]
        print(f"  data types gain: {', '.join(gained)}")
    print(f"  {src.domain} will be deleted and added to known_domains.")

    if not args.yes:
        try:
            ans = input("Apply? [Y/n] ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return
        if ans == "n":
            return

    conn.execute(
        "UPDATE services SET data_types=?, added_at=?, last_used=?, "
        "notes=?, identifier=?, source=? WHERE id=?",
        (json.dumps(merged_types), added_at, last_used,
         notes, identifier, source, dest.id),
    )
    conn.execute("DELETE FROM services WHERE id = ?", (src.id,))
    conn.execute(
        "INSERT OR IGNORE INTO known_domains (domain, first_seen) VALUES (?,?)",
        (src.domain, src.added_at),
    )
    conn.commit()
    print(f"Done. {src.domain} merged into {dest.domain}.")


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------

def cmd_normalize(args, conn):
    import json
    import tldextract as _tldx
    from collections import defaultdict

    services = db.get_services(conn)

    renames    = []  # (svc, new_domain, new_name)
    merges     = []  # (svc_from, svc_into)
    name_fixes = []  # (svc, new_name)
    infra      = []  # svc — shipping/sending infrastructure, not a direct signup

    # Group every service by its normalized (eTLD+1) domain.
    groups: dict = defaultdict(list)
    for svc in services:
        nd = normalize_domain(svc.domain)
        if nd in SHIPPING_SENDERS:
            infra.append(svc)
        else:
            groups[nd].append(svc)

    for new_domain, svcs in groups.items():
        new_name = guess_name(new_domain)
        exact    = next((s for s in svcs if s.domain == new_domain), None)
        movers   = [s for s in svcs if s.domain != new_domain]

        if not movers:
            # Domain already canonical — check name only.
            if exact and new_name != exact.name and _tldx.extract(exact.domain).domain in CANONICAL_NAMES:
                name_fixes.append((exact, new_name))
            continue

        if exact:
            # Canonical record exists — every mover folds into it.
            for svc in movers:
                merges.append((svc, exact))
        else:
            # No canonical record yet — first mover gets renamed, rest fold into it.
            primary = movers[0]
            renames.append((primary, new_domain, new_name))
            for svc in movers[1:]:
                merges.append((svc, primary))

    total = len(renames) + len(merges) + len(name_fixes) + len(infra)
    if not total:
        print("Nothing to normalize.")
        return

    if infra:
        print(f"Shipping/infrastructure entries ({len(infra)}) — not direct signups:")
        for svc in infra:
            print(f"  {svc.domain:<40}  \"{svc.name}\"")

    if renames:
        print(f"Domain renames ({len(renames)}):")
        for svc, new_domain, new_name in renames:
            name_note = f'  name: "{svc.name}" → "{new_name}"' if new_name != svc.name else ""
            print(f"  {svc.domain:<40} → {new_domain}{name_note}")

    if merges:
        print(f"\nMerges ({len(merges)}) — subdomain folded into canonical record:")
        for svc_from, svc_into in merges:
            gained = [t for t in svc_from.data_types if t not in svc_into.data_types]
            gain_note = f"  gains: {', '.join(gained)}" if gained else ""
            print(f"  {svc_from.domain:<40} → {svc_into.domain} (ID {svc_into.id}){gain_note}")

    if name_fixes:
        print(f"\nName corrections ({len(name_fixes)}):")
        for svc, new_name in name_fixes:
            print(f"  {svc.domain:<40}  \"{svc.name}\" → \"{new_name}\"")

    if not args.yes:
        try:
            ans = input(f"\nApply {total} change(s)? [Y/n] ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return
        if ans == "n":
            return

    for svc, new_domain, new_name in renames:
        conn.execute("UPDATE services SET domain = ?, name = ? WHERE id = ?",
                     (new_domain, new_name, svc.id))

    for svc_from, svc_into in merges:
        merged_types = list(dict.fromkeys(svc_into.data_types + svc_from.data_types))
        last_useds = [x for x in [svc_into.last_used, svc_from.last_used] if x]
        conn.execute(
            "UPDATE services SET "
            "  data_types = ?, added_at = MIN(added_at, ?), last_used = ?,"
            "  notes      = COALESCE(NULLIF(notes,''), ?),"
            "  identifier = COALESCE(identifier, ?), source = COALESCE(source, ?)"
            " WHERE id = ?",
            (json.dumps(merged_types), svc_from.added_at,
             max(last_useds) if last_useds else None,
             svc_from.notes, svc_from.identifier, svc_from.source,
             svc_into.id),
        )
        conn.execute("DELETE FROM services WHERE id = ?", (svc_from.id,))

    for svc, new_name in name_fixes:
        conn.execute("UPDATE services SET name = ? WHERE id = ?", (new_name, svc.id))

    # Remove infrastructure entries and seed known_domains so they stay filtered.
    for svc in infra:
        conn.execute("DELETE FROM services WHERE id = ?", (svc.id,))
        conn.execute(
            "INSERT OR IGNORE INTO known_domains (domain, first_seen) VALUES (?,?)",
            (svc.domain, svc.added_at),
        )

    # Normalize known_domains table too.
    for row in conn.execute("SELECT domain, first_seen FROM known_domains").fetchall():
        norm = normalize_domain(row["domain"])
        if norm != row["domain"]:
            conn.execute(
                "INSERT OR IGNORE INTO known_domains (domain, first_seen) VALUES (?,?)",
                (norm, row["first_seen"]),
            )
            conn.execute("DELETE FROM known_domains WHERE domain = ?", (row["domain"],))

    conn.commit()
    print(f"Done. {total} change(s) applied.")


# ---------------------------------------------------------------------------
# stale
# ---------------------------------------------------------------------------

def cmd_stale(args, conn):
    duration = args.duration or "1y"
    cutoff = datetime.now() - timedelta(days=_parse_duration(duration))
    services = [
        s for s in db.get_services(conn)
        if s.status == "active" and datetime.fromisoformat(s.added_at) < cutoff
    ]

    if not services:
        print(f"No active services older than {duration}.")
        return

    fmt = "{:<25}  {:<30}  {:<22}  {}"
    print(f"\n{len(services)} active service(s) older than {duration}:\n")
    print(fmt.format("Name", "Domain", "Data Types", "Age"))
    print("─" * 85)
    for s in services:
        name = (s.name + " [HME]" if s.hide_my_email else s.name)[:24]
        print(fmt.format(
            name, s.domain[:29],
            ", ".join(s.data_types)[:21] or "—",
            _fmt_age(s.added_at),
        ))

    print()
    try:
        ans = input("Mark all for deletion? [y/n/select] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return

    if ans == "y":
        for svc in services:
            db.update_service_status(conn, svc.id, "deletion_requested")
        print(f"Marked {len(services)} service(s) for deletion.")
        print("crumb doesn't send deletion requests for you.")

    elif ans == "select":
        marked = 0
        for i, svc in enumerate(services, 1):
            dtypes = ", ".join(svc.data_types) or "—"
            print(f"\n[{i}/{len(services)}] {svc.name} ({svc.domain}) — {dtypes} — {_fmt_age(svc.added_at)}")
            try:
                choice = input("  Mark for deletion? [y/n/q] ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                break
            if choice == "q":
                break
            if choice == "y":
                db.update_service_status(conn, svc.id, "deletion_requested")
                if svc.hide_my_email:
                    relay = f" ({svc.identifier})" if svc.identifier else ""
                    print(f"  → Deactivate Hide My Email relay{relay} in iCloud Settings.")
                else:
                    print(f"  → Contact {svc.domain} to request deletion.")
                marked += 1
        print(f"\nMarked {marked} service(s) for deletion.")
        if marked:
            print("crumb doesn't send deletion requests for you.")


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------

def cmd_identity_add(args, conn):
    import getpass
    print("Add personal identifiers (stored as SHA-256 hashes — plaintext is never saved).\n")

    prompts = [
        ("email",  "Email address",               False),
        ("phone",  "Phone number",                False),
        ("gov_id", "Government ID (SSN, passport, etc.)", True),
    ]

    total = 0
    for itype, label, hidden in prompts:
        print(f"{label}s — one per line, blank line to skip:")
        while True:
            try:
                value = getpass.getpass(f"  {label}: ") if hidden else input(f"  {label}: ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                return
            if not value:
                break
            try:
                added = add_identifier(itype, value)
            except ValueError as e:
                print(f"  Error: {e}")
                continue
            print(f"  {'Stored' if added else 'Already stored'} (hash only).")
            if added:
                total += 1
        print()

    print(f"{total} new identifier(s) stored in {IDENTIFIERS_PATH}")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(prog="crumb", description="Track where your personal data lives.")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    sub.required = True

    pa = sub.add_parser("add", help="Add a service manually")
    pa.add_argument("domain")
    pa.add_argument("-n", "--name", help="Human-readable name (guessed if omitted)")
    pa.add_argument("-d", "--data", nargs="+", metavar="TYPE",
                    help=f"Data types held: {', '.join(DATA_TYPES)}")
    pa.add_argument("--last-used", metavar="DATE")
    pa.add_argument("--notes")
    pa.add_argument("--source", metavar="SOURCE", help="Where this service got your data")

    pl = sub.add_parser("ls", help="List services")
    pl.add_argument("--status", default="all",
                    choices=["all", "active", "dormant", "deletion_requested", "deleted"])
    pl.add_argument("--data", metavar="TYPE", help="Filter by data type")
    pl.add_argument("--source", metavar="SOURCE", help="Filter by source")

    pf = sub.add_parser("forget", help="Mark service(s) for deletion")
    pf.add_argument("target", nargs="+", help="Service ID(s) or domain(s)")
    pf_action = pf.add_mutually_exclusive_group()
    pf_action.add_argument("--done", action="store_true",
                           help="Mark as fully deleted (data confirmed removed)")
    pf_action.add_argument("--purge", action="store_true",
                           help="Remove the record from the database entirely")

    pe = sub.add_parser("edit", help="Edit a service entry")
    pe.add_argument("target", help="Service ID or domain")
    pe.add_argument("-n", "--name")
    pe.add_argument("--domain")
    pe.add_argument("-d", "--data", nargs="+", metavar="TYPE")
    pe.add_argument("--last-used", metavar="DATE")
    pe.add_argument("--status", choices=STATUS_VALUES)
    pe.add_argument("--notes")
    pe.add_argument("--source")

    pr = sub.add_parser("risk", help="Risk-ranked exposure report")
    pr.add_argument("--top", type=int, metavar="N")
    pr.add_argument("--stale", metavar="DURATION",
                    help="Only active services older than DURATION (e.g. 6m, 1y, 30d)")

    pst = sub.add_parser("stale", help="List and action dormant active services")
    pst.add_argument("duration", nargs="?", default="1y", metavar="DURATION",
                     help="Age threshold, e.g. 6m, 1y, 30d (default: 1y)")

    pm = sub.add_parser("merge", help="Fold one service into another, combining data types")
    pm.add_argument("source", help="Domain or ID to fold in (will be deleted)")
    pm.add_argument("dest",   help="Domain or ID to keep")
    pm.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    pn = sub.add_parser("normalize", help="Apply eTLD+1 grouping and canonical names to the ledger")
    pn.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    pid = sub.add_parser("identity", help="Manage hashed personal identifiers")
    pid_sub = pid.add_subparsers(dest="identity_cmd", metavar="ACTION")
    pid_sub.required = True
    pid_sub.add_parser("add", help="Add email, phone, or gov_id identifiers (stored as hashes)")

    ps = sub.add_parser("scan", help="Scan inbox for services")
    ps.add_argument("--folder", nargs="+", default=["INBOX", "[Gmail]/All Mail"],
                    metavar="FOLDER", help="IMAP folder(s) to scan (default: INBOX and [Gmail]/All Mail)")
    ps.add_argument("--limit", type=int, default=0, metavar="N", help="Cap at N most recent messages")
    ps.add_argument("--no-extract", action="store_true", help="Skip body extraction")
    ps.add_argument("--auto", action="store_true", help="Skip interactive review")
    ps.add_argument("--reextract", action="store_true",
                    help="Re-run body extraction on existing services and update data types")

    args = p.parse_args()
    conn = db.get_conn()
    db.init_db(conn)
    if args.cmd == "identity":
        cmd_identity_add(args, conn)
    else:
        {"add": cmd_add, "ls": cmd_ls, "forget": cmd_forget, "edit": cmd_edit,
         "risk": cmd_risk, "stale": cmd_stale, "scan": cmd_scan,
         "merge": cmd_merge, "normalize": cmd_normalize}[args.cmd](args, conn)


if __name__ == "__main__":
    main()
