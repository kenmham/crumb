# crumb

A local CLI that tracks what personal data you've given to which services, and helps you clean it up.

crumb keeps a ledger of everywhere you've left personal information: which services, what data types (email, phone, payment, address, government ID, etc.), and when. It scans your email to find signups you forgot about, ranks your exposure by risk, and gives you a deletion workflow for stale accounts.

Everything is stored locally in a SQLite database. Identity matching (detecting your phone number or email in message bodies) uses argon2 hashes, so crumb never holds your sensitive data in plaintext.

crumb is not a breach monitoring service and not a data broker removal tool. It won't contact services on your behalf or scan the dark web. It's a personal inventory: you maintain it, you own it, it stays on your machine.

`crumb add`, `crumb scan`, `crumb risk`, `crumb forget`.

where you left yourself.

## Installation

Requires Python 3.9+.

```bash
pipx install --editable /path/to/crumb
```

`pipx` installs crumb into an isolated environment and puts the `crumb` command
on your PATH. Use `--editable` if you want source changes to take effect
immediately without reinstalling.

---

## Quick start

```bash
# Scan your inbox for services (prompts for IMAP credentials on first run)
crumb scan

# Review your ledger
crumb ls

# See what's most exposed
crumb risk

# Find accounts you haven't touched in over a year
crumb stale
```

---

## Commands

### `crumb scan`

Connects to your mailbox over IMAP, extracts sender domains, groups them by
registered domain (e.g. `mail.example.com` → `example.com`), and walks you
through adding new ones to your ledger.

```
crumb scan [--folder FOLDER [FOLDER ...]] [--limit N] [--no-extract] [--auto]
```

- Scans **INBOX** and **[Gmail]/All Mail** by default. Pass `--folder` to
  override.
- Checkpoints are stored per folder so incremental scans only fetch new mail.
- If a review is interrupted, the pending candidates are saved and resumed on
  the next run — no re-fetching required.
- Body extraction samples one email per domain to detect data types (phone,
  address, payment keywords). Pass `--no-extract` to skip.
- If you have stored identifiers (see `crumb identity add`), body text is
  checked against your hashed phone numbers and email addresses for high-confidence
  auto-tagging.
- `--auto` skips interactive review and adds all candidates directly.

IMAP credentials are stored in `~/.crumb/config.ini` (host, user, password).
Use an app password, not your account password.

**Filtering**

crumb automatically ignores:

- Personal mailbox domains (gmail.com, icloud.com, etc.)
- Shipping and email-infrastructure senders (Narvar, Klaviyo, Shopify, etc.)
  that send on behalf of merchants but are not services you signed up for.

---

### `crumb ls`

List your ledger.

```
crumb ls [--status active|dormant|deletion_requested|deleted|all]
         [--data TYPE] [--source SOURCE]
```

Services signed up via Apple Hide My Email are shown with a `[HME]` tag.

---

### `crumb add`

Add a service manually.

```
crumb add DOMAIN [-n NAME] [-d TYPE [TYPE ...]] [--last-used DATE]
          [--notes TEXT] [--source SOURCE]
```

`--source` records where this service got your data from (e.g. another service
that sold or shared it). This feeds the downstream warning in `crumb forget` and
the distribution bonus in `crumb risk`.

**Data types:** `email`, `phone`, `address`, `payment`, `name`, `dob`,
`username`, `location`, `ip`, `purchases`, `gov_id`

---

### `crumb forget`

Mark a service for deletion.

```
crumb forget TARGET [TARGET ...] [--done | --purge]
```

`TARGET` is a service ID or domain. Three modes:

| Flag | Effect |
|------|--------|
| *(none)* | Mark as `deletion_requested`. Prints guidance on how to contact the service. |
| `--done` | Mark as `deleted` — data confirmed removed. |
| `--purge` | Hard-delete the record and add the domain to the known-domains list so it won't resurface in future scans. |

If the service has downstream services (others whose `source` points to it),
crumb warns you that they may also hold your data.

For Hide My Email accounts, crumb tells you which relay to deactivate in iCloud
Settings.

---

### `crumb edit`

Edit a service entry.

```
crumb edit TARGET [-n NAME] [--domain DOMAIN] [-d TYPE [TYPE ...]]
           [--last-used DATE] [--status STATUS] [--notes TEXT] [--source SOURCE]
```

---

### `crumb risk`

Risk-ranked exposure report.

```
crumb risk [--top N] [--stale DURATION]
```

Each service is scored on:

- **Data density** — breadth of data types held
- **Dormancy** — how long since the account was active
- **Status weight** — `deletion_requested` services score low; `dormant` score
  slightly higher than `active` (forgotten ≠ safe)
- **Downstream count** — services used as a `source` by others incur a penalty
  per downstream service (distribution point risk)
- **Hide My Email discount** — relay can be killed unilaterally; exposure is
  lower

`--stale DURATION` narrows the report to active services older than the given
duration (e.g. `6m`, `1y`, `90d`).

---

### `crumb stale`

List active accounts older than a threshold and action them.

```
crumb stale [DURATION]
```

Default duration is `1y`. Prints a table of matching services and ends with:

```
Mark all for deletion? [y/n/select]
```

`select` lets you step through each service individually.

---

### `crumb merge`

Fold one service record into another, combining their data types.

```
crumb merge SOURCE DEST [--yes]
```

`SOURCE` is deleted and its domain is seeded into known-domains. The earlier
`added_at` date and later `last_used` date are preserved on `DEST`.

---

### `crumb normalize`

Retroactively apply eTLD+1 grouping and canonical brand names to your ledger.

```
crumb normalize [--yes]
```

What it does:

- **Domain renames** — `mail.example.com` → `example.com`
- **Merges** — multiple subdomain variants fold into one canonical record,
  combining data types
- **Name corrections** — applies the built-in canonical name map
  (`linkedin.com` → `LinkedIn`, `ups.com` → `UPS`, etc.)
- **Infrastructure removal** — records for shipping/ESP senders
  (Narvar, Klaviyo, etc.) are deleted and seeded into known-domains

Shows a preview of all changes and asks for confirmation before applying.

---

### `crumb identity add`

Store hashed versions of your personal identifiers so the scanner can
auto-tag services with high confidence.

```
crumb identity add
```

Prompts for email addresses, phone numbers, and government IDs. Each value is:

1. Normalized (lowercase for email; digits-only for phone; stripped for gov_id)
2. Hashed with **Argon2id** (time_cost=2, memory=19 MB) and a random salt
3. Stored in `~/.crumb/identifiers` — plaintext is never written

The value is never echoed back. Government IDs are accepted for future use but
are not matched during email scanning (they don't appear in email bodies).

During `crumb scan`, body text is checked against your stored phone and email
hashes. A match auto-tags that data type on the service.

---

## Data files

All data is stored under `~/.crumb/`:

| File | Contents |
|------|----------|
| `crumb.db` | SQLite ledger (services, scan history, checkpoints) |
| `config.ini` | IMAP credentials |
| `identifiers` | Argon2id hashes of your personal identifiers (no plaintext) |

---

## Statuses

| Status | Meaning |
|--------|---------|
| `active` | Account in use |
| `dormant` | No longer used but not yet forgotten |
| `deletion_requested` | Deletion request sent, awaiting confirmation |
| `deleted` | Data confirmed removed |
