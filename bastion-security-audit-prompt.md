# Bastion Security Audit & Verification Prompt
# Run with: claude --model claude-opus-4-6

You are performing an independent security audit of this codebase. A prior
review identified vulnerabilities and produced a patch. Your job is to:

1. Verify every fix in the patch was applied correctly and completely
2. Independently audit the full codebase for any additional vulnerabilities
   the prior review may have missed
3. Fix anything you find — do not just report it

Work autonomously through all steps. Read every relevant file before drawing
conclusions. Never speculate about code you haven't opened.

---

## Context

This is **Bastion** — a Python/Flask network gateway and firewall management
platform. It runs on a personal Linux machine and controls nftables firewall
rules via a REST API and web dashboard. There is currently **no authentication**
on any endpoint (auth is a planned future feature). The operator is a single
user running this on their home/personal network.

The threat model is:
- Attacker on the same LAN (most likely)
- Malicious web page open in the operator's browser (CSRF)
- Compromised remote blocklist server (DNS filter plugin)
- Supply-chain attack via CI/CD pipeline

---

## Step 1 — Read the patch that was already applied

A security patch was applied addressing these issues. Verify each fix is
present, correct, and complete by reading the actual file content:

### Fix 1 — Default bind address (`bastion/cli.py`)
Verify: `--host` default is `127.0.0.1`, NOT `0.0.0.0`.
Verify: The security warning fires when `host in ("0.0.0.0", "::")` regardless
of demo mode (the `not demo and` condition should be removed).

### Fix 2 — CSRF + Origin protection (`bastion/web/app.py`)
Verify: A `before_request` hook exists that checks all mutating `/api/v1/*`
requests (POST/PUT/DELETE/PATCH) for:
  - A valid `X-CSRF-Token` header (compared with `secrets.compare_digest`)
  - An `Origin` header that matches the server's own host when present
Verify: An `after_request` hook adds these headers to every response:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store` on `/api/` routes
  - A `Content-Security-Policy` header
Verify: The CSRF token is injected into the dashboard template via
`render_template(..., csrf_token=_csrf_token)`.

### Fix 3 — System info information leak (`bastion/api/routes.py`)
Verify: `GET /api/v1/system/info` does NOT return `hostname`, `platform`, or
`python` version fields.
Verify: `GET /api/v1/system/config` does NOT return `environment` (from
`BASTION_ENVIRONMENT` or `FLASK_ENV`).
Verify: The `import platform` line has been removed since it's now unused.

### Fix 4 — DNS blocklist TLS + size cap (`bastion/plugins/dns_filter/blocklist.py`)
Verify: `load_from_url` rejects `http://` URLs (only `https://` is accepted).
Verify: It uses `ssl.create_default_context()` — NOT a bare `urlopen(url)`.
Verify: It reads at most `_MAX_BLOCKLIST_BYTES + 1` bytes and rejects responses
that exceed the cap (value should be 10 MB = `10 * 1024 * 1024`).

### Fix 5 — Pinned CI action SHAs (`.github/workflows/ci.yml`)
Verify every `uses:` line references a full 40-character commit SHA, not a
floating tag like `@v4` or `@v5`. The expected pinned versions are:
  - `actions/checkout` → `11bd71901bbe5b1630ceea73d27597364c9af683` (v4.2.2)
  - `actions/setup-python` → `42375524e23c412d93fb67b49958b491fce71c38` (v5.4.0)
  - `actions/cache` → `1bd1e32a3bdc45362d1e726936510720a7c30a57` (v4.2.0)
  - `codecov/codecov-action` → `b9fd7d16f6d7d1b5d2bec1a2887e65ceed900238` (v4.6.0)

---

## Step 2 — Independent full-codebase audit

After verifying the patch, independently audit every source file for additional
vulnerabilities. Read each file — do not assume. Files to cover:

```
bastion/api/routes.py
bastion/cli.py
bastion/core/engine.py
bastion/core/manager.py
bastion/core/models.py
bastion/core/monitor.py
bastion/plugins/__init__.py
bastion/plugins/dns_filter/__init__.py
bastion/plugins/dns_filter/blocklist.py
bastion/web/app.py
bastion/web/templates/dashboard.html
Dockerfile
.env.example
.gitignore
config/bastion.example.yaml
config/rules.example.yaml
pyproject.toml
.github/workflows/ci.yml
```

For each file, specifically check:

**API / Flask layer (`routes.py`, `app.py`)**
- Are there any endpoints that bypass the CSRF `before_request` hook?
- Does the `enforce_csrf_and_origin` hook correctly cover ALL mutating methods?
- Is `secrets.compare_digest` used (not `==`) for the CSRF token comparison?
- Are there any debug routes, test routes, or commented-out bypasses?
- Does the `Content-Security-Policy` header allow anything it shouldn't?
- Is there any user-supplied data reflected back in a response without sanitization?

**Firewall engine (`engine.py`, `models.py`, `manager.py`)**
- Does `rule_to_nft_statement` use validated enums everywhere, or is any
  user input interpolated into nft commands as raw strings?
- Are `interface_in`, `interface_out`, `log_prefix`, and `jump_target` fields
  sanitized before being interpolated into the nft script?
- Could a crafted rule name, tag, or description break out of the nft script
  via quote injection (e.g., a name containing `"`)?
- Is `yaml.safe_load` used everywhere YAML is loaded? Confirm `yaml.load` is
  never used.
- Does `PortRange.from_string` validate that both parts are integers before
  constructing? Could `"80; drop table"` get through?

**Plugin system (`plugins/__init__.py`)**
- The plugin loader calls `importlib.import_module(f"bastion.plugins.{name}")`.
  Confirm `_PLUGIN_NAME_RE` rejects any name that could escape the
  `bastion.plugins` namespace (e.g., names with dots, slashes, or Python
  builtins like `os`, `sys`, `subprocess`).
- Can a user-supplied plugin name from the API (`POST /api/v1/plugins/<n>/enable`)
  trigger loading an arbitrary module?

**DNS filter (`dns_filter/__init__.py`, `blocklist.py`)**
- In `parse_dns_query`, are there any integer overflow or out-of-bounds reads
  possible with a crafted packet?
- Does `build_sinkhole_response` validate the packet before building a response?
- In `blocklist.py`, could a valid-looking blocklist line inject a domain that
  bypasses `_is_valid_domain`?

**Monitor (`monitor.py`)**
- Does `discover_hosts` safely parse `/proc/net/arp`, or could a crafted ARP
  entry cause issues?
- Is any data from `psutil.net_connections` (remote IPs, hostnames) returned
  directly in API responses without sanitization?

**Docker / deployment**
- Does the `Dockerfile` use a pinned base image digest, or a floating tag?
- Are there any secrets, credentials, or sensitive env vars baked into the image?
- Is the non-root user (`bastion`) applied before the `CMD`?

**Dashboard template (`dashboard.html`)**
- Is the injected `csrf_token` used on all mutating API calls made by the
  dashboard JavaScript?
- Is there any `{{ variable | safe }}` or unescaped template variable that
  could allow XSS?
- Are there any hardcoded credentials, API keys, or internal hostnames?

**.gitignore / .env.example**
- Does `.gitignore` exclude `.env`, `*.yaml` config files with real values,
  and any key/secret files?
- Does `.env.example` have any real secret values accidentally left in?

---

## Step 3 — Fix everything you find

For each new issue discovered:
- Fix it directly in the file. Do not just leave a comment or TODO.
- Keep fixes minimal and targeted — don't refactor unrelated code.
- Add a short inline comment explaining why the fix is necessary.
- Run `python -m black bastion tests` after all edits to ensure formatting.
- Run `python -m ruff check bastion tests` to confirm no lint errors.
- Run `python -m pytest tests/ -x -q` to confirm tests still pass.

If a fix would break existing tests, update the tests to match the new
secure behavior — don't weaken the fix to preserve a test.

---

## Step 4 — Summary report

When finished, print a structured report:

```
## Bastion Security Audit Report

### Patch verification
- Fix 1 (bind address): PASS / FAIL — <detail>
- Fix 2 (CSRF + headers): PASS / FAIL — <detail>
- Fix 3 (info leak): PASS / FAIL — <detail>
- Fix 4 (DNS TLS + size cap): PASS / FAIL — <detail>
- Fix 5 (CI SHA pinning): PASS / FAIL — <detail>

### New issues found and fixed
- <file>:<line> — <severity: CRITICAL/HIGH/MEDIUM/LOW> — <description> — FIXED
  (or NOT FIXED if it requires manual action, with explanation)

### Issues found but NOT auto-fixable (require manual action)
- <description and recommended action>

### Files with no issues
- <list>

### Test results
- <pytest output summary>
```

Be specific. "No issues found" is only acceptable if you actually read the file
and checked each item in the checklist above.
