# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a security issue:

- Email: grantbobo31@gmail.com
- Or use [GitHub Security Advisories](https://github.com/gbudja/bastion/security/advisories/new)

Include:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations (optional)

You will receive an acknowledgement within 72 hours. We aim to triage and publish a fix within 14 days for critical issues.

## Scope

In-scope for reports:

- Remote code execution via the API or plugin system
- Authentication bypass (when auth is implemented)
- Secrets or credentials exposed via API responses or logs
- Path traversal or arbitrary file read/write via API endpoints
- Insecure defaults that could silently expose a user's system

Out of scope:

- Attacks requiring physical access to the server
- Social engineering
- Issues in third-party dependencies (report those upstream, but let us know too)
- Demo-mode only behaviors that are clearly labeled as unsafe for production

## Current trust model

Bastion **does not yet implement authentication or authorization**. The API and dashboard are open to any client that can reach the bind address. This is documented prominently in the README.

Until authentication is implemented:

- Run Bastion behind a firewall or reverse proxy that enforces access controls
- Bind to `127.0.0.1` with `--host 127.0.0.1` unless you understand the exposure
- Do not run live mode (`sudo bastion start`) on internet-facing hosts without additional network-level controls

## Security hardening

See [docs/SECURE_DEPLOYMENT.md](docs/SECURE_DEPLOYMENT.md) for guidance on running Bastion securely.

---

Bastion is a security-focused platform. Responsible disclosure is appreciated.
