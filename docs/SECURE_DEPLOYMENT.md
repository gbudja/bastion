# Secure Deployment Guide

This document covers hardening Bastion for environments where untrusted clients may have network access to the host.

> **Bastion does not yet implement authentication.** All API endpoints and the dashboard are open to any client that can reach the bind address. The guidance below compensates for this at the network and host level until auth is implemented.

---

## 1. Secret key

The Flask secret key protects session cookies. It must come from the environment — never hardcode it.

```bash
export BASTION_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

- Use at least 32 bytes of random data.
- Store it in a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager, systemd `EnvironmentFile` with `0600` permissions).
- Rotate it if you believe it has been exposed.

If `BASTION_SECRET_KEY` is not set and demo mode is off, Bastion will refuse to start.

---

## 2. Bind address

By default, Bastion binds to `0.0.0.0` (all interfaces). Restrict this unless you have network-level controls in place.

**Loopback only (safest — use behind a reverse proxy):**

```bash
bastion start --host 127.0.0.1
```

**Specific interface:**

```bash
bastion start --host 192.168.1.10
```

---

## 3. Reverse proxy

Run Bastion behind nginx or Caddy. This lets you:

- Terminate TLS
- Add HTTP basic auth as a temporary layer until Bastion's own auth is implemented
- Apply rate limiting
- Log access in a centralized place

**Minimal nginx example:**

```nginx
server {
    listen 443 ssl;
    server_name bastion.example.internal;

    ssl_certificate     /etc/ssl/bastion.crt;
    ssl_certificate_key /etc/ssl/bastion.key;

    # Temporary basic auth until Bastion auth is implemented
    auth_basic           "Bastion";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass         http://127.0.0.1:8443;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
    }
}
```

---

## 4. systemd service

Run Bastion as a non-root user wherever possible. Live nftables operations require `CAP_NET_ADMIN`; use `AmbientCapabilities` instead of running as root.

```ini
[Unit]
Description=Bastion Network Gateway
After=network.target

[Service]
Type=simple
User=bastion
Group=bastion
EnvironmentFile=/etc/bastion/bastion.env
ExecStart=/usr/local/bin/bastion start --host 127.0.0.1
Restart=on-failure
RestartSec=5

# Grant only the capability needed for nftables
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

# Harden the process
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/bastion /var/log/bastion

[Install]
WantedBy=multi-user.target
```

Create `/etc/bastion/bastion.env` (mode `0600`, owner `bastion`):

```
BASTION_SECRET_KEY=<generated-value>
```

---

## 5. Firewall rules

Restrict access to the Bastion dashboard/API port at the host firewall level so only authorized hosts can connect:

```bash
# Allow only your management workstation
nft add rule inet filter input tcp dport 8443 ip saddr 192.168.1.5 accept
nft add rule inet filter input tcp dport 8443 drop
```

---

## 6. Plugin safety

- Only enable plugins you trust. Plugins run in-process with full access to the Bastion API and host filesystem (subject to OS-level restrictions).
- Blocklist URLs for the DNS filter plugin are fetched at enable time using `urllib`. Ensure the URL sources are trusted.
- Sandboxed plugin execution is on the [roadmap](../README.md#roadmap) but not yet implemented.

---

## 7. Log hygiene

- Bastion logs to stdout by default. Capture with `journald` or redirect to a file.
- Avoid `DEBUG` log level in production — it emits nft commands and rule details.
- Log files containing firewall rule data should be accessible only to root/bastion user.

---

## 8. Demo mode vs live mode

| | Demo mode | Live mode |
|---|---|---|
| Root required | No | Yes (or `CAP_NET_ADMIN`) |
| nftables applied | No | Yes |
| Secret key required | No (random per run) | **Yes** |
| Suitable for production | No | With hardening |

Demo mode is safe to run as an unprivileged user for evaluation. It generates nft scripts but never executes them against the kernel.

---

## 9. What is not yet implemented

The following are known gaps. Do not deploy Bastion in production without understanding them:

- **No authentication or authorization** — all API endpoints are open
- **No rate limiting on API endpoints**
- **No CSRF protection** (relevant when auth + browser sessions are added)
- **No TLS built-in** — use a reverse proxy
- **No sandboxed plugin execution**

These are tracked in the [roadmap](../README.md#roadmap).
