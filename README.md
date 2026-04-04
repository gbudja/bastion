# Bastion

Bastion is a Python-based network gateway and firewall platform focused on strict rule validation, modular plugin enforcement, and API-driven policy management.

It provides a structured, programmatic approach to defining and enforcing network security rules, with support for DNS filtering, rule chains, and production-safe validation.

Bastion is designed with security-first principles, including strict input validation, environment-based secrets, and controlled rule application workflows.

---

## Quick Demo

```bash
pip install -e .
set BASTION_SECRET_KEY=dev
bastion start --demo
```

Test the health endpoint:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status": "ok"}
```

---

## Core Features

* Strict firewall rule validation and CIDR parsing
* nftables-oriented rules engine with apply and rollback support
* REST API for firewall, monitoring, plugins, and system control
* Modular plugin system (DNS filtering implemented)
* CLI interface and demo dashboard
* Config-driven architecture with environment-based secrets

---

## Components

Bastion currently includes:

* An nftables-oriented firewall rules engine with rule validation, nft script rendering, apply, and rollback support
* A Flask REST API for firewall, monitoring, plugin, and system endpoints
* A demo web dashboard that renders simulated gateway metrics and firewall data
* A plugin system with bundled DNS filtering support
* A Click-based CLI with `bastion start --demo`

---

## Current Status

This repository is in an early stage. The implemented components are test-covered and installable.

The live firewall backend is intended for Linux systems with nftables available. On non-Linux systems, use demo mode.

---

## Installation

```bash
git clone https://github.com/gbudja/bastion.git
cd bastion
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

For non-demo runs, set a Flask secret key in the environment:

```bash
export BASTION_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

---

## Running Bastion

### Demo mode

```bash
bastion start --demo
```

### Live mode (Linux with nftables)

```bash
export BASTION_SECRET_KEY="replace-with-a-real-secret"
bastion start
```

The dashboard is available at:

```
http://<host>:<port>/
```

Health endpoint:

```
GET /health
```

---

## Configuration

Example configuration files:

* [config/bastion.example.yaml](config/bastion.example.yaml)
* [config/rules.example.yaml](config/rules.example.yaml)

`BASTION_SECRET_KEY` must be provided via environment variables and is not stored in configuration files.

---

## API

Base path:

```
/api/v1
```

### Firewall routes

| Method | Endpoint                         | Description             |
| ------ | -------------------------------- | ----------------------- |
| GET    | `/api/v1/rules`                  | List rules with filters |
| POST   | `/api/v1/rules`                  | Create a rule           |
| GET    | `/api/v1/rules/<rule_id>`        | Fetch a rule            |
| PUT    | `/api/v1/rules/<rule_id>`        | Update a rule           |
| DELETE | `/api/v1/rules/<rule_id>`        | Delete a rule           |
| POST   | `/api/v1/rules/<rule_id>/toggle` | Toggle rule state       |
| GET    | `/api/v1/rules/groups`           | List grouped rules      |
| GET    | `/api/v1/rules/validate`         | Validate ruleset        |
| POST   | `/api/v1/rules/apply`            | Apply rules             |
| POST   | `/api/v1/rules/rollback`         | Roll back rules         |

---

### Monitoring routes

| Method | Endpoint                   | Description       |
| ------ | -------------------------- | ----------------- |
| GET    | `/api/v1/monitor/stats`    | Dashboard metrics |
| GET    | `/api/v1/monitor/hosts`    | Discovered hosts  |
| GET    | `/api/v1/monitor/sessions` | Active sessions   |

---

### Plugin routes

| Method   | Endpoint                               | Description         |
| -------- | -------------------------------------- | ------------------- |
| GET      | `/api/v1/plugins`                      | List plugins        |
| POST     | `/api/v1/plugins/<name>/enable`        | Enable plugin       |
| POST     | `/api/v1/plugins/<name>/disable`       | Disable plugin      |
| GET      | `/api/v1/plugins/<name>/routes`        | Plugin routes       |
| GET/POST | `/api/v1/plugins/<name>/api/<subpath>` | Invoke plugin route |

---

### System route

| Method | Endpoint              | Description              |
| ------ | --------------------- | ------------------------ |
| GET    | `/api/v1/system/info` | Runtime and version info |

---

## DNS Filtering Plugin

Relevant files:

* [bastion/plugins/dns_filter/**init**.py](bastion/plugins/dns_filter/__init__.py)
* [bastion/plugins/dns_filter/blocklist.py](bastion/plugins/dns_filter/blocklist.py)

Features:

* Blocklist loading from text files, hosts files, and remote URLs
* Allowlist overrides
* Parent-domain matching
* DNS query parsing
* Sinkhole response generation for blocked domains
* Plugin API routes for status and lookup

---

## Project Structure

```text
bastion/
  api/
  core/
  plugins/
    dns_filter/
  web/
    templates/
config/
tests/
  test_firewall.py
  test_dns_filter.py
```

---

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/test_firewall.py tests/test_dns_filter.py -v
python -m ruff check bastion tests
python -m black --check bastion tests
python -m mypy bastion --ignore-missing-imports
```

---

## Roadmap

* [x] Core firewall rules engine
* [x] REST API
* [x] Demo dashboard
* [x] Plugin system
* [x] DNS filtering plugin
* [x] CLI entry point

### Planned

* [ ] Authentication and authorization
* [ ] Sandboxed plugin execution
* [ ] IDS/IPS integration
* [ ] VPN management
* [ ] Traffic shaping
* [ ] HA clustering

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
