# Bastion

Open-source network gateway and firewall management platform written in Python.

Bastion currently includes:

- An nftables-oriented firewall rules engine with rule validation, nft script rendering, apply, and rollback support
- A Flask REST API for firewall, monitoring, plugin, and system endpoints
- A demo web dashboard that renders simulated gateway metrics and firewall data
- A plugin system with bundled DNS filtering support
- A Click-based CLI with `bastion start --demo`

## Current status

This repository is in an early stage. The implemented pieces are test-covered and installable, but the live firewall backend is intended for Linux systems with nftables available. On non-Linux systems, use demo mode.

## Installation

```bash
git clone https://github.com/gbudja/bastion.git
cd bastion
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

For non-demo runs, set a Flask secret key in the environment before starting the app:

```bash
export BASTION_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

## Running Bastion

Demo mode:

```bash
bastion start --demo
```

Live mode on Linux with nftables installed:

```bash
export BASTION_SECRET_KEY="replace-with-a-real-secret"
bastion start
```

The dashboard is served at `http://<host>:<port>/` and the health endpoint is `GET /health`.

## Configuration

Example configuration files live in [config/bastion.example.yaml](/C:/Users/grant/Desktop/bastion-project/config/bastion.example.yaml) and [config/rules.example.yaml](/C:/Users/grant/Desktop/bastion-project/config/rules.example.yaml).

`BASTION_SECRET_KEY` must come from the environment. It is not stored in the committed config template.

## API

The API is mounted under `/api/v1`.

### Firewall routes

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/v1/rules` | List rules with optional `group`, `state`, `direction`, `q`, and repeated `tag` filters |
| POST | `/api/v1/rules` | Create a rule |
| GET | `/api/v1/rules/<rule_id>` | Fetch a rule |
| PUT | `/api/v1/rules/<rule_id>` | Update a rule |
| DELETE | `/api/v1/rules/<rule_id>` | Delete a rule |
| POST | `/api/v1/rules/<rule_id>/toggle` | Toggle rule state |
| GET | `/api/v1/rules/groups` | List grouped rules |
| GET | `/api/v1/rules/validate` | Validate current ruleset |
| POST | `/api/v1/rules/apply` | Apply current ruleset |
| POST | `/api/v1/rules/rollback` | Roll back to the previous ruleset |

### Monitoring routes

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/v1/monitor/stats` | Dashboard metrics payload |
| GET | `/api/v1/monitor/hosts` | Discovered hosts |
| GET | `/api/v1/monitor/sessions` | Active sessions snapshot |

### Plugin routes

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/v1/plugins` | List discoverable plugins and status |
| POST | `/api/v1/plugins/<name>/enable` | Enable a plugin |
| POST | `/api/v1/plugins/<name>/disable` | Disable a plugin |
| GET | `/api/v1/plugins/<name>/routes` | List plugin-provided API routes |
| GET/POST | `/api/v1/plugins/<name>/api/<subpath>` | Invoke a plugin-provided route |

### System route

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/v1/system/info` | Version and runtime information |

## DNS filtering plugin

The bundled DNS filter plugin lives in [bastion/plugins/dns_filter/__init__.py](/C:/Users/grant/Desktop/bastion-project/bastion/plugins/dns_filter/__init__.py) and [bastion/plugins/dns_filter/blocklist.py](/C:/Users/grant/Desktop/bastion-project/bastion/plugins/dns_filter/blocklist.py).

Implemented behavior:

- Blocklist loading from plain-text files, hosts files, and HTTP/HTTPS URLs
- Allowlist overrides
- Parent-domain matching
- Minimal DNS query parsing
- Sinkhole response generation for blocked A-record queries
- Plugin API routes for status and domain lookups

## Project structure

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

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/test_firewall.py tests/test_dns_filter.py -v
python -m ruff check bastion tests
python -m black --check bastion tests
python -m mypy bastion --ignore-missing-imports
```

## Roadmap

- [x] Core firewall rules engine
- [x] REST API
- [x] Demo dashboard
- [x] Plugin system
- [x] DNS filtering plugin
- [x] CLI entry point
- [ ] Authentication and authorization
- [ ] Sandboxed plugin execution
- [ ] IDS/IPS integration
- [ ] VPN management
- [ ] Traffic shaping
- [ ] HA clustering

## License

GPL-3.0-or-later. See [LICENSE](/C:/Users/grant/Desktop/bastion-project/LICENSE).
