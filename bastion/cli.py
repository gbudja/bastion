"""
Bastion CLI

Command-line interface for starting, managing, and configuring Bastion.
"""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bastion import __version__

console = Console()

BANNER = r"""
[bold cyan]
  ██████╗  █████╗ ███████╗████████╗██╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
  ██████╔╝███████║███████╗   ██║   ██║██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══██║╚════██║   ██║   ██║██║   ██║██║╚██╗██║
  ██████╔╝██║  ██║███████║   ██║   ██║╚██████╔╝██║ ╚████║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold cyan]
[dim]  Open-Source Network Gateway & Firewall  v{version}[/dim]
"""


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """Bastion — Open-Source Network Gateway & Firewall"""
    setup_logging(verbose)


@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=8443, help="Port number")
@click.option("--demo", is_flag=True, help="Run in demo mode (no root required)")
@click.option("--config", type=click.Path(), default=None, help="Config file path")
def start(host: str, port: int, demo: bool, config: str | None) -> None:
    """Start the Bastion gateway."""
    console.print(BANNER.format(version=__version__))

    if demo:
        console.print(
            Panel(
                "[yellow]Running in DEMO mode[/yellow]\n"
                "Firewall rules will be generated but not applied.\n"
                "Dashboard will show simulated data.",
                title="Demo Mode",
                border_style="yellow",
            )
        )

    from bastion.api.routes import init_api
    from bastion.core.engine import NftablesBackend
    from bastion.core.manager import RuleManager
    from bastion.core.monitor import NetworkMonitor
    from bastion.plugins import PluginManager
    from bastion.web.app import create_app

    # Initialize components
    backend = NftablesBackend(demo_mode=demo)
    rule_manager = RuleManager(backend=backend)
    monitor = NetworkMonitor(demo_mode=demo)
    plugin_manager = PluginManager()
    plugin_manager.load_all()

    # Initialize API
    init_api(rule_manager, monitor, plugin_manager)

    # Create and configure Flask app
    app = create_app(rule_manager, monitor, plugin_manager, demo_mode=demo)

    # Load saved rules
    try:
        rule_manager.load()
        console.print(f"[green]✓[/green] Loaded {len(rule_manager.get_all_rules())} rules")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not load rules: {e}")

    # Warn when binding to all interfaces — no auth yet, always dangerous.
    if host in ("0.0.0.0", "::"):
        console.print(
            Panel(
                "[red]WARNING:[/red] Binding to all interfaces with no authentication.\n"
                "The API and dashboard are open to any reachable client.\n"
                "Use [bold]--host 127.0.0.1[/bold] or run behind an authenticated reverse proxy.\n"
                "See [bold]docs/SECURE_DEPLOYMENT.md[/bold] for guidance.",
                title="Security Notice",
                border_style="red",
            )
        )

    # Check nftables availability
    if not demo and not backend.is_available():
        console.print(
            "[red]✗ nftables not available.[/red] "
            "Install with: apt install nftables\n"
            "  Or run with --demo flag for demo mode."
        )
        sys.exit(1)

    # Print status
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style="bold")
    info_table.add_column()
    info_table.add_row("Dashboard:", f"http://{host}:{port}")
    info_table.add_row("API:", f"http://{host}:{port}/api/v1")
    info_table.add_row("Mode:", "Demo" if demo else "Live")
    info_table.add_row("Backend:", "nftables")
    console.print(info_table)
    console.print()

    # ── Why we do NOT use Flask-SocketIO / engineio here ─────────────────
    #
    # `SocketIO(app)` permanently wraps app.wsgi_app with python-engineio's
    # WSGIApp middleware. In python-engineio 4.x + Werkzeug 3.x threading
    # mode, the pass-through path for plain HTTP requests is broken: Flask
    # generates the response, but the start_response callback through the
    # engineio middleware layer does not flush it to the client. Every HTTP
    # request hangs indefinitely. This affects even trivial routes like
    # /health that have no I/O at all.
    #
    # Fix: do not create the SocketIO instance. Serve directly with
    # app.run(threaded=True), which gives each request its own OS thread
    # with no intervening middleware. WebSocket support can be added in a
    # future production-mode path using gunicorn + gevent workers.
    # ─────────────────────────────────────────────────────────────────────

    # Background metrics collection — stores data in monitor.system_history
    # and monitor.network_history for the REST API to serve on demand.
    def _background_metrics() -> None:
        import time

        log = logging.getLogger(__name__)
        while True:
            try:
                monitor.get_dashboard_data()
            except Exception as exc:
                log.debug("Metric collection error: %s", exc)
            time.sleep(5)

    threading.Thread(
        target=_background_metrics,
        daemon=True,
        name="bastion-metrics",
    ).start()

    console.print("[green]✓ Bastion is running[/green]\n")

    # Werkzeug threaded dev server — correct for demo mode.
    # For production use, run behind gunicorn:
    #   gunicorn "bastion.web.app:create_app(...)" --workers 4 --bind 0.0.0.0:8443
    app.run(host=host, port=port, threaded=True, use_reloader=False, debug=False)


@cli.command()
def status() -> None:
    """Show Bastion service status."""
    console.print("[bold]Bastion Status[/bold]")
    # TODO: Check if running, show PID, uptime, etc.
    console.print("[dim]Status check not yet implemented[/dim]")


@cli.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Validate without applying")
def apply(rule_file: str, dry_run: bool) -> None:
    """Apply firewall rules from a YAML file."""
    from bastion.core.engine import NftablesBackend
    from bastion.core.manager import RuleManager

    backend = NftablesBackend(demo_mode=dry_run)
    manager = RuleManager(backend=backend)
    manager.load(Path(rule_file))

    if dry_run:
        result = manager.validate()
        if result["valid"]:
            console.print("[green]✓ Ruleset is valid[/green]")
            console.print(f"  {result['enabled_rules']} enabled rules")
        else:
            console.print("[red]✗ Validation errors:[/red]")
            for err in result["errors"]:
                console.print(f"  Rule {err['rule_id']}: {err['errors']}")

        if result["warnings"]:
            console.print("[yellow]Warnings:[/yellow]")
            for w in result["warnings"]:
                console.print(f"  {w}")

        console.print("\n[bold]Generated nft script:[/bold]")
        console.print(result["script_preview"])
    else:
        result = manager.apply()
        if result["success"]:
            console.print(f"[green]✓ Applied {result['rules_applied']} rules[/green]")
        else:
            console.print(f"[red]✗ Failed: {result.get('error')}[/red]")


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
