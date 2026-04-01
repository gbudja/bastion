"""
Bastion Plugin System

Provides a base class for plugins and a loader/manager that handles
discovery, lifecycle management, and inter-plugin communication
via an event bus.
"""

from __future__ import annotations

import importlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class PluginState(str, Enum):
    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class PluginMeta:
    """Plugin metadata."""

    name: str
    version: str
    description: str
    author: str = ""
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict = field(default_factory=dict)


class BastionPlugin(ABC):
    """
    Base class for all Bastion plugins.

    Subclass this and implement the required methods to create a plugin.
    Place your plugin in the plugins directory and Bastion will auto-discover it.
    """

    @abstractmethod
    def get_meta(self) -> PluginMeta:
        """Return plugin metadata."""
        ...

    @abstractmethod
    def on_enable(self, config: dict) -> None:
        """Called when the plugin is enabled. Initialize resources here."""
        ...

    @abstractmethod
    def on_disable(self) -> None:
        """Called when the plugin is disabled. Clean up resources here."""
        ...

    def on_config_update(self, config: dict) -> None:
        """Called when plugin configuration is updated."""
        pass

    def get_api_routes(self) -> list[dict]:
        """
        Return additional API routes this plugin provides.

        Each dict should have: method, path, handler, description.
        """
        return []

    def get_dashboard_widgets(self) -> list[dict]:
        """
        Return dashboard widget definitions.

        Each dict should have: id, title, template, position.
        """
        return []


class EventBus:
    """
    Simple pub/sub event bus for inter-plugin communication.

    Plugins can subscribe to events and publish events that other
    plugins react to.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable]] = {}

    def subscribe(self, event: str, handler: Callable) -> None:
        """Subscribe a handler to an event type."""
        self._handlers.setdefault(event, []).append(handler)
        logger.debug("Subscribed to event '%s': %s", event, handler.__qualname__)

    def unsubscribe(self, event: str, handler: Callable) -> None:
        """Unsubscribe a handler from an event type."""
        if event in self._handlers:
            self._handlers[event] = [h for h in self._handlers[event] if h != handler]

    def publish(self, event: str, data: Any = None) -> None:
        """Publish an event to all subscribed handlers."""
        handlers = self._handlers.get(event, [])
        for handler in handlers:
            try:
                handler(data)
            except Exception as e:
                logger.error(
                    "Event handler %s failed for event '%s': %s",
                    handler.__qualname__,
                    event,
                    e,
                )


class PluginManager:
    """
    Manages the lifecycle of Bastion plugins.

    Handles discovery, loading, enabling, disabling, and configuration
    of plugins from a plugin directory.
    """

    def __init__(self, plugin_dir: Optional[Path] = None) -> None:
        self.plugin_dir = plugin_dir or Path("/etc/bastion/plugins")
        self.event_bus = EventBus()
        self._plugins: dict[str, BastionPlugin] = {}
        self._states: dict[str, PluginState] = {}
        self._configs: dict[str, dict] = {}

    def discover(self) -> list[str]:
        """Discover available plugins in the plugin directory."""
        discovered: list[str] = []

        if not self.plugin_dir.exists():
            logger.debug("Plugin directory does not exist: %s", self.plugin_dir)
            return discovered

        for path in self.plugin_dir.iterdir():
            if path.is_dir() and (path / "__init__.py").exists():
                discovered.append(path.name)
            elif path.suffix == ".py" and path.stem != "__init__":
                discovered.append(path.stem)

        logger.info("Discovered %d plugins: %s", len(discovered), discovered)
        return discovered

    def load_plugin(self, name: str) -> Optional[PluginMeta]:
        """Load a plugin by name without enabling it."""
        try:
            module = importlib.import_module(f"bastion.plugins.{name}")

            # Look for a Plugin class in the module
            plugin_cls = getattr(module, "Plugin", None)
            if not plugin_cls or not issubclass(plugin_cls, BastionPlugin):
                logger.error("Plugin '%s' has no valid Plugin class", name)
                return None

            instance = plugin_cls()
            meta = instance.get_meta()

            self._plugins[name] = instance
            self._states[name] = PluginState.LOADED
            logger.info("Loaded plugin: %s v%s", meta.name, meta.version)
            return meta

        except Exception as e:
            logger.error("Failed to load plugin '%s': %s", name, e)
            self._states[name] = PluginState.ERROR
            return None

    def enable_plugin(self, name: str, config: Optional[dict] = None) -> bool:
        """Enable a loaded plugin."""
        plugin = self._plugins.get(name)
        if not plugin:
            logger.error("Plugin '%s' not loaded", name)
            return False

        try:
            cfg = config or self._configs.get(name, {})
            plugin.on_enable(cfg)
            self._states[name] = PluginState.ENABLED
            self._configs[name] = cfg
            self.event_bus.publish("plugin.enabled", {"name": name})
            logger.info("Enabled plugin: %s", name)
            return True
        except Exception as e:
            logger.error("Failed to enable plugin '%s': %s", name, e)
            self._states[name] = PluginState.ERROR
            return False

    def disable_plugin(self, name: str) -> bool:
        """Disable an enabled plugin."""
        plugin = self._plugins.get(name)
        if not plugin:
            return False

        try:
            plugin.on_disable()
            self._states[name] = PluginState.DISABLED
            self.event_bus.publish("plugin.disabled", {"name": name})
            logger.info("Disabled plugin: %s", name)
            return True
        except Exception as e:
            logger.error("Failed to disable plugin '%s': %s", name, e)
            return False

    def get_status(self) -> list[dict]:
        """Get status of all known plugins."""
        result = []
        for name, plugin in self._plugins.items():
            meta = plugin.get_meta()
            result.append({
                "name": name,
                "display_name": meta.name,
                "version": meta.version,
                "description": meta.description,
                "author": meta.author,
                "state": self._states.get(name, PluginState.LOADED).value,
                "config": self._configs.get(name, {}),
            })
        return result
