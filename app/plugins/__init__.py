from __future__ import annotations
import importlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger("netpulse.plugins")

@runtime_checkable
class NetPulsePlugin(Protocol):
    """Protocol that all NetPulse plugins must implement."""
    name: str
    description: str
    version: str
    category: str

    def initialize(self, config: Dict[str, Any]) -> None: ...
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]: ...
    def cleanup(self) -> None: ...


class PluginManager:
    """Manages loading, running, and tracking plugins."""

    def __init__(self):
        self.plugins: Dict[str, Any] = {}
        self.plugin_results: Dict[str, List[Dict[str, Any]]] = {}

    def register(self, plugin_instance):
        self.plugins[plugin_instance.name] = plugin_instance
        self.plugin_results[plugin_instance.name] = []
        logger.info(f"Plugin registered: {plugin_instance.name} v{plugin_instance.version}")

    def get_plugin(self, name: str):
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        return [
            {"name": p.name, "description": p.description, "version": p.version, "category": p.category}
            for p in self.plugins.values()
        ]

    def execute_plugin(self, name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        plugin = self.plugins.get(name)
        if not plugin:
            return {"error": f"Plugin '{name}' not found"}
        try:
            result = plugin.execute(context)
            self.plugin_results[name].append(result)
            if len(self.plugin_results[name]) > 100:
                self.plugin_results[name] = self.plugin_results[name][-100:]
            return result
        except Exception as e:
            return {"error": str(e)}

    def get_results(self, name: str) -> List[Dict[str, Any]]:
        return self.plugin_results.get(name, [])


plugin_manager = PluginManager()


def load_builtin_plugins() -> None:
    from app.plugins.builtin.arp_spoof_detector import ArpSpoofDetector
    from app.plugins.builtin.rogue_dhcp_detector import RogueDhcpDetector
    from app.plugins.builtin.port_knock_detector import PortKnockDetector

    for cls in (ArpSpoofDetector, RogueDhcpDetector, PortKnockDetector):
        instance = cls()
        instance.initialize({})
        plugin_manager.register(instance)

    logger.info(f"Loaded {len(plugin_manager.plugins)} built-in plugins")
