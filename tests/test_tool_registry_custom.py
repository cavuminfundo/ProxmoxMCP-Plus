from __future__ import annotations

import inspect
from unittest.mock import MagicMock

from proxmox_mcp.services.tool_catalog import BUILTIN_TOOL_NAMES
from proxmox_mcp.services.tool_wrappers import _READ_ONLY_TOOLS
from proxmox_mcp.services.builtin_tool_plugins import CoreToolsPlugin

CUSTOM_HOST_TOOLS = [
    "get_apt_updates",
    "refresh_apt_repositories",
    "upgrade_apt_packages",
    "get_node_disks",
    "get_smart_status",
    "get_node_journal",
    "get_node_services",
    "restart_node_service",
    "get_node_network",
    "get_node_tasks",
]

READ_ONLY_CUSTOM_TOOLS = [
    "get_apt_updates",
    "get_node_disks",
    "get_smart_status",
    "get_node_journal",
    "get_node_services",
    "get_node_network",
    "get_node_tasks",
]

MUTATING_CUSTOM_TOOLS = [
    "refresh_apt_repositories",
    "upgrade_apt_packages",
    "restart_node_service",
]


def test_custom_tools_in_builtin_tool_names():
    for tool_name in CUSTOM_HOST_TOOLS:
        assert tool_name in BUILTIN_TOOL_NAMES, f"{tool_name} missing from BUILTIN_TOOL_NAMES"


def test_custom_tools_read_only_and_mutating_classification():
    for tool_name in READ_ONLY_CUSTOM_TOOLS:
        assert tool_name in _READ_ONLY_TOOLS, f"{tool_name} missing from _READ_ONLY_TOOLS"
    for tool_name in MUTATING_CUSTOM_TOOLS:
        assert tool_name not in _READ_ONLY_TOOLS, f"{tool_name} should not be in _READ_ONLY_TOOLS"


def test_core_tools_plugin_registers_and_invokes_custom_tools_with_target():
    registered_tools = {}

    class DummyRegistry:
        def tool(self, description=None):
            def decorator(fn):
                registered_tools[fn.__name__] = fn
                return fn
            return decorator

    server = MagicMock()
    server.proxmox_managers = {}
    server.tool_registry = DummyRegistry()

    invoked = {}

    def fake_wrap_sync(server_arg, tool_name, handler_factory, **kwargs):
        def wrapped(*args, **kw):
            mock_ts = MagicMock()
            handler = handler_factory(mock_ts)
            res = handler(*args, **kw)
            invoked[tool_name] = (args, kw, res)
            return res
        return wrapped

    plugin = CoreToolsPlugin()
    plugin._wrap_sync = fake_wrap_sync
    plugin.register(server)

    sample_calls = {
        "get_apt_updates": {"node": "pve1", "target": "lab"},
        "refresh_apt_repositories": {"node": "pve1", "target": "lab"},
        "upgrade_apt_packages": {"node": "pve1", "target": "lab"},
        "get_node_disks": {"node": "pve1", "target": "lab"},
        "get_smart_status": {"node": "pve1", "disk": "/dev/sda", "target": "lab"},
        "get_node_journal": {"node": "pve1", "last_lines": 50, "target": "lab"},
        "get_node_services": {"node": "pve1", "target": "lab"},
        "restart_node_service": {"node": "pve1", "service": "pveproxy", "target": "lab"},
        "get_node_network": {"node": "pve1", "target": "lab"},
        "get_node_tasks": {"node": "pve1", "limit": 20, "target": "lab"},
    }

    for tool_name in CUSTOM_HOST_TOOLS:
        assert tool_name in registered_tools, f"{tool_name} not registered by CoreToolsPlugin"
        sig = inspect.signature(registered_tools[tool_name])
        assert "target" in sig.parameters, f"{tool_name} missing 'target' parameter"

        # Invoke tool function to cover the registration body and wrapper call
        fn = registered_tools[tool_name]
        result = fn(**sample_calls[tool_name])
        assert tool_name in invoked, f"{tool_name} was not invoked through wrapper"
        assert result is not None
