"""Tests for Proxmox Backup Server (PBS) tools and MCP integration."""

from __future__ import annotations

import json
from unittest.mock import MagicMock
import pytest

from proxmox_mcp.services.tool_catalog import BUILTIN_TOOL_NAMES
from proxmox_mcp.services.tool_wrappers import _READ_ONLY_TOOLS, RegistryPluginBase
from proxmox_mcp.tools.pbs import PBSTools
from proxmox_mcp.core.targets import ResolvedTarget
from proxmox_mcp.config.models import ProxmoxConfig, AuthConfig


def _extract_json(content_list):
    assert len(content_list) == 1
    return json.loads(content_list[0].text)


def test_no_destructive_tools_in_builtin_catalog_or_pbs():
    destructive_keywords = {"delete_datastore", "forget", "prune", "gc", "wipe_disk", "zpool_destroy", "destroy"}
    for name in BUILTIN_TOOL_NAMES:
        for kw in destructive_keywords:
            assert kw not in name, f"Destructive keyword '{kw}' found in tool catalog: '{name}'"

    pbs_methods = [m for m in dir(PBSTools) if not m.startswith("_")]
    for method in pbs_methods:
        for kw in {"delete", "forget", "prune", "gc", "wipe", "destroy"}:
            assert kw not in method.lower(), f"Destructive method '{method}' found in PBSTools"


def test_pbs_get_datastores_enriches_status():
    mock_api = MagicMock()
    mock_api.admin.datastore.get.return_value = [
        {"store": "backup1", "comment": "Main backup store"},
        {"store": "backup2", "comment": "Secondary"},
    ]
    statuses = {
        "backup1": {"total": 1000, "used": 500},
        "backup2": {"total": 2000, "used": 100},
    }
    mock_api.admin.datastore.side_effect = lambda name: MagicMock(
        status=MagicMock(get=MagicMock(return_value=statuses[name]))
    )

    tools = PBSTools(mock_api)
    result = _extract_json(tools.get_datastores())

    assert len(result) == 2
    assert result[0]["store"] == "backup1"
    assert result[0]["status"] == {"total": 1000, "used": 500}
    assert result[1]["store"] == "backup2"
    assert result[1]["status"] == {"total": 2000, "used": 100}


def test_pbs_get_tasks_filters():
    mock_api = MagicMock()
    mock_api.nodes("localhost").tasks.get.return_value = [
        {"upid": "UPID:1", "store": "backup1", "endtime": None, "status": "running"},
        {"upid": "UPID:2", "store": "backup1", "endtime": 123456, "status": "stopped"},
        {"upid": "UPID:3", "store": "backup2", "endtime": None, "status": "running"},
    ]

    tools = PBSTools(mock_api)
    res_all = _extract_json(tools.get_tasks(limit=10, running_only=False))
    assert len(res_all) == 3

    res_running = _extract_json(tools.get_tasks(limit=10, running_only=True))
    assert len(res_running) == 2
    assert {t["upid"] for t in res_running} == {"UPID:1", "UPID:3"}

    res_store = _extract_json(tools.get_tasks(limit=10, running_only=False, store="backup2"))
    assert len(res_store) == 1
    assert res_store[0]["upid"] == "UPID:3"


def test_pbs_get_task_log():
    mock_api = MagicMock()
    mock_api.nodes("localhost").tasks("UPID:test").log.get.return_value = [
        {"n": 1, "t": "starting task"},
        {"n": 2, "t": "task successful"},
    ]

    tools = PBSTools(mock_api)
    result = _extract_json(tools.get_task_log("UPID:test", start=0, limit=100))
    assert len(result) == 2
    assert result[1]["t"] == "task successful"


def test_pbs_get_disks():
    mock_api = MagicMock()
    mock_api.nodes("localhost").disks.list.get.return_value = [
        {"devpath": "/dev/sda", "size": 1000000000, "wearout": 0},
    ]

    tools = PBSTools(mock_api)
    result = _extract_json(tools.get_disks())
    assert len(result) == 1
    assert result[0]["devpath"] == "/dev/sda"


def test_pbs_get_zfs_all_and_specific():
    mock_api = MagicMock()
    mock_api.nodes("localhost").disks.zfs.get.return_value = [
        {"name": "rpool", "size": 500000},
    ]
    mock_api.nodes("localhost").disks.zfs("rpool").get.return_value = {
        "name": "rpool", "state": "ONLINE",
    }

    tools = PBSTools(mock_api)
    res_all = _extract_json(tools.get_zfs())
    assert len(res_all) == 1
    assert res_all[0]["name"] == "rpool"

    res_pool = _extract_json(tools.get_zfs("rpool"))
    assert res_pool["state"] == "ONLINE"


def test_pbs_verify_datastore():
    mock_api = MagicMock()
    mock_api.admin.datastore("backup1").verify.post.return_value = "UPID:localhost:1234:verify"

    tools = PBSTools(mock_api)
    result = _extract_json(tools.verify_datastore("backup1", ignore_verified=True))
    assert result["status"] == "started"
    assert result["store"] == "backup1"
    assert result["upid"] == "UPID:localhost:1234:verify"


def test_pbs_scrub_zfs_with_fallback():
    mock_api = MagicMock()
    mock_api.nodes("localhost").disks.zfs("rpool").scrub.put.return_value = "UPID:localhost:5678:scrub"

    tools = PBSTools(mock_api)
    res_put = _extract_json(tools.scrub_zfs("rpool"))
    assert res_put["status"] == "started"
    assert res_put["pool"] == "rpool"
    assert res_put["upid"] == "UPID:localhost:5678:scrub"

    # Test fallback to POST when PUT raises AttributeError
    mock_api_fallback = MagicMock()
    mock_api_fallback.nodes("localhost").disks.zfs("rpool").scrub.put.side_effect = AttributeError("No put")
    mock_api_fallback.nodes("localhost").disks.zfs("rpool").scrub.post.return_value = "UPID:localhost:9999:scrub"

    tools_fallback = PBSTools(mock_api_fallback)
    res_post = _extract_json(tools_fallback.scrub_zfs("rpool"))
    assert res_post["status"] == "started"
    assert res_post["upid"] == "UPID:localhost:9999:scrub"


def test_pbs_tools_readonly_enforcement():
    pbs_read_only = {
        "pbs_get_datastores",
        "pbs_get_tasks",
        "pbs_get_task_log",
        "pbs_get_disks",
        "pbs_get_zfs",
    }
    pbs_mutation = {
        "pbs_verify_datastore",
        "pbs_scrub_zfs",
    }

    assert pbs_read_only.issubset(_READ_ONLY_TOOLS)
    assert not pbs_mutation.intersection(_READ_ONLY_TOOLS)

    # Test execution enforcement with dummy server
    class DummyServer:
        def __init__(self, readonly: bool):
            self.target_registry = MagicMock()
            resolved = ResolvedTarget(
                name="pbs_ro",
                config=ProxmoxConfig(host="pbs.local", port=8007, service="PBS"),
                auth=AuthConfig(user="u", token_name="t", token_value="v"),
                kind="pbs",
                readonly=readonly,
            )
            self.target_registry.resolve.return_value = resolved
            self.target_command_policies = {"pbs_ro": MagicMock()}
            self.target_command_policies["pbs_ro"].evaluate_operation.return_value = MagicMock(allowed=True, code="OK")
            self.metrics = MagicMock()
            self.target_toolsets = {
                "pbs_ro": MagicMock()
            }
        def target_tools(self, name):
            return self.target_toolsets[name]

    plugin = RegistryPluginBase()
    server_ro = DummyServer(readonly=True)

    # Mutation tool must be rejected
    wrapped_verify = plugin._wrap_sync(server_ro, "pbs_verify_datastore", lambda ts: ts.verify, expected_service="PBS")
    with pytest.raises(ValueError, match="is configured read-only"):
        wrapped_verify(store="store1")

    wrapped_scrub = plugin._wrap_sync(server_ro, "pbs_scrub_zfs", lambda ts: ts.scrub, expected_service="PBS")
    with pytest.raises(ValueError, match="is configured read-only"):
        wrapped_scrub(pool="rpool")

    # Read-only tool must pass
    server_ro.target_toolsets["pbs_ro"].get_ds = MagicMock(return_value=[])
    wrapped_get_ds = plugin._wrap_sync(server_ro, "pbs_get_datastores", lambda ts: ts.get_ds, expected_service="PBS")
    assert wrapped_get_ds() == []
