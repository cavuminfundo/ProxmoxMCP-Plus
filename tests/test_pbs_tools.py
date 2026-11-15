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


def test_pbs_tools_rejects_path_traversal_segments():
    mock_api = MagicMock()
    tools = PBSTools(mock_api)
    bad_inputs = ["../etc", "../../api2/json/access/users", "store/sub", "pool?x=1", "pool#frag"]
    for bad in bad_inputs:
        with pytest.raises(ValueError, match="Invalid resource path segment"):
            tools.get_tasks(store=bad)
        with pytest.raises(ValueError, match="Invalid resource path segment"):
            tools.get_task_log(upid=bad)
        with pytest.raises(ValueError, match="Invalid resource path segment"):
            tools.get_zfs(pool=bad)
        with pytest.raises(ValueError, match="Invalid resource path segment"):
            tools.verify_datastore(store=bad)
        with pytest.raises(ValueError, match="Invalid resource path segment"):
            tools.scrub_zfs(pool=bad)
    mock_api.admin.datastore.assert_not_called()
    mock_api.nodes.assert_not_called()


def test_pbs_tools_error_and_fallback_branches():
    mock_api = MagicMock()
    tools = PBSTools(mock_api)

    # Non-list datastores + status error fallback
    mock_api.admin.datastore.get.return_value = {"unexpected": True}
    assert _extract_json(tools.get_datastores()) == {"unexpected": True}

    mock_api.admin.datastore.get.return_value = [{"store": "ds1"}]
    mock_api.admin.datastore.side_effect = lambda _name: MagicMock(
        status=MagicMock(get=MagicMock(side_effect=RuntimeError("status fail")))
    )
    assert _extract_json(tools.get_datastores()) == [{"store": "ds1"}]

    # API errors on all methods
    mock_api.admin.datastore.get.side_effect = RuntimeError("ds err")
    with pytest.raises(RuntimeError):
        tools.get_datastores()

    mock_api.nodes("localhost").tasks.get.side_effect = RuntimeError("tasks err")
    with pytest.raises(RuntimeError):
        tools.get_tasks()

    mock_api.nodes("localhost").tasks("UPID:1").log.get.side_effect = RuntimeError("log err")
    with pytest.raises(RuntimeError):
        tools.get_task_log("UPID:1")

    mock_api.nodes("localhost").disks.list.get.side_effect = RuntimeError("disks err")
    with pytest.raises(RuntimeError):
        tools.get_disks()

    mock_api.nodes("localhost").disks.zfs.get.side_effect = RuntimeError("zfs err")
    with pytest.raises(RuntimeError):
        tools.get_zfs()

    # verify_datastore with outdated_after and dict upid + error branch
    mock_api.admin.datastore.side_effect = None
    mock_api.admin.datastore("ds1").verify.post.return_value = {"data": {"upid": "UPID:v1"}}
    res_v = _extract_json(tools.verify_datastore("ds1", outdated_after=7))
    assert res_v["upid"] == "UPID:v1"
    mock_api.admin.datastore("ds1").verify.post.side_effect = RuntimeError("verify err")
    with pytest.raises(RuntimeError):
        tools.verify_datastore("ds1")

    # scrub_zfs: AttributeError fallback to post(), 405 fallback, and non-405 error
    scrub_ep = mock_api.nodes("localhost").disks.zfs("rpool").scrub
    scrub_ep.put.side_effect = AttributeError("no put")
    scrub_ep.post.return_value = {"data": {"upid": "UPID:s1"}}
    assert _extract_json(tools.scrub_zfs("rpool"))["upid"] == "UPID:s1"

    scrub_ep.put.side_effect = RuntimeError("405 Method Not Allowed")
    scrub_ep.post.return_value = "UPID:s2"
    assert _extract_json(tools.scrub_zfs("rpool"))["upid"] == "UPID:s2"

    scrub_ep.put.side_effect = RuntimeError("500 internal")
    with pytest.raises(RuntimeError):
        tools.scrub_zfs("rpool")


@pytest.mark.asyncio
async def test_pbs_plugin_wrappers_list_targets_and_models():
    from types import SimpleNamespace
    from pydantic import ValidationError
    from proxmox_mcp.config.models import CommandPolicyConfig, TargetConfig
    from proxmox_mcp.observability import ToolMetrics
    from proxmox_mcp.security.command_policy import CommandPolicyGate
    from proxmox_mcp.services.builtin_tool_plugins import CoreToolsPlugin, PBSToolsPlugin

    # Cover ProxmoxConfig/TargetConfig validators (including non-str service and PBS port default)
    pc = ProxmoxConfig(host="10.0.0.20", service="pbs")
    assert pc.service == "PBS" and pc.port == 8007
    with pytest.raises(ValidationError):
        ProxmoxConfig(host="10.0.0.20", service=123)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        TargetConfig(host="10.0.0.20", service=123, auth=AuthConfig(user="u", token_name="t", token_value="v"))  # type: ignore[arg-type]

    # Cover _wrap_async TypeError fallback for legacy stub registry
    class LegacyReg:
        def resolve(self, requested):
            return ResolvedTarget(
                name="default",
                config=ProxmoxConfig(host="10.0.0.10"),
                auth=AuthConfig(user="u", token_name="t", token_value="v"),
                kind="standalone",
                readonly=False,
            )

    async def fake_async_handler():
        return "ok"

    fake_srv_async = SimpleNamespace(
        target_registry=LegacyReg(),
        metrics=ToolMetrics(),
        target_command_policies={"default": CommandPolicyGate(CommandPolicyConfig())},
        target_toolsets={"default": SimpleNamespace(h=fake_async_handler)},
        target_tools=lambda _name: SimpleNamespace(h=fake_async_handler),
        logger=MagicMock(),
    )
    assert await RegistryPluginBase()._wrap_async(fake_srv_async, "get_nodes", lambda ts: ts.h)() == "ok"

    # Cover CoreToolsPlugin.list_targets PBS discover and all 7 PBSToolsPlugin wrappers
    registered = {}

    class FakeRegistry:
        def tool(self, **_kw):
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

    pbs_target = ResolvedTarget(
        name="pbs",
        config=ProxmoxConfig(host="10.0.0.20", service="PBS"),
        auth=AuthConfig(user="u@pbs", token_name="t", token_value="v"),
        kind="pbs",
        readonly=False,
    )
    mock_api = MagicMock()
    mock_api.admin.datastore.get.return_value = [{"store": "ds1"}]
    mock_api.admin.datastore("ds1").status.get.return_value = {"total": 100}
    mock_api.admin.datastore("ds1").verify.post.return_value = "UPID:v"
    mock_api.nodes("localhost").tasks.get.return_value = []
    mock_api.nodes("localhost").tasks("UPID:1").log.get.return_value = []
    mock_api.nodes("localhost").disks.list.get.return_value = []
    mock_api.nodes("localhost").disks.zfs.get.return_value = []
    mock_api.nodes("localhost").disks.zfs("rpool").scrub.put.return_value = "UPID:s"

    class RealLikeReg:
        def resolve(self, requested=None, *, expected_service=None):
            return pbs_target
        def describe(self, discover=None, allowed_names=None):
            return [discover(pbs_target)]

    pbs_srv = SimpleNamespace(
        tool_registry=FakeRegistry(),
        proxmox_managers={"pbs": MagicMock(get_api=MagicMock(return_value=mock_api))},
        target_registry=RealLikeReg(),
        config=SimpleNamespace(mcp=SimpleNamespace(client_permissions=None, transport="STDIO")),
        metrics=ToolMetrics(),
        target_command_policies={"pbs": CommandPolicyGate(CommandPolicyConfig())},
        target_toolsets={"pbs": SimpleNamespace(pbs_tools=PBSTools(mock_api))},
        target_tools=lambda _name: SimpleNamespace(pbs_tools=PBSTools(mock_api)),
        logger=MagicMock(),
    )
    CoreToolsPlugin().register(pbs_srv)
    PBSToolsPlugin().register(pbs_srv)

    assert registered["list_targets"]() == [{"reachable": True, "nodes": ["localhost"]}]
    assert registered["pbs_get_datastores"]()
    assert registered["pbs_get_tasks"]()
    assert registered["pbs_get_task_log"](upid="UPID:1")
    assert registered["pbs_get_disks"]()
    assert registered["pbs_get_zfs"]()
    assert registered["pbs_verify_datastore"](store="ds1")
    assert registered["pbs_scrub_zfs"](pool="rpool")
