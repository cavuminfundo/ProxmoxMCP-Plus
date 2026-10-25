"""Tests for NodeTools custom methods and zero-N+1 get_nodes optimization."""
from unittest.mock import MagicMock
import pytest
from proxmox_mcp.tools.node import NodeTools


@pytest.fixture
def mock_api():
    api = MagicMock()
    return api


def test_list_bridges_success_and_error(mock_api):
    mock_api.nodes.return_value.network.get.return_value = [{"iface": "vmbr0"}]
    tools = NodeTools(mock_api)
    result = tools.list_bridges("node1")
    assert "vmbr0" in result[0].text

    mock_api.nodes.return_value.network.get.side_effect = RuntimeError("network failed")
    with pytest.raises(RuntimeError):
        tools.list_bridges("node1")


def test_get_apt_updates(mock_api):
    updates_payload = [
        {"package": "pve-manager", "title": "PVE Manager", "version": "8.2.4", "old_version": "8.2.2"}
    ]
    mock_api.nodes.return_value.apt.update.get.return_value = updates_payload
    tools = NodeTools(mock_api)
    result = tools.get_apt_updates("node1")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.apt.update.get.assert_called_once()
    assert "pve-manager" in result[0].text

    mock_api.nodes.return_value.apt.update.get.side_effect = RuntimeError("apt update failed")
    with pytest.raises(RuntimeError):
        tools.get_apt_updates("node1")


def test_refresh_apt_repositories(mock_api):
    mock_api.nodes.return_value.apt.update.post.return_value = "UPID:node1:00001234:00005678:aptupdate"
    tools = NodeTools(mock_api)
    result = tools.refresh_apt_repositories("node1")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.apt.update.post.assert_called_once()
    assert "UPID:node1" in result[0].text

    mock_api.nodes.return_value.apt.update.post.side_effect = RuntimeError("refresh failed")
    with pytest.raises(RuntimeError):
        tools.refresh_apt_repositories("node1")


def test_upgrade_apt_packages(mock_api):
    mock_api.nodes.return_value.apt.upgrade.post.return_value = "UPID:node1:00001234:00005678:aptupgrade"
    tools = NodeTools(mock_api)
    result = tools.upgrade_apt_packages("node1")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.apt.upgrade.post.assert_called_once()
    assert "UPID:node1" in result[0].text

    mock_api.nodes.return_value.apt.upgrade.post.side_effect = RuntimeError("upgrade failed")
    with pytest.raises(RuntimeError):
        tools.upgrade_apt_packages("node1")


def test_get_node_disks(mock_api):
    disks_payload = [
        {"devpath": "/dev/sda", "size": 512110190592, "health": "PASSED", "model": "TestDisk"}
    ]
    mock_api.nodes.return_value.disks.list.get.return_value = disks_payload
    tools = NodeTools(mock_api)
    result = tools.get_node_disks("node1")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.disks.list.get.assert_called_once()
    assert "/dev/sda" in result[0].text

    mock_api.nodes.return_value.disks.list.get.side_effect = RuntimeError("disks failed")
    with pytest.raises(RuntimeError):
        tools.get_node_disks("node1")


def test_get_smart_status(mock_api):
    smart_payload = {
        "health": "PASSED",
        "attributes": [{"id": 1, "name": "Raw_Read_Error_Rate", "value": 100}]
    }
    mock_api.nodes.return_value.disks.smart.get.return_value = smart_payload
    tools = NodeTools(mock_api)
    result = tools.get_smart_status("node1", "/dev/sda")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.disks.smart.get.assert_called_once_with(disk="/dev/sda")
    assert "PASSED" in result[0].text

    mock_api.nodes.return_value.disks.smart.get.side_effect = RuntimeError("smart failed")
    with pytest.raises(RuntimeError):
        tools.get_smart_status("node1", "/dev/sda")


def test_get_node_journal(mock_api):
    journal_payload = ["Oct 25 09:00:00 node1 systemd[1]: Started Proxmox VE."]
    mock_api.nodes.return_value.journal.get.return_value = journal_payload
    tools = NodeTools(mock_api)
    result = tools.get_node_journal("node1", last_lines=100)
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.journal.get.assert_called_once_with(last_lines=100)
    assert "Started Proxmox VE" in result[0].text

    mock_api.nodes.return_value.journal.get.side_effect = RuntimeError("journal failed")
    with pytest.raises(RuntimeError):
        tools.get_node_journal("node1", last_lines=100)


def test_get_node_services(mock_api):
    services_payload = [
        {"service": "pveproxy", "state": "running", "desc": "PVE API Proxy Server"}
    ]
    mock_api.nodes.return_value.services.get.return_value = services_payload
    tools = NodeTools(mock_api)
    result = tools.get_node_services("node1")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.services.get.assert_called_once()
    assert "pveproxy" in result[0].text

    mock_api.nodes.return_value.services.get.side_effect = RuntimeError("services failed")
    with pytest.raises(RuntimeError):
        tools.get_node_services("node1")


def test_restart_node_service(mock_api):
    mock_api.nodes.return_value.services.return_value.restart.post.return_value = "OK"
    tools = NodeTools(mock_api)
    result = tools.restart_node_service("node1", "pveproxy")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.services.assert_called_with("pveproxy")
    mock_api.nodes.return_value.services.return_value.restart.post.assert_called_once()
    assert "pveproxy" in result[0].text

    mock_api.nodes.return_value.services.return_value.restart.post.side_effect = RuntimeError("restart failed")
    with pytest.raises(RuntimeError):
        tools.restart_node_service("node1", "pveproxy")


def test_get_node_network(mock_api):
    network_payload = [
        {"iface": "vmbr0", "type": "bridge", "address": "192.0.2.10", "netmask": "24", "active": 1}
    ]
    mock_api.nodes.return_value.network.get.return_value = network_payload
    tools = NodeTools(mock_api)
    result = tools.get_node_network("pve-test")
    assert len(result) == 1
    mock_api.nodes.assert_called_with("pve-test")
    mock_api.nodes.return_value.network.get.assert_called_once()
    assert "192.0.2.10" in result[0].text

    mock_api.nodes.return_value.network.get.side_effect = RuntimeError("network failed")
    with pytest.raises(RuntimeError):
        tools.get_node_network("pve-test")


def test_get_node_tasks(mock_api):
    tasks_payload = [
        {"upid": "UPID:node1:00001:00001:task", "type": "aptupdate", "status": "OK", "user": "root@pam"}
    ]
    mock_api.nodes.return_value.tasks.get.return_value = tasks_payload
    tools = NodeTools(mock_api)
    result = tools.get_node_tasks("node1", limit=50)
    assert len(result) == 1
    mock_api.nodes.assert_called_with("node1")
    mock_api.nodes.return_value.tasks.get.assert_called_once_with(limit=50)
    assert "UPID:node1" in result[0].text

    mock_api.nodes.return_value.tasks.get.side_effect = RuntimeError("tasks failed")
    with pytest.raises(RuntimeError):
        tools.get_node_tasks("node1", limit=50)


def test_get_nodes_zero_n_plus_one(mock_api):
    """Zero-N+1: When cluster node payload already contains uptime/maxcpu/mem/maxmem, status.get() must not be called."""
    node_payload = [
        {
            "node": "pve-test",
            "type": "node",
            "status": "online",
            "uptime": 86400,
            "maxcpu": 8,
            "mem": 16000000000,
            "maxmem": 32000000000,
        }
    ]
    mock_api.nodes.get.return_value = node_payload

    tools = NodeTools(mock_api)
    result = tools.get_nodes()
    assert len(result) == 1
    assert "pve-test" in result[0].text

    # Verify zero-N+1: status.get() was NOT called on individual node
    mock_api.nodes.return_value.status.get.assert_not_called()

    # Verify caching path returns cached result without refetching
    cached_result = tools.get_nodes()
    assert len(cached_result) == 1
    mock_api.nodes.get.assert_called_once()


def test_get_nodes_fallback_and_error(mock_api):
    """Test get_nodes when node lacks metrics (fetches status.get) and error handling."""
    mock_api.nodes.get.return_value = [
        {"node": "node1", "status": "online"}
    ]
    mock_api.nodes.return_value.status.get.return_value = {
        "status": "online",
        "uptime": 120,
        "cpuinfo": {"cpus": 4},
        "memory": {"used": 1024, "total": 4096},
    }
    tools = NodeTools(mock_api)
    res = tools.get_nodes()
    assert "node1" in res[0].text

    # Test status.get failure fallback
    tools._cache.clear()
    mock_api.nodes.return_value.status.get.side_effect = RuntimeError("status error")
    res2 = tools.get_nodes()
    assert "node1" in res2[0].text

    # Test nodes.get API failure
    tools._cache.clear()
    mock_api.nodes.get.side_effect = RuntimeError("nodes error")
    with pytest.raises(RuntimeError):
        tools.get_nodes()


def test_get_node_status_offline_fallback(mock_api):
    mock_api.nodes.return_value.status.get.side_effect = RuntimeError("node is unreachable")
    mock_api.nodes.get.return_value = [{"node": "node1", "status": "offline", "mem": 100, "maxmem": 200}]
    tools = NodeTools(mock_api)
    result = tools.get_node_status("node1")
    assert "OFFLINE" in result[0].text
