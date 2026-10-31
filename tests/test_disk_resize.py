"""Unit tests for resize_vm_disk and resize_container_disk domain methods and plugins."""

from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from proxmoxer.core import ResourceException

from mcp.types import TextContent as Content
from proxmox_mcp.tools.definitions import (
    RESIZE_CONTAINER_DISK_DESC,
    RESIZE_VM_DISK_DESC,
)
from proxmox_mcp.tools.vm import VMTools
from proxmox_mcp.tools.containers import ContainerTools
from proxmox_mcp.services.builtin_tool_plugins import (
    VMToolsPlugin,
    ContainerToolsPlugin,
)


@pytest.mark.parametrize("size", ["+10G", "10G", "10.5M", "+100", "500K", "2T"])
def test_resize_vm_disk_valid_sizes(size):
    api = Mock()
    api.nodes.return_value.qemu.return_value.resize.put.return_value = "UPID:pve:resize1"
    tool = VMTools(api)
    res = tool.resize_vm_disk("pve", "100", "scsi0", size)
    assert "Disk resize initiated." in res[0].text
    api.nodes("pve").qemu("100").resize.put.assert_called_once_with(disk="scsi0", size=size)


def test_resize_vm_disk_rejects_non_string_size():
    api = Mock()
    tool = VMTools(api)
    with pytest.raises(ValueError, match="Size must be a string"):
        tool.resize_vm_disk("pve", "100", "scsi0", 10)  # type: ignore[arg-type]
    api.nodes.return_value.qemu.return_value.resize.put.assert_not_called()


@pytest.mark.parametrize("size", ["-5G", "-10M", "-1", "-0.5G"])
def test_resize_vm_disk_rejects_negative_sizes(size):
    api = Mock()
    tool = VMTools(api)
    with pytest.raises(ValueError, match="Disk shrinking is not supported"):
        tool.resize_vm_disk("pve", "100", "scsi0", size)
    api.nodes.return_value.qemu.return_value.resize.put.assert_not_called()


@pytest.mark.parametrize("size", ["10GB", "abc", "", "+", "10G "])
def test_resize_vm_disk_rejects_malformed_sizes(size):
    api = Mock()
    tool = VMTools(api)
    with pytest.raises(ValueError, match="Invalid size format"):
        tool.resize_vm_disk("pve", "100", "scsi0", size)
    api.nodes.return_value.qemu.return_value.resize.put.assert_not_called()


@pytest.mark.parametrize("disk", ["scsi0", "virtio1", "sata2", "ide0", "scsi10"])
def test_resize_vm_disk_valid_disks(disk):
    api = Mock()
    api.nodes.return_value.qemu.return_value.resize.put.return_value = "UPID:pve:resize2"
    tool = VMTools(api)
    res = tool.resize_vm_disk("pve", "100", disk, "+5G")
    assert "Disk resize initiated." in res[0].text
    api.nodes("pve").qemu("100").resize.put.assert_called_once_with(disk=disk, size="+5G")


@pytest.mark.parametrize("disk", ["rootfs", "mp0", "scsi", "nvme0", "scsi0a", "ide"])
def test_resize_vm_disk_rejects_invalid_disks(disk):
    api = Mock()
    tool = VMTools(api)
    with pytest.raises(ValueError, match="Invalid VM disk identifier"):
        tool.resize_vm_disk("pve", "100", disk, "+5G")
    api.nodes.return_value.qemu.return_value.resize.put.assert_not_called()


@pytest.mark.parametrize("size", ["+5G", "20G", "1.5G", "+500M", "1T"])
def test_resize_container_disk_valid_sizes(size):
    api = Mock()
    api.nodes.return_value.lxc.return_value.resize.put.return_value = "UPID:pve:ctresize1"
    tool = ContainerTools(api)
    res = tool.resize_container_disk("pve", "101", size)
    assert "Disk resize initiated." in res[0].text
    api.nodes("pve").lxc("101").resize.put.assert_called_once_with(disk="rootfs", size=size)


def test_resize_container_disk_rejects_non_string_size():
    api = Mock()
    tool = ContainerTools(api)
    with pytest.raises(ValueError, match="Size must be a string"):
        tool.resize_container_disk("pve", "101", 10)  # type: ignore[arg-type]
    api.nodes.return_value.lxc.return_value.resize.put.assert_not_called()


@pytest.mark.parametrize("size", ["-5G", "-100M", "-1"])
def test_resize_container_disk_rejects_negative_sizes(size):
    api = Mock()
    tool = ContainerTools(api)
    with pytest.raises(ValueError, match="Disk shrinking is not supported"):
        tool.resize_container_disk("pve", "101", size)
    api.nodes.return_value.lxc.return_value.resize.put.assert_not_called()


@pytest.mark.parametrize("size", ["bad", "", "+", "5GiB"])
def test_resize_container_disk_rejects_malformed_sizes(size):
    api = Mock()
    tool = ContainerTools(api)
    with pytest.raises(ValueError, match="Invalid size format"):
        tool.resize_container_disk("pve", "101", size)
    api.nodes.return_value.lxc.return_value.resize.put.assert_not_called()


@pytest.mark.parametrize("disk", ["rootfs", "mp0", "mp1", "mp12"])
def test_resize_container_disk_valid_disks(disk):
    api = Mock()
    api.nodes.return_value.lxc.return_value.resize.put.return_value = "UPID:pve:ctresize2"
    tool = ContainerTools(api)
    res = tool.resize_container_disk("pve", "101", "+10G", disk=disk)
    assert "Disk resize initiated." in res[0].text
    api.nodes("pve").lxc("101").resize.put.assert_called_once_with(disk=disk, size="+10G")


@pytest.mark.parametrize("disk", ["scsi0", "virtio0", "mp", "rootfs0", "sda1"])
def test_resize_container_disk_rejects_invalid_disks(disk):
    api = Mock()
    tool = ContainerTools(api)
    with pytest.raises(ValueError, match="Invalid container disk identifier"):
        tool.resize_container_disk("pve", "101", "+10G", disk=disk)
    api.nodes.return_value.lxc.return_value.resize.put.assert_not_called()


def test_resize_vm_disk_success_with_job_and_digest():
    api = Mock()
    resize_mock = api.nodes.return_value.qemu.return_value.resize
    resize_mock.put.return_value = "UPID:pve:000123:resize"
    tasks_mock = api.nodes.return_value.tasks.return_value

    job_store = Mock()
    job_store.register_task.return_value = {"job_id": "job-vm-resize-1"}

    tool = VMTools(api, job_store=job_store)
    result = tool.resize_vm_disk("pve", "100", "scsi0", "+10G", digest="abc123digest")

    resize_mock.put.assert_called_once_with(disk="scsi0", size="+10G", digest="abc123digest")
    assert "Disk resize initiated." in result[0].text
    assert "Task ID: UPID:pve:000123:resize" in result[0].text
    assert "Job ID: job-vm-resize-1" in result[0].text

    job_store.register_task.assert_called_once()
    kwargs = job_store.register_task.call_args.kwargs
    assert kwargs["tool_name"] == "resize_vm_disk"
    assert kwargs["node"] == "pve"
    assert kwargs["upid"] == "UPID:pve:000123:resize"
    assert kwargs["retry_spec"] == {
        "kind": "vm.resize",
        "params": {"node": "pve", "vmid": "100", "disk": "scsi0", "size": "+10G"},
    }

    # Verify retry and cancel factories
    retry_factory = kwargs["retry_factory"]
    retry_factory()
    assert resize_mock.put.call_count == 2

    cancel_factory = kwargs["cancel_factory"]
    cancel_factory("UPID:pve:000123:resize")
    tasks_mock.delete.assert_called_once()


def test_resize_vm_disk_without_job_store():
    api = Mock()
    api.nodes.return_value.qemu.return_value.resize.put.return_value = "UPID:pve:000124:resize"

    tool = VMTools(api, job_store=None)
    result = tool.resize_vm_disk("pve", "100", "virtio0", "50G")

    assert "Disk resize initiated." in result[0].text
    assert "Task ID: UPID:pve:000124:resize" in result[0].text
    assert "Job ID: n/a" in result[0].text


def test_resize_container_disk_success_with_job_and_default_disk():
    api = Mock()
    resize_mock = api.nodes.return_value.lxc.return_value.resize
    resize_mock.put.return_value = "UPID:pve:000456:resize"
    tasks_mock = api.nodes.return_value.tasks.return_value

    job_store = Mock()
    job_store.register_task.return_value = {"job_id": "job-ct-resize-1"}

    tool = ContainerTools(api, job_store=job_store)
    result = tool.resize_container_disk("pve", "101", "+8G", digest="ctdigest789")

    resize_mock.put.assert_called_once_with(disk="rootfs", size="+8G", digest="ctdigest789")
    assert "Disk resize initiated." in result[0].text
    assert "Task ID: UPID:pve:000456:resize" in result[0].text
    assert "Job ID: job-ct-resize-1" in result[0].text

    job_store.register_task.assert_called_once()
    kwargs = job_store.register_task.call_args.kwargs
    assert kwargs["tool_name"] == "resize_container_disk"
    assert kwargs["node"] == "pve"
    assert kwargs["upid"] == "UPID:pve:000456:resize"
    assert kwargs["retry_spec"] == {
        "kind": "ct.resize",
        "params": {"node": "pve", "vmid": "101", "disk": "rootfs", "size": "+8G"},
    }

    # Verify retry and cancel factories
    retry_factory = kwargs["retry_factory"]
    retry_factory()
    assert resize_mock.put.call_count == 2

    cancel_factory = kwargs["cancel_factory"]
    cancel_factory("UPID:pve:000456:resize")
    tasks_mock.delete.assert_called_once()


def test_resize_container_disk_without_job_store():
    api = Mock()
    api.nodes.return_value.lxc.return_value.resize.put.return_value = "UPID:pve:000457:resize"

    tool = ContainerTools(api, job_store=None)
    result = tool.resize_container_disk("pve", "101", "+2G", disk="mp0")

    assert "Disk resize initiated." in result[0].text
    assert "Task ID: UPID:pve:000457:resize" in result[0].text
    assert "Job ID: n/a" in result[0].text


def test_resize_vm_disk_pve_exceptions():
    api = Mock()
    resize_mock = api.nodes.return_value.qemu.return_value.resize
    resize_mock.put.side_effect = ResourceException(500, "Internal Server Error", "storage backend error")

    tool = VMTools(api)
    with pytest.raises(RuntimeError, match=r"Failed to resize_vm_disk.*storage backend error"):
        tool.resize_vm_disk("pve", "100", "scsi0", "+10G")

    resize_mock.put.side_effect = Exception("VM 100 does not exist")
    with pytest.raises(ValueError, match=r"VM 100 not found on node pve"):
        tool.resize_vm_disk("pve", "100", "scsi0", "+10G")


def test_resize_container_disk_pve_exceptions():
    api = Mock()
    resize_mock = api.nodes.return_value.lxc.return_value.resize
    resize_mock.put.side_effect = ResourceException(500, "Internal Server Error", "out of space")

    tool = ContainerTools(api)
    with pytest.raises(RuntimeError, match=r"Failed to resize_container_disk.*out of space"):
        tool.resize_container_disk("pve", "101", "+5G")

    resize_mock.put.side_effect = Exception("Container 101 does not exist")
    with pytest.raises(ValueError, match=r"Container 101 not found on node pve"):
        tool.resize_container_disk("pve", "101", "+5G")


def test_plugin_registration():
    registered_tools = {}

    def register(name=None, description=None, annotations=None):
        def decorator(func):
            tool_name = name or func.__name__
            registered_tools[tool_name] = {"func": func, "description": description}
            return func
        return decorator

    mock_vm_tools = Mock()
    mock_vm_tools.resize_vm_disk.return_value = [Content(type="text", text="ok")]
    mock_container_tools = Mock()
    mock_container_tools.resize_container_disk.return_value = [Content(type="text", text="ok")]
    mock_toolset = SimpleNamespace(vm_tools=mock_vm_tools, container_tools=mock_container_tools)

    default_target = SimpleNamespace(name="default", readonly=False, ssh=None)
    target_reg = SimpleNamespace(
        names=("default",),
        resolve=lambda target: default_target,
    )
    server = SimpleNamespace(
        tool_registry=SimpleNamespace(tool=register),
        target_registry=target_reg,
        target_tools=lambda name="default": mock_toolset,
        proxmox_managers={"default": mock_toolset},
        target_command_policies={"default": SimpleNamespace(evaluate_operation=lambda *args, **kwargs: SimpleNamespace(code="OP_ALLOW", allowed=True))},
        config=SimpleNamespace(ssh=None),
        logger=Mock(),
        metrics=Mock(),
    )

    VMToolsPlugin().register(server)
    assert "resize_vm_disk" in registered_tools
    assert registered_tools["resize_vm_disk"]["description"] == RESIZE_VM_DISK_DESC
    res_vm = registered_tools["resize_vm_disk"]["func"](node="pve", vmid="100", disk="scsi0", size="+10G")
    assert res_vm[0].text == "ok"
    mock_vm_tools.resize_vm_disk.assert_called_once_with(node="pve", vmid="100", disk="scsi0", size="+10G", digest=None)

    ContainerToolsPlugin().register(server)
    assert "resize_container_disk" in registered_tools
    assert registered_tools["resize_container_disk"]["description"] == RESIZE_CONTAINER_DISK_DESC
    res_ct = registered_tools["resize_container_disk"]["func"](node="pve", vmid="100", size="+10G")
    assert res_ct[0].text == "ok"
    mock_container_tools.resize_container_disk.assert_called_once_with(node="pve", vmid="100", size="+10G", disk="rootfs", digest=None)

