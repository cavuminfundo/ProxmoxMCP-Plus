"""Named Proxmox target resolution and safe discovery metadata."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from typing import Any

from proxmox_mcp.config.models import Config, ProxmoxConfig, AuthConfig, TargetConfig
from proxmox_mcp.security.sanitization import sanitize_string


@dataclass(frozen=True)
class ResolvedTarget:
    name: str
    config: ProxmoxConfig
    auth: AuthConfig
    kind: str
    readonly: bool
    api_tunnel: Any | None = None
    ssh: Any | None = None
    command_policy: Any | None = None


class TargetRegistry:
    """Resolve legacy or named target configuration without guessing."""

    def __init__(self, config: Config):
        self.is_legacy = config.targets is None
        if config.targets is not None and (config.proxmox is not None or config.auth is not None):
            raise ValueError("Use either legacy proxmox/auth configuration or targets, not both")
        if not self.is_legacy:
            if not config.targets:
                raise ValueError("At least one Proxmox target must be configured")
            self._targets = {
                name: self._from_named(name, target)
                for name, target in config.targets.items()
            }
        elif config.proxmox is not None and config.auth is not None:
            self._targets = {"default": ResolvedTarget(
                name="default", config=config.proxmox, auth=config.auth,
                kind="standalone", readonly=False,
                api_tunnel=config.api_tunnel, ssh=config.ssh,
                command_policy=config.command_policy,
            )}
        else:
            raise ValueError("Proxmox configuration requires either targets or proxmox/auth")

    @staticmethod
    def _from_named(name: str, target: TargetConfig) -> ResolvedTarget:
        if not name.strip():
            raise ValueError("Proxmox target names cannot be empty")
        proxmox = ProxmoxConfig(
            host=target.host, port=target.port, timeout=target.timeout,
            verify_ssl=target.verify_ssl, service=target.service,
            session_pool_size=target.session_pool_size, session_pool_timeout=target.session_pool_timeout,
        )
        return ResolvedTarget(
            name=name, config=proxmox, auth=target.auth, kind=target.kind,
            readonly=target.readonly, api_tunnel=target.api_tunnel,
            ssh=target.ssh, command_policy=target.command_policy,
        )

    def resolve(self, requested: str | None = None, *, expected_service: str | None = None) -> ResolvedTarget:
        if requested is not None:
            try:
                target = self._targets[requested]
            except KeyError as exc:
                available = ", ".join(sorted(self._targets))
                raise ValueError(f"Unknown Proxmox target {requested!r}; available targets: {available}") from exc
            if expected_service is not None and target.config.service.upper() != expected_service.upper():
                raise ValueError(f"Target '{target.name}' is configured as {target.config.service}, not {expected_service}")
            return target

        if expected_service is not None:
            matching = [t for t in self._targets.values() if t.config.service.upper() == expected_service.upper()]
            if len(matching) == 1:
                return matching[0]
            if not matching:
                raise ValueError(f"No {expected_service} target is configured")
            available = ", ".join(sorted(t.name for t in matching))
            raise ValueError(f"Multiple {expected_service} targets are configured; specify target: {available}")

        if len(self._targets) == 1:
            return next(iter(self._targets.values()))
        available = ", ".join(sorted(self._targets))
        raise ValueError(f"Multiple Proxmox targets are configured; specify target: {available}")

    def describe(
        self,
        discover: Callable[[ResolvedTarget], dict[str, Any]] | None = None,
        allowed_names: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        descriptions = []
        for target in sorted(self._targets.values(), key=lambda item: item.name):
            if allowed_names is not None and target.name not in allowed_names:
                continue
            item = {
                "name": target.name,
                "kind": target.kind,
                "host": sanitize_string(target.config.host),
                "port": target.config.port,
                "readonly": target.readonly,
            }
            if discover is not None:
                try:
                    discovery = discover(target)
                    item.update({
                        "reachable": bool(discovery.get("reachable", False)),
                        "nodes": list(discovery.get("nodes", [])),
                    })
                except Exception:
                    item.update({
                        "reachable": False,
                        "nodes": [],
                        "error": f"Unable to reach target '{target.name}'",
                    })
            descriptions.append(item)
        return descriptions

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._targets))
