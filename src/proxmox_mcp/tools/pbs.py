"""Proxmox Backup Server (PBS) management and inspection tools."""

from __future__ import annotations

import json
from typing import Any, List, Optional
from mcp.types import TextContent as Content
from proxmox_mcp.tools.base import ProxmoxTool


class PBSTools(ProxmoxTool):
    """Tools for interacting with Proxmox Backup Server endpoints."""

    def _json_fmt(self, data: Any) -> List[Content]:
        return [Content(type="text", text=json.dumps(data, indent=2, sort_keys=True))]

    def get_datastores(self) -> List[Content]:
        try:
            datastores = self.proxmox.admin.datastore.get()
            enriched = []
            if isinstance(datastores, list):
                for ds in datastores:
                    item = dict(ds) if isinstance(ds, dict) else {"store": ds}
                    store_name = item.get("store") or item.get("name")
                    if store_name:
                        try:
                            status = self.proxmox.admin.datastore(store_name).status.get()
                            item["status"] = status
                        except Exception:
                            pass
                    enriched.append(item)
            else:
                enriched = datastores
            return self._json_fmt(enriched)
        except Exception as e:
            self._handle_error("get datastores", e)

    def get_tasks(
        self,
        limit: int = 50,
        running_only: bool = False,
        store: Optional[str] = None,
    ) -> List[Content]:
        try:
            params: dict[str, Any] = {"limit": limit}
            if running_only:
                params["running"] = 1
            if store:
                params["store"] = store
            tasks = self.proxmox.nodes("localhost").tasks.get(**params)
            if isinstance(tasks, list):
                if running_only:
                    tasks = [t for t in tasks if not isinstance(t, dict) or (t.get("endtime") is None and t.get("status") != "stopped")]
                if store:
                    tasks = [t for t in tasks if not isinstance(t, dict) or "store" not in t or t.get("store") == store]
            return self._json_fmt(tasks)
        except Exception as e:
            self._handle_error("get tasks", e)

    def get_task_log(self, upid: str, start: int = 0, limit: int = 500) -> List[Content]:
        try:
            res = self.proxmox.nodes("localhost").tasks(upid).log.get(start=start, limit=limit)
            return self._json_fmt(res)
        except Exception as e:
            self._handle_error(f"get task log for '{upid}'", e)

    def get_disks(self) -> List[Content]:
        try:
            res = self.proxmox.nodes("localhost").disks.list.get()
            return self._json_fmt(res)
        except Exception as e:
            self._handle_error("get disks", e)

    def get_zfs(self, pool: Optional[str] = None) -> List[Content]:
        try:
            if pool:
                res = self.proxmox.nodes("localhost").disks.zfs(pool).get()
            else:
                res = self.proxmox.nodes("localhost").disks.zfs.get()
            return self._json_fmt(res)
        except Exception as e:
            self._handle_error("get zfs", e)

    def verify_datastore(
        self,
        store: str,
        ignore_verified: bool = True,
        outdated_after: Optional[int] = None,
        approval_token: Optional[str] = None,
    ) -> List[Content]:
        _ = approval_token
        try:
            params: dict[str, Any] = {"ignore-verified": ignore_verified}
            if outdated_after is not None:
                params["outdated-after"] = outdated_after
            raw = self.proxmox.admin.datastore(store).verify.post(**params)
            upid = raw.get("data") if isinstance(raw, dict) else raw
            if isinstance(upid, dict):
                upid = upid.get("upid", "")
            return self._json_fmt({
                "status": "started",
                "store": store,
                "upid": str(upid) if upid else "",
            })
        except Exception as e:
            self._handle_error(f"verify datastore '{store}'", e)

    def scrub_zfs(self, pool: str, approval_token: Optional[str] = None) -> List[Content]:
        _ = approval_token
        try:
            raw = None
            try:
                raw = self.proxmox.nodes("localhost").disks.zfs(pool).scrub.put()
            except (AttributeError, NotImplementedError):
                raw = self.proxmox.nodes("localhost").disks.zfs(pool).scrub.post()
            except Exception as exc:
                if "405" in str(exc) or "Method Not Allowed" in str(exc):
                    raw = self.proxmox.nodes("localhost").disks.zfs(pool).scrub.post()
                else:
                    raise
            upid = raw.get("data") if isinstance(raw, dict) else raw
            if isinstance(upid, dict):
                upid = upid.get("upid", "")
            return self._json_fmt({
                "status": "started",
                "pool": pool,
                "upid": str(upid) if upid else "",
            })
        except Exception as e:
            self._handle_error(f"scrub zfs pool '{pool}'", e)
