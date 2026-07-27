"""
Node-related tools for Proxmox MCP.

This module provides tools for managing and monitoring Proxmox nodes:
- Listing all nodes in the cluster with their status
- Getting detailed node information including:
  * CPU usage and configuration
  * Memory utilization
  * Uptime statistics
  * Health status

The tools handle both basic and detailed node information retrieval,
with fallback mechanisms for partial data availability.
"""
from typing import List
from mcp.types import TextContent as Content
from proxmox_mcp.tools.base import ProxmoxTool

class NodeTools(ProxmoxTool):
    """Tools for managing Proxmox nodes.
    
    Provides functionality for:
    - Retrieving cluster-wide node information
    - Getting detailed status for specific nodes
    - Monitoring node health and resources
    - Handling node-specific API operations
    
    Implements fallback mechanisms for scenarios where detailed
    node information might be temporarily unavailable.
    """

    def get_nodes(self) -> List[Content]:
        """List all nodes in the Proxmox cluster with detailed status.

        Retrieves comprehensive information for each node including:
        - Basic status (online/offline)
        - Uptime statistics
        - CPU configuration and count
        - Memory usage and capacity
        
        Implements a fallback mechanism that returns basic information
        if detailed status retrieval fails for any node.

        Returns:
            List of Content objects containing formatted node information:
            {
                "node": "node_name",
                "status": "online/offline",
                "uptime": seconds,
                "maxcpu": cpu_count,
                "memory": {
                    "used": bytes,
                    "total": bytes
                }
            }

        Raises:
            RuntimeError: If the cluster-wide node query fails
        """
        cached = self._cache_get("nodes:list")
        if cached is not None:
            return self._format_response(cached, "nodes")

        try:
            result = self._call_with_retry("get nodes", lambda: self.proxmox.nodes.get())
            nodes = []
            
            # Extract necessary information directly from the cluster-wide nodes query
            for node in result:
                nodes.append({
                    "node": node["node"],
                    "status": node.get("status", "unknown"),
                    "uptime": node.get("uptime", 0),
                    "maxcpu": node.get("maxcpu", "N/A"),
                    "memory": {
                        "used": node.get("mem", 0),
                        "total": node.get("maxmem", 0)
                    }
                })
            self._cache_set("nodes:list", nodes, ttl_seconds=5)
            return self._format_response(nodes, "nodes")
        except Exception as e:
            self._handle_error("get nodes", e)

    def get_node_status(self, node: str) -> List[Content]:
        """Get detailed status information for a specific node.

        Retrieves comprehensive status information including:
        - CPU usage and configuration
        - Memory utilization details
        - Uptime and load statistics
        - Network status
        - Storage health
        - Running tasks and services

        Args:
            node: Name/ID of node to query (e.g., 'pve1', 'proxmox-node2')

        Returns:
            List of Content objects containing detailed node status:
            {
                "uptime": seconds,
                "cpu": {
                    "usage": percentage,
                    "cores": count
                },
                "memory": {
                    "used": bytes,
                    "total": bytes,
                    "free": bytes
                },
                ...additional status fields
            }

        Raises:
            ValueError: If the specified node is not found
            RuntimeError: If status retrieval fails (node offline, network issues)
        """
        try:
            result = self.proxmox.nodes(node).status.get()
            # The Proxmox /nodes/{node}/status endpoint does NOT include a
            # `status` field in its response (that field only exists in the
            # /nodes list endpoint). A successful response here is itself
            # proof the node is reachable, so we inject "online" to keep the
            # formatter from always rendering "UNKNOWN".
            if "status" not in result:
                result["status"] = "online"
            return self._format_response((node, result), "node_status")
        except Exception as e:
            try:
                nodes = self.proxmox.nodes.get()
            except Exception:
                self._handle_error(f"get status for node {node}", e)

            for entry in nodes:
                if entry.get("node") != node:
                    continue
                if entry.get("status") == "offline":
                    self.logger.warning(
                        "Using offline status for node %s due to status error: %s",
                        node,
                        e,
                    )
                    fallback = {
                        "status": "offline",
                        "uptime": 0,
                        "maxcpu": "N/A",
                        "memory": {
                            "used": entry.get("mem", 0),
                            "total": entry.get("maxmem", 0),
                        },
                    }
                    return self._format_response((node, fallback), "node_status")
                break

            self._handle_error(f"get status for node {node}", e)

    def get_apt_updates(self, node: str) -> List[Content]:
        """Get list of available APT package updates for a specific node.

        Args:
            node: Name/ID of node to query (e.g. 'proxmox1')

        Returns:
            List of Content objects containing available APT package updates.
        """
        try:
            updates = self.proxmox.nodes(node).apt.update.get()
            return self._format_response((node, updates), "apt_updates")
        except Exception as e:
            self._handle_error(f"get APT updates for node {node}", e)

    def refresh_apt_repositories(self, node: str) -> List[Content]:
        """Trigger an APT package repository refresh (apt-get update) on a node.

        Args:
            node: Name/ID of node to query (e.g. 'proxmox1')

        Returns:
            List of Content objects containing task UPID or status.
        """
        try:
            upid = self.proxmox.nodes(node).apt.update.post()
            return self._format_response({"node": node, "status": "task_started", "upid": upid}, "apt_refresh")
        except Exception as e:
            self._handle_error(f"refresh APT repositories for node {node}", e)

    def upgrade_apt_packages(self, node: str) -> List[Content]:
        """Trigger an APT package upgrade via Proxmox API on a node.

        Args:
            node: Name/ID of node to upgrade (e.g. 'proxmox1')

        Returns:
            List of Content objects containing task UPID or status.
        """
        try:
            upid = self.proxmox.nodes(node).apt.upgrade.post()
            return self._format_response({"node": node, "status": "task_started", "upid": upid}, "apt_upgrade")
        except Exception as e:
            self._handle_error(f"upgrade APT packages for node {node}", e)

    def get_node_disks(self, node: str) -> List[Content]:
        """List physical disks, partitions, and health info on a Proxmox node."""
        try:
            disks = self.proxmox.nodes(node).disks.list.get()
            return self._format_response((node, disks), "node_disks")
        except Exception as e:
            self._handle_error(f"get disks for node {node}", e)

    def get_smart_status(self, node: str, disk: str) -> List[Content]:
        """Get SMART attributes, health status, and wearout info for a specific disk."""
        try:
            smart = self.proxmox.nodes(node).disks.smart.get(disk=disk)
            return self._format_response((node, disk, smart), "smart_status")
        except Exception as e:
            self._handle_error(f"get SMART status for disk {disk} on node {node}", e)

    def get_node_journal(self, node: str, last_lines: int = 100) -> List[Content]:
        """Get recent systemd journal logs from a Proxmox node."""
        try:
            journal = self.proxmox.nodes(node).journal.get(last_lines=last_lines)
            return self._format_response((node, journal), "node_journal")
        except Exception as e:
            self._handle_error(f"get journal logs for node {node}", e)

    def get_node_services(self, node: str) -> List[Content]:
        """List systemd services and their running status on a Proxmox node."""
        try:
            services = self.proxmox.nodes(node).services.get()
            return self._format_response((node, services), "node_services")
        except Exception as e:
            self._handle_error(f"get services for node {node}", e)

    def restart_node_service(self, node: str, service: str) -> List[Content]:
        """Restart a specific systemd service on a Proxmox node."""
        try:
            res = self.proxmox.nodes(node).services(service).restart.post()
            return self._format_response({"node": node, "service": service, "status": "restarted", "result": res}, "node_service_restart")
        except Exception as e:
            self._handle_error(f"restart service {service} on node {node}", e)

    def get_node_network(self, node: str) -> List[Content]:
        """Get network interfaces configuration and status on a Proxmox node."""
        try:
            net = self.proxmox.nodes(node).network.get()
            return self._format_response((node, net), "node_network")
        except Exception as e:
            self._handle_error(f"get network for node {node}", e)

    def get_node_tasks(self, node: str, limit: int = 50) -> List[Content]:
        """Get history of active and recent tasks on a Proxmox node."""
        try:
            tasks = self.proxmox.nodes(node).tasks.get(limit=limit)
            return self._format_response((node, tasks), "node_tasks")
        except Exception as e:
            self._handle_error(f"get tasks for node {node}", e)
