## ⚡ Performance Optimization: Concurrent VM and Container Lookup

### 💡 What
Modified `get_containers` and `get_vms` functions (in `src/proxmox_mcp/tools/containers.py` and `src/proxmox_mcp/tools/vm.py`) to fetch node resources concurrently rather than sequentially during fallback node-scans. When `proxmox.cluster.resources.get` is unavailable or yields incomplete results, the tools now use `concurrent.futures.ThreadPoolExecutor` to perform the node-by-node inventory lookups in parallel.

### 🎯 Why
The fallback mechanism originally performed an $O(N)$ sequential loop over every node in the cluster, querying `proxmox.nodes(node_name).lxc.get()` and `proxmox.nodes(node_name).qemu.get()`. In a multi-node cluster with network latency, these synchronous requests can take a significant amount of time. Concurrency allows the MCP plugin to fetch the necessary information almost as fast as a single node lookup.

### 📊 Measured Improvement
A simulated benchmark script with 10 nodes and a 0.1s network latency for the API call showed an improvement from **1.00s (Sequential)** down to **0.11s (Concurrent)**. This is a near 9x performance improvement for clusters with 10 nodes. Real-world clusters with slower network paths or higher numbers of nodes will see even more substantial speedups.
