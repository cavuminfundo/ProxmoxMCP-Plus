💡 **What:** Extracted fields directly from `nodes.get()` API response to fix N+1 query issue in `get_nodes()`.

🎯 **Why:** The `get_nodes` tool was making an individual `status.get()` API call for each node returned by `nodes.get()`. Since `nodes.get()` returns all the necessary fields (`status`, `uptime`, `maxcpu`, `mem`, `maxmem`), the inner API call inside the loop was redundant and causing significant N+1 slowdown as cluster size scaled.

📊 **Measured Improvement:** Measured with a mock Proxmox object simulating 100ms `nodes.get()` and 50ms `status.get()` calls.
- **Baseline (50 nodes):** 2.6225 seconds
- **Improved (50 nodes):** 0.1006 seconds
- **Change:** 96% reduction in latency for a 50 node cluster.
