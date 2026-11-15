# Design Spec: Supporto PBS (8007), parametro `balloon` in `update_vm_config` e hardening `command_policy`

**Data:** 2026-11-15
**Workspace:** `/home/federico/ProxmoxMCP-Plus`
**Runtime target:** Docker (`ghcr.io/cavuminfundo/proxmoxmcp-plus:latest`, `/opt/stacks/proxmox-mcp/compose.yaml` + `/opt/stacks/proxmox-mcp/config-cluster.json`)
**Classificazione:** Architectural

---

## 1. Obiettivi

1. **Supporto Proxmox Backup Server (PBS) su porta 8007:** aggiungere il supporto nativo a target `PBS` con tool dedicati per lettura (`datastore`, `task`, `task log`, `dischi`, `ZFS`) e manutenzioni non distruttive (`verify` datastore, `scrub` ZFS), mantenendo bloccate le azioni distruttive (`delete_datastore`, `forget`, `prune`, `gc`, `wipe_disk`, `zpool destroy`).
2. **Parametro `balloon` in `update_vm_config`:** esporre `balloon` nella signature del tool e del wrapper FastMCP per consentire la riduzione simultanea di `memory` e `balloon` evitando l'errore PVE `balloon value too large`.
3. **Ampliamento controllato `command_policy.allow_patterns`:** abilitare diagnostica e manutenzioni sicure (`zpool`, `smartctl`, `zramctl`, `sysctl` read-only, `apt`/`apt-get`/`apt-cache`) con hardening anti-injection/chaining e blocco esplicito dei sottocomandi distruttivi.

---

## 2. Architettura & Modelli

### 2.1 Supporto Target PBS (`config/models.py`, `core/targets.py`, `core/proxmox.py`, `server.py`)

- **`ProxmoxConfig` e `TargetConfig`** (`src/proxmox_mcp/config/models.py`):
  - Estendere `kind` in `TargetConfig` a `Literal["cluster", "standalone", "pbs"]`.
  - Supportare `service: Literal["PVE", "PBS"] = "PVE"` (normalizzato uppercase) con un `model_validator` che imposta `port = 8007` quando `service == "PBS"` e `port` non è esplicitamente specificata (mantenendo `8006` come default per `PVE`).
- **`ProxmoxManager`** (`src/proxmox_mcp/core/proxmox.py`):
  - Passare `service=self.config.service` a `proxmoxer.ProxmoxAPI(...)`.
  - `proxmoxer.backends.https.SERVICES["PBS"]` gestisce nativamente `default_port=8007` e `token_separator=':'` (formato `PBSAPIToken=user@pbs!tokenid:secret`).
- **Isolamento PVE ↔ PBS** (`src/proxmox_mcp/core/targets.py`, `src/proxmox_mcp/server.py`):
  - `TargetRegistry` espone un helper `resolve_for_service(requested, expected_service)` (o filtro analogo) che:
    - rifiuta target `PBS` quando viene invocato un tool `PVE`, restituendo un errore esplicito;
    - rifiuta target `PVE` quando viene invocato un tool `pbs_*`;
    - se `target` è omesso su un tool `pbs_*` ed esiste un solo target `PBS` configurato, lo seleziona automaticamente (anche in presenza di più target PVE).
  - Su target `PBS`, `ProxmoxMCPServer` non inizializza toolset PVE non applicabili o ne blocca il dispatch con errore chiaro prima di qualsiasi chiamata API.

### 2.2 Toolset `PBSTools` (`src/proxmox_mcp/tools/pbs.py` + `services/builtin_tool_plugins.py` + `tools/definitions.py`)

Tutti i tool PBS accettano `target: Optional[str] = None` e rispettano `target.readonly`.

**Tool in sola lettura:**
- `pbs_get_datastores(target=None)`: interroga `GET /admin/datastore` e arricchisce ciascun datastore con `GET /admin/datastore/{store}/status` (spazio totale/usato/disponibile, gc-status).
- `pbs_get_tasks(target=None, limit=50, running_only=False, store=None)`: interroga `GET /nodes/localhost/tasks` (con filtri client/query supportati dall'API PBS).
- `pbs_get_task_log(upid, target=None, start=0, limit=500)`: interroga `GET /nodes/localhost/tasks/{upid}/log` e restituisce le righe di log formattate.
- `pbs_get_disks(target=None)`: interroga `GET /nodes/localhost/disks/list`.
- `pbs_get_zfs(target=None, pool=None)`: interroga `GET /nodes/localhost/disks/zfs` (o `/nodes/localhost/disks/zfs/{pool}` se `pool` è specificato).

**Tool di manutenzione sicura (non distruttivi, bloccati se `readonly=True`):**
- `pbs_verify_datastore(store, target=None, ignore_verified=True, outdated_after=None)`: esegue `POST /admin/datastore/{store}/verify` e restituisce l'UPID del task avviato.
- `pbs_scrub_zfs(pool, target=None)`: avvia lo scrub ZFS sul pool indicato (`PUT /nodes/localhost/disks/zfs/{pool}/scrub` / `POST` secondo specifica API PBS verificata in implementazione) e restituisce l'UPID.

**Guardrail azioni distruttive:**
- Nessun tool viene esposto per `delete_datastore`, `forget`, `prune`, `gc`, `wipe_disk`, `zpool destroy` o modifica utenti/token PBS.
- `pbs_verify_datastore` e `pbs_scrub_zfs` vengono registrati in `high_risk_operations` di `CommandPolicyConfig` così da rispettare anche `high_risk_mode` / `require_approval_token` se configurati.

---

## 3. Parametro `balloon` in `update_vm_config`

- **File coinvolti:**
  - `src/proxmox_mcp/tools/vm.py` (`VMTools.update_vm_config`)
  - `src/proxmox_mcp/services/builtin_tool_plugins.py` (`VMToolsPlugin._register_vm_config_tools`)
  - `src/proxmox_mcp/tools/definitions.py` (`UPDATE_VM_CONFIG_DESC`)
- **Contratto e validazione:**
  - Aggiungere `balloon: Optional[int] = None`.
  - Se `balloon is not None`:
    - `if balloon < 0: raise ValueError("balloon must be >= 0 (0 disables ballooning)")`
    - `if memory is not None and balloon > memory: raise ValueError("balloon cannot exceed memory")`
    - `payload["balloon"] = int(balloon)`
  - Includere `"balloon"` nel controllo per la nota *pending restart* (`{"memory", "balloon", "cores", "sockets"} & payload.keys()`).

---

## 4. Ampliamento controllato e Hardening `command_policy`

### 4.1 Hardening `CommandPolicyGate` (`src/proxmox_mcp/security/command_policy.py`)

- **Blocco metacaratteri / shell chaining:** prima o dentro `evaluate()`, rifiutare comandi contenenti operatori di concatenazione/subshell/redirezione (`;`, `&&`, `||`, `|`, `` ` ``, `$(`, `>`, `<`, newline `\n`/`\r`), così che un pattern consentito non possa mai essere usato come prefisso per eseguire comandi arbitrari nemmeno quando `full_match_allow_patterns=False` (LXC/VM).
- **Nuovi `deny_patterns` di default** (`src/proxmox_mcp/config/models.py`):
  - `r"(^|\s)rm\s+-rf(\s|$)"`
  - `r":\(\)\{:\|:\&\};:"`
  - `r"(^|\s)apt(-get)?\s+(remove|purge|autoremove|dpkg)(\s|$)"`
  - `r"(^|\s)zpool\s+(destroy|create|export|offline|detach|remove|labelclear|reguid|split)(\s|$)"`
  - `r"(^|\s)zpool\s+scrub\s+-s(\s|$)"`
  - `r"(^|\s)sysctl\s+(-w|--write|--system|-p)(\s|=|$)"`
  - `r"(^|\s)zramctl\s+.*(--reset|--size|-r|-s)(\s|=|$)"`

### 4.2 Nuovi `allow_patterns` di default (`src/proxmox_mcp/config/models.py` & `config/loader.py`)

Oltre ai 10 pattern esistenti (`lsblk`, `df`, `growpart`, `resize2fs`, `xfs_growfs`, `systemctl`, `ip`, `ss`, `findmnt`, `parted`), aggiungere:
- `zpool`:
  - `r"^zpool\s+(status|list|iostat|get)(\s|$)"`
  - `r"^zpool\s+scrub\s+[A-Za-z0-9_.-]+$"`
- `smartctl`:
  - `r"^smartctl\s+(-[aHiIl]|--scan|--info|--health|--all|--json|-j)(\s|$)"`
- `zramctl`:
  - `r"^zramctl(\s+(--output|--bytes|--raw|--noheadings|--json|-[onbrj])([=\s][A-Za-z0-9_,.:/-]+)?)*$"`
- `sysctl` (sola lettura):
  - `r"^sysctl(\s+(-[anN]|--all|--names|--values))*(\s+[A-Za-z0-9_./-]+)*$"`
- `apt` / `apt-get` / `apt-cache`:
  - `r"^apt(-get)?\s+(update|list|show|policy|upgrade|dist-upgrade|full-upgrade|check)(\s|$)"`
  - `r"^apt-cache\s+(policy|show|search|madison|depends|rdepends)(\s|$)"`

In `src/proxmox_mcp/config/loader.py` (riga ~166), quando `COMMAND_POLICY_ALLOW_PATTERNS` non è valorizzata nelle variabili d'ambiente, preservare i default di `CommandPolicyConfig` invece di sovrascriverli con `[]`.

---

## 5. Impatto Docker & Strategia di Test

- **Runtime Docker (`romm`):** nessuna modifica obbligatoria a `/opt/stacks/proxmox-mcp/compose.yaml`. Dopo il rilascio dell'immagine, sarà sufficiente aggiungere in `/opt/stacks/proxmox-mcp/config-cluster.json` il target `"pbs"` con `"service": "PBS"`, `"port": 8007`, `"kind": "pbs"` e credenziali API PBS.
- **Test `pytest`:**
  - `tests/test_pbs_tools.py`: mock `ProxmoxAPI` per tutti i tool `pbs_*` (datastore, task, task log, disks, zfs, verify, scrub), enforcement `readonly=True`, isolamento target PVE ↔ PBS, auto-risoluzione singolo target PBS.
  - `tests/test_guest_configuration.py` (o test dedicato): `update_vm_config` con `balloon=0`, `balloon <= memory`, `balloon < 0` (errore), `balloon > memory` (errore).
  - `tests/test_command_policy.py`: nuovi comandi ammessi, sottocomandi distruttivi bloccati (`zpool destroy`, `apt remove`, `sysctl -w`, `zramctl --reset`) e tentativi di shell chaining/injection (`;`, `&&`, `|`, `$()`).
