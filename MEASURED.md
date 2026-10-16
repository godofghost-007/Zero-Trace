# MEASURED.md — Phase 0 evidence register

Every number in this file was produced by a command on this machine on **2026-10-17**, unless a row says otherwise.
Nothing here is copied from the specification. Where the spec claims a figure, it is labelled `[source]` and listed under "Claims not yet verified".

Reproduce with the commands in the last section. Scratch space: `C:\Users\aniru\AppData\Local\Temp\opencode`.

---

## 1. Host

| Item | Measured value | Command |
|---|---|---|
| OS | Microsoft Windows 11 Home Single Language, build **26300**, 64-bit | `Get-CimInstance Win32_OperatingSystem` |
| Host | Dell Inc. **Inspiron 3593** | `Get-CimInstance Win32_ComputerSystem` |
| CPU | Intel **Core i3-1005G1** @ 1.20 GHz | `Get-CimInstance Win32_Processor` |
| Cores | **2 physical / 4 logical** | same |
| RAM (total) | **19.77 GB** | `Win32_ComputerSystem.TotalPhysicalMemory` |
| GPU | Intel **UHD Graphics** (integrated only, no dedicated VRAM) | `Win32_VideoController` |
| Pagefile | `C:\pagefile.sys`, 6.2 GB allocated | `Win32_PageFileUsage` |
| Shell | `C:\WINDOWS\system32\cmd.exe` | `$env:ComSpec` |
| PowerShell | 5.1.26100.9711 (Desktop edition) | `$PSVersionTable` |

## 2. Disk

| Volume | Free | Note |
|---|---:|---|
| **E:** (project) | **96.9 GB** | repo root `E:\zerotrace-demo` |
| C: (system, LM Studio models, Docker/WSL) | **15.6 GB** | crowded — this is why the project lives on E: |
| D: | 358.9 GB | not used |
| F: | 204.4 GB | source notes (`F:\vertual.kali`) |

## 3. Toolchain

| Tool | State | Detail |
|---|---|---|
| `git` | ✅ **2.49.0** | `C:\Program Files\Git\cmd\git.exe`; global identity `godofghost-007` |
| `docker` | ⚠️ **29.4.3** installed, **daemon stopped** | `com.docker.service` = Stopped; `npipe:////./pipe/dockerDesktopLinuxEngine` unreachable |
| `docker-compose` | ✅ present | `C:\Program Files\Docker\Docker\resources\bin\docker-compose.exe` |
| WSL2 | ✅ installed, **both distros Stopped** | `Ubuntu` (default), `docker-desktop` |
| `node` / `npm` | ✅ present | `C:\Program Files\nodejs\` |
| `py` launcher | ✅ **3.13** (default) | `C:\Users\aniru\AppData\Local\Programs\Python\Python313\python.exe` |
| uv-managed Python | ✅ **3.14.3** | `%APPDATA%\uv\python\cpython-3.14.3-...` |
| **`python` on PATH** | ❌ **BROKEN** | resolves to the Microsoft Store alias `...\WindowsApps\python.exe` → *"Python was not found"* |
| **`pip` on PATH** | ❌ **BROKEN** | points at `C:\Program Files\Python312\Scripts\pip.exe`, but that install has **no `python.exe`** (partial removal) |
| `curl` | ✅ via `curl.exe` only | the PowerShell `curl` alias is `Invoke-WebRequest` and does **not** accept curl flags |

**Decision required (Phase 2):** the project needs one canonical interpreter. Recommended: **Python 3.13 via `py -3.13`**, with a project virtualenv at `E:\zerotrace-demo\.venv`.
Not 3.14: `xgboost`, `onnxruntime` and other native wheels lag new CPython releases. Not the Store alias; not the half-removed 3.12.

## 4. Inference runtime (LM Studio)

| Item | Measured value |
|---|---|
| Endpoint | `http://localhost:1235/v1` (OpenAI-compatible, non-default port) |
| Native API | `http://localhost:1235/api/v0/models` |
| JIT loading | enabled, `unloadPreviousJITModelOnLoad: true`, TTL 3600 s |
| Concurrency | **one model resident at a time** |
| `/v1` model list | returns `phi-4-mini-reasoning`, `text-embedding-nomic-embed-text-v1.5` |

### Model registry as OpenCode sees it

| OpenCode ref | Quant | Tools | Context limit reported |
|---|---|---|---|
| `lmstudio/qwen3.5-4b` | Q4_K_M | ✅ true | **32,768** *(was 136,704 before the fix)* |
| `lmstudio/qwen/qwen3.5-9b` | Q4_K_M | ✅ true | 262,144 |
| `lmstudio/phi-4-mini-reasoning` | Q6_K | ❌ **false** | 131,072 |

### Live instance state (`/api/v0/models`)

```
LOADED : qwen3.5-4b        type=vlm  arch=qwen35  quant=Q4_K_M  ctx=32768/262144
idle   : qwen/qwen3.5-9b            (not-loaded)
idle   : phi-4-mini-reasoning       (not-loaded)
idle   : text-embedding-nomic-embed-text-v1.5 (not-loaded)
```

**Confirmed applied:** the 4B's context allocation is now **32,768** — the fix recommended earlier is in effect.

**Not yet confirmed:** `parallel` slots and KV-cache quantisation. The earlier reading was `parallel: 4`; the current value must be re-checked in LM Studio's model settings. `parallel: 4` multiplies KV memory by roughly 4×.

**Asset note:** the 4B loads as `type=vlm`, meaning the `mmproj` vision projector is also resident. The project needs no vision. Removing the two `mmproj` files (4B 0.63 GB + 9B 0.86 GB ≈ **1.5 GB on disk**) removes a per-load memory component and cannot affect code generation.

### Model files (verified earlier today)

| File | Size |
|---|---:|
| `Qwen3.5-4B-Q4_K_M.gguf` | 2.52 GB |
| `Qwen3.5-4B mmproj` | 0.63 GB |
| `Qwen3.5-9B-Q4_K_M.gguf` | 5.24 GB |
| `Qwen3.5-9B mmproj` | 0.86 GB |
| `Phi-4-mini-reasoning-Q6_K.gguf` | 2.94 GB |

## 5. Memory snapshot (LM Studio loaded, Docker stopped)

| Process | Working set |
|---|---:|
| `llama-server` (4B @ 32K) | **4,661 MB** |
| `msedge` × 4 tabs | ~2,279 MB total |
| `Code` (VS Code) × 2 | ~1,016 MB total |
| `Memory Compression` | 389 MB |
| `opencode-cli` | 349 MB |
| `explorer` | 335 MB |

| Metric | Value |
|---|---:|
| Free physical RAM | **1.08 GB** |
| Commit limit | 26.0 GB |
| Commit free | **1.41 GB** |

**Finding:** with only the editor, a browser and one 4B model loaded, free physical RAM is **1.08 GB** and commit headroom is **1.41 GB**. The spec's own rule is to leave 2–3 GB of host headroom. Docker is *not even running* yet.

**Consequence for the build:** the "≈9 GB stack `[source]`" target cannot be validated on this host while Edge and VS Code are open. Every footprint measurement must record what else was running, and the acceptance test must specify a closed-browser configuration.

## 6. Inference throughput

Benchmark: `scripts/bench-lmstudio.ps1`, 42-token prompt, `max_tokens=192`, `temperature=0`, run 2026-10-17 with Edge and VS Code open, Docker stopped.

| Measurement | Value |
|---|---|
| **Effective generation tok/s, 4B @ 32K** | **2.02** (192 tokens in 95,124 ms) |
| Same with `chat_template_kwargs.enable_thinking=false` | **2.05** (192 tokens in 93,714 ms) |
| Content returned | **0 characters in both runs** — `finish_reason: length`, empty `content` |
| Reasoning emitted | 625 characters in **both** runs |
| Raw records | `scripts/bench-results.json` |

### Three findings

**1. Throughput is ~2 tok/s — 4–6× slower than the 8–12 tok/s assumed earlier.**
At this rate a 400-token agent turn costs **≈3.3 minutes**, and a 1,000-token file-plus-diff turn costs **≈8 minutes**. This is the single most important number in the project: it sets what a "task" can be.

**2. Thinking mode consumed the entire budget and returned no content.**
Both runs spent all 192 tokens on reasoning and emitted an **empty `content`** with `finish_reason: length`. A model that answers with nothing and makes no tool calls cannot drive an agent.

**3. `enable_thinking=false` was silently ignored.**
The two runs are behaviourally identical (625 reasoning characters each), so the request field had no effect — it was dropped, not rejected. The thinking switch must be found elsewhere; a parameter probe is running. Options: the LM Studio per-model *Thinking / Non-thinking* setting, a different request field, or a chat template that actually supports the toggle.

### Speed hypotheses to test (settings only, no code)

| Hypothesis | Evidence | Action |
|---|---|---|
| KV cache offloaded to the integrated GPU | earlier instance config showed `offload_kv_cache_to_gpu: true`; UHD has no dedicated VRAM, so every attention step crosses shared memory | turn **Offload KV cache to GPU** off, re-measure |
| `parallel: 4` reserving 4 slots of KV | earlier instance config | set **Parallel requests = 1** |
| Vision projector resident | model loads as `type=vlm` | remove the two `mmproj` files (no vision needed) |
| Host contention / paging | Edge ~2.3 GB + VS Code ~1 GB with only 1.08 GB free before the run | close both while benchmarking, re-measure |

**Rule until re-measured:** do not treat this host as capable of chatty multi-turn agent work. Each task must be a small, surgical turn: one function, one file, one question.


## 7. End-to-end chain check

| Check | Result |
|---|---|
| LM Studio `/v1/models` | ✅ 200 |
| LM Studio chat completion (Phi-4-mini) | ✅ 200 |
| LM Studio chat completion (Qwen3.5-4B) | ✅ 200 |
| OpenCode provider `lmstudio` registered, baseURL `:1235` | ✅ (`/api/provider`) |
| OpenCode model discovery | ✅ 3 models, `enabled: true`, `status: active` |
| **OpenCode → LM Studio → 4B round trip** | ✅ `opencode run -m lmstudio/qwen3.5-4b` returned `CONNECTED` |

## 8. Claims not yet verified

From the specification, awaiting measurement. Do not present these as facts.

| Claim | Status |
|---|---|
| ≈9 GB total stack footprint `[source]` | unverified — no stack exists yet |
| 16 GB minimum RAM `[source]` | host has 19.77 GB; minimum spec not tested |
| Guard adds ≤50 ms `[source]` | unverified — no Guard yet |
| Jailbreak catch ≥92% `[source]` | unverified — no classifier yet |
| Subdomain recall ≥90% / precision ≥95% `[source]` | unverified |
| XGBoost beats CVSS baseline `[source]` | unverified — no model yet |
| Score fixture `71` | **contradicted** by arithmetic; correct value is **73** |

## 9. How to reproduce

```powershell
# host + toolchain
Get-CimInstance Win32_OperatingSystem, Win32_ComputerSystem, Win32_Processor
Get-PSDrive -PSProvider FileSystem
py -0p

# inference state
(Invoke-WebRequest 'http://localhost:1235/api/v0/models' -UseBasicParsing).Content
(Invoke-WebRequest 'http://localhost:1235/v1/models'  -UseBasicParsing).Content

# throughput (writes scripts/bench-results.json)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\bench-lmstudio.ps1 -MaxTokens 192

# memory snapshot
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 ProcessName, WorkingSet64
```

---

**Rule for this file:** a row is either a command output or it is labelled `[source]` / `unverified`. No remembered numbers.
