# Scanner sandbox and egress boundaries

ZeroTrace runs Nmap and Subfinder as bounded subprocesses. The application-level
controls are always on; the host-level controls below are the production target
for a Linux deployment. They are intentionally documented separately because a
local Windows preview cannot provide the same kernel isolation.

## Application-level controls

`app.recon.SubprocessRunner` enforces:

- an executable path that must already exist; no shell, no command string;
- argument NUL rejection and an argument vector, not shell interpolation;
- `stdin=DEVNULL`, captured stdout/stderr, a hard timeout, and an output cap;
- a new process group so a timeout can terminate the whole scanner tree;
- an explicit environment allowlist through `scanner_environment()`.

The allowlist passes only `PATH`, `PATHEXT`, `SYSTEMROOT`, `WINDIR`, `TEMP`,
`TMP`, `HOME`, `USERPROFILE`, locale, timezone, and CA-bundle variables. It
never passes `DATABASE_URL`, `ZEROTRACE_*` keys, cloud credentials, Guard
provider keys, or the BFF/engine API keys. A regression test sets a fake
`ZEROTRACE_ENGINE_API_KEY` and proves a child process sees `missing`.

Scanners still need network egress to the authorized target. The engine itself
must remain loopback-only and must not be exposed through Caddy or the public
edge.

## Host-level reference (Linux)

Run the engine as an unprivileged service account in its own container or
systemd unit. The following systemd hardening is a reference, not a substitute
for an egress firewall:

```ini
[Service]
User=zerotrace-engine
Group=zerotrace-engine
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
MemoryMax=2G
TasksMax=256
ReadWritePaths=/var/lib/zerotrace-engine
```

For a container deployment, add `--read-only`, a writable `tmpfs` for `/tmp`,
`--cap-drop=ALL`, `--security-opt no-new-privileges`, a non-root UID, and a
memory/PID limit. Do not mount the Docker socket or the host home directory.

## Egress allowlist

The strongest practical control is a per-scan network namespace with an egress
firewall that permits only the resolved target addresses and required DNS. A
host firewall rule alone is weaker because it is shared by all scans. If a
per-scan namespace is not available, use a dedicated engine host/network and
document the residual risk.

Example nftables shape (adapt to the target resolver and port policy):

```nft
table inet zt_scan {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ip daddr 10.20.30.40 tcp dport { 80, 443 } accept
    ip daddr 10.20.30.40 udp dport 53 accept
    ct state established,related accept
  }
}
```

Nmap needs raw sockets for some scan types. Prefer unprivileged connect scans
and do not grant `CAP_NET_RAW` unless the operator explicitly accepts the risk.
ZeroTrace's bounded scan profiles do not enable exploitation, brute force,
automatic remediation, or unauthorized public-target scans.

## Acceptance evidence

The application-level allowlist and timeout behavior can be tested on any OS.
The host-level control requires a Linux host and a negative egress canary: a
scan process must fail to reach a non-allowlisted host while reaching the
authorized fixture. Record the host image digest, firewall ruleset, canary
result, and reviewer in `tasks/evidence/`. Until that evidence exists, do not
claim enforced per-scan network isolation.
