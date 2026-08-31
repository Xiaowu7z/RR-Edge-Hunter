# RR Edge Hunter

**Cloudflare Preferred-IP Selector · Desktop**

RR Edge Hunter is a local Cloudflare ingress-IP selector. The default scan requires no user hostname: it first performs three bounded TCP-connect rounds, then pins `speed.cloudflare.com` to shortlisted candidates on port `443` and retains strict certificate, SNI, Host, CF-RAY, and actual-peer validation for real download samples.

The output is a bare IPv4 or IPv6 address. Put it only in the proxy node's `address` or `server` field. Keep the node's original port, UUID, protocol, TLS SNI, HTTP Host, and WebSocket Path unchanged.

> Cloudflare's published ranges indicate ownership, not an official speed ranking. Anycast results vary by carrier, location, egress, time, and network conditions.

## One-click defaults

| Setting | Default |
| --- | --- |
| Address family | IPv4 |
| Target bandwidth | 100 Mbps |
| Strategy | Asia Hunt |
| Measurement identity | `speed.cloudflare.com:443` |
| Candidate source | Official Cloudflare pool by default; optional restricted public-IP imports |
| Output | Replace node `address/server` only |

Asia Hunt still prioritizes success rate, round floor, minimum/average throughput, and variance. POP labels such as HKG, NRT, SIN, ICN, and TPE are tie-breakers only.

## Portable Windows build (the only release)

[Download the latest Windows x64 portable ZIP](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip), extract it, open the `CF-IP-Optimizer` directory, and run `CF-IP-Optimizer.exe`. The runtime is included, so Python is not required. Keep the executable next to its `_internal` directory instead of moving the EXE by itself. An installer is no longer published.

### Run from source

Python 3.11 or newer is required; no third-party Python package is needed.

- Windows: `start-windows.bat`
- macOS/Linux: `./start-unix.sh`
- Generic: `python rr_optimizer.py ui`

The UI binds to `127.0.0.1` only and does not upload measurement history.

## How it works

1. Load current `speed.cloudflare.com` DNS seeds and a bounded deterministic sample of Cloudflare-published CIDRs.
2. Optionally add any safe public-unicast address as a restricted candidate. Private, local, multicast, and reserved targets are rejected. The default one-click pool remains official-only and no third-party remote pool is preloaded.
3. Run three TCP-connect rounds per candidate with a one-second per-connect bound and up to 50 workers. This cheap stage only forms a shortlist and can never make an address copyable.
4. Target modes test the 10 lowest-latency candidates. Maximum Bandwidth tests 20 candidates and reserves several positions across latency bands/prefixes so throughput-rich routes are not excluded too early.
5. Pin `speed.cloudflare.com:443` to each shortlisted address and run bounded real HTTPS downloads with strict certificate, SNI, Host, CF-RAY, and actual-peer checks. Confirmed results require two successful samples; failed confirmations are replaced by the next candidate.
6. Expose only candidates with two successful strict download samples, then rank them by round floor, average throughput, variance, and TTFB; POP is only a near-tie preference.

The default workflow measures the current client-to-Cloudflare ingress path. It does not need the VPS origin IP and does not rewrite node configuration.

## Custom candidate pools

Long paste, local TXT/CSV/TSV/JSON/Base64 files, bounded CIDR sampling, IPv4/IPv6 endpoint notation, and public HTTPS subscriptions are supported. Imports do not need to intersect the speed hostname's current DNS answers or belong to an official Cloudflare CIDR. External addresses remain restricted until they pass three TCP rounds and two `speed.cloudflare.com:443` downloads with system-certificate, SNI, Host, actual-peer, and CF-RAY validation; Argo adds its node-host compatibility gate. Private, local, multicast, reserved, wrong-family, and malformed targets are rejected; candidate count, concurrency, and traffic remain bounded.

No third-party relay pool is built in or fetched automatically. Explicit user imports never bypass the strict gates above.

## Optional advanced Argo compatibility check

Normal preferred-IP scanning needs no hostname. Enable the advanced Argo check only when you want to verify a candidate against your own node. Supply the original TLS SNI/HTTP Host hostname, original TLS port, and optionally the WebSocket Path.

Candidates must then pass certificate, SNI, Host, and actual-peer checks; a supplied Path must complete a valid WebSocket `101` upgrade. This is an additional gate only. The final output remains a bare IP, and all other node fields stay unchanged.

## Optional Cloudflare DNS synchronization

After a successful scan, a champion may be written to one explicitly selected Cloudflare DNS record. This feature is off by default and ordinary scanning requires no Cloudflare credentials.

- IPv4 maps to `A`; IPv6 maps to `AAAA`.
- Only the current run's stable champion with two successful strict download samples is accepted; it may come from an official range or an explicitly imported external public candidate that passed every gate.
- The record is forced to **DNS-only** (gray cloud).
- A 32-character Zone ID and full record FQDN are required.
- Only an API Token is accepted; the minimum permission is **DNS: Edit** for the selected Zone. Global API Keys are not accepted.
- The token remains in request memory/authorization headers and is excluded from logs, history, JSON/CSV exports, and release artifacts.
- Phase one is read-only inspection and a change preview. Phase two requires explicit confirmation; state changes after preview force a new preview.
- Existing CNAMEs, duplicate same-type records, or ambiguous record state are rejected. The tool never deletes, merges, or converts them automatically.
- The written type, address, and DNS-only state are read back and verified.

DNS synchronization is an optional output and does not alter the Argo hostname or any node port, UUID, SNI, Host, or Path.

## Scheduled desktop runs

The desktop UI can rerun every 5–1,440 minutes. The first run starts immediately and later runs begin only after the previous run finishes plus the chosen interval. Estimated per-run and theoretical daily traffic are shown before activation.

Successful scheduled runs may optionally synchronize the champion to DNS after an additional authorization confirmation. A DNS error is sanitized and skips/pauses synchronization; it does not stop measurement, local result storage, or future selection runs.

## CLI examples

```bash
python rr_optimizer.py run --purpose direct --family ipv4 --mode asia --target-mbps 100
python rr_optimizer.py run --purpose direct --family ipv4 --mode asia --ips my-ip-list.txt --csv result.csv
python rr_optimizer.py run --purpose argo --target-host argo.example.com --node-port 8443 --ws-path /vless --family ipv4 --mode asia
```

## Security and privacy

- The local UI is loopback-only and state-changing requests require a random session token.
- TLS certificate and actual-peer verification stay enabled; probes do not inherit a system HTTP proxy.
- HTTPS subscriptions enforce public-target, size, redirect, and DNS-rebinding checks.
- Cloudflare API tokens never enter logs, history, or exports; errors are sanitized.
- The project does not provide arbitrary host/route changes, port scanning, vulnerability testing, stress testing, or access-control bypass.

See [SECURITY.md](SECURITY.md) and [NOTICE.md](NOTICE.md).

## Development

```bash
python -m unittest discover -s tests -v
python -m py_compile rr_optimizer.py cfopt/*.py
node --check web/app.js
```

The application version remains **1.0.0**. No open-source license has been selected; obtain permission before redistributing or reusing the code.
