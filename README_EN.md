# RR Edge Hunter

**Cloudflare Preferred-IP Selector · Desktop**

RR Edge Hunter is a local Cloudflare ingress-IP selector. The default scan requires no user hostname: it pins `speed.cloudflare.com` to each candidate on port `443`, retains normal TLS certificate, SNI, Host, and actual-peer validation, and performs staged multi-round downloads.

The output is a bare IPv4 or IPv6 address. Put it only in the proxy node's `address` or `server` field. Keep the node's original port, UUID, protocol, TLS SNI, HTTP Host, and WebSocket Path unchanged.

> Cloudflare's published ranges indicate ownership, not an official speed ranking. Anycast results vary by carrier, location, egress, time, and network conditions.

## One-click defaults

| Setting | Default |
| --- | --- |
| Address family | IPv4 |
| Target bandwidth | 100 Mbps |
| Strategy | Asia Hunt |
| Measurement identity | `speed.cloudflare.com:443` |
| Candidate source | Official Cloudflare pool, optionally plus imported official-range IPs |
| Output | Replace node `address/server` only |

Asia Hunt still prioritizes success rate, round floor, minimum/average throughput, and variance. POP labels such as HKG, NRT, SIN, ICN, and TPE are tie-breakers only.

## Install

[Download the latest Windows portable package](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip), extract it, and run `CF-IP-Optimizer.exe`. Python is bundled; keep the adjacent `_internal` directory.

### Testing channel

[Manually download the current Windows testing package](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/download/testing/CF-IP-Optimizer-Windows-x64-testing.zip).

The testing and stable packages intentionally remain at internal version **1.0.0**, so this package must be installed manually. The testing channel does not replace the stable `latest` link.

### Run from source

Python 3.11 or newer is required; no third-party Python package is needed.

- Windows: `start-windows.bat`
- macOS/Linux: `./start-unix.sh`
- Generic: `python rr_optimizer.py ui`

The UI binds to `127.0.0.1` only and does not upload measurement history.

## How it works

1. Load current `speed.cloudflare.com` DNS seeds and a bounded deterministic sample of Cloudflare-published CIDRs.
2. Optionally add imported addresses that belong to official Cloudflare ranges.
3. Pin `speed.cloudflare.com:443` to each exact candidate while retaining system certificate validation, SNI, Host, and TCP-peer checks.
4. Run Pre, Micro, and repeated Full downloads. Failed Full rounds count as `0 Mbps`.
5. Rank by reliability, round floor, minimum/average throughput, variance, and TTFB; POP is only a near-tie preference.

The default workflow measures the current client-to-Cloudflare ingress path. It does not need the VPS origin IP and does not rewrite node configuration.

## Custom candidate pools

Long paste, local TXT/CSV/TSV/JSON/Base64 files, bounded CIDR sampling, IPv4/IPv6 endpoint notation, and public HTTPS subscriptions are supported. Imported addresses do not need to intersect the speed hostname's current DNS answers, but every tested target must belong to an official Cloudflare CIDR. Private, reserved, non-Cloudflare, wrong-family, and malformed targets are rejected; candidate count, concurrency, and download traffic are bounded.

Unofficial third-party relays are not mixed into the default official pool.

## Optional advanced Argo compatibility check

Normal preferred-IP scanning needs no hostname. Enable the advanced Argo check only when you want to verify a candidate against your own node. Supply the original TLS SNI/HTTP Host hostname, original TLS port, and optionally the WebSocket Path.

Candidates must then pass certificate, SNI, Host, and actual-peer checks; a supplied Path must complete a valid WebSocket `101` upgrade. This is an additional gate only. The final output remains a bare IP, and all other node fields stay unchanged.

## Optional Cloudflare DNS synchronization

After a successful scan, a champion may be written to one explicitly selected Cloudflare DNS record. This feature is off by default and ordinary scanning requires no Cloudflare credentials.

- IPv4 maps to `A`; IPv6 maps to `AAAA`.
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
