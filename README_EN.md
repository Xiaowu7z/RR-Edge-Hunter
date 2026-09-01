# RR Edge Hunter

**Cloudflare Preferred-IP Selector · Desktop**

RR Edge Hunter runs locally against the current computer and network egress. Each round generates 100 addresses from an online maintained pool, checks every address three times with 50-way concurrency, keeps the 10 lowest-latency candidates, and tests them one by one with up to five seconds of real download traffic. Only complete one-second windows contribute to peak throughput. The first IP that reaches the requested bandwidth is returned; otherwise a fresh round begins automatically.

The output is a bare IPv4 or IPv6 address. Put it only in the VMess/VLESS node's `address` or `server` field. Keep the original port, UUID, protocol, TLS SNI, HTTP Host, and WebSocket Path unchanged.

## One-click defaults

| Setting | Default |
| --- | --- |
| Address family | IPv4 |
| Target bandwidth | 100 Mbps |
| Scan flow | 100 IPs → three checks → 10 lowest RTT → first target hit |
| Transport | TLS 443 with strict certificates; optional plain HTTP 80 |
| Speed target | Dynamically supplied, with cached/official fallback |
| Candidate source | Public `baipiao.eu.org` maintained pool plus optional safe imports |
| Output | Replace node `address/server` only |

The UI exposes one understandable flow instead of Balanced, Asia Hunt, and Maximum Bandwidth choices. A failed round is followed by another until a result is found or the user stops it, so there is no honest fixed total-traffic ceiling.

## Portable Windows build (the only release)

[Download the latest Windows x64 portable ZIP](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip), extract it, open the `CF-IP-Optimizer` directory, and run `CF-IP-Optimizer.exe`. The runtime is bundled; Python and an installer are not required. Keep the executable next to its `_internal` directory.

### Run from source

Python 3.11 or newer is required; no third-party Python package is needed.

- Windows: `start-windows.bat`
- macOS/Linux: `./start-unix.sh`
- Generic: `python rr_optimizer.py ui`

The UI binds to `127.0.0.1` only and does not upload measurement history.

## How it works

1. Fetch IPv4/IPv6 ranges, the current speed-test URL, and the POP-location table from `https://www.baipiao.eu.org/cloudflare/`; cache successful data for six hours.
2. Sample up to 100 ranges per round. IPv4 keeps the first three octets and randomizes the last; IPv6 keeps the first three hextets and randomizes the remaining five. Safe user imports may occupy part of the round.
3. Check every candidate three times with 50-way concurrency. Each attempt includes TCP, optional TLS, and a `Host: cloudflare.com` request; any failed attempt or missing `CF-RAY` rejects the candidate.
4. Sort by average TCP latency and retain the best 10.
5. Pin the dynamically supplied speed host to each candidate in latency order. TLS retains platform certificate, SNI, Host, and actual-peer validation; non-TLS uses port 80.
6. Download for at most five seconds per candidate. Peak kB/s is calculated only from complete one-second windows; the final partial window is ignored.
7. Return the first candidate whose peak reaches `target Mbps × 128 kB/s`. Optional Argo validation is an additional gate.
8. Start a fresh round when none of the 10 candidates reaches the target. Copy and Cloudflare A/AAAA DNS-only synchronization are enabled only for a verified result.

The default workflow measures the current client-to-Cloudflare ingress path. It needs neither a VPS origin IP nor an Argo hostname.

## Custom candidate pools

Long paste, local TXT/CSV/TSV/JSON/Base64 files, bounded CIDR sampling, IPv4/IPv6 endpoint notation, and public HTTPS subscriptions are supported. Imports need not intersect current speed-host DNS answers or belong to an official Cloudflare CIDR. Private, loopback, link-local, multicast, reserved, wrong-family, and malformed entries are rejected. An external public IP remains unusable until it passes the same three checks and real-download gate.

The default maintained endpoints are the public interfaces used by [badafans/better-cloudflare-ip](https://github.com/badafans/better-cloudflare-ip). This project independently implements publicly described and observable behavior. The upstream repository currently declares no open-source license, so its source code is neither copied nor bundled here.

## Optional advanced Argo compatibility check

Normal scanning needs no hostname. Enable this check only to validate the winning route against your own node hostname, TLS port, and optional WebSocket Path. The candidate must then pass certificate, SNI, Host, actual-peer, and optional WebSocket `101` checks. The output remains a bare IP and all other node fields stay unchanged.

## Optional Cloudflare DNS synchronization

A verified result can be written to one explicitly selected Cloudflare DNS record. This feature is off by default.

- IPv4 maps to `A`; IPv6 maps to `AAAA`.
- The record is forced to **DNS-only**.
- A 32-character Zone ID and full record FQDN are required.
- Only a target-Zone API Token with **DNS: Edit** is accepted; Global API Keys are rejected.
- A read-only preview precedes explicit confirmation and read-back verification.
- CNAME conflicts, duplicate same-type records, and ambiguous states are rejected without deletion or conversion.
- Tokens never enter logs, history, or exports.

## Scheduled desktop runs

The desktop UI can rerun every 5–1,440 minutes. The first run starts immediately and later runs start only after the previous run finishes plus the selected interval. The UI shows a first-candidate-hit estimate, not a false hard ceiling, and warns that retries or fresh rounds consume more traffic. Successful runs may optionally synchronize DNS after separate authorization.

## CLI examples

```bash
python rr_optimizer.py run --purpose direct --family ipv4 --mode reference --target-mbps 100
python rr_optimizer.py run --purpose direct --family ipv4 --mode reference --ips my-ip-list.txt --csv result.csv
python rr_optimizer.py run --purpose direct --family ipv4 --mode reference --target-mbps 100 --no-tls
python rr_optimizer.py run --purpose argo --target-host argo.example.com --node-port 8443 --ws-path /vless --family ipv4 --mode reference
```

## Security and privacy

- The local UI is loopback-only and state-changing requests require a random session token.
- TLS mode retains platform certificate, SNI, Host, and actual-peer verification; plain HTTP 80 requires an explicit choice.
- The maintained pool is cached, with official Cloudflare ranges as an offline fallback.
- HTTPS subscriptions enforce public-target, size, redirect, and DNS-rebinding checks.
- Cloudflare API tokens never enter logs, history, or exports.
- The project does not provide arbitrary host/route changes, port scanning, vulnerability testing, stress testing, or access-control bypass.

See [SECURITY.md](SECURITY.md) and [NOTICE.md](NOTICE.md).

## Development and release

```bash
python -m unittest discover -s tests -v
python -m py_compile rr_optimizer.py cfopt/*.py
node --check web/app.js
```

The application version remains **1.0.0**. The only published artifact is the Windows x64 portable ZIP plus its SHA-256. No open-source license has been selected for this repository; obtain permission before redistributing or reusing its code.
