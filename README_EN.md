# RR Edge Hunter

**Cloudflare Preferred-IP Selector · Desktop**

RR Edge Hunter runs locally against the current computer and network egress. First paste an existing VMess/VLESS WebSocket-over-TLS Argo node that works in V2rayNG. Each round generates 100 addresses from an online maintained pool, checks every address three times with 50-way concurrency, keeps the 10 lowest-latency candidates, and tests them one by one with up to five seconds of real download traffic.

After the bandwidth target is met, the app changes only `address/server` in the full Xray outbound, preserves its port, UUID, protocol, TLS SNI, HTTP Host, WS Path, and other fields, then requests V2rayNG's default delay URL, `https://www.gstatic.com/generate_204`, through that node. Only a candidate that passes this complete proxy test is displayed as a bare IP.

## One-click defaults

| Setting | Default |
| --- | --- |
| Address family | IPv4 |
| Target bandwidth | 100 Mbps |
| Scan flow | 100 IPs → three checks → 10 lowest RTT → first target hit |
| Transport | TLS 443 with strict certificates; optional plain HTTP 80 |
| Speed target | Dynamically supplied, with cached/official fallback |
| Candidate source | Public `baipiao.eu.org` maintained pool plus optional safe imports |
| Node gate | Bundled official Xray-core must reach V2rayNG's default `generate_204` URL through the full node |
| Output | Only an IP that passes the V2rayNG-equivalent node-delay test; replace `address/server` only |

The UI exposes one understandable flow instead of Balanced, Asia Hunt, and Maximum Bandwidth choices. A failed round is followed by another until a result is found or the user stops it, so there is no honest fixed total-traffic ceiling.

## Portable Windows build (the only release)

[Download the latest Windows x64 portable ZIP](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip), extract it, open the `CF-IP-Optimizer` directory, and run `CF-IP-Optimizer.exe`. Python and a pinned official Xray-core are bundled; no installer is required. Keep the executable next to its `_internal` and `xray` directories.

### Run from source

Python 3.11 or newer is required; no third-party Python package is needed. The full-node gate also requires official Xray-core v26.7.28 at `runtime/xray.exe`, or a path supplied in `RR_EDGE_HUNTER_XRAY`.

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
7. After a candidate reaches `target Mbps × 128 kB/s`, change only `address/server` in its complete Xray node configuration, launch the local Xray outbound, and request V2rayNG's default `generate_204` delay URL through it.
8. Continue when the full proxy connection fails, and start a fresh round when necessary. Copy and Cloudflare A/AAAA DNS-only synchronization are enabled only for a result that passes both gates.

The workflow does not test the VPS origin IP, but it requires an existing node so the candidate is proven with the same protocol, credentials, port, TLS, and transport settings V2rayNG will use.

## Custom candidate pools

Long paste, local TXT/CSV/TSV/JSON/Base64 files, bounded CIDR sampling, IPv4/IPv6 endpoint notation, and public HTTPS subscriptions are supported. Imports need not intersect current speed-host DNS answers or belong to an official Cloudflare CIDR. Private, loopback, link-local, multicast, reserved, wrong-family, and malformed entries are rejected. An external public IP remains unusable until it passes the same three checks and real-download gate.

The default maintained endpoints are the public interfaces used by [badafans/better-cloudflare-ip](https://github.com/badafans/better-cloudflare-ip). This project independently implements publicly described and observable behavior. The upstream repository currently declares no open-source license, so its source code is neither copied nor bundled here.

## V2rayNG node-usability gate

Argo verification is part of the main flow. Paste a complete `vmess://` or `vless://` share link; WebSocket + TLS nodes on Cloudflare HTTPS ports `443/2053/2083/2087/2096/8443` are supported. The credential-bearing configuration remains only in process memory and never enters settings, history, logs, exports, or error text. It is sent directly to the bundled official Xray-core over standard input, with only the candidate address changed. The app then reaches `https://www.gstatic.com/generate_204` through a local SOCKS inbound and accepts HTTP 200/204. This verifies a real proxy connection rather than only ICMP, TCP, TLS, or WebSocket reachability.

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
python rr_optimizer.py run --purpose argo --node-link-file my-node.txt --family ipv4 --mode reference --target-mbps 100
python rr_optimizer.py run --purpose argo --node-link-file my-node.txt --family ipv4 --mode reference --ips my-ip-list.txt --csv result.csv
python rr_optimizer.py run --purpose argo --node-link-file my-node.txt --family ipv4 --mode reference --target-mbps 100 --no-tls
```

## Security and privacy

- The local UI is loopback-only and state-changing requests require a random session token.
- TLS mode retains platform certificate, SNI, Host, and actual-peer verification; plain HTTP 80 requires an explicit choice.
- The maintained pool is cached, with official Cloudflare ranges as an offline fallback.
- HTTPS subscriptions enforce public-target, size, redirect, and DNS-rebinding checks.
- Cloudflare API tokens never enter logs, history, or exports.
- The project does not provide arbitrary host/route changes, port scanning, vulnerability testing, stress testing, or access-control bypass.

See [SECURITY.md](SECURITY.md), [NOTICE.md](NOTICE.md), and [third-party notices](THIRD_PARTY_NOTICES.md).

## Development and release

```bash
python -m unittest discover -s tests -v
python -m py_compile rr_optimizer.py cfopt/*.py
node --check web/app.js
```

The application version remains **1.0.0**. The only published artifact is the Windows x64 portable ZIP plus its SHA-256. No open-source license has been selected for this repository; obtain permission before redistributing or reusing its code.
