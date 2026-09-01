# RR Edge Hunter · CF IP Optimizer for Windows

> Find a usable Cloudflare IPv4/IPv6 locally on Windows, with scheduled runs and optional per-run DNS updates. No proxy node, subscription, UUID, or server deployment is required.
>
> [Download Windows version](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest) · [Android version](https://github.com/Xiaowu7z/RR-Edge-Hunter-Android)

RR Edge Hunter generates candidate Cloudflare IPs on the current computer and network, performs three RTT/CF-RAY checks, ranks latency, and runs download measurements until one IP reaches the requested bandwidth.

## Features

- IPv4/IPv6 and non-TLS port 80/TLS port 443;
- a single run or automatic runs every 1, 2, 4, 6, 12, or 24 hours;
- one qualifying IP per completed run;
- manual DNS writes from the result page, or an authorized update of the same Cloudflare DNS-only A/AAAA record after every scheduled run;
- local UI, task state, results, stop controls, and IP-pool updates;
- an Edge Atlas-style dashboard with a live status console and winner card, without exposing internal CLI menus.

The first scheduled run starts immediately. A new interval begins only after the previous run finishes, so two scans never overlap. Scheduling works only while the desktop program remains open.

## Quick start

1. Download and fully extract `CF-IP-Optimizer-Windows-x64.zip`.
2. Run `CF-IP-Optimizer.exe` without moving it out of the extracted folder.
3. Select the scan options and either a single run or a schedule.
4. Optionally authorize one DNS record for automatic per-run updates, then start.

## Defaults

| Setting | Default |
| --- | --- |
| Address family | IPv4 |
| Transport | non-TLS port 80 |
| Target bandwidth | 1 Mbps |
| RTT workers | 50 |

The scan keeps retrying until a target is reached or the user stops it.

## Selection flow

1. Prepare and cache IPv4/IPv6 ranges and data-center metadata.
2. Generate random candidate IPs from the pool.
3. Run three RTT and CF-RAY checks per candidate.
4. Send the lowest-latency candidates to download measurement.
5. Finish when an IP reaches the target bandwidth, or automatically start another round.

Third-party source and license information is kept in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) instead of the user interface.

## Scheduled desktop runs

The 24-hour interval is shown as all-day mode. Stopping the task cancels the active scan and all future runs. The app does not install a system service or continue after it closes.

## Cloudflare DNS

The single result can optionally be written as a DNS-only A or AAAA record. Manual writes require a read-only preview followed by explicit confirmation and read-back verification. Scheduled writes require explicit authorization when the schedule starts and always update the same single record. Tokens are kept only in process memory and are cleared when the schedule stops or the program closes.

## Source use

Python 3.11+ and Go 1.22+ are required:

```bash
python rr_optimizer.py ui
python -m unittest discover -s tests -v
```

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [SECURITY.md](SECURITY.md).
