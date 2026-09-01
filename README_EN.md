# RR Edge Hunter · CF IP Optimizer for Windows

> Find a usable Cloudflare IPv4/IPv6 locally on Windows, with scheduled runs and optional per-run DNS updates. No proxy node, subscription, UUID, or server deployment is required.
>
> [Download Windows version](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest) · [Android version](https://github.com/Xiaowu7z/RR-Edge-Hunter-Android)

Candidate generation, three RTT/CF-RAY checks, latency ranking, download measurement, speed calculation, target stopping, and round retries are all performed by the pinned, unmodified `better-cloudflare-ip` Go program.

## Features

- IPv4/IPv6 and non-TLS port 80/TLS port 443;
- a single run or automatic runs every 1, 2, 4, 6, 12, or 24 hours;
- one qualifying IP from the original engine per completed run;
- manual DNS writes from the result page, or an authorized update of the same Cloudflare DNS-only A/AAAA record after every scheduled run;
- local UI, task state, results, stop controls, and original-data updates.

The first scheduled run starts immediately. A new interval begins only after the previous run finishes, so two scans never overlap. Scheduling works only while the desktop program remains open.

## Quick start

1. Download and fully extract `CF-IP-Optimizer-Windows-x64.zip`.
2. Run `CF-IP-Optimizer.exe` without moving it out of the extracted folder.
3. Select the scan options and either a single run or a schedule.
4. Optionally authorize one DNS record for automatic per-run updates, then start.

The vendored [main.go](third_party/better-cloudflare-ip/main.go) is byte-identical to `badafans/better-cloudflare-ip` commit `c4f4cdd4c44243c964e68881a451d8e1f3fd5210`. Its SHA-256 is:

```text
83663f1e2655943ebae2d99d520a35f8c5dd58142ac58cf2169220e35deb11ab
```

CI verifies that digest before compiling the Windows helper. Python only sends the original menu inputs and parses the original final summary.

## Defaults

| Setting | Default |
| --- | --- |
| Address family | IPv4 |
| Transport | non-TLS port 80 |
| Target bandwidth | 1 Mbps |
| RTT workers | 50 |

The original engine keeps retrying until a target is reached or the user stops it.

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
