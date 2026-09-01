# RR Edge Hunter · CF IP Optimizer

The desktop app no longer contains an RR-written scan algorithm and never asks for a proxy node link. Candidate generation, three RTT/CF-RAY checks, latency ranking, download measurement, speed calculation, target stopping, and round retries are all performed by the pinned, unmodified `better-cloudflare-ip` Go program.

RR only supplies the desktop UI, displays/copies the result, optionally schedules repeated runs of that same original program, and writes the single result to one confirmed Cloudflare DNS-only A/AAAA record when requested.

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

The desktop UI offers single runs or 1, 2, 4, 6, 12, and 24-hour intervals. The first run starts immediately; each later interval begins only after the preceding run finishes. Every run keeps exactly one IP returned by the original engine. DNS can be updated automatically after each run or manually from the result page. The schedule exists only while the desktop program remains open.

## Cloudflare DNS

The single result can optionally be written as a DNS-only A or AAAA record. Manual writes require a read-only preview followed by explicit confirmation and read-back verification. Scheduled writes require explicit authorization when the schedule starts and always update the same single record. Tokens are kept only in process memory and are cleared when the schedule stops or the program closes.

## Source use

Python 3.11+ and Go 1.22+ are required:

```bash
python rr_optimizer.py ui
python -m unittest discover -s tests -v
```

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [SECURITY.md](SECURITY.md).
