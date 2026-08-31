from __future__ import annotations

import hashlib
import ipaddress
import math


FALLBACK_V4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

FALLBACK_V6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

NETWORKS_V4 = tuple(ipaddress.ip_network(item) for item in FALLBACK_V4)
NETWORKS_V6 = tuple(ipaddress.ip_network(item) for item in FALLBACK_V6)

# Keep the built-in pool bounded.  These are deterministic samples from the
# published Cloudflare ranges, not an assertion that every sampled address is
# usable for every zone. Every address still has to pass the live public-speed
# probes; optional Argo mode adds a separate user-host compatibility gate.
DEFAULT_OFFICIAL_SAMPLE_LIMIT = 112


def is_cloudflare_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    networks = NETWORKS_V6 if address.version == 6 else NETWORKS_V4
    return any(address in network for network in networks)


def family_of(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    return "IPv6" if address.version == 6 else "IPv4"


def normalized_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.split("%", 1)[0]))


def prefix_of(value: str) -> str:
    address = ipaddress.ip_address(value)
    prefix = 48 if address.version == 6 else 24
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def sample_official_cloudflare_ips(
    family: str,
    limit: int = DEFAULT_OFFICIAL_SAMPLE_LIMIT,
    seed: object | None = None,
) -> list[str]:
    """Return a bounded, evenly spread sample from Cloudflare's published CIDRs.

    With no seed the historical stable sample is retained for callers that need
    reproducibility.  A run-scoped seed rotates the addresses inside every
    official prefix without changing the prefix coverage or the hard limit.
    """
    if family not in {"IPv4", "IPv6"}:
        raise ValueError("协议族必须是 IPv4 或 IPv6")
    if limit <= 0:
        return []
    networks = NETWORKS_V4 if family == "IPv4" else NETWORKS_V6
    per_network = max(1, math.ceil(limit / len(networks)))
    buckets: list[list[str]] = []
    for network in networks:
        if network.version == 4 and network.prefixlen <= 30:
            start = int(network.network_address) + 1
            span = max(0, network.num_addresses - 2)
        else:
            # Avoid the all-zero subnet-router address while retaining the
            # entire usable body of very large IPv6 announcements.
            start = int(network.network_address) + int(network.num_addresses > 1)
            span = max(0, network.num_addresses - int(network.num_addresses > 1))
        count = min(per_network, span)
        offsets: set[int] = set()
        cursor = 0
        while len(offsets) < count:
            seed_part = "" if seed is None else f":{seed}"
            digest = hashlib.blake2b(
                f"rr-edge-hunter:official{seed_part}:{network.with_prefixlen}:{cursor}".encode("utf-8"),
                digest_size=16,
            ).digest()
            offsets.add(int.from_bytes(digest, "big") % span)
            cursor += 1
        buckets.append([str(ipaddress.ip_address(start + offset)) for offset in sorted(offsets)])

    output: list[str] = []
    for index in range(per_network):
        for bucket in buckets:
            if index < len(bucket):
                output.append(bucket[index])
                if len(output) >= limit:
                    return output
    return output
