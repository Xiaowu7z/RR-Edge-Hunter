from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .version import VERSION


SPEED_HOST = "speed.cloudflare.com"


@dataclass(frozen=True)
class ModeParams:
    name: str
    label: str
    pre_bytes: int
    micro_bytes: int
    full_bytes: int
    full_rounds: int
    micro_candidates: int
    final_candidates: int
    pre_concurrency: int
    micro_concurrency: int
    full_concurrency: int = 1
    asia_hunt: bool = False
    early_stop: bool = True


BALANCED = ModeParams(
    name="balanced",
    label="均衡模式",
    pre_bytes=16_000,
    micro_bytes=0,
    full_bytes=0,
    full_rounds=2,
    micro_candidates=10,
    final_candidates=2,
    pre_concurrency=50,
    micro_concurrency=1,
)

ASIA_HUNT = ModeParams(
    name="asia",
    label="亚洲狩猎",
    pre_bytes=16_000,
    micro_bytes=0,
    full_bytes=0,
    full_rounds=2,
    micro_candidates=10,
    final_candidates=3,
    pre_concurrency=50,
    micro_concurrency=1,
    asia_hunt=True,
)

MAX_BANDWIDTH = ModeParams(
    name="max",
    label="最大带宽",
    pre_bytes=16_000,
    micro_bytes=0,
    full_bytes=0,
    full_rounds=2,
    micro_candidates=20,
    final_candidates=3,
    pre_concurrency=50,
    micro_concurrency=1,
    early_stop=False,
)

# Public reference-compatible flow: three RTT/CF-RAY checks, ten lowest RTT
# candidates, then one serial five-second peak-window download per candidate.
# The historical modes remain import-compatible for older CLI/config files,
# while the product UI now selects this single predictable mode.
REFERENCE = ModeParams(
    name="reference",
    label="快速优选",
    pre_bytes=0,
    micro_bytes=0,
    full_bytes=0,
    full_rounds=1,
    micro_candidates=10,
    final_candidates=1,
    pre_concurrency=50,
    micro_concurrency=1,
)

MODES = {
    REFERENCE.name: REFERENCE,
    BALANCED.name: BALANCED,
    ASIA_HUNT.name: ASIA_HUNT,
    MAX_BANDWIDTH.name: MAX_BANDWIDTH,
}


@dataclass
class ProbeResult:
    ok: bool
    error: str = ""
    family: str = ""
    target_ip: str = ""
    actual_remote_address: str = ""
    target_matches_remote: bool = False
    remote_is_ipv6: bool = False
    sni: str = SPEED_HOST
    cert_verified: bool = False
    http_code: int = 0
    http_version: str = ""
    tcp_ms: float = -1.0
    tls_ms: float = -1.0
    ttfb_ms: float = -1.0
    body_ms: float = -1.0
    total_ms: float = -1.0
    bytes_downloaded: int = 0
    bytes_target: int = 0
    payload_mbps: float = 0.0
    complete_mbps: float = 0.0
    colo: str = ""
    loc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Snapshot:
    family: str
    ips: list[str]
    sources: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class IpMetric:
    ip: str
    family: str
    min_complete_mbps: float = 0.0
    avg_complete_mbps: float = 0.0
    max_complete_mbps: float = 0.0
    min_payload_mbps: float = 0.0
    avg_payload_mbps: float = 0.0
    success_rate_pct: float = 0.0
    variation_pct: float = 0.0
    median_ttfb_ms: float = -1.0
    round_floor_mbps: float = 0.0
    rounds_tested: int = 0
    source_tags: list[str] = field(default_factory=list)
    pop: str = ""
    loc: str = ""
    edge_score: int = 0
    pop_drift: bool = False
    stability: str = ""
    peak_kbps: int = 0
    latency_ms: int = 0
    data_center: str = ""
    scan_round: int = 0
    use_tls: bool = True
    node_delay_ms: float = -1.0

    @property
    def mb_per_sec(self) -> float:
        return self.avg_complete_mbps / 8.0

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["mb_per_sec"] = self.mb_per_sec
        return row


@dataclass
class PopDiscovery:
    counts: dict[str, int]
    candidates: list[dict[str, Any]]
    ip_to_pop: dict[str, str]
    ip_to_loc: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FamilyRunResult:
    family: str
    ranked: list[IpMetric]
    asia_ranked: list[IpMetric]
    invalid: bool = False
    discovery: PopDiscovery | None = None
    estimated_traffic_mb: float = 0.0
    elapsed_seconds: float = 0.0
    candidate_count: int = 0
    compatible_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "ranked": [item.to_dict() for item in self.ranked],
            "asia_ranked": [item.to_dict() for item in self.asia_ranked],
            "invalid": self.invalid,
            "discovery": self.discovery.to_dict() if self.discovery else None,
            "estimated_traffic_mb": self.estimated_traffic_mb,
            "elapsed_seconds": self.elapsed_seconds,
            "candidate_count": self.candidate_count,
            "compatible_count": self.compatible_count,
        }


@dataclass
class OptimizerResult:
    created_at: str
    mode: str
    operator: str
    requested_family: str
    ip_count: int
    target_host: str
    source_kind: str
    families: list[FamilyRunResult]
    elapsed_seconds: float
    cancelled: bool = False
    rejected_ip_count: int = 0
    purpose: str = "direct"
    target_mbps: int = 100
    node_port: int = 443
    node_sni: str = ""
    node_host: str = ""
    ws_path: str = ""
    measurement_host: str = SPEED_HOST
    measurement_port: int = 443
    network_fingerprints: dict[str, str] = field(default_factory=dict)
    use_tls: bool = True
    version: str = VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "mode": self.mode,
            "operator": self.operator,
            "requested_family": self.requested_family,
            "ip_count": self.ip_count,
            "target_host": self.target_host,
            "source_kind": self.source_kind,
            "elapsed_seconds": self.elapsed_seconds,
            "cancelled": self.cancelled,
            "rejected_ip_count": self.rejected_ip_count,
            "purpose": self.purpose,
            "target_mbps": self.target_mbps,
            "node_port": self.node_port,
            "node_sni": self.node_sni,
            "node_host": self.node_host,
            "ws_path": self.ws_path,
            "measurement_host": self.measurement_host,
            "measurement_port": self.measurement_port,
            "use_tls": self.use_tls,
            "families": [family.to_dict() for family in self.families],
        }
