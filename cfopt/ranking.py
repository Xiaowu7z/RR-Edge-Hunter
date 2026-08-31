from __future__ import annotations

import math
import statistics
from dataclasses import dataclass

from .models import IpMetric


def _round_one(value: float) -> float:
    return round(value * 10.0) / 10.0


def address_floor(speeds: list[float], failed_count: int) -> float:
    if failed_count > 0:
        return 0.0
    valid = [item for item in speeds if item > 0.0 and math.isfinite(item)]
    return min(valid) if valid else 0.0


def success_rate(successes: int, total: int) -> float:
    return 0.0 if total <= 0 else _round_one(successes * 100.0 / total)


def median_ttfb(values: list[float]) -> float:
    valid = sorted(item for item in values if item > 0.0 and math.isfinite(item))
    return statistics.median(valid) if valid else -1.0


def variation(speeds: list[float]) -> float:
    values = [item for item in speeds if item >= 0.0 and math.isfinite(item)]
    if len(values) < 2:
        return 0.0
    average = statistics.fmean(values)
    if average <= 0.0:
        return 0.0
    return _round_one((max(values) - min(values)) * 100.0 / average)


def stability_label(variation_pct: float, success_rate_pct: float) -> str:
    if success_rate_pct >= 90.0 and variation_pct <= 15.0:
        return "优秀"
    if success_rate_pct >= 75.0 and variation_pct <= 30.0:
        return "良好"
    if success_rate_pct >= 50.0:
        return "一般"
    return "较差"


def _confirmed(item: IpMetric) -> bool:
    return item.rounds_tested >= 2 and item.success_rate_pct >= 99.9 and item.round_floor_mbps > 0.0


def rank(metrics: list[IpMetric]) -> list[IpMetric]:
    return sorted(
        metrics,
        key=lambda item: (
            -int(_confirmed(item)),
            -item.round_floor_mbps,
            -item.success_rate_pct,
            -item.min_complete_mbps,
            -item.avg_complete_mbps,
            item.variation_pct,
            item.median_ttfb_ms if item.median_ttfb_ms >= 0.0 else math.inf,
        ),
    )


def rank_maximum(metrics: list[IpMetric]) -> list[IpMetric]:
    """Rank confirmed candidates by two-sample average download throughput."""
    return sorted(
        metrics,
        key=lambda item: (
            -int(_confirmed(item)),
            -item.avg_complete_mbps,
            -item.max_complete_mbps,
            -item.round_floor_mbps,
            -item.success_rate_pct,
            item.variation_pct,
            item.median_ttfb_ms if item.median_ttfb_ms >= 0.0 else math.inf,
        ),
    )


def rank_asia(metrics: list[IpMetric]) -> list[IpMetric]:
    return sorted(
        metrics,
        key=lambda item: (
            -int(_confirmed(item)),
            -item.round_floor_mbps,
            -item.success_rate_pct,
            -item.min_complete_mbps,
            -item.avg_complete_mbps,
            item.variation_pct,
            item.median_ttfb_ms if item.median_ttfb_ms >= 0.0 else math.inf,
            -item.edge_score,
            item.pop_drift,
        ),
    )
