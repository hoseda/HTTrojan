"""
Golden Baseline Management

Creation, storage, and management of trusted reference configurations.
"""

from .golden_baseline import (
    FrameFingerprint,
    GoldenBaseline
)

from .baseline_builder import (
    GoldenBaselineBuilder,
    build_golden,
    quick_baseline_stats
)

__all__ = [
    'FrameFingerprint',
    'GoldenBaseline',
    'GoldenBaselineBuilder',
    'build_golden',
    'quick_baseline_stats'
]