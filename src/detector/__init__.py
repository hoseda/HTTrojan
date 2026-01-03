"""
Trojan Detection System

Complete detection infrastructure including baseline management
and differential analysis.
"""

# Re-export commonly used components
from .baseline import (
    GoldenBaseline,
    GoldenBaselineBuilder,
    build_golden
)

from .differential import (
    FrameDifferentialDetector,
    AnomalyReport,
    quick_detect,
    detect_and_print
)

__all__ = [
    'GoldenBaseline',
    'GoldenBaselineBuilder',
    'build_golden',
    'FrameDifferentialDetector',
    'AnomalyReport',
    'quick_detect',
    'detect_and_print'
]