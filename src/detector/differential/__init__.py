"""
Differential Analysis Module
Phase 3: Golden vs Suspect comparison
"""

from .frame_anomaly import (
    AnomalyType,
    SeverityLevel,
    FrameAnomaly,
    AnomalyCluster,
    AnomalyReport
)

from .frame_differential_detector import (
    FrameDifferentialDetector,
    quick_detect,
    detect_and_print
)

from .enhanced_differential_detector import (
    EnhancedDifferentialDetector,
    enhanced_quick_detect
)

__all__ = [
    # Anomaly structures
    'AnomalyType',
    'SeverityLevel',
    'FrameAnomaly',
    'AnomalyCluster',
    'AnomalyReport',
    
    # Base detector
    'FrameDifferentialDetector',
    'quick_detect',
    'detect_and_print',
    
    # Enhanced detector
    'EnhancedDifferentialDetector',
    'enhanced_quick_detect',
]