"""
Frame Anomaly Data Structures

Represents detected anomalies in bitstream comparison.
Core data structures for Trojan detection results.

Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class AnomalyType(Enum):
    """Types of anomalies that can be detected"""
    FRAME_ADDED = "frame_added"              # Frame in suspect, not in golden
    FRAME_REMOVED = "frame_removed"          # Frame in golden, not in suspect
    FRAME_MODIFIED = "frame_modified"        # Frame data differs
    UNUSED_REGION_MOD = "unused_region_mod"  # Modification in unused region
    ROUTING_CHANGE = "routing_change"        # Routing frame modified
    LOGIC_CHANGE = "logic_change"            # Logic frame modified
    CLOCK_CHANGE = "clock_change"            # Clock frame modified
    IO_CHANGE = "io_change"                  # IO frame modified


class SeverityLevel(Enum):
    """Severity levels for anomalies"""
    CRITICAL = "CRITICAL"  # High-confidence Trojan
    HIGH = "HIGH"          # Likely Trojan
    MEDIUM = "MEDIUM"      # Suspicious
    LOW = "LOW"            # Minor difference
    INFO = "INFO"          # Informational


@dataclass
class FrameAnomaly:
    """
    Represents a single frame anomaly
    
    This is the core data structure for representing differences
    between golden and suspect bitstreams.
    """
    # Anomaly identification
    anomaly_id: str
    anomaly_type: AnomalyType
    severity: SeverityLevel
    
    # Frame information
    far_value: int
    far_hex: str
    block_type: int
    block_type_name: str
    column: int
    minor: int
    top_bottom: int
    
    # Spatial location
    tiles_affected: List[str]
    tiles_used: List[str]      # Tiles that are in used set
    tiles_unused: List[str]    # Tiles that are in unused set
    
    # Bit-level differences
    bits_changed: int
    changed_bit_positions: List[int] = field(default_factory=list)
    
    # Frame type classification
    is_routing_frame: bool = False
    is_logic_frame: bool = False
    is_clock_frame: bool = False
    is_io_frame: bool = False
    
    # Golden vs Suspect data
    golden_data: Optional[bytes] = None
    suspect_data: Optional[bytes] = None
    
    # Analysis
    description: str = ""
    suspicion_reason: str = ""
    attack_vectors: List[str] = field(default_factory=list)
    confidence_score: float = 0.0  # 0.0 to 1.0
    transient: bool = False
    
    # Metadata
    detection_timestamp: datetime = field(default_factory=datetime.now)
    
    def is_in_unused_region(self) -> bool:
        """Check if anomaly is primarily in unused region"""
        return len(self.tiles_unused) > len(self.tiles_used)
    
    def get_summary(self) -> str:
        """Get one-line summary of anomaly"""
        return (f"{self.severity.value}: {self.anomaly_type.value} @ "
                f"FAR {self.far_hex} ({self.block_type_name}) "
                f"- {self.bits_changed} bits changed")
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'anomaly_id': self.anomaly_id,
            'type': self.anomaly_type.value,
            'severity': self.severity.value,
            'far': self.far_hex,
            'block_type': self.block_type_name,
            'location': f"X{self.column}Y{self.minor}",
            'tiles_affected': self.tiles_affected,
            'tiles_unused': self.tiles_unused,
            'bits_changed': self.bits_changed,
            'is_routing': self.is_routing_frame,
            'is_unused_region': self.is_in_unused_region(),
            'description': self.description,
            'confidence': self.confidence_score,
            'attack_vectors': self.attack_vectors,
            'transient': self.transient
        }
    
    def __str__(self) -> str:
        return self.get_summary()


@dataclass
class AnomalyCluster:
    """
    Group of related anomalies
    
    Anomalies that are spatially close or functionally related
    may be part of the same Trojan.
    """
    cluster_id: str
    anomalies: List[FrameAnomaly]
    
    # Cluster properties
    center_column: int
    center_y: int
    spatial_extent: Tuple[int, int, int, int]  # (x_min, y_min, x_max, y_max)
    
    # Aggregate severity
    max_severity: SeverityLevel
    avg_confidence: float
    
    # Classification
    cluster_type: str  # "routing_detour", "hidden_logic", "clock_manipulation", etc.
    description: str
    
    def size(self) -> int:
        """Get number of anomalies in cluster"""
        return len(self.anomalies)
    
    def total_bits_changed(self) -> int:
        """Get total bits changed across all anomalies"""
        return sum(a.bits_changed for a in self.anomalies)


class AnomalyReport:
    """
    Complete anomaly detection report
    
    Contains all detected anomalies and summary statistics.
    """
    
    def __init__(self, 
                 golden_id: str,
                 suspect_id: str):
        """
        Initialize anomaly report
        
        Args:
            golden_id: Golden baseline ID
            suspect_id: Suspect bitstream ID
        """
        self.golden_id = golden_id
        self.suspect_id = suspect_id
        self.detection_timestamp = datetime.now()
        
        # Anomalies
        self.anomalies: List[FrameAnomaly] = []
        self.clusters: List[AnomalyCluster] = []
        
        # Statistics
        self.total_frames_compared = 0
        self.frames_with_differences = 0
        self.total_bits_changed = 0
        
        # Severity breakdown
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        
        # Type breakdown
        self.type_counts: Dict[str, int] = {}
        
        # Verdict
        self.trojan_detected: bool = False
        self.confidence: float = 0.0
        self.summary: str = ""
    
    def add_anomaly(self, anomaly: FrameAnomaly) -> None:
        """
        Add an anomaly to the report
        
        Args:
            anomaly: FrameAnomaly to add
        """
        self.anomalies.append(anomaly)
        
        # Update severity counts
        if anomaly.severity == SeverityLevel.CRITICAL:
            self.critical_count += 1
        elif anomaly.severity == SeverityLevel.HIGH:
            self.high_count += 1
        elif anomaly.severity == SeverityLevel.MEDIUM:
            self.medium_count += 1
        elif anomaly.severity == SeverityLevel.LOW:
            self.low_count += 1
        
        # Update type counts
        type_str = anomaly.anomaly_type.value
        if type_str not in self.type_counts:
            self.type_counts[type_str] = 0
        self.type_counts[type_str] += 1
        
        # Update total bits changed
        self.total_bits_changed += anomaly.bits_changed
        
        if anomaly.bits_changed > 0:
            self.frames_with_differences += 1
    
    def finalize(self) -> None:
        """
        Finalize the report and compute verdict
        
        Call this after all anomalies have been added.
        """
        # Determine if Trojan detected
        self.trojan_detected = (self.critical_count > 0 or 
                               self.high_count >= 3)
        
        # Calculate confidence
        if self.anomalies:
            self.confidence = sum(a.confidence_score for a in self.anomalies) / len(self.anomalies)
        
        # Generate summary
        self.summary = self._generate_summary()
    
    def _generate_summary(self) -> str:
        """Generate text summary of findings"""
        routing_mods = len(self.get_routing_anomalies())
        if self.trojan_detected:
            verdict = "TROJAN DETECTED"
        elif self.high_count > 0 or self.medium_count > 0:
            verdict = "SUSPICIOUS MODIFICATIONS FOUND"
        elif len(self.anomalies) > 0 or routing_mods > 0 or self.total_bits_changed > 0:
            verdict = "MODIFICATIONS DETECTED"
        else:
            verdict = "NO SIGNIFICANT ANOMALIES"
        
        summary = [
            f"Detection Report: {verdict}",
            f"",
            f"Compared: {self.golden_id} vs {self.suspect_id}",
            f"Total Frames Compared: {self.total_frames_compared}",
            f"Frames with Differences: {self.frames_with_differences}",
            f"Total Bits Changed: {self.total_bits_changed}",
            f"",
            f"Anomaly Breakdown:",
            f"  CRITICAL: {self.critical_count}",
            f"  HIGH:     {self.high_count}",
            f"  MEDIUM:   {self.medium_count}",
            f"  LOW:      {self.low_count}",
            f"",
            f"Overall Confidence: {self.confidence:.2%}"
        ]
        
        return "\n".join(summary)
    
    def get_critical_anomalies(self) -> List[FrameAnomaly]:
        """Get all critical severity anomalies"""
        return [a for a in self.anomalies if a.severity == SeverityLevel.CRITICAL]
    
    def get_high_severity_anomalies(self) -> List[FrameAnomaly]:
        """Get all high severity anomalies"""
        return [a for a in self.anomalies if a.severity == SeverityLevel.HIGH]
    
    def get_unused_region_anomalies(self) -> List[FrameAnomaly]:
        """Get anomalies in unused regions (prime Trojan candidates)"""
        return [a for a in self.anomalies if a.is_in_unused_region()]
    
    def get_routing_anomalies(self) -> List[FrameAnomaly]:
        """Get routing-related anomalies"""
        return [a for a in self.anomalies if a.is_routing_frame]
    
    def get_anomalies_by_type(self, anomaly_type: AnomalyType) -> List[FrameAnomaly]:
        """Get anomalies of specific type"""
        return [a for a in self.anomalies if a.anomaly_type == anomaly_type]
    
    def get_statistics(self) -> Dict:
        """Get report statistics as dictionary"""
        return {
            'golden_id': self.golden_id,
            'suspect_id': self.suspect_id,
            'timestamp': self.detection_timestamp.isoformat(),
            'total_anomalies': len(self.anomalies),
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
            'frames_compared': self.total_frames_compared,
            'frames_different': self.frames_with_differences,
            'bits_changed': self.total_bits_changed,
            'trojan_detected': self.trojan_detected,
            'confidence': self.confidence,
            'type_breakdown': self.type_counts
        }
    
    def to_json(self) -> Dict:
        """Convert entire report to JSON-serializable dictionary"""
        return {
            'metadata': {
                'golden_id': self.golden_id,
                'suspect_id': self.suspect_id,
                'timestamp': self.detection_timestamp.isoformat(),
                'trojan_detected': self.trojan_detected,
                'confidence': self.confidence
            },
            'statistics': self.get_statistics(),
            'summary': self.summary,
            'anomalies': [a.to_dict() for a in self.anomalies]
        }
    
    def __len__(self) -> int:
        """Return number of anomalies"""
        return len(self.anomalies)
    
    def __str__(self) -> str:
        return self.summary


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'AnomalyType',
    'SeverityLevel',
    'FrameAnomaly',
    'AnomalyCluster',
    'AnomalyReport'
]