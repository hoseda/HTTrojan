"""
Frame Differential Detector - Core Trojan Detection Engine

Implements frame-level differential analysis to detect Trojans
by comparing golden vs suspect bitstreams.

Based on: "Turning the Table: Using Bitstream Reverse Engineering 
          to Detect FPGA Trojans" by Wafi Danesh

Part of: FPGA Trojan Detection System
"""

from typing import List, Set, Dict, Optional, Tuple
from collections import defaultdict
import hashlib

# Import integration layer
from src.mapping.integration.frame_obj_adapter import (
    AdaptedFrame,
    FrameDataExtractor
)

from src.mapping.integration.bitstream_loader import LoadedBitstream
from src.mapping.integration.bitstream_loader import BitstreamLoader

# Import baseline
from src.detector.baseline.golden_baseline import GoldenBaseline

# Import anomaly structures
from src.detector.differential.frame_anomaly import (
    FrameAnomaly,
    AnomalyType,
    SeverityLevel,
    AnomalyReport
)

# Import existing analysis infrastructure
from analysis.assembler.frame_mapper import FrameMapper
from analysis.frame_rules import BlockType


class FrameDifferentialDetector:
    """
    Frame-Level Differential Trojan Detector
    
    Core detection engine that implements the paper's methodology:
    1. Compare golden vs suspect bitstreams frame-by-frame
    2. Identify frames with modifications
    3. Map modifications to physical tiles
    4. Assess if modifications are in unused regions
    5. Classify anomalies by severity and type
    
    Usage:
        detector = FrameDifferentialDetector()
        
        # Load baselines
        golden = GoldenBaseline.load("golden.pkl")
        suspect = bitstream_loader.load("suspect.bit")
        
        # Detect anomalies
        report = detector.detect(golden, suspect)
        
        # Analyze results
        if report.trojan_detected:
            print("TROJAN DETECTED!")
            for anomaly in report.get_critical_anomalies():
                print(f"  {anomaly.get_summary()}")
    """
    
    def __init__(self):
        """Initialize the detector"""
        self.frame_mapper = FrameMapper()
        
        # Detection parameters
        self.min_bits_for_significance = 5  # Minimum changed bits to consider
        self.unused_region_weight = 2.0     # Severity multiplier for unused regions
        
        # Statistics
        self.detections_performed = 0
        self.total_anomalies_found = 0
    
    def detect(self,
              golden: GoldenBaseline,
              suspect: LoadedBitstream,
              verbose: bool = True) -> AnomalyReport:
        """
        Perform differential detection
        
        Main entry point for Trojan detection.
        
        Args:
            golden: Golden baseline (trusted reference)
            suspect: Suspect bitstream to analyze
            verbose: Print progress messages
            
        Returns:
            AnomalyReport with all detected anomalies
        """
        if verbose:
            print("\n" + "="*70)
            print("FPGA Trojan Detection - Differential Analysis")
            print("="*70)
            print(f"Golden:  {golden.baseline_id}")
            print(f"Suspect: {suspect.info.filename}")
            print(f"")
        
        # Create report
        report = AnomalyReport(
            golden_id=golden.baseline_id,
            suspect_id=suspect.info.filename
        )
        
        # Step 1: Find structural differences (added/removed frames)
        if verbose:
            print("[1/4] Analyzing frame structure...")
        
        structural_anomalies = self._detect_structural_differences(
            golden, suspect
        )
        for anomaly in structural_anomalies:
            report.add_anomaly(anomaly)
        
        if verbose:
            print(f"      Found {len(structural_anomalies)} structural differences")
        
        # Step 2: Compare frame data for common frames
        if verbose:
            print("[2/4] Comparing frame data...")
        
        data_anomalies = self._detect_data_differences(
            golden, suspect
        )
        for anomaly in data_anomalies:
            report.add_anomaly(anomaly)
        
        if verbose:
            print(f"      Found {len(data_anomalies)} data modifications")
        
        # Step 3: Classify anomalies by location and type
        if verbose:
            print("[3/4] Classifying anomalies...")
        
        self._classify_anomalies(report.anomalies, golden)
        
        # Step 4: Assess severity and generate verdict
        if verbose:
            print("[4/4] Assessing severity...")
        
        self._assess_severity(report.anomalies, golden)
        
        # Finalize report
        report.total_frames_compared = len(golden) + len(suspect)
        report.finalize()
        
        # Update statistics
        self.detections_performed += 1
        self.total_anomalies_found += len(report.anomalies)
        
        if verbose:
            print(f"")
            print(f"Detection complete: {len(report.anomalies)} anomalies found")
            print("="*70 + "\n")
        
        return report
    
    def _detect_structural_differences(self,
                                      golden: GoldenBaseline,
                                      suspect: LoadedBitstream) -> List[FrameAnomaly]:
        """
        Detect frames added or removed
        
        Args:
            golden: Golden baseline
            suspect: Suspect bitstream
            
        Returns:
            List of structural anomalies
        """
        anomalies = []
        
        golden_fars = golden.get_expected_frames()
        suspect_fars = set(suspect.get_all_far_values())
        
        # Frames added in suspect
        added_fars = suspect_fars - golden_fars
        for far in added_fars:
            anomaly = self._create_added_frame_anomaly(far, suspect)
            if anomaly:
                anomalies.append(anomaly)
        
        # Frames removed from suspect
        removed_fars = golden_fars - suspect_fars
        for far in removed_fars:
            anomaly = self._create_removed_frame_anomaly(far, golden)
            if anomaly:
                anomalies.append(anomaly)
        
        return anomalies
    
    def _create_added_frame_anomaly(self,
                                   far: int,
                                   suspect: LoadedBitstream) -> Optional[FrameAnomaly]:
        """
        Create anomaly for frame added in suspect
        
        Args:
            far: Frame address
            suspect: Suspect bitstream
            
        Returns:
            FrameAnomaly or None
        """
        suspect_frame = suspect.get_frame(far)
        if not suspect_frame:
            return None
        
        # Get frame coverage
        coverage = self.frame_mapper.map_frame(far)
        
        # Generate anomaly ID
        anomaly_id = f"added_{far:08X}"
        
        anomaly = FrameAnomaly(
            anomaly_id=anomaly_id,
            anomaly_type=AnomalyType.FRAME_ADDED,
            severity=SeverityLevel.MEDIUM,  # Will be reassessed
            far_value=far,
            far_hex=f"0x{far:08X}",
            block_type=suspect_frame.block_type,
            block_type_name=BlockType.get_name(suspect_frame.block_type),
            column=suspect_frame.column,
            minor=suspect_frame.minor,
            top_bottom=suspect_frame.top_bottom,
            tiles_affected=list(coverage.tiles_affected),
            tiles_used=[],  # Will be filled by classification
            tiles_unused=[],
            bits_changed=FrameDataExtractor.count_set_bits(suspect_frame.frame_data),
            is_routing_frame=coverage.is_routing_frame,
            is_logic_frame=coverage.is_logic_frame,
            is_clock_frame=coverage.is_clock_frame,
            is_io_frame=coverage.is_io_frame,
            golden_data=None,
            suspect_data=suspect_frame.frame_data,
            description=f"Frame added in suspect (not in golden)",
            suspicion_reason="Unexpected frame configuration"
        )
        
        return anomaly

    def _detect_transient_history_mismatches(self,
                                            golden_frame: AdaptedFrame,
                                            suspect_history: List[AdaptedFrame],
                                            golden_history: List[bytes]) -> List[FrameAnomaly]:
        """
        Detect mismatches in the write sequence (transient modifications)
        """
        anomalies = []
        zipped = min(len(suspect_history), len(golden_history))

        for idx in range(zipped):
            suspect_frame = suspect_history[idx]
            expected_data = golden_history[idx]
            if suspect_frame.frame_data != expected_data:
                anomaly = self._create_modified_frame_anomaly(
                    golden_frame,
                    suspect_frame,
                    is_transient=True,
                    write_index=idx + 1,
                    reference_data=expected_data,
                    transient_note=f"Write #{idx + 1} deviates from golden configuration sequence"
                )
                if anomaly:
                    anomalies.append(anomaly)

        if len(suspect_history) > len(golden_history):
            for idx in range(zipped, len(suspect_history)):
                suspect_frame = suspect_history[idx]
                anomaly = self._create_modified_frame_anomaly(
                    golden_frame,
                    suspect_frame,
                    is_transient=True,
                    write_index=idx + 1,
                    reference_data=golden_frame.frame_data,
                    transient_note=f"Unexpected extra write #{idx + 1} not present in golden history"
                )
                if anomaly:
                    anomalies.append(anomaly)

        return anomalies
    
    def _create_removed_frame_anomaly(self,
                                     far: int,
                                     golden: GoldenBaseline) -> Optional[FrameAnomaly]:
        """
        Create anomaly for frame removed from suspect
        
        Args:
            far: Frame address
            golden: Golden baseline
            
        Returns:
            FrameAnomaly or None
        """
        golden_frame = golden.get_frame(far)
        if not golden_frame:
            return None
        
        # Get frame coverage
        coverage = self.frame_mapper.map_frame(far)
        
        # Generate anomaly ID
        anomaly_id = f"removed_{far:08X}"
        
        anomaly = FrameAnomaly(
            anomaly_id=anomaly_id,
            anomaly_type=AnomalyType.FRAME_REMOVED,
            severity=SeverityLevel.LOW,  # Usually less suspicious
            far_value=far,
            far_hex=f"0x{far:08X}",
            block_type=golden_frame.block_type,
            block_type_name=BlockType.get_name(golden_frame.block_type),
            column=golden_frame.column,
            minor=golden_frame.minor,
            top_bottom=golden_frame.top_bottom,
            tiles_affected=list(coverage.tiles_affected),
            tiles_used=[],
            tiles_unused=[],
            bits_changed=FrameDataExtractor.count_set_bits(golden_frame.frame_data),
            is_routing_frame=coverage.is_routing_frame,
            is_logic_frame=coverage.is_logic_frame,
            is_clock_frame=coverage.is_clock_frame,
            is_io_frame=coverage.is_io_frame,
            golden_data=reference,
            suspect_data=None,
            description=f"Frame removed in suspect (present in golden)",
            suspicion_reason="Missing expected configuration"
        )
        
        return anomaly
    
    def _detect_data_differences(self,
                                golden: GoldenBaseline,
                                suspect: LoadedBitstream) -> List[FrameAnomaly]:
        """
        Detect frames with data modifications
        
        Compares frame data byte-by-byte for common frames.
        
        Args:
            golden: Golden baseline
            suspect: Suspect bitstream
            
        Returns:
            List of data modification anomalies
        """
        anomalies = []
        
        # Get common frames
        golden_fars = golden.get_expected_frames()
        suspect_fars = set(suspect.get_all_far_values())
        common_fars = golden_fars.intersection(suspect_fars)


        print(f"DEBUG: Golden frames: {len(golden_fars)}")
        print(f"DEBUG: Suspect frames: {len(suspect_fars)}")
        print(f"DEBUG: Common frames: {len(common_fars)}")
        
        # Compare each common frame
        for far in common_fars:
            golden_frame = golden.get_frame(far)
            suspect_frame = suspect.get_frame(far)
            
            if not golden_frame or not suspect_frame:
                continue
            
            # Compare final data first
            if golden_frame.frame_data != suspect_frame.frame_data:
                anomaly = self._create_modified_frame_anomaly(
                    golden_frame, suspect_frame
                )
                if anomaly:
                    anomalies.append(anomaly)
                continue

            # Final data matches – inspect write history for hidden modifications
            golden_history = golden.get_write_history(far)
            suspect_history = suspect.get_write_history(far)

            if golden_history and suspect_history:
                transient_anomalies = self._detect_transient_history_mismatches(
                    golden_frame, suspect_history, golden_history
                )
                anomalies.extend(transient_anomalies)
        
        return anomalies

    def _create_modified_frame_anomaly(self,
                                      golden_frame: AdaptedFrame,
                                      suspect_frame: AdaptedFrame,
                                      is_transient: bool = False,
                                      write_index: int = 0,
                                      reference_data: Optional[bytes] = None,
                                      transient_note: Optional[str] = None) -> Optional[FrameAnomaly]:
        """
        Create anomaly for modified frame
        
        Args:
            golden_frame: Frame from golden baseline
            suspect_frame: Frame from suspect bitstream
            
        Returns:
            FrameAnomaly or None
        """
        far = golden_frame.far_value
        
        reference = reference_data if reference_data is not None else golden_frame.frame_data

        # Find bit-level differences
        diff_bits = FrameDataExtractor.compare_frames(
            reference,
            suspect_frame.frame_data
        )
        
        # Skip if too few bits changed (noise threshold)
        if len(diff_bits) < self.min_bits_for_significance:
            return None
        
        # Get frame coverage
        coverage = self.frame_mapper.map_frame(far)
        
        # Determine primary anomaly type
        if coverage.is_routing_frame:
            anomaly_type = AnomalyType.ROUTING_CHANGE
        elif coverage.is_logic_frame:
            anomaly_type = AnomalyType.LOGIC_CHANGE
        elif coverage.is_clock_frame:
            anomaly_type = AnomalyType.CLOCK_CHANGE
        elif coverage.is_io_frame:
            anomaly_type = AnomalyType.IO_CHANGE
        else:
            anomaly_type = AnomalyType.FRAME_MODIFIED
        
        # Generate anomaly ID
        anomaly_id = f"modified_{far:08X}"
        
        description_suffix = " (transient write)" if is_transient else ""
        suspicion_note = transient_note if (is_transient and transient_note) else (
            "Intermediate configuration differed" if is_transient else "Final configuration differs"
        )

        anomaly = FrameAnomaly(
            anomaly_id=anomaly_id,
            anomaly_type=anomaly_type,
            severity=SeverityLevel.MEDIUM,  # Will be reassessed
            far_value=far,
            far_hex=f"0x{far:08X}",
            block_type=golden_frame.block_type,
            block_type_name=BlockType.get_name(golden_frame.block_type),
            column=golden_frame.column,
            minor=golden_frame.minor,
            top_bottom=golden_frame.top_bottom,
            tiles_affected=list(coverage.tiles_affected),
            tiles_used=[],  # Will be filled by classification
            tiles_unused=[],
            bits_changed=len(diff_bits),
            changed_bit_positions=diff_bits[:100],  # Store first 100
            is_routing_frame=coverage.is_routing_frame,
            is_logic_frame=coverage.is_logic_frame,
            is_clock_frame=coverage.is_clock_frame,
            is_io_frame=coverage.is_io_frame,
            golden_data=reference,
            suspect_data=suspect_frame.frame_data,
            description=f"{len(diff_bits)} bits modified in {coverage.block_type_name} frame{description_suffix}",
            suspicion_reason=suspicion_note,
            transient=is_transient,
        )

        if is_transient:
            anomaly.suspicion_reason += f" (write #{write_index})"
            if "transient_payload" not in anomaly.attack_vectors:
                anomaly.attack_vectors.append("transient_payload")
        
        return anomaly
    
    def _classify_anomalies(self,
                           anomalies: List[FrameAnomaly],
                           golden: GoldenBaseline) -> None:
        """
        Classify anomalies by location (used vs unused regions)
        
        This is critical for Trojan detection - modifications in unused
        regions are highly suspicious.
        
        Args:
            anomalies: List of anomalies to classify
            golden: Golden baseline with tile usage info
        """
        for anomaly in anomalies:
            # Classify tiles
            tiles_used = []
            tiles_unused = []
            
            for tile in anomaly.tiles_affected:
                if golden.is_tile_used(tile):
                    tiles_used.append(tile)
                else:
                    tiles_unused.append(tile)
            
            anomaly.tiles_used = tiles_used
            anomaly.tiles_unused = tiles_unused
            
            # Update anomaly type if in unused region
            if len(tiles_unused) > len(tiles_used):
                if anomaly.anomaly_type == AnomalyType.FRAME_MODIFIED:
                    anomaly.anomaly_type = AnomalyType.UNUSED_REGION_MOD
    
    def _assess_severity(self,
                        anomalies: List[FrameAnomaly],
                        golden: GoldenBaseline) -> None:
        """
        Assess severity and confidence for each anomaly
        
        Implements detection heuristics from the paper:
        - Unused region modifications = HIGH/CRITICAL
        - Clock modifications = CRITICAL
        - IO modifications = HIGH
        - Routing modifications = HIGH/MEDIUM
        - Small targeted changes = HIGH (typical Trojan signature)
        
        Args:
            anomalies: List of anomalies to assess
            golden: Golden baseline
        """
        for anomaly in anomalies:
            severity, confidence, reason, vectors = self._calculate_severity(
                anomaly, golden
            )
            
            anomaly.severity = severity
            anomaly.confidence_score = confidence
            anomaly.suspicion_reason = reason
            anomaly.attack_vectors = vectors
    
    def _calculate_severity(self,
                           anomaly: FrameAnomaly,
                           golden: GoldenBaseline) -> Tuple[SeverityLevel, float, str, List[str]]:
        """
        Calculate severity level for an anomaly
        
        Returns:
            (severity, confidence, reason, attack_vectors)
        """
        severity = SeverityLevel.LOW
        confidence = 0.5
        reason = "Standard modification"
        attack_vectors = []
        
        # CRITICAL: Clock network modifications
        if anomaly.is_clock_frame:
            severity = SeverityLevel.CRITICAL
            confidence = 0.95
            reason = "Clock network modification detected (CRITICAL)"
            attack_vectors.append("clock_manipulation")
            attack_vectors.append("timing_attack")
        
        # CRITICAL: IO modifications (data exfiltration risk)
        elif anomaly.is_io_frame and anomaly.is_in_unused_region():
            severity = SeverityLevel.CRITICAL
            confidence = 0.90
            reason = "IO modification in unused region (data exfiltration risk)"
            attack_vectors.append("data_exfiltration")
            attack_vectors.append("covert_channel")
        
        # HIGH: Routing modifications in unused regions
        elif anomaly.is_routing_frame and anomaly.is_in_unused_region():
            severity = SeverityLevel.HIGH
            confidence = 0.85
            reason = "Routing modification in unused region (prime Trojan location)"
            attack_vectors.append("routing_detour")
            attack_vectors.append("hidden_routing_trojan")
            
            # Even higher if small targeted change (typical Trojan)
            if 5 <= anomaly.bits_changed <= 50:
                severity = SeverityLevel.CRITICAL
                confidence = 0.90
                reason = "Small targeted routing change in unused region (TROJAN SIGNATURE)"
                attack_vectors.append("minimal_footprint_trojan")
        
        # HIGH: Routing modifications in used regions (potential detour)
        elif anomaly.is_routing_frame and len(anomaly.tiles_used) > 0:
            severity = SeverityLevel.HIGH
            confidence = 0.70
            reason = "Routing modification in used region (possible detour)"
            attack_vectors.append("routing_detour")
            attack_vectors.append("path_manipulation")
        
        # MEDIUM: Logic modifications in unused regions
        elif anomaly.is_logic_frame and anomaly.is_in_unused_region():
            severity = SeverityLevel.MEDIUM
            confidence = 0.75
            reason = "Logic modification in unused region"
            attack_vectors.append("hidden_logic")
            attack_vectors.append("trojan_payload")
        
        # MEDIUM: Frame added in unused region
        elif anomaly.anomaly_type == AnomalyType.FRAME_ADDED:
            if anomaly.is_in_unused_region():
                severity = SeverityLevel.MEDIUM
                confidence = 0.70
                reason = "Unexpected frame configuration in unused region"
                attack_vectors.append("unauthorized_configuration")
            else:
                severity = SeverityLevel.LOW
                confidence = 0.50
                reason = "Unexpected frame configuration in used region"
        
        # LOW: Frame removed (usually tool differences)
        elif anomaly.anomaly_type == AnomalyType.FRAME_REMOVED:
            severity = SeverityLevel.LOW
            confidence = 0.40
            reason = "Frame removed (likely tool version difference)"
        
        # Transient writes should never be ignored even if final state matches
        if anomaly.transient:
            if "transient_payload" not in attack_vectors:
                attack_vectors.append("transient_payload")
            if severity in {SeverityLevel.LOW, SeverityLevel.MEDIUM}:
                severity = SeverityLevel.HIGH
                confidence = max(confidence, 0.80)
                reason = f"{reason}; transient configuration observed"
            else:
                reason = f"{reason} (transient configuration observed)"
        
        return severity, confidence, reason, attack_vectors
    
    def detect_quick(self,
                    golden_path: str,
                    suspect_path: str) -> AnomalyReport:
        """
        Quick detection from file paths
        
        Convenience method that loads both bitstreams and runs detection.
        
        Args:
            golden_path: Path to golden bitstream or baseline
            suspect_path: Path to suspect bitstream
            
        Returns:
            AnomalyReport
        """
        
        # Load golden
        if golden_path.endswith('.pkl'):
            golden = GoldenBaseline.load(golden_path)
        else:
            from src.detector.baseline.baseline_builder import GoldenBaselineBuilder
            builder = GoldenBaselineBuilder()
            golden = builder.build_from_bitstream(golden_path)
        
        # Load suspect
        loader = BitstreamLoader()
        suspect = loader.load(suspect_path)
        
        if not golden or not suspect:
            raise ValueError("Failed to load golden or suspect bitstream")
        
        # Run detection
        return self.detect(golden, suspect)
    
    def get_statistics(self) -> Dict:
        """
        Get detector statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'detections_performed': self.detections_performed,
            'total_anomalies_found': self.total_anomalies_found,
            'avg_anomalies_per_detection': (
                self.total_anomalies_found / self.detections_performed
                if self.detections_performed > 0 else 0
            )
        }
    
# ============================================================================
# Convenience Functions
# ============================================================================

def quick_detect(golden_path: str, suspect_path: str) -> AnomalyReport:
    """
    Quick Trojan detection from file paths
    
    Args:
        golden_path: Path to golden bitstream (.bit) or baseline (.pkl)
        suspect_path: Path to suspect bitstream (.bit)
        
    Returns:
        AnomalyReport with detection results
    """
    detector = FrameDifferentialDetector()
    return detector.detect_quick(golden_path, suspect_path)


def detect_and_print(golden_path: str, suspect_path: str) -> None:
    """
    Detect and print results immediately
    
    Args:
        golden_path: Path to golden bitstream/baseline
        suspect_path: Path to suspect bitstream
    """
    report = quick_detect(golden_path, suspect_path)
    
    print("\n" + "="*70)
    print(report.summary)
    print("="*70)
    
    if report.trojan_detected:
        print("\n⚠️  TROJAN DETECTED - CRITICAL FINDINGS:")
        for anomaly in report.get_critical_anomalies():
            print(f"\n  {anomaly.get_summary()}")
            print(f"     Location: {anomaly.tiles_affected[:3]}...")
            print(f"     Reason: {anomaly.suspicion_reason}")
    
    print("\n")


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'FrameDifferentialDetector',
    'quick_detect',
    'detect_and_print'
]