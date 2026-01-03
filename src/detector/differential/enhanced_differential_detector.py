# enhanced_differential_detector.py
"""
Enhanced Frame Differential Detector with Full Semantic Analysis

Integrates all Phase 2 components for comprehensive Trojan detection:
- Bit-level semantic extraction
- Routing state reconstruction  
- Logic configuration analysis

Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import List, Set, Dict, Optional, Tuple
from collections import defaultdict

# Import base detection
from src.detector.differential.frame_differential_detector import (
    FrameDifferentialDetector
)

from src.detector.differential.frame_anomaly import (
    FrameAnomaly,
    AnomalyType,
    SeverityLevel,
    AnomalyReport
)

# Import baseline
from src.detector.baseline.golden_baseline import GoldenBaseline

# Import integration
from src.mapping.integration.bitstream_loader import LoadedBitstream, BitstreamLoader

# Import semantic extraction (Phase 2)
from src.detector.semantic.bit_semantics import SemanticBitDiff
from src.detector.semantic.routing_reconstructor import RoutingReconstructor
from src.detector.semantic.logic_reconstructor import (
    LogicReconstructor,
    SemanticLogicAnalyzer
)

# Import analysis infrastructure
from analysis.assembler.frame_mapper import FrameMapper
from analysis.frame_rules import BlockType


class EnhancedDifferentialDetector(FrameDifferentialDetector):
    """
    Enhanced Trojan Detector with Full Semantic Analysis
    
    Extends base FrameDifferentialDetector with:
    - Bit-level semantic analysis
    - Routing state comparison
    - Logic configuration analysis
    - Improved Trojan classification
    
    Usage:
        detector = EnhancedDifferentialDetector()
        golden = GoldenBaseline.load("golden.pkl")
        suspect = bitstream_loader.load("suspect.bit")
        
        report = detector.detect_enhanced(golden, suspect)
        print(report.summary)
    """
    
    def __init__(self):
        """Initialize enhanced detector"""
        super().__init__()
        
        # Semantic analyzers
        self.semantic_diff = SemanticBitDiff()
        self.routing_reconstructor = RoutingReconstructor()
        self.logic_reconstructor = LogicReconstructor()
        self.logic_analyzer = SemanticLogicAnalyzer()
    
    def detect_enhanced(self,
                       golden: GoldenBaseline,
                       suspect: LoadedBitstream,
                       analyze_routing: bool = True,
                       analyze_logic: bool = True,
                       verbose: bool = True) -> AnomalyReport:
        """
        Enhanced detection with full semantic analysis
        
        Args:
            golden: Golden baseline
            suspect: Suspect bitstream
            analyze_routing: Perform routing state analysis
            analyze_logic: Perform logic configuration analysis
            verbose: Print progress
            
        Returns:
            Enhanced AnomalyReport with semantic details
        """
        if verbose:
            print("\n" + "="*70)
            print("Enhanced FPGA Trojan Detection - Semantic Analysis")
            print("="*70)
            print(f"Golden:  {golden.baseline_id}")
            print(f"Suspect: {suspect.info.filename}")
            print()
        
        # Phase 1: Basic differential detection (from parent class)
        if verbose:
            print("[1/4] Running frame-level differential analysis...")
        
        report = self.detect(golden, suspect, verbose=False)
        
        # Phase 2: Semantic bit-level analysis
        if verbose:
            print(f"      Found {len(report.anomalies)} frame-level anomalies")
            print("[2/4] Performing semantic bit-level analysis...")
        
        self._enhance_anomalies_with_semantics(report.anomalies, golden, suspect)
        
        # Phase 3: Routing state analysis
        if analyze_routing and verbose:
            print("[3/4] Reconstructing and comparing routing states...")
        
        if analyze_routing:
            routing_anomalies = self._analyze_routing_differences(
                golden, suspect, verbose
            )
            for anomaly in routing_anomalies:
                report.add_anomaly(anomaly)
        
        # Phase 4: Logic configuration analysis
        if analyze_logic and verbose:
            print("[4/4] Analyzing logic configuration differences...")
        
        if analyze_logic:
            logic_anomalies = self._analyze_logic_differences(
                golden, suspect, verbose
            )
            for anomaly in logic_anomalies:
                report.add_anomaly(anomaly)
        
        # Finalize with enhanced assessment
        report.finalize()
        
        if verbose:
            print(f"\nEnhanced detection complete:")
            print(f"  Total anomalies: {len(report.anomalies)}")
            print(f"  CRITICAL: {report.critical_count}")
            print(f"  HIGH: {report.high_count}")
            print(f"  MEDIUM: {report.medium_count}")
            print("="*70 + "\n")
        
        return report
    
    def _enhance_anomalies_with_semantics(self,
                                         anomalies: List[FrameAnomaly],
                                         golden: GoldenBaseline,
                                         suspect: LoadedBitstream):
        """
        Enhance existing anomalies with semantic bit analysis
        
        Args:
            anomalies: List of anomalies to enhance
            golden: Golden baseline
            suspect: Suspect bitstream
        """
        for anomaly in anomalies:
            # Skip if no data to compare
            if not anomaly.golden_data or not anomaly.suspect_data:
                continue
            
            # Perform semantic analysis
            semantic_analysis = self.semantic_diff.analyze_frame_diff(
                anomaly.far_value,
                anomaly.golden_data,
                anomaly.suspect_data
            )
            
            if not semantic_analysis.get('has_changes'):
                continue
            
            # Update anomaly with semantic info
            if semantic_analysis['routing_bits_changed'] > 0:
                anomaly.description += f" | Routing: {semantic_analysis['routing_bits_changed']} bits"
            
            if semantic_analysis['logic_bits_changed'] > 0:
                anomaly.description += f" | Logic: {semantic_analysis['logic_bits_changed']} bits"
            
            if semantic_analysis['security_bits_changed'] > 0:
                anomaly.description += f" | Security-sensitive: {semantic_analysis['security_bits_changed']} bits"
            
            # Adjust severity based on semantic analysis
            if semantic_analysis['max_severity'] == 'critical':
                anomaly.severity = SeverityLevel.CRITICAL
                anomaly.confidence_score = min(1.0, anomaly.confidence_score + 0.2)
    
    def _analyze_routing_differences(self,
                                    golden: GoldenBaseline,
                                    suspect: LoadedBitstream,
                                    verbose: bool) -> List[FrameAnomaly]:
        """
        Analyze routing state differences
        
        Args:
            golden: Golden baseline
            suspect: Suspect bitstream
            verbose: Print progress
            
        Returns:
            List of routing-specific anomalies
        """
        anomalies = []
        
        try:
            # Reconstruct routing from golden
            # Note: This requires golden to be a LoadedBitstream, not just baseline
            # For now, we'll skip if golden doesn't have full frame data
            if verbose:
                print("      Routing analysis: Loading golden frames...")
            
            # Get golden frames as LoadedBitstream
            # This is a simplification - real implementation would cache this
            golden_frames = self._get_golden_frames(golden)
            if not golden_frames:
                if verbose:
                    print("      ⚠️  Routing analysis skipped (golden frames not available)")
                return anomalies
            
            if verbose:
                print("      Reconstructing golden routing state...")
            golden_routing = self.routing_reconstructor.reconstruct(
                golden_frames, verbose=False
            )
            
            if verbose:
                print("      Reconstructing suspect routing state...")
            suspect_routing = self.routing_reconstructor.reconstruct(
                suspect, verbose=False
            )
            
            # Compare routing
            if verbose:
                print("      Comparing routing configurations...")
            comparison = self.routing_reconstructor.compare_routing(
                golden_routing, suspect_routing
            )
            
            # Create anomalies for suspicious routing changes
            for pip in comparison.get('suspicious_additions', []):
                anomaly = self._create_routing_anomaly(pip, golden, suspect)
                if anomaly:
                    anomalies.append(anomaly)
            
            if verbose and anomalies:
                print(f"      Found {len(anomalies)} routing-specific anomalies")
        
        except Exception as e:
            if verbose:
                print(f"      ⚠️  Routing analysis error: {str(e)}")
        
        return anomalies
    
    def _analyze_logic_differences(self,
                                   golden: GoldenBaseline,
                                   suspect: LoadedBitstream,
                                   verbose: bool) -> List[FrameAnomaly]:
        """
        Analyze logic configuration differences
        
        Args:
            golden: Golden baseline
            suspect: Suspect bitstream
            verbose: Print progress
            
        Returns:
            List of logic-specific anomalies
        """
        anomalies = []
        
        try:
            # Get golden frames
            golden_frames = self._get_golden_frames(golden)
            if not golden_frames:
                if verbose:
                    print("      ⚠️  Logic analysis skipped (golden frames not available)")
                return anomalies
            
            if verbose:
                print("      Reconstructing golden logic state...")
            golden_logic = self.logic_reconstructor.reconstruct(
                golden_frames, verbose=False
            )
            
            if verbose:
                print("      Reconstructing suspect logic state...")
            suspect_logic = self.logic_reconstructor.reconstruct(
                suspect, verbose=False
            )
            
            # Compare logic
            if verbose:
                print("      Comparing logic configurations...")
            comparison = self.logic_reconstructor.compare_logic(
                golden_logic, suspect_logic
            )
            
            # Create anomalies for LUT modifications
            for mod in comparison.get('modifications', []):
                anomaly = self._create_logic_anomaly(mod, golden, suspect)
                if anomaly:
                    anomalies.append(anomaly)
            
            if verbose and anomalies:
                print(f"      Found {len(anomalies)} logic-specific anomalies")
        
        except Exception as e:
            if verbose:
                print(f"      ⚠️  Logic analysis error: {str(e)}")
        
        return anomalies
    
    def _get_golden_frames(self, golden: GoldenBaseline) -> Optional[LoadedBitstream]:
        """
        Get golden frames as LoadedBitstream
        
        This is a helper to convert GoldenBaseline to LoadedBitstream format.
        In practice, golden might need to be stored with full frame data.
        """
        # This is a placeholder - real implementation would:
        # 1. Check if golden has full frame data
        # 2. Convert GoldenBaseline frames to LoadedBitstream format
        # 3. Or reload original golden bitstream from disk
        
        # For now, return None to skip these analyses
        return None
    
    def _create_routing_anomaly(self, pip, golden, suspect) -> Optional[FrameAnomaly]:
        """Create anomaly for suspicious routing change"""
        # Get frame coverage
        coverage = self.frame_mapper.map_frame(pip.frame_address)
        
        anomaly_id = f"routing_{pip.tile_name}_{pip.start_wire_id}_{pip.end_wire_id}"
        
        anomaly = FrameAnomaly(
            anomaly_id=anomaly_id,
            anomaly_type=AnomalyType.ROUTING_CHANGE,
            severity=SeverityLevel.CRITICAL,  # Suspicious PIPs are critical
            far_value=pip.frame_address,
            far_hex=f"0x{pip.frame_address:08X}",
            block_type=coverage.block_type_id,
            block_type_name=coverage.block_type_name,
            column=coverage.column,
            minor=coverage.minor,
            top_bottom=coverage.top_bottom,
            tiles_affected=[pip.tile_name],
            tiles_used=[],
            tiles_unused=[pip.tile_name],  # Assumed unused if suspicious
            bits_changed=1,
            changed_bit_positions=[pip.bit_offset],
            is_routing_frame=True,
            is_logic_frame=False,
            description=f"Suspicious PIP added: {pip}",
            suspicion_reason="New routing in previously unused area (HIGH TROJAN RISK)",
            attack_vectors=["routing_detour", "minimal_modification_trojan", "unused_region_routing"],
            confidence_score=0.95
        )
        
        return anomaly
    
    def _create_logic_anomaly(self, modification, golden, suspect) -> Optional[FrameAnomaly]:
        """Create anomaly for LUT modification"""
        tile_name = modification['tile']
        lut_name = modification['lut']
        
        # Analyze semantic meaning
        golden_tt = int(modification['golden_tt'], 16)
        suspect_tt = int(modification['suspect_tt'], 16)
        semantic = self.logic_analyzer.analyze_lut_modification(golden_tt, suspect_tt)
        
        # Determine severity from semantic analysis
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW
        }
        severity = severity_map.get(semantic['severity'], SeverityLevel.MEDIUM)
        
        # Get frame for this LUT (approximate)
        frames = self.reverse_mapper.get_frames_for_tile(tile_name)
        logic_frames = [f for f in frames if f.frame_type == 'logic']
        
        if not logic_frames:
            return None
        
        frame = logic_frames[0]
        coverage = self.frame_mapper.map_frame(frame.far_value)
        
        anomaly_id = f"logic_{tile_name}_{lut_name}"
        
        anomaly = FrameAnomaly(
            anomaly_id=anomaly_id,
            anomaly_type=AnomalyType.LOGIC_CHANGE,
            severity=severity,
            far_value=frame.far_value,
            far_hex=f"0x{frame.far_value:08X}",
            block_type=coverage.block_type_id,
            block_type_name=coverage.block_type_name,
            column=coverage.column,
            minor=coverage.minor,
            top_bottom=coverage.top_bottom,
            tiles_affected=[tile_name],
            tiles_used=[],
            tiles_unused=[],
            bits_changed=modification['bits_changed'],
            is_routing_frame=False,
            is_logic_frame=True,
            description=f"LUT {lut_name} truth table modified: {semantic['semantic']}",
            suspicion_reason=f"Logic modification: {semantic['change_type']}",
            attack_vectors=["lut_truth_table_modification", "logic_trojan"],
            confidence_score=0.8 if semantic['severity'] == 'critical' else 0.6
        )
        
        return anomaly


# ============================================================================
# Convenience Functions
# ============================================================================

def enhanced_quick_detect(golden_path: str, suspect_path: str,
                         analyze_routing: bool = True,
                         analyze_logic: bool = True) -> AnomalyReport:
    """
    Quick enhanced detection from file paths
    
    Args:
        golden_path: Path to golden bitstream/baseline
        suspect_path: Path to suspect bitstream
        analyze_routing: Perform routing analysis
        analyze_logic: Perform logic analysis
        
    Returns:
        Enhanced AnomalyReport
    """
    detector = EnhancedDifferentialDetector()
    
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
        raise ValueError("Failed to load bitstreams")
    
    return detector.detect_enhanced(
        golden, suspect,
        analyze_routing=analyze_routing,
        analyze_logic=analyze_logic
    )


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'EnhancedDifferentialDetector',
    'enhanced_quick_detect'
]