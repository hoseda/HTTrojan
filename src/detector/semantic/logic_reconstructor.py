# logic_reconstructor.py
"""
Logic Configuration Reconstructor
Extracts LUT truth tables and FF configurations from bitstream

Phase 2.3: Convert logic frame bits to configured logic state
Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

# Import semantic extraction
from src.detector.semantic.bit_semantics import FrameBitExtractor

# Import integration layer
from src.mapping.integration.bitstream_loader import LoadedBitstream
from src.mapping.integration.frame_obj_adapter import AdaptedFrame

# Import analysis infrastructure
from analysis.assembler.frame_mapper import FrameMapper
from analysis.frame_rules import BlockType


@dataclass(frozen=True)
class LUTConfiguration:
    """
    Configuration of a single LUT
    """
    tile_name: str
    slice_name: str
    lut_name: str  # 'A', 'B', 'C', or 'D'
    truth_table: int  # 64-bit init value
    frame_address: int
    
    def is_initialized(self) -> bool:
        """Check if LUT has non-zero configuration"""
        return self.truth_table != 0
    
    def is_constant(self) -> bool:
        """Check if LUT outputs constant (all 0s or all 1s)"""
        return self.truth_table == 0 or self.truth_table == 0xFFFFFFFFFFFFFFFF
    
    def get_input_count(self) -> int:
        """Estimate number of inputs used (simplified)"""
        # Real implementation would analyze truth table structure
        if self.is_constant():
            return 0
        # For now, assume max inputs if not constant
        return 6
    
    def __str__(self):
        return f"LUT_{self.lut_name}[{self.slice_name}] = 0x{self.truth_table:016X}"


@dataclass(frozen=True)
class FFConfiguration:
    """
    Configuration of a flip-flop
    """
    tile_name: str
    slice_name: str
    ff_name: str
    init_value: bool
    clock_enable: bool
    set_reset: bool
    frame_address: int
    
    def __str__(self):
        return (f"FF_{self.ff_name}[{self.slice_name}] "
                f"INIT={self.init_value} CE={self.clock_enable} SR={self.set_reset}")


@dataclass
class SliceConfiguration:
    """
    Complete configuration of a SLICE
    
    A SLICE contains:
    - 4 LUTs (A, B, C, D)
    - 4 FFs
    - Multiplexers
    - Carry chain logic
    """
    tile_name: str
    slice_name: str
    luts: Dict[str, LUTConfiguration] = field(default_factory=dict)
    ffs: Dict[str, FFConfiguration] = field(default_factory=dict)
    
    def is_used(self) -> bool:
        """Check if slice has any configuration"""
        return any(lut.is_initialized() for lut in self.luts.values())
    
    def get_logic_depth(self) -> int:
        """Estimate logic depth (number of active LUTs)"""
        return sum(1 for lut in self.luts.values() if lut.is_initialized())


@dataclass
class LogicConfiguration:
    """
    Complete logic configuration state from a bitstream
    
    Contains all LUT configurations, FF states, and slice properties.
    """
    bitstream_id: str
    luts: Dict[Tuple[str, str], LUTConfiguration] = field(default_factory=dict)  # (tile, lut_name) -> config
    ffs: Dict[Tuple[str, str], FFConfiguration] = field(default_factory=dict)
    slices: Dict[Tuple[str, str], SliceConfiguration] = field(default_factory=dict)  # (tile, slice) -> config
    
    def add_lut(self, lut: LUTConfiguration):
        """Add LUT configuration"""
        key = (lut.tile_name, lut.lut_name)
        self.luts[key] = lut
        
        # Update slice
        slice_key = (lut.tile_name, lut.slice_name)
        if slice_key not in self.slices:
            self.slices[slice_key] = SliceConfiguration(
                tile_name=lut.tile_name,
                slice_name=lut.slice_name
            )
        self.slices[slice_key].luts[lut.lut_name] = lut
    
    def add_ff(self, ff: FFConfiguration):
        """Add FF configuration"""
        key = (ff.tile_name, ff.ff_name)
        self.ffs[key] = ff
        
        # Update slice
        slice_key = (ff.tile_name, ff.slice_name)
        if slice_key not in self.slices:
            self.slices[slice_key] = SliceConfiguration(
                tile_name=ff.tile_name,
                slice_name=ff.slice_name
            )
        self.slices[slice_key].ffs[ff.ff_name] = ff
    
    def get_lut(self, tile_name: str, lut_name: str) -> Optional[LUTConfiguration]:
        """Get LUT configuration"""
        return self.luts.get((tile_name, lut_name))
    
    def get_slice(self, tile_name: str, slice_name: str) -> Optional[SliceConfiguration]:
        """Get slice configuration"""
        return self.slices.get((tile_name, slice_name))
    
    def get_used_tiles(self) -> Set[str]:
        """Get all tiles with logic configuration"""
        tiles = set()
        for lut in self.luts.values():
            if lut.is_initialized():
                tiles.add(lut.tile_name)
        return tiles
    
    def get_statistics(self) -> Dict:
        """Get logic statistics"""
        initialized_luts = sum(1 for lut in self.luts.values() if lut.is_initialized())
        used_slices = sum(1 for s in self.slices.values() if s.is_used())
        
        return {
            'total_luts': len(self.luts),
            'initialized_luts': initialized_luts,
            'total_ffs': len(self.ffs),
            'total_slices': len(self.slices),
            'used_slices': used_slices,
            'tiles_with_logic': len(self.get_used_tiles())
        }


class LogicReconstructor:
    """
    Logic Configuration Reconstruction Engine
    
    Extracts LUT truth tables and FF configurations from bitstream.
    This tells us what logic functions are implemented.
    
    Usage:
        reconstructor = LogicReconstructor()
        logic = reconstructor.reconstruct(loaded_bitstream)
        print(f"Found {len(logic.luts)} configured LUTs")
    """
    
    def __init__(self):
        """Initialize logic reconstructor"""
        self.frame_mapper = FrameMapper()
        self.bit_extractor = FrameBitExtractor()
    
    def reconstruct(self, bitstream: LoadedBitstream,
                   verbose: bool = True) -> LogicConfiguration:
        """
        Reconstruct logic configuration from bitstream
        
        Args:
            bitstream: Loaded bitstream to analyze
            verbose: Print progress messages
            
        Returns:
            LogicConfiguration with all LUT/FF configs
        """
        if verbose:
            print(f"\nReconstructing logic configuration from {bitstream.info.filename}")
        
        logic_config = LogicConfiguration(
            bitstream_id=bitstream.info.filename
        )
        
        # Process all frames
        frame_count = 0
        logic_frame_count = 0
        
        for frame in bitstream:
            frame_count += 1
            
            # Get frame coverage
            coverage = self.frame_mapper.map_frame(frame.far_value)
            
            # Only process logic frames in CLB columns
            if not coverage.is_logic_frame or coverage.block_type_id != BlockType.CLB:
                continue
            
            logic_frame_count += 1
            
            # Extract LUTs and FFs from this frame
            self._extract_logic_from_frame(frame, coverage, logic_config)
            
            if verbose and frame_count % 100 == 0:
                stats = logic_config.get_statistics()
                print(f"  Processed {frame_count} frames, "
                      f"found {stats['initialized_luts']} LUTs...")
        
        if verbose:
            stats = logic_config.get_statistics()
            print(f"\nLogic reconstruction complete:")
            print(f"  Total frames: {frame_count}")
            print(f"  Logic frames: {logic_frame_count}")
            print(f"  Total LUTs: {stats['total_luts']}")
            print(f"  Initialized LUTs: {stats['initialized_luts']}")
            print(f"  Total FFs: {stats['total_ffs']}")
            print(f"  Used slices: {stats['used_slices']}")
        
        return logic_config
    
    def _extract_logic_from_frame(self, frame: AdaptedFrame,
                                   coverage,
                                   logic_config: LogicConfiguration):
        """
        Extract LUT and FF configurations from a logic frame
        
        Args:
            frame: Frame to analyze
            coverage: Frame coverage information
            logic_config: Logic configuration to update
        """
        # For each tile affected by this frame
        for tile_name in coverage.tiles_affected:
            # Only process CLB tiles
            if 'CLB' not in tile_name:
                continue
            
            # Extract LUTs (simplified - assumes slice naming)
            for slice_idx in range(2):  # 2 slices per CLB
                slice_name = f"SLICE_{slice_idx}"
                
                # Extract 4 LUTs per slice
                for lut_name in ['A', 'B', 'C', 'D']:
                    try:
                        truth_table = self.bit_extractor.extract_lut_truth_table(
                            frame.frame_data, lut_name
                        )
                        
                        lut = LUTConfiguration(
                            tile_name=tile_name,
                            slice_name=slice_name,
                            lut_name=lut_name,
                            truth_table=truth_table,
                            frame_address=frame.far_value
                        )
                        
                        logic_config.add_lut(lut)
                    except:
                        continue
                
                # Extract FFs (simplified)
                for ff_idx in range(4):
                    try:
                        ff_name = f"FF_{ff_idx}"
                        
                        # Extract FF control bits (approximate positions)
                        base_bit = 1088 + (ff_idx * 8)
                        init_val = self.bit_extractor.extract_bit(frame.frame_data, base_bit)
                        ce = self.bit_extractor.extract_bit(frame.frame_data, base_bit + 1)
                        sr = self.bit_extractor.extract_bit(frame.frame_data, base_bit + 2)
                        
                        ff = FFConfiguration(
                            tile_name=tile_name,
                            slice_name=slice_name,
                            ff_name=ff_name,
                            init_value=init_val,
                            clock_enable=ce,
                            set_reset=sr,
                            frame_address=frame.far_value
                        )
                        
                        logic_config.add_ff(ff)
                    except:
                        continue
    
    def compare_logic(self, golden_logic: LogicConfiguration,
                     suspect_logic: LogicConfiguration) -> Dict:
        """
        Compare two logic configurations
        
        Finds LUT truth table differences - key for Trojan detection.
        
        Args:
            golden_logic: Golden reference logic
            suspect_logic: Suspect logic to analyze
            
        Returns:
            Dictionary with comparison results
        """
        # Get all LUT keys
        golden_keys = set(golden_logic.luts.keys())
        suspect_keys = set(suspect_logic.luts.keys())
        
        common_keys = golden_keys.intersection(suspect_keys)
        added_luts = suspect_keys - golden_keys
        removed_luts = golden_keys - suspect_keys
        
        # Check for truth table modifications
        modified_luts = []
        for key in common_keys:
            golden_lut = golden_logic.luts[key]
            suspect_lut = suspect_logic.luts[key]
            
            if golden_lut.truth_table != suspect_lut.truth_table:
                modified_luts.append({
                    'tile': key[0],
                    'lut': key[1],
                    'golden_tt': f"0x{golden_lut.truth_table:016X}",
                    'suspect_tt': f"0x{suspect_lut.truth_table:016X}",
                    'bits_changed': bin(golden_lut.truth_table ^ suspect_lut.truth_table).count('1')
                })
        
        return {
            'golden_lut_count': len(golden_keys),
            'suspect_lut_count': len(suspect_keys),
            'common_luts': len(common_keys),
            'added_luts': len(added_luts),
            'removed_luts': len(removed_luts),
            'modified_luts': len(modified_luts),
            'modifications': modified_luts[:20]  # Show first 20
        }
    
    def visualize_logic_diff(self, golden_logic: LogicConfiguration,
                            suspect_logic: LogicConfiguration):
        """
        Print visual diff of logic changes
        
        Args:
            golden_logic: Golden logic
            suspect_logic: Suspect logic
        """
        comparison = self.compare_logic(golden_logic, suspect_logic)
        
        print("\n" + "="*70)
        print("Logic Configuration Comparison")
        print("="*70)
        print(f"Golden LUTs:   {comparison['golden_lut_count']}")
        print(f"Suspect LUTs:  {comparison['suspect_lut_count']}")
        print(f"Common:        {comparison['common_luts']}")
        print(f"Modified:      {comparison['modified_luts']}")
        print(f"")
        
        if comparison['modified_luts'] > 0:
            print(f"Modified LUT truth tables:")
            for mod in comparison['modifications']:
                print(f"  {mod['tile']} LUT_{mod['lut']}:")
                print(f"    Golden:  {mod['golden_tt']}")
                print(f"    Suspect: {mod['suspect_tt']}")
                print(f"    Changed: {mod['bits_changed']} bits")
            
            if comparison['modified_luts'] > 20:
                print(f"  ... and {comparison['modified_luts'] - 20} more")
        
        print("="*70 + "\n")


class SemanticLogicAnalyzer:
    """
    Semantic analysis of logic modifications
    
    Goes beyond raw truth table comparison to understand
    what a logic change actually does functionally.
    """
    
    def __init__(self):
        """Initialize semantic analyzer"""
        pass
    
    def analyze_lut_modification(self, golden_tt: int, suspect_tt: int) -> Dict:
        """
        Analyze what a LUT truth table modification does
        
        Args:
            golden_tt: Golden truth table
            suspect_tt: Suspect truth table
            
        Returns:
            Dictionary with semantic analysis
        """
        # XOR to find changed bits
        changed_bits = golden_tt ^ suspect_tt
        num_changed = bin(changed_bits).count('1')
        
        # Classify change type
        if num_changed == 0:
            change_type = "no_change"
        elif num_changed <= 4:
            change_type = "minimal_targeted"  # Suspicious for Trojan
        elif num_changed <= 16:
            change_type = "moderate"
        elif num_changed <= 32:
            change_type = "substantial"
        else:
            change_type = "complete_rewrite"
        
        # Check if changes from/to constant
        golden_constant = (golden_tt == 0 or golden_tt == 0xFFFFFFFFFFFFFFFF)
        suspect_constant = (suspect_tt == 0 or suspect_tt == 0xFFFFFFFFFFFFFFFF)
        
        if not golden_constant and suspect_constant:
            semantic = "function_disabled"
            severity = "medium"
        elif golden_constant and not suspect_constant:
            semantic = "function_enabled"  # New logic = suspicious
            severity = "high"
        elif change_type == "minimal_targeted":
            semantic = "targeted_modification"  # Prime Trojan signature
            severity = "critical"
        else:
            semantic = "function_changed"
            severity = "medium"
        
        return {
            'bits_changed': num_changed,
            'change_type': change_type,
            'semantic': semantic,
            'severity': severity,
            'golden_constant': golden_constant,
            'suspect_constant': suspect_constant
        }


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'LUTConfiguration',
    'FFConfiguration',
    'SliceConfiguration',
    'LogicConfiguration',
    'LogicReconstructor',
    'SemanticLogicAnalyzer'
]