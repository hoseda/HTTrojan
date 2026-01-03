"""
Baseline Builder - Golden Reference Construction

Builds GoldenBaseline from bitstreams and provides utilities
for baseline management and tile usage analysis.

Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import Set, List, Optional, Dict
from pathlib import Path
from datetime import datetime

# Import integration layer
from src.mapping.integration.bitstream_loader import (
    BitstreamLoader,
    LoadedBitstream
)

from src.mapping.integration.frame_obj_adapter import FrameDataExtractor
from src.mapping.integration.frame_obj_adapter import AdaptedFrame

# Import baseline
from src.detector.baseline.golden_baseline import GoldenBaseline

# Import existing analysis infrastructure
from analysis.assembler.frame_mapper import FrameMapper
from analysis.assembler.reverse_mapper import ReverseMapper


class GoldenBaselineBuilder:
    """
    Builder for creating GoldenBaseline instances
    
    Provides high-level methods to construct golden baselines
    from bitstreams, with optional tile usage analysis.
    
    Usage:
        builder = GoldenBaselineBuilder()
        
        # Build from bitstream file
        golden = builder.build_from_bitstream("golden.bit")
        
        # Add tile usage information (optional but recommended)
        used_tiles = builder.extract_used_tiles_from_frames(golden)
        golden.set_used_tiles(used_tiles)
        
        # Save for later use
        golden.save("golden_baseline.pkl")
    """
    
    def __init__(self):
        """Initialize the builder"""
        self.bitstream_loader = BitstreamLoader()
        self.frame_mapper = FrameMapper()
        self.reverse_mapper = ReverseMapper()
        
        # Statistics
        self.baselines_created = 0
    
    def build_from_bitstream(self, 
                            bitstream_path: str,
                            baseline_id: Optional[str] = None,
                            auto_detect_usage: bool = True) -> Optional[GoldenBaseline]:
        """
        Build golden baseline from bitstream file
        
        Args:
            bitstream_path: Path to golden bitstream (.bit)
            baseline_id: Optional custom ID (uses filename if None)
            auto_detect_usage: Automatically detect used tiles
            
        Returns:
            GoldenBaseline or None on error
        """
        try:
            # Load bitstream using existing infrastructure
            loaded_bs = self.bitstream_loader.load(bitstream_path)
            
            if not loaded_bs:
                print(f"Failed to load bitstream: {bitstream_path}")
                return None
            
            # Create baseline ID
            if baseline_id is None:
                baseline_id = f"golden_{loaded_bs.info.filename}_{int(datetime.now().timestamp())}"
            
            # Create golden baseline
            golden = GoldenBaseline(baseline_id)
            
            # Store bitstream info
            golden.info = loaded_bs.info
            golden.bitstream_hash = loaded_bs.info.compute_hash()
            
            # Add all frames and capture write history
            golden.add_frames(loaded_bs.frames)
            golden.set_bulk_write_history({far: [frame.frame_data for frame in history]
                                           for far, history in loaded_bs._write_history.items()})
            
            # Auto-detect used tiles if requested
            if auto_detect_usage:
                used_tiles = self.extract_used_tiles_from_frames(loaded_bs)
                golden.set_used_tiles(used_tiles)
            
            # Validate
            is_valid, errors = golden.validate()
            if not is_valid:
                print(f"Warning: Golden baseline validation failed:")
                for error in errors:
                    print(f"  - {error}")
            
            self.baselines_created += 1
            
            return golden
            
        except Exception as e:
            print(f"Error building golden baseline: {str(e)}")
            return None
    
    def build_from_loaded(self,
                         loaded_bitstream: LoadedBitstream,
                         baseline_id: Optional[str] = None) -> GoldenBaseline:
        """
        Build golden baseline from already-loaded bitstream
        
        Args:
            loaded_bitstream: LoadedBitstream instance
            baseline_id: Optional custom ID
            
        Returns:
            GoldenBaseline
        """
        if baseline_id is None:
            baseline_id = f"golden_{loaded_bitstream.info.filename}_{int(datetime.now().timestamp())}"
        
        golden = GoldenBaseline(baseline_id)
        golden.info = loaded_bitstream.info
        golden.bitstream_hash = loaded_bitstream.info.compute_hash()
        golden.add_frames(loaded_bitstream.frames)
        golden.set_bulk_write_history({far: [frame.frame_data for frame in history]
                                       for far, history in loaded_bitstream._write_history.items()})
        
        self.baselines_created += 1
        
        return golden
    
    def extract_used_tiles_from_frames(self, 
                                      loaded_bitstream: LoadedBitstream,
                                      threshold: float = 0.01) -> Set[str]:
        """
        Extract used tiles by analyzing configured frames
        
        This heuristic considers tiles "used" if their frames contain
        non-default configuration (sufficient number of set bits).
        
        Args:
            loaded_bitstream: Loaded bitstream to analyze
            threshold: Minimum ratio of set bits to consider frame "used"
            
        Returns:
            Set of tile names that appear to be used
        """
        
        
        used_tiles = set()
        
        for frame in loaded_bitstream:
            # Check if frame has significant configuration
            set_bit_count = FrameDataExtractor.count_set_bits(frame.frame_data)
            total_bits = 1312
            
            if set_bit_count / total_bits > threshold:
                # Frame appears configured, mark its tiles as used
                coverage = self.frame_mapper.map_frame(frame.far_value)
                used_tiles.update(coverage.tiles_affected)
        
        return used_tiles
    
    def extract_used_tiles_from_netlist(self, netlist_path: str) -> Set[str]:
        """
        Extract used tiles from netlist/placement file
        
        This would parse XDL, NCD, or other netlist formats to
        determine actual tile usage. Currently a placeholder.
        
        Args:
            netlist_path: Path to netlist file
            
        Returns:
            Set of tile names
        """
        # Placeholder for future implementation
        # Would parse XDL/NCD files to extract actual placement
        print("Warning: Netlist parsing not yet implemented")
        return set()
    
    def add_tile_usage_from_file(self, 
                                 golden: GoldenBaseline,
                                 tile_list_file: str) -> None:
        """
        Add tile usage from a text file
        
        File format: one tile name per line
        
        Args:
            golden: GoldenBaseline to update
            tile_list_file: Path to file with tile names
        """
        try:
            with open(tile_list_file, 'r') as f:
                tiles = set(line.strip() for line in f if line.strip())
            
            golden.set_used_tiles(tiles)
            print(f"Loaded {len(tiles)} used tiles from {tile_list_file}")
            
        except Exception as e:
            print(f"Error loading tile list: {str(e)}")
    
    def compare_baselines(self, 
                         golden1: GoldenBaseline,
                         golden2: GoldenBaseline) -> Dict:
        """
        Compare two golden baselines
        
        Useful for understanding differences between tool versions
        or design iterations.
        
        Args:
            golden1: First baseline
            golden2: Second baseline
            
        Returns:
            Dictionary with comparison results
        """
        fars1 = golden1.get_expected_frames()
        fars2 = golden2.get_expected_frames()
        
        common_fars = fars1.intersection(fars2)
        only_in_1 = fars1 - fars2
        only_in_2 = fars2 - fars1
        
        # Count data differences
        data_differences = []
        for far in common_fars:
            data1 = golden1.get_frame_data(far)
            data2 = golden2.get_frame_data(far)
            
            if data1 != data2:
                data_differences.append(far)
        
        return {
            'baseline1_id': golden1.baseline_id,
            'baseline2_id': golden2.baseline_id,
            'frames_in_1': len(golden1),
            'frames_in_2': len(golden2),
            'common_frames': len(common_fars),
            'only_in_1': len(only_in_1),
            'only_in_2': len(only_in_2),
            'data_differences': len(data_differences),
            'difference_rate': len(data_differences) / len(common_fars) if common_fars else 0
        }
    
    def merge_baselines(self,
                       baselines: List[GoldenBaseline],
                       merge_id: str) -> GoldenBaseline:
        """
        Merge multiple baselines (take union of frames)
        
        Useful when you have multiple golden references and want
        to create a comprehensive baseline.
        
        Args:
            baselines: List of GoldenBaseline instances
            merge_id: ID for merged baseline
            
        Returns:
            Merged GoldenBaseline
        """
        merged = GoldenBaseline(merge_id)
        
        # Merge frames (first baseline wins on conflicts)
        for baseline in baselines:
            for far in baseline.get_expected_frames():
                if not merged.has_frame(far):
                    frame = baseline.get_frame(far)
                    if frame:
                        merged.add_frame(frame)
        
        # Merge used tiles (union)
        all_used_tiles = set()
        for baseline in baselines:
            all_used_tiles.update(baseline.used_tiles)
        
        merged.set_used_tiles(all_used_tiles)
        
        return merged
    
    def create_minimal_baseline(self, 
                               fars: List[int],
                               baseline_id: str) -> GoldenBaseline:
        """
        Create a minimal baseline with only specified FARs
        
        Useful for testing or focusing on specific regions.
        
        Args:
            fars: List of frame addresses to include
            baseline_id: Baseline ID
            
        Returns:
            GoldenBaseline with empty frames
        """
        golden = GoldenBaseline(baseline_id)
        
        # Create empty frames for specified FARs
        from analysis.frame_rules import FrameAddress
        
        for far in fars:
            fields = FrameAddress.decode(far)
            
            # Create empty frame
            empty_data = b'\x00' * 164
            
            frame = AdaptedFrame(
                far_value=far,
                far_hex=f"0x{far:08X}",
                block_type=fields['block_type'],
                top_bottom=fields['top_bottom'],
                column=fields['major'],
                major=fields['major'],
                minor=fields['minor'],
                frame_data=empty_data,
                frame_index=0,
                data_word_count=41
            )
            
            golden.add_frame(frame)
        
        return golden
    
    def get_statistics(self) -> Dict:
        """
        Get builder statistics
        
        Returns:
            Dictionary with statistics
        """
        loader_stats = self.bitstream_loader.get_statistics()
        
        return {
            'baselines_created': self.baselines_created,
            'loader_statistics': loader_stats
        }


# ============================================================================
# Convenience Functions
# ============================================================================

def build_golden(bitstream_path: str, 
                output_path: Optional[str] = None) -> Optional[GoldenBaseline]:
    """
    Convenience function to build and optionally save golden baseline
    
    Args:
        bitstream_path: Path to golden bitstream
        output_path: Optional path to save baseline
        
    Returns:
        GoldenBaseline or None
    """
    builder = GoldenBaselineBuilder()
    golden = builder.build_from_bitstream(bitstream_path)
    
    if golden and output_path:
        golden.save(output_path)
        print(f"Golden baseline saved to: {output_path}")
    
    return golden


def quick_baseline_stats(bitstream_path: str) -> None:
    """
    Quick analysis of bitstream for baseline creation
    
    Args:
        bitstream_path: Path to bitstream
    """
    builder = GoldenBaselineBuilder()
    golden = builder.build_from_bitstream(bitstream_path)
    
    if not golden:
        print("Failed to build baseline")
        return
    
    stats = golden.get_statistics()
    
    print("\n" + "="*70)
    print("Golden Baseline Statistics")
    print("="*70)
    print(f"Baseline ID:      {stats['baseline_id']}")
    print(f"Total Frames:     {stats['total_frames']}")
    print(f"Columns Covered:  {stats['configured_columns']}")
    print(f"Used Tiles:       {stats['used_tiles']}")
    print(f"")
    print(f"Block Type Distribution:")
    for block_type, count in stats['block_types'].items():
        print(f"  Type {block_type}: {count} frames")
    print("="*70 + "\n")


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'GoldenBaselineBuilder',
    'build_golden',
    'quick_baseline_stats'
]