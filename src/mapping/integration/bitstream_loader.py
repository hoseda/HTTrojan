# src/mapping/integration/bitstream_loader.py
"""
Bitstream Loader - High-level bitstream parsing

Uses your existing Parser and adapts results for detection framework.
Provides clean interface for loading bitstreams.

Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import Dict, List, Optional
from pathlib import Path
import hashlib
from datetime import datetime

# Import your existing parser
from src.parser.file_loader import Parser, Header

# Import adapter
from src.mapping.integration.frame_obj_adapter import (
    FrameObjAdapter,
    AdaptedFrame
)


class BitstreamInfo:
    """
    Metadata about a loaded bitstream
    
    Contains header information and statistics.
    """
    
    def __init__(self, header: Header, filepath: str):
        """
        Initialize bitstream info
        
        Args:
            header: Header from parser
            filepath: Path to bitstream file
        """
        self.filepath = Path(filepath)
        self.filename = self.filepath.name
        
        # Extract header information
        self.design_name = self._extract_value(header.design_name)
        self.device_name = self._extract_value(header.device_name)
        self.build_date = self._extract_value(header.build_date)
        self.build_time = self._extract_value(header.build_time)
        
        # Metadata
        self.load_timestamp = datetime.now()
        self.file_size = self.filepath.stat().st_size if self.filepath.exists() else 0
        self.sha256_hash = None  # Computed on demand
        
        # Statistics (filled by loader)
        self.frame_count = 0
        self.block_type_distribution = {}
        self.column_coverage = set()
        self.unique_far_count = 0
        self.multi_write_far_count = 0
        self.total_writes = 0
    
    def _extract_value(self, token) -> str:
        """Extract string value from HeaderToken"""
        if token is None:
            return "Unknown"
        
        if hasattr(token, 'value'):
            val = token.value
            if isinstance(val, bytes):
                return val.decode('ascii', errors='ignore')
            return str(val)
        
        return str(token)
    
    def compute_hash(self) -> str:
        """
        Compute SHA256 hash of bitstream file
        
        Returns:
            Hex string of hash
        """
        if self.sha256_hash:
            return self.sha256_hash
        
        hasher = hashlib.sha256()
        with open(self.filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        
        self.sha256_hash = hasher.hexdigest()
        return self.sha256_hash
    
    def __str__(self) -> str:
        transient_ratio = 0
        if self.unique_far_count:
            transient_ratio = self.multi_write_far_count / self.unique_far_count
        return (f"BitstreamInfo({self.filename})\n"
                f"  Design: {self.design_name}\n"
                f"  Device: {self.device_name}\n"
                f"  Built: {self.build_date} {self.build_time}\n"
                f"  Frames: {self.frame_count}\n"
                f"  Unique FARs: {self.unique_far_count} (multi-write: {self.multi_write_far_count}, ratio: {transient_ratio:.2%})\n"
                f"  Columns: {len(self.column_coverage)}")


class LoadedBitstream:
    """
    Complete representation of a loaded bitstream
    
    Contains all frames and metadata, ready for analysis.
    """
    
    def __init__(self, info: BitstreamInfo, frames: List[AdaptedFrame]):
        """
        Initialize loaded bitstream
        
        Args:
            info: Bitstream metadata
            frames: List of adapted frames
        """
        self.info = info
        self.frames = frames
        
        # Build indices for fast lookup
        self._frame_by_far: Dict[int, AdaptedFrame] = {}
        self._frames_by_column: Dict[int, List[AdaptedFrame]] = {}
        self._frames_by_block_type: Dict[int, List[AdaptedFrame]] = {}
        self._write_history: Dict[int, List[AdaptedFrame]] = {}
        
        self._build_indices()
    
    def _build_indices(self):
        """Build lookup indices from frame list"""
        far_write_counts: Dict[int, int] = {}
        for frame in self.frames:
            # FAR index (last write)
            self._frame_by_far[frame.far_value] = frame

            # Track write history
            if frame.far_value not in self._write_history:
                self._write_history[frame.far_value] = []
            self._write_history[frame.far_value].append(frame)
            far_write_counts[frame.far_value] = far_write_counts.get(frame.far_value, 0) + 1
            
            # Column index
            if frame.column not in self._frames_by_column:
                self._frames_by_column[frame.column] = []
            self._frames_by_column[frame.column].append(frame)
            
            # Block type index
            if frame.block_type not in self._frames_by_block_type:
                self._frames_by_block_type[frame.block_type] = []
            self._frames_by_block_type[frame.block_type].append(frame)
        
        # Update info statistics
        self.info.frame_count = len(self.frames)
        self.info.column_coverage = set(self._frames_by_column.keys())
        self.info.block_type_distribution = {
            bt: len(frames) for bt, frames in self._frames_by_block_type.items()
        }
        self.info.unique_far_count = len(self._write_history)
        self.info.multi_write_far_count = sum(1 for count in far_write_counts.values() if count > 1)
        self.info.total_writes = sum(far_write_counts.values())
    
    def get_frame(self, far_value: int) -> Optional[AdaptedFrame]:
        """
        Get frame by FAR value
        
        Args:
            far_value: Frame address
            
        Returns:
            AdaptedFrame or None
        """
        return self._frame_by_far.get(far_value)
    
    def get_frames_by_column(self, column: int) -> List[AdaptedFrame]:
        """
        Get all frames in a column
        
        Args:
            column: Column index
            
        Returns:
            List of frames
        """
        return self._frames_by_column.get(column, [])
    
    def get_frames_by_block_type(self, block_type: int) -> List[AdaptedFrame]:
        """
        Get all frames of a specific block type
        
        Args:
            block_type: Block type (0=CLB, 1=BRAM, etc.)
            
        Returns:
            List of frames
        """
        return self._frames_by_block_type.get(block_type, [])

    def get_write_history(self, far_value: int) -> List[AdaptedFrame]:
        """
        Get all writes captured for a specific FAR

        Args:
            far_value: Frame address

        Returns:
            List of AdaptedFrame instances in chronological order
        """
        return self._write_history.get(far_value, [])

    def get_write_history_bytes(self, far_value: int) -> List[bytes]:
        """
        Get write history as raw frame data bytes
        """
        return [frame.frame_data for frame in self._write_history.get(far_value, [])]

    def get_first_nonmatching_write(self, far_value: int, reference_data: bytes) -> Optional[AdaptedFrame]:
        """
        Return the first write whose data differs from reference_data

        Args:
            far_value: Frame address
            reference_data: Golden frame data to compare

        Returns:
            AdaptedFrame of first differing write or None if all match
        """
        for frame in self._write_history.get(far_value, []):
            if frame.frame_data != reference_data:
                return frame
        return None
    
    def get_all_far_values(self) -> List[int]:
        """
        Get list of all FAR values in bitstream
        
        Returns:
            Sorted list of FAR values
        """
        return sorted(self._frame_by_far.keys())
    
    def __len__(self) -> int:
        """Return number of frames"""
        return len(self.frames)
    
    def __iter__(self):
        """Iterate over frames"""
        return iter(self.frames)


class BitstreamLoader:
    """
    High-level bitstream loader
    
    Uses your existing Parser and provides clean interface
    for loading bitstreams into the detection framework.
    
    Usage:
        loader = BitstreamLoader()
        bitstream = loader.load("design.bit")
        
        print(f"Loaded {len(bitstream)} frames")
        print(f"Device: {bitstream.info.device_name}")
        
        # Access frames
        for frame in bitstream:
            print(f"Frame {frame.far_hex}")
    """
    
    def __init__(self):
        """Initialize the loader"""
        self.parser = None  # Created per-load
        self.adapter = FrameObjAdapter()
        
        # Statistics
        self.bitstreams_loaded = 0
        self.total_frames_loaded = 0
    
    def load(self, bitstream_path: str, 
             validate: bool = True,
             capture_history: bool = True) -> Optional[LoadedBitstream]:
        """
        Load a bitstream file
        
        Args:
            bitstream_path: Path to .bit file
            validate: Whether to validate adapted frames
            capture_history: Keep intermediate writes for each FAR
            
        Returns:
            LoadedBitstream or None on failure
        """
        try:
            # Initialize parser with your existing Parser class
            self.parser = Parser(bitstream_path)
            
            # Parse bitstream using your parser
            header, frame_objs = self.parser.parse()
            
            # Create bitstream info from header
            info = BitstreamInfo(header, bitstream_path)
            
            # Adapt frames
            adapted_frames = self.adapter.adapt_batch(frame_objs)
            
            # Validate if requested
            if validate:
                adapted_frames = self._validate_frames(adapted_frames)
            
            # Create loaded bitstream
            bitstream = LoadedBitstream(info, adapted_frames)
            if not capture_history:
                # Drop history if not requested to reduce memory footprint
                bitstream._write_history = {far: [frames[-1]] for far, frames in bitstream._write_history.items()}
            
            # Update statistics
            self.bitstreams_loaded += 1
            self.total_frames_loaded += len(adapted_frames)
            
            return bitstream
            
        except Exception as e:
            print(f"Error loading bitstream {bitstream_path}: {str(e)}")
            return None
    
    def _validate_frames(self, frames: List[AdaptedFrame]) -> List[AdaptedFrame]:
        """
        Validate adapted frames
        
        Args:
            frames: List of adapted frames
            
        Returns:
            List of valid frames (invalid ones filtered out)
        """
        valid_frames = []
        
        for frame in frames:
            is_valid, error_msg = self.adapter.validate_frame_data(frame)
            
            if is_valid:
                valid_frames.append(frame)
            else:
                print(f"Warning: Invalid frame {frame.far_hex}: {error_msg}")
        
        return valid_frames
    
    def load_multiple(self, bitstream_paths: List[str]) -> Dict[str, LoadedBitstream]:
        """
        Load multiple bitstreams
        
        Args:
            bitstream_paths: List of paths to .bit files
            
        Returns:
            Dictionary mapping filename to LoadedBitstream
        """
        results = {}
        
        for path in bitstream_paths:
            bitstream = self.load(path)
            if bitstream:
                results[Path(path).name] = bitstream
        
        return results
    
    def compare_bitstreams(self, path1: str, path2: str) -> Dict:
        """
        Quick comparison of two bitstreams
        
        Args:
            path1: First bitstream path
            path2: Second bitstream path
            
        Returns:
            Dictionary with comparison statistics
        """
        bs1 = self.load(path1, validate=False)
        bs2 = self.load(path2, validate=False)
        
        if not bs1 or not bs2:
            return {'error': 'Failed to load one or both bitstreams'}
        
        # Get FAR sets
        fars1 = set(bs1.get_all_far_values())
        fars2 = set(bs2.get_all_far_values())
        
        # Calculate differences
        common_fars = fars1.intersection(fars2)
        only_in_1 = fars1 - fars2
        only_in_2 = fars2 - fars1
        
        # Count frame data differences
        data_differences = []
        for far in common_fars:
            frame1 = bs1.get_frame(far)
            frame2 = bs2.get_frame(far)
            
            if frame1 and frame2:
                if frame1.frame_data != frame2.frame_data:
                    data_differences.append(far)
        
        return {
            'bitstream1': bs1.info.filename,
            'bitstream2': bs2.info.filename,
            'frames_in_1': len(bs1),
            'frames_in_2': len(bs2),
            'common_frames': len(common_fars),
            'only_in_1': len(only_in_1),
            'only_in_2': len(only_in_2),
            'data_differences': len(data_differences),
            'changed_fars': [f"0x{far:08X}" for far in sorted(data_differences)[:20]]
        }
    
    def get_statistics(self) -> Dict:
        """
        Get loader statistics
        
        Returns:
            Dictionary with statistics
        """
        adapter_stats = self.adapter.get_statistics()
        
        return {
            'bitstreams_loaded': self.bitstreams_loaded,
            'total_frames_loaded': self.total_frames_loaded,
            'adapter_statistics': adapter_stats
        }


# ============================================================================
# Convenience Functions
# ============================================================================

def load_bitstream(filepath: str) -> Optional[LoadedBitstream]:
    """
    Convenience function to load a bitstream
    
    Args:
        filepath: Path to bitstream file
        
    Returns:
        LoadedBitstream or None
    """
    loader = BitstreamLoader()
    return loader.load(filepath)


def quick_compare(golden_path: str, suspect_path: str) -> None:
    """
    Quick comparison of two bitstreams with printed output
    
    Args:
        golden_path: Path to golden bitstream
        suspect_path: Path to suspect bitstream
    """
    loader = BitstreamLoader()
    comparison = loader.compare_bitstreams(golden_path, suspect_path)
    
    if 'error' in comparison:
        print(f"Error: {comparison['error']}")
        return
    
    print("\n" + "="*70)
    print("Bitstream Comparison")
    print("="*70)
    print(f"Golden:  {comparison['bitstream1']} ({comparison['frames_in_1']} frames)")
    print(f"Suspect: {comparison['bitstream2']} ({comparison['frames_in_2']} frames)")
    print(f"")
    print(f"Common frames:      {comparison['common_frames']}")
    print(f"Only in golden:     {comparison['only_in_1']}")
    print(f"Only in suspect:    {comparison['only_in_2']}")
    print(f"Data differences:   {comparison['data_differences']}")
    
    if comparison['data_differences'] > 0:
        print(f"")
        print(f"Changed frames (first 20):")
        for far_hex in comparison['changed_fars']:
            print(f"  {far_hex}")
    
    print("="*70 + "\n")


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'BitstreamInfo',
    'LoadedBitstream',
    'BitstreamLoader',
    'load_bitstream',
    'quick_compare'
]