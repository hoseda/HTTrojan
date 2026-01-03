"""
Golden Baseline - Trusted Reference Configuration

Represents a known-good bitstream configuration.
Used as reference for Trojan detection via differential analysis.

Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import pickle
import json
from pathlib import Path

# Import integration layer
from src.mapping.integration.frame_obj_adapter import AdaptedFrame
from src.mapping.integration.bitstream_loader import BitstreamInfo
from src.mapping.integration.frame_obj_adapter import FrameDataExtractor

@dataclass
class FrameFingerprint:
    """
    Lightweight fingerprint of a frame for comparison
    
    Stores only essential data for fast comparison.
    """
    far_value: int
    data_hash: int  # Hash of frame_data for quick comparison
    block_type: int
    column: int
    minor: int
    
    def __hash__(self):
        return hash(self.far_value)
    
    def __eq__(self, other):
        if not isinstance(other, FrameFingerprint):
            return False
        return self.far_value == other.far_value


class GoldenBaseline:
    """
    Golden Baseline - Trusted Reference State
    
    Represents a known-good bitstream configuration used as
    the baseline for detecting Trojans via differential analysis.
    
    The golden baseline contains:
    - Complete frame data for all configured frames
    - Metadata about the design
    - Coverage information (which tiles/resources are used)
    - Checksums for integrity verification
    
    Usage:
        # Create from bitstream
        golden = GoldenBaseline.from_bitstream(loaded_bitstream)
        
        # Save for later use
        golden.save("golden_baseline.pkl")
        
        # Load saved baseline
        golden = GoldenBaseline.load("golden_baseline.pkl")
        
        # Check if suspect frame matches
        if golden.has_frame(far_value):
            is_match = golden.verify_frame(far_value, suspect_data)
    """
    
    def __init__(self, baseline_id: str):
        """
        Initialize golden baseline
        
        Args:
            baseline_id: Unique identifier for this baseline
        """
        self.baseline_id = baseline_id
        self.creation_timestamp = datetime.now()
        
        # Bitstream metadata
        self.info: Optional[BitstreamInfo] = None
        self.bitstream_hash: Optional[str] = None
        
        # Frame storage
        self._frames: Dict[int, AdaptedFrame] = {}  # FAR -> Frame
        self._frame_fingerprints: Dict[int, FrameFingerprint] = {}  # FAR -> Fingerprint
        self._write_history: Dict[int, List[bytes]] = {}  # FAR -> list of frame_data writes
        
        # Coverage information
        self.configured_fars: Set[int] = set()  # All FARs in golden
        self.configured_columns: Set[int] = set()  # Columns with configuration
        self.block_type_counts: Dict[int, int] = {}  # Block type statistics
        
        # Tile usage (populated externally)
        self.used_tiles: Set[str] = set()  # Tiles used by design
        self.unused_tiles: Set[str] = set()  # Tiles not used
        
        # Validation
        self.is_validated: bool = False
        self.validation_errors: List[str] = []
    
    def add_frame(self, frame: AdaptedFrame) -> None:
        """
        Add a frame to the golden baseline
        
        Args:
            frame: AdaptedFrame to add
        """
        far = frame.far_value
        
        # Store complete frame
        self._frames[far] = frame
        
        # Create and store fingerprint
        fingerprint = FrameFingerprint(
            far_value=far,
            data_hash=hash(frame.frame_data),
            block_type=frame.block_type,
            column=frame.column,
            minor=frame.minor
        )
        self._frame_fingerprints[far] = fingerprint
        
        # Update coverage
        self.configured_fars.add(far)
        self.configured_columns.add(frame.column)
        
        # Update block type counts
        if frame.block_type not in self.block_type_counts:
            self.block_type_counts[frame.block_type] = 0
        self.block_type_counts[frame.block_type] += 1
    
    def add_frames(self, frames: List[AdaptedFrame]) -> None:
        """
        Add multiple frames
        
        Args:
            frames: List of AdaptedFrames
        """
        for frame in frames:
            self.add_frame(frame)

    def set_write_history(self, far_value: int, history: List[bytes]) -> None:
        """
        Set write history for a specific FAR

        Args:
            far_value: Frame address
            history: Ordered list of frame_data bytes captured during configuration
        """
        if history:
            self._write_history[far_value] = [bytes(entry) for entry in history]

    def set_bulk_write_history(self, history_map: Dict[int, List[bytes]]) -> None:
        """
        Set write history for multiple FARs at once
        """
        for far, history in history_map.items():
            self.set_write_history(far, history)
    
    def has_frame(self, far_value: int) -> bool:
        """
        Check if golden contains a frame
        
        Args:
            far_value: Frame address
            
        Returns:
            True if frame exists in golden
        """
        return far_value in self._frames
    
    def get_frame(self, far_value: int) -> Optional[AdaptedFrame]:
        """
        Get frame from golden baseline
        
        Args:
            far_value: Frame address
            
        Returns:
            AdaptedFrame or None
        """
        return self._frames.get(far_value)

    def get_write_history(self, far_value: int) -> List[bytes]:
        """
        Get recorded write history for a FAR
        """
        return self._write_history.get(far_value, [])
    
    def get_frame_data(self, far_value: int) -> Optional[bytes]:
        """
        Get frame data only (no metadata)
        
        Args:
            far_value: Frame address
            
        Returns:
            Frame data bytes or None
        """
        frame = self.get_frame(far_value)
        return frame.frame_data if frame else None
    
    def verify_frame(self, far_value: int, suspect_data: bytes) -> bool:
        """
        Verify if suspect frame data matches golden
        
        Args:
            far_value: Frame address
            suspect_data: Frame data to verify
            
        Returns:
            True if data matches golden exactly
        """
        golden_data = self.get_frame_data(far_value)
        if golden_data is None:
            return False
        
        return golden_data == suspect_data
    
    def find_differences(self, far_value: int, suspect_data: bytes) -> Optional[List[int]]:
        """
        Find bit positions that differ from golden
        
        Args:
            far_value: Frame address
            suspect_data: Frame data to compare
            
        Returns:
            List of bit offsets that differ, or None if frame not in golden
        """
        golden_data = self.get_frame_data(far_value)
        if golden_data is None:
            return None
        
        if golden_data == suspect_data:
            return []  # No differences
        
        # Find differing bits
        return FrameDataExtractor.compare_frames(golden_data, suspect_data)
    
    def set_used_tiles(self, tiles: Set[str]) -> None:
        """
        Set which tiles are used by the design
        
        This information is used to identify unused regions where
        Trojans are more likely to hide.
        
        Args:
            tiles: Set of tile names used by legitimate design
        """
        self.used_tiles = tiles
    
    def is_tile_used(self, tile_name: str) -> bool:
        """
        Check if a tile is used by the golden design
        
        Args:
            tile_name: Tile name to check
            
        Returns:
            True if tile is used
        """
        return tile_name in self.used_tiles
    
    def get_expected_frames(self) -> Set[int]:
        """
        Get set of all expected frame addresses
        
        Returns:
            Set of FAR values that should be configured
        """
        return self.configured_fars.copy()
    
    def get_statistics(self) -> Dict:
        """
        Get baseline statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'baseline_id': self.baseline_id,
            'creation_time': self.creation_timestamp.isoformat(),
            'total_frames': len(self._frames),
            'configured_columns': len(self.configured_columns),
            'block_types': dict(self.block_type_counts),
            'used_tiles': len(self.used_tiles),
            'is_validated': self.is_validated,
            'bitstream_hash': self.bitstream_hash,
            'write_history_tracked': len(self._write_history)
        }
    
    def validate(self) -> Tuple[bool, List[str]]:
        """
        Validate the golden baseline integrity
        
        Returns:
            (is_valid, list_of_errors)
        """
        errors = []
        
        # Check basic requirements
        if len(self._frames) == 0:
            errors.append("No frames in golden baseline")
        
        if self.info is None:
            errors.append("No bitstream info")
        
        # Check frame data integrity
        for far, frame in self._frames.items():
            if len(frame.frame_data) != 164:
                errors.append(f"Frame {far:08X} has invalid data length")
        
        # Check fingerprint consistency
        for far, fingerprint in self._frame_fingerprints.items():
            if far not in self._frames:
                errors.append(f"Fingerprint {far:08X} has no corresponding frame")
        
        self.is_validated = len(errors) == 0
        self.validation_errors = errors
        
        return self.is_validated, errors
    
    def save(self, filepath: str, format: str = 'pickle') -> bool:
        """
        Save golden baseline to disk
        
        Args:
            filepath: Output file path
            format: 'pickle' or 'json' (pickle is faster, json is readable)
            
        Returns:
            True on success
        """
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            if format == 'pickle':
                with open(path, 'wb') as f:
                    pickle.dump(self, f)
            
            elif format == 'json':
                # Convert to JSON-serializable format
                data = self._to_json_dict()
                with open(path, 'w') as f:
                    json.dump(data, f, indent=2)
            
            else:
                raise ValueError(f"Unknown format: {format}")
            
            return True
            
        except Exception as e:
            print(f"Error saving golden baseline: {str(e)}")
            return False
    
    @classmethod
    def load(cls, filepath: str, format: str = 'pickle') -> Optional['GoldenBaseline']:
        """
        Load golden baseline from disk
        
        Args:
            filepath: Input file path
            format: 'pickle' or 'json'
            
        Returns:
            GoldenBaseline or None on error
        """
        try:
            path = Path(filepath)
            
            if format == 'pickle':
                with open(path, 'rb') as f:
                    return pickle.load(f)
            
            elif format == 'json':
                with open(path, 'r') as f:
                    data = json.load(f)
                return cls._from_json_dict(data)
            
            else:
                raise ValueError(f"Unknown format: {format}")
                
        except Exception as e:
            print(f"Error loading golden baseline: {str(e)}")
            return None
    
    def _to_json_dict(self) -> Dict:
        """Convert to JSON-serializable dictionary"""
        # Note: This is a simplified version
        # Full implementation would need custom serialization for all fields
        return {
            'baseline_id': self.baseline_id,
            'creation_timestamp': self.creation_timestamp.isoformat(),
            'bitstream_hash': self.bitstream_hash,
            'configured_fars': list(self.configured_fars),
            'configured_columns': list(self.configured_columns),
            'block_type_counts': self.block_type_counts,
            'used_tiles': list(self.used_tiles),
            'frame_count': len(self._frames),
            # Note: Frame data not included in JSON (too large)
            # Use pickle format for complete storage
        }
    
    @classmethod
    def _from_json_dict(cls, data: Dict) -> 'GoldenBaseline':
        """Create from JSON dictionary"""
        # Note: Simplified version
        # This only restores metadata, not frame data
        baseline = cls(data['baseline_id'])
        baseline.bitstream_hash = data.get('bitstream_hash')
        baseline.configured_fars = set(data.get('configured_fars', []))
        baseline.configured_columns = set(data.get('configured_columns', []))
        baseline.block_type_counts = data.get('block_type_counts', {})
        baseline.used_tiles = set(data.get('used_tiles', []))
        # Write history not stored in JSON format
        
        return baseline
    
    def __len__(self) -> int:
        """Return number of frames"""
        return len(self._frames)
    
    def __str__(self) -> str:
        return (f"GoldenBaseline(id={self.baseline_id}, "
                f"frames={len(self._frames)}, "
                f"columns={len(self.configured_columns)}, "
                f"used_tiles={len(self.used_tiles)})")
    
    def __repr__(self) -> str:
        return self.__str__()


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'FrameFingerprint',
    'GoldenBaseline'
]