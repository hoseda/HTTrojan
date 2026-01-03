# column_mapper.py
# Spatial classification layer for Virtex-5 VLX50T columns
# Maps column indices to their architectural properties
# Part of: "Turning the Table: Using Bitstream Reverse Engineering to Detect FPGA Trojans"

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from enum import Enum
from functools import lru_cache

# Import from frame_rules.py
from analysis.frame_rules import (
    DeviceConstants,
    BlockType,
    ColumnClassification
)


# ============================================================================
# Column Type Enumeration
# ============================================================================

class ColumnType(Enum):
    """
    Enumeration of all column types in Virtex-5
    Makes type checking more robust than strings
    """
    CLB = "CLB"           # Configurable Logic Blocks
    IOB = "IOB"           # Input/Output Blocks
    BRAM = "BRAM"         # Block RAM
    CLK = "CLK"           # Clock distribution
    UNKNOWN = "UNKNOWN"   # Invalid/unmapped


# ============================================================================
# Column Descriptor Classes
# ============================================================================

@dataclass(frozen=True)
class ColumnDescriptor:
    """
    Immutable descriptor containing all properties of a column
    
    This is the core data structure that describes what a column contains
    and how it behaves. Frozen (immutable) for thread-safety and caching.
    
    Attributes:
        column_index: Physical column number (0-47 for VLX50T)
        column_type: Type of column (CLB, BRAM, IOB, CLK)
        tile_types: List of tile types present in this column
        frames_per_column: Total number of frames
        routing_frame_count: How many frames contain routing
        logic_frame_count: How many frames contain logic configuration
        contains_routing: Does this column have any routing resources?
        contains_logic: Does this column have logic configuration?
        block_type_default: Primary block type for this column
        is_security_critical: Can Trojans hide here effectively?
    """
    column_index: int
    column_type: ColumnType
    tile_types: Tuple[str, ...]  # Tuple for immutability
    frames_per_column: int
    routing_frame_count: int
    logic_frame_count: int
    contains_routing: bool
    contains_logic: bool
    block_type_default: int  # BlockType enum value
    is_security_critical: bool
    
    # Additional metadata
    description: str = ""
    special_properties: Tuple[str, ...] = field(default_factory=tuple)
    
    def get_block_type_for_minor(self, minor: int) -> int:
        """
        Get the appropriate block type for a given minor address
        
        This is critical for BRAM columns which have TWO block types:
        - Minors 0-27: BRAM_INT (interconnect)
        - Minors 28-91: BRAM_CONTENT (memory content)
        
        Args:
            minor: Minor address (frame index within column)
            
        Returns:
            Block type enum value
        """
        if self.column_type == ColumnType.BRAM:
            # BRAM columns have split personality
            if minor < 28:
                return BlockType.BRAM_INT  # First 28 frames are interconnect
            else:
                return BlockType.BRAM_CONTENT  # Remaining 64 frames are content
        
        # All other columns have single block type
        return self.block_type_default
    
    def is_minor_valid(self, minor: int) -> bool:
        """
        Check if a minor address is valid for this column
        
        Args:
            minor: Minor address to validate
            
        Returns:
            True if minor is within valid range
        """
        return 0 <= minor < self.frames_per_column
    
    def get_routing_frame_range(self) -> Tuple[int, int]:
        """
        Get the minor address range for routing frames
        
        Returns:
            (start_minor, end_minor) tuple
        """
        return (0, self.routing_frame_count)
    
    def get_logic_frame_range(self) -> Tuple[int, int]:
        """
        Get the minor address range for logic configuration frames
        
        Returns:
            (start_minor, end_minor) tuple
        """
        return (self.routing_frame_count, self.frames_per_column)
    
    def is_routing_frame(self, minor: int) -> bool:
        """
        Determine if a specific frame is primarily routing
        
        Args:
            minor: Frame index within column
            
        Returns:
            True if this frame contains routing configuration
        """
        return minor < self.routing_frame_count
    
    def is_edge_column(self) -> bool:
        """
        Check if this is an edge column (IOB)
        Edge columns are security-critical for data exfiltration
        """
        return self.column_type == ColumnType.IOB


# ============================================================================
# Column Mapper - Main Coordinator Class
# ============================================================================

class ColumnMapper:
    """
    Central coordinator for column spatial classification
    
    This class manages all column-related queries and provides a clean
    interface to the rest of the system. It pre-computes column descriptors
    at initialization for fast lookups.
    
    Usage:
        mapper = ColumnMapper()
        desc = mapper.get_column_descriptor(23)
        print(f"Column 23 is {desc.column_type}")
    """
    
    def __init__(self):
        """
        Initialize the column mapper
        
        Pre-computes all column descriptors for the device.
        This is done once at startup for performance.
        """
        self._column_descriptors: Dict[int, ColumnDescriptor] = {}
        self._type_to_columns: Dict[ColumnType, List[int]] = {
            ColumnType.CLB: [],
            ColumnType.BRAM: [],
            ColumnType.IOB: [],
            ColumnType.CLK: [],
        }
        
        # Build all descriptors
        self._build_column_descriptors()
        
        # Build reverse indices
        self._build_reverse_indices()
    
    def _build_column_descriptors(self):
        """
        Build column descriptor for each column in the device
        
        This reads from frame_rules.py and creates rich descriptor objects.
        """
        for col_idx in range(DeviceConstants.TOTAL_COLUMNS):
            # Get raw data from frame_rules
            col_type_str = ColumnClassification.get_column_type(col_idx)
            tile_types = ColumnClassification.get_tile_types_in_column(col_idx)
            total_frames = ColumnClassification.get_frames_per_column(col_idx)
            routing_frames = ColumnClassification.get_routing_frames_count(col_idx)
            logic_frames = ColumnClassification.get_logic_frames_count(col_idx)
            
            # Convert string type to enum
            try:
                col_type = ColumnType(col_type_str)
            except ValueError:
                col_type = ColumnType.UNKNOWN
            
            # Determine properties based on column type
            contains_routing = routing_frames > 0
            contains_logic = logic_frames > 0
            
            # Get default block type
            if col_type == ColumnType.CLB:
                block_type_default = BlockType.CLB
                is_critical = True  # Logic + routing = prime Trojan target
                description = "Configurable Logic Block column with routing"
                special_props = ("logic", "routing", "carry_chain")
                
            elif col_type == ColumnType.BRAM:
                block_type_default = BlockType.BRAM_CONTENT  # Default to content
                is_critical = True  # Can hide payloads
                description = "Block RAM column (content + interconnect)"
                special_props = ("memory", "dual_block_type", "interconnect")
                
            elif col_type == ColumnType.IOB:
                block_type_default = BlockType.IOB
                is_critical = True  # Data exfiltration risk
                description = "Input/Output Block column"
                special_props = ("io_pins", "edge_column", "exfiltration_risk")
                
            elif col_type == ColumnType.CLK:
                block_type_default = BlockType.CLK
                is_critical = True  # Clock manipulation = powerful attack
                description = "Clock distribution column"
                special_props = ("global_clocking", "timing_sensitive")
                
            else:
                block_type_default = BlockType.CLB  # Fallback
                is_critical = False
                description = "Unknown column type"
                special_props = ()
            
            # Create descriptor
            descriptor = ColumnDescriptor(
                column_index=col_idx,
                column_type=col_type,
                tile_types=tuple(tile_types),
                frames_per_column=total_frames,
                routing_frame_count=routing_frames,
                logic_frame_count=logic_frames,
                contains_routing=contains_routing,
                contains_logic=contains_logic,
                block_type_default=block_type_default,
                is_security_critical=is_critical,
                description=description,
                special_properties=special_props
            )
            
            self._column_descriptors[col_idx] = descriptor
    
    def _build_reverse_indices(self):
        """
        Build reverse lookup tables: column_type → list of columns
        
        This enables fast queries like "give me all BRAM columns"
        """
        for col_idx, descriptor in self._column_descriptors.items():
            if descriptor.column_type in self._type_to_columns:
                self._type_to_columns[descriptor.column_type].append(col_idx)
        
        # Sort for deterministic output
        for col_list in self._type_to_columns.values():
            col_list.sort()
    
    # ========================================================================
    # Public Query Interface
    # ========================================================================
    
    @lru_cache(maxsize=128)
    def get_column_descriptor(self, column_index: int) -> Optional[ColumnDescriptor]:
        """
        Get the full descriptor for a column
        
        This is the primary lookup method. Returns a rich object with
        all column properties. Cached for performance.
        
        Args:
            column_index: Column index (0-47)
            
        Returns:
            ColumnDescriptor or None if invalid
            
        Example:
            desc = mapper.get_column_descriptor(23)
            if desc and desc.contains_routing:
                print("Column has routing resources")
        """
        return self._column_descriptors.get(column_index)
    
    def get_column_type(self, column_index: int) -> ColumnType:
        """
        Get just the column type (CLB, BRAM, etc.)
        
        Args:
            column_index: Column index
            
        Returns:
            ColumnType enum value
        """
        descriptor = self.get_column_descriptor(column_index)
        return descriptor.column_type if descriptor else ColumnType.UNKNOWN
    
    def get_block_type(self, column_index: int, minor: int) -> Optional[int]:
        """
        Get the block type for a specific frame location
        
        This handles the BRAM special case where block type depends on minor.
        Critical for correct FAR encoding/decoding.
        
        Args:
            column_index: Column index
            minor: Minor address (frame within column)
            
        Returns:
            Block type enum value or None if invalid
            
        Example:
            # BRAM column behavior
            bt1 = mapper.get_block_type(4, 10)   # Returns BRAM_INT
            bt2 = mapper.get_block_type(4, 50)   # Returns BRAM_CONTENT
        """
        descriptor = self.get_column_descriptor(column_index)
        if not descriptor:
            return None
        
        if not descriptor.is_minor_valid(minor):
            return None
        
        return descriptor.get_block_type_for_minor(minor)
    
    def validate_column_minor(self, column_index: int, minor: int) -> Tuple[bool, Optional[str]]:
        """
        Validate that a column + minor combination is legal
        
        Args:
            column_index: Column index
            minor: Minor address
            
        Returns:
            (is_valid, error_message) tuple
        """
        descriptor = self.get_column_descriptor(column_index)
        
        if not descriptor:
            return False, f"Invalid column index: {column_index}"
        
        if not descriptor.is_minor_valid(minor):
            return False, f"Minor {minor} out of range for column {column_index} (max: {descriptor.frames_per_column - 1})"
        
        return True, None
    
    def get_columns_by_type(self, column_type: ColumnType) -> List[int]:
        """
        Get all columns of a specific type
        
        Args:
            column_type: Type to search for
            
        Returns:
            Sorted list of column indices
            
        Example:
            bram_cols = mapper.get_columns_by_type(ColumnType.BRAM)
            # Returns: [4, 8, 12, 16, 20, 28, 32, 36, 40, 44]
        """
        return self._type_to_columns.get(column_type, []).copy()
    
    def get_adjacent_columns(self, column_index: int, 
                            column_type_filter: Optional[ColumnType] = None,
                            max_distance: int = 3) -> List[int]:
        """
        Get nearby columns, optionally filtered by type
        
        Useful for analyzing routing patterns and Trojan propagation paths.
        
        Args:
            column_index: Center column
            column_type_filter: Only return columns of this type (optional)
            max_distance: Maximum distance in columns
            
        Returns:
            List of adjacent column indices
            
        Example:
            # Find nearby BRAM columns for data flow analysis
            nearby = mapper.get_adjacent_columns(25, ColumnType.BRAM, max_distance=5)
        """
        adjacent = []
        
        for offset in range(-max_distance, max_distance + 1):
            if offset == 0:
                continue
            
            target_col = column_index + offset
            if 0 <= target_col < DeviceConstants.TOTAL_COLUMNS:
                descriptor = self.get_column_descriptor(target_col)
                if descriptor:
                    if column_type_filter is None or descriptor.column_type == column_type_filter:
                        adjacent.append(target_col)
        
        return sorted(adjacent)
    
    def get_routing_density(self, column_index: int) -> float:
        """
        Calculate routing frame density (ratio of routing to total frames)
        
        High routing density = more routing resources = more Trojan hiding spots
        
        Args:
            column_index: Column to analyze
            
        Returns:
            Ratio (0.0 to 1.0) of routing frames to total frames
        """
        descriptor = self.get_column_descriptor(column_index)
        if not descriptor or descriptor.frames_per_column == 0:
            return 0.0
        
        return descriptor.routing_frame_count / descriptor.frames_per_column
    
    def is_security_critical_column(self, column_index: int) -> bool:
        """
        Determine if modifications to this column are security-critical
        
        Used by Trojan detector to prioritize analysis.
        
        Args:
            column_index: Column to check
            
        Returns:
            True if column is high-value target for Trojans
        """
        descriptor = self.get_column_descriptor(column_index)
        return descriptor.is_security_critical if descriptor else False
    
    def get_column_statistics(self) -> Dict:
        """
        Get device-wide column statistics
        
        Useful for understanding device architecture and coverage.
        
        Returns:
            Dictionary with column type counts and properties
        """
        stats = {
            'total_columns': DeviceConstants.TOTAL_COLUMNS,
            'by_type': {},
            'routing_column_count': 0,
            'logic_column_count': 0,
            'security_critical_count': 0,
            'total_frames': 0
        }
        
        for col_type in ColumnType:
            if col_type != ColumnType.UNKNOWN:
                cols = self.get_columns_by_type(col_type)
                stats['by_type'][col_type.value] = {
                    'count': len(cols),
                    'columns': cols
                }
        
        for descriptor in self._column_descriptors.values():
            if descriptor.contains_routing:
                stats['routing_column_count'] += 1
            if descriptor.contains_logic:
                stats['logic_column_count'] += 1
            if descriptor.is_security_critical:
                stats['security_critical_count'] += 1
            stats['total_frames'] += descriptor.frames_per_column
        
        return stats
    
    def print_column_info(self, column_index: int):
        """
        Pretty-print detailed information about a column
        
        Useful for debugging and analysis.
        
        Args:
            column_index: Column to display
        """
        descriptor = self.get_column_descriptor(column_index)
        
        if not descriptor:
            print(f"Column {column_index}: INVALID")
            return
        
        print(f"\n{'='*70}")
        print(f"Column {column_index} - {descriptor.column_type.value}")
        print(f"{'='*70}")
        print(f"Description: {descriptor.description}")
        print(f"Tile Types: {', '.join(descriptor.tile_types)}")
        print(f"")
        print(f"Frame Configuration:")
        print(f"  Total Frames:   {descriptor.frames_per_column}")
        print(f"  Routing Frames: {descriptor.routing_frame_count} (minors 0-{descriptor.routing_frame_count-1})")
        print(f"  Logic Frames:   {descriptor.logic_frame_count} (minors {descriptor.routing_frame_count}-{descriptor.frames_per_column-1})")
        print(f"")
        print(f"Properties:")
        print(f"  Contains Routing: {descriptor.contains_routing}")
        print(f"  Contains Logic:   {descriptor.contains_logic}")
        print(f"  Security Critical: {descriptor.is_security_critical}")
        print(f"  Default Block Type: {BlockType.get_name(descriptor.block_type_default)}")
        print(f"")
        if descriptor.special_properties:
            print(f"Special Properties: {', '.join(descriptor.special_properties)}")
        print(f"{'='*70}\n")


# ============================================================================
# Module-level convenience functions
# ============================================================================

# Global singleton instance for easy access
_global_mapper: Optional[ColumnMapper] = None

def get_global_mapper() -> ColumnMapper:
    """
    Get or create the global ColumnMapper singleton
    
    Returns:
        Global ColumnMapper instance
    """
    global _global_mapper
    if _global_mapper is None:
        _global_mapper = ColumnMapper()
    return _global_mapper


def get_column_info(column_index: int) -> Optional[ColumnDescriptor]:
    """
    Convenience function for quick column lookups
    
    Args:
        column_index: Column to query
        
    Returns:
        ColumnDescriptor or None
    """
    return get_global_mapper().get_column_descriptor(column_index)


# ============================================================================
# Export main classes and functions
# ============================================================================

__all__ = [
    'ColumnType',
    'ColumnDescriptor',
    'ColumnMapper',
    'get_global_mapper',
    'get_column_info'
]