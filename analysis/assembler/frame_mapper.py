# frame_mapper.py
# Forward mapping: Frame Address → Tiles → Resources
# Core engine for bitstream interpretation and Trojan detection
# Part of: "Turning the Table: Using Bitstream Reverse Engineering to Detect FPGA Trojans"

from dataclasses import dataclass
from typing import List, Set, Tuple, Optional, Dict
from enum import Enum
from functools import lru_cache


# Import from column_mapper.py
from analysis.assembler.column_mapper import (
    ColumnMapper,
    ColumnDescriptor,
    ColumnType,
    get_global_mapper
)


# Import from frame_rules.py
from analysis.frame_rules import (
    DeviceConstants,
    FrameAddress,
    BlockType
)

# ============================================================================
# Resource Category Enumeration
# ============================================================================

class ResourceCategory(Enum):
    """
    Categories of FPGA resources that frames can configure
    Used for semantic classification of frames
    """
    ROUTING = "routing"              # Interconnect PIPs and switches
    LOGIC = "logic"                  # LUTs, FFs, carry chains
    MEMORY = "memory"                # BRAM content
    CLOCK = "clock"                  # Clock distribution
    IO = "io"                        # Input/output configuration
    CONTROL = "control"              # Control signals, enables
    UNKNOWN = "unknown"              # Cannot determine


class TrojanRiskLevel(Enum):
    """
    Risk levels for Trojan insertion in different frame types
    Based on paper analysis of attack vectors
    """
    CRITICAL = "CRITICAL"  # Prime target (routing in unused regions)
    HIGH = "HIGH"          # High-value (clock, IO, routing)
    MEDIUM = "MEDIUM"      # Moderate (logic, BRAM interconnect)
    LOW = "LOW"            # Low priority (BRAM content, control)


# ============================================================================
# Frame Coverage Result Object
# ============================================================================

@dataclass(frozen=True)
class FrameCoverage:
    """
    Complete information about what a frame configures
    
    This is the primary output of frame_mapper. It contains everything
    needed to understand what a frame does, where it affects, and how
    it relates to Trojan detection.
    
    The object is frozen (immutable) for thread-safety and caching.
    """
    # Frame identification
    far_value: int
    far_hex: str
    block_type_id: int
    block_type_name: str
    
    # Spatial location
    column: int
    column_type: str
    minor: int
    top_bottom: int
    top_bottom_name: str
    
    # Tile coverage
    tiles_affected: Tuple[str, ...]
    tile_count: int
    tile_coordinates: Tuple[Tuple[int, int], ...]
    y_range: Tuple[int, int]
    
    # Resource classification
    resource_categories: Tuple[ResourceCategory, ...]
    is_routing_frame: bool
    is_logic_frame: bool
    is_memory_frame: bool
    is_clock_frame: bool
    is_io_frame: bool
    
    # Bit-level semantics
    routing_bit_ranges: Tuple[Tuple[int, int], ...]
    logic_bit_ranges: Tuple[Tuple[int, int], ...]
    total_routing_bits: int
    total_logic_bits: int
    
    # Security analysis
    is_security_critical: bool
    trojan_risk_level: TrojanRiskLevel
    attack_vectors: Tuple[str, ...]
    
    # Column context
    column_descriptor: ColumnDescriptor
    
    # Validation
    is_valid: bool
    validation_warnings: Tuple[str, ...]
    
    def __str__(self) -> str:
        """Human-readable representation"""
        return (f"Frame {self.far_hex} ({self.block_type_name}) @ "
                f"Col{self.column}[{self.column_type}] Minor{self.minor} "
                f"{'Top' if self.top_bottom else 'Bot'} → "
                f"{self.tile_count} tiles, "
                f"{'ROUTING' if self.is_routing_frame else 'LOGIC'}")
    
    def get_summary(self) -> Dict:
        """Get dictionary summary of key properties"""
        return {
            'far': self.far_hex,
            'location': f"X{self.column}Y{self.y_range}",
            'type': self.block_type_name,
            'tiles': self.tile_count,
            'routing': self.is_routing_frame,
            'risk': self.trojan_risk_level.value
        }


# ============================================================================
# Tile Range Descriptor
# ============================================================================

@dataclass(frozen=True)
class TileRange:
    """
    Describes the spatial extent of tiles affected by a frame
    """
    x_coordinate: int
    y_start: int
    y_end: int
    tile_types: Tuple[str, ...]
    
    def __contains__(self, coordinate: Tuple[int, int]) -> bool:
        """Check if a coordinate is within this range"""
        x, y = coordinate
        return x == self.x_coordinate and self.y_start <= y < self.y_end
    
    def get_all_coordinates(self) -> List[Tuple[int, int]]:
        """Get all (x, y) coordinates in this range"""
        return [(self.x_coordinate, y) for y in range(self.y_start, self.y_end)]


# ============================================================================
# Frame Mapper - Main Forward Mapping Engine
# ============================================================================

class FrameMapper:
    """
    Forward mapping engine: Frame Address → Physical Resources
    
    This is the core component that interprets frame addresses and
    determines what they configure. It's essential for:
    - Bitstream interpretation
    - Trojan detection
    - Configuration coverage analysis
    
    Usage:
        mapper = FrameMapper()
        coverage = mapper.map_frame(far_value)
        print(f"Frame affects: {coverage.tiles_affected}")
        print(f"Risk level: {coverage.trojan_risk_level}")
    """
    
    def __init__(self, column_mapper: Optional[ColumnMapper] = None):
        """
        Initialize the frame mapper
        
        Args:
            column_mapper: Optional ColumnMapper instance (creates one if None)
        """
        self.column_mapper = column_mapper or get_global_mapper()
        
        # Performance: cache for frequently accessed frames
        self._coverage_cache: Dict[int, FrameCoverage] = {}
    
    # ========================================================================
    # Core Mapping Methods
    # ========================================================================
    
    @lru_cache(maxsize=256)
    def map_frame(self, far_value: int) -> FrameCoverage:
        """
        Complete forward mapping of a frame address
        
        This is the PRIMARY method - takes a FAR and returns everything
        about what it configures.
        
        Args:
            far_value: Frame Address Register value (32-bit)
            
        Returns:
            FrameCoverage object with complete information
            
        Example:
            coverage = mapper.map_frame(0x00020340)
            for tile in coverage.tiles_affected:
                print(f"Frame configures: {tile}")
        """
        # Validate frame address
        is_valid, validation_msg = FrameAddress.validate(far_value)
        warnings = [] if is_valid else [validation_msg or "Invalid FAR"]
        
        # Decode frame address fields
        fields = FrameAddress.decode(far_value)
        block_type_id = fields['block_type']
        top_bottom = fields['top_bottom']
        major = fields['major']
        minor = fields['minor']
        
        # Get block type name
        block_type_name = BlockType.get_name(block_type_id)
        
        # Get column context
        column_desc = self.column_mapper.get_column_descriptor(major)
        if not column_desc:
            # Create minimal coverage for invalid column
            return self._create_invalid_coverage(far_value, "Invalid column")
        
        # Verify block type matches column (handle BRAM special case)
        expected_block = column_desc.get_block_type_for_minor(minor)
        if expected_block != block_type_id:
            warnings.append(f"Block type {block_type_name} unexpected for column {major}")
        
        # Calculate spatial coverage
        tile_range = self._calculate_tile_range(major, minor, top_bottom, column_desc)
        tiles = self._generate_tile_names(tile_range)
        coordinates = tile_range.get_all_coordinates()
        
        # Determine resource categories
        categories = self._classify_resources(block_type_id, column_desc, minor)
        
        # Get bit-level semantics
        routing_bits, logic_bits = self._get_bit_semantics(far_value, block_type_id, minor, column_desc)
        
        # Assess security risk
        risk_level, attack_vectors = self._assess_trojan_risk(
            block_type_id, column_desc, minor, categories
        )
        
        # Build coverage object
        coverage = FrameCoverage(
            # Frame identification
            far_value=far_value,
            far_hex=f"0x{far_value:08X}",
            block_type_id=block_type_id,
            block_type_name=block_type_name,
            
            # Spatial location
            column=major,
            column_type=column_desc.column_type.value,
            minor=minor,
            top_bottom=top_bottom,
            top_bottom_name="Top" if top_bottom == 1 else "Bottom",
            
            # Tile coverage
            tiles_affected=tuple(tiles),
            tile_count=len(tiles),
            tile_coordinates=tuple(coordinates),
            y_range=(tile_range.y_start, tile_range.y_end),
            
            # Resource classification
            resource_categories=tuple(categories),
            is_routing_frame=ResourceCategory.ROUTING in categories,
            is_logic_frame=ResourceCategory.LOGIC in categories,
            is_memory_frame=ResourceCategory.MEMORY in categories,
            is_clock_frame=ResourceCategory.CLOCK in categories,
            is_io_frame=ResourceCategory.IO in categories,
            
            # Bit-level semantics
            routing_bit_ranges=tuple(routing_bits),
            logic_bit_ranges=tuple(logic_bits),
            total_routing_bits=sum(end - start for start, end in routing_bits),
            total_logic_bits=sum(end - start for start, end in logic_bits),
            
            # Security analysis
            is_security_critical=column_desc.is_security_critical,
            trojan_risk_level=risk_level,
            attack_vectors=tuple(attack_vectors),
            
            # Column context
            column_descriptor=column_desc,
            
            # Validation
            is_valid=is_valid and len(warnings) == 0,
            validation_warnings=tuple(warnings)
        )
        
        return coverage
    
    def _calculate_tile_range(self, column: int, minor: int, top_bottom: int,
                              column_desc: ColumnDescriptor) -> TileRange:
        """
        Calculate the vertical range of tiles affected by a frame
        
        Each frame covers 20 tile rows vertically. The device is split
        into top (Y >= 80) and bottom (Y < 80) halves.
        
        Args:
            column: Column (X) coordinate
            minor: Minor address (frame index within column)
            top_bottom: 0 = bottom half, 1 = top half
            column_desc: Column descriptor
            
        Returns:
            TileRange object
        """
        # Each frame covers this many tile rows
        tiles_per_frame = DeviceConstants.TILES_PER_ROW
        
        # Calculate Y base offset
        if top_bottom == 1:  # Top half
            y_base = 80  # Top half starts at Y=80
        else:  # Bottom half
            y_base = 0
        
        # Calculate Y range for this frame
        y_start = y_base + (minor * tiles_per_frame)
        y_end = y_start + tiles_per_frame
        
        # Clamp to device bounds
        y_end = min(y_end, DeviceConstants.TOTAL_TILE_ROWS)
        
        return TileRange(
            x_coordinate=column,
            y_start=y_start,
            y_end=y_end,
            tile_types=column_desc.tile_types
        )
    
    def _generate_tile_names(self, tile_range: TileRange) -> List[str]:
        """
        Generate all tile names in a range
        
        Format: "TILETYPE_X#Y#"
        
        Args:
            tile_range: Tile range to generate names for
            
        Returns:
            List of tile names
        """
        tiles = []
        for tile_type in tile_range.tile_types:
            for y in range(tile_range.y_start, tile_range.y_end):
                tile_name = f"{tile_type}_X{tile_range.x_coordinate}Y{y}"
                tiles.append(tile_name)
        return tiles
    
    def _classify_resources(self, block_type: int, column_desc: ColumnDescriptor,
                           minor: int) -> Set[ResourceCategory]:
        """
        Determine what resource categories this frame configures
        
        Args:
            block_type: Block type ID
            column_desc: Column descriptor
            minor: Minor address
            
        Returns:
            Set of resource categories
        """
        categories = set()
        
        # Check block type properties
        if BlockType.contains_routing(block_type):
            categories.add(ResourceCategory.ROUTING)
        
        if BlockType.contains_logic(block_type):
            categories.add(ResourceCategory.LOGIC)
        
        # Specific block type classification
        if block_type == BlockType.CLB:
            if column_desc.is_routing_frame(minor):
                categories.add(ResourceCategory.ROUTING)
            else:
                categories.add(ResourceCategory.LOGIC)
        
        elif block_type == BlockType.IOB:
            categories.add(ResourceCategory.IO)
            categories.add(ResourceCategory.ROUTING)
        
        elif block_type == BlockType.BRAM_CONTENT:
            categories.add(ResourceCategory.MEMORY)
        
        elif block_type == BlockType.BRAM_INT:
            categories.add(ResourceCategory.ROUTING)
        
        elif block_type == BlockType.CLK:
            categories.add(ResourceCategory.CLOCK)
            categories.add(ResourceCategory.ROUTING)
        
        # Add control if it has control signals
        if block_type in [BlockType.CLB, BlockType.IOB, BlockType.CLK]:
            categories.add(ResourceCategory.CONTROL)
        
        return categories if categories else {ResourceCategory.UNKNOWN}
    
    def _get_bit_semantics(self, far_value: int, block_type: int, minor: int,
                          column_desc: ColumnDescriptor) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
        """
        Get bit range semantics for routing and logic
        
        Args:
            far_value: Frame address
            block_type: Block type ID
            minor: Minor address
            column_desc: Column descriptor
            
        Returns:
            (routing_bit_ranges, logic_bit_ranges) tuple of lists
        """
        routing_ranges = []
        logic_ranges = []
        
        # Use BitRegions from frame_rules
        if block_type == BlockType.CLB:
            if column_desc.is_routing_frame(minor):
                routing_ranges = [(0, 832)]  # Interconnect + CLB routing
            else:
                logic_ranges = [(832, 1200)]  # LUTs, FFs, etc.
        
        elif block_type == BlockType.IOB:
            routing_ranges = [(0, 800)]
            logic_ranges = [(800, 1312)]
        
        elif block_type == BlockType.BRAM_CONTENT:
            logic_ranges = [(0, 1312)]  # All memory content
        
        elif block_type == BlockType.BRAM_INT:
            routing_ranges = [(0, 1312)]  # All routing
        
        elif block_type == BlockType.CLK:
            routing_ranges = [(0, 1312)]  # All clock routing
        
        return routing_ranges, logic_ranges
    
    def _assess_trojan_risk(self, block_type: int, column_desc: ColumnDescriptor,
                           minor: int, categories: Set[ResourceCategory]) -> Tuple[TrojanRiskLevel, List[str]]:
        """
        Assess Trojan insertion risk for this frame
        
        Based on paper's analysis of common attack vectors:
        - Routing modifications (highest risk)
        - Unused region tampering
        - Clock network manipulation
        - IO exfiltration paths
        
        Args:
            block_type: Block type ID
            column_desc: Column descriptor
            minor: Minor address
            categories: Resource categories
            
        Returns:
            (risk_level, attack_vectors) tuple
        """
        attack_vectors = []
        
        # Clock manipulation is CRITICAL
        if ResourceCategory.CLOCK in categories:
            attack_vectors.append("clock_network_tampering")
            attack_vectors.append("timing_manipulation")
            return TrojanRiskLevel.CRITICAL, attack_vectors
        
        # IO exfiltration is CRITICAL
        if column_desc.column_type == ColumnType.IOB:
            attack_vectors.append("data_exfiltration")
            attack_vectors.append("covert_channel_creation")
            return TrojanRiskLevel.CRITICAL, attack_vectors
        
        # Routing in CLB is HIGH risk (common Trojan hiding spot)
        if ResourceCategory.ROUTING in categories and block_type == BlockType.CLB:
            attack_vectors.append("routing_detour")
            attack_vectors.append("minimal_modification_trojan")
            attack_vectors.append("unused_region_routing")
            return TrojanRiskLevel.HIGH, attack_vectors
        
        # BRAM interconnect is HIGH (can intercept data)
        if block_type == BlockType.BRAM_INT:
            attack_vectors.append("memory_access_interception")
            attack_vectors.append("data_flow_manipulation")
            return TrojanRiskLevel.HIGH, attack_vectors
        
        # Logic configuration is MEDIUM
        if ResourceCategory.LOGIC in categories:
            attack_vectors.append("hidden_logic_insertion")
            attack_vectors.append("lut_truth_table_modification")
            return TrojanRiskLevel.MEDIUM, attack_vectors
        
        # BRAM content is MEDIUM (payload storage)
        if ResourceCategory.MEMORY in categories:
            attack_vectors.append("malicious_payload_storage")
            return TrojanRiskLevel.MEDIUM, attack_vectors
        
        # Default to LOW
        return TrojanRiskLevel.LOW, attack_vectors
    
    def _create_invalid_coverage(self, far_value: int, error: str) -> FrameCoverage:
        """
        Create a minimal coverage object for invalid FARs
        
        Args:
            far_value: Invalid FAR value
            error: Error message
            
        Returns:
            FrameCoverage with error information
        """
        return FrameCoverage(
            far_value=far_value,
            far_hex=f"0x{far_value:08X}",
            block_type_id=-1,
            block_type_name="INVALID",
            column=-1,
            column_type="INVALID",
            minor=-1,
            top_bottom=-1,
            top_bottom_name="INVALID",
            tiles_affected=tuple(),
            tile_count=0,
            tile_coordinates=tuple(),
            y_range=(0, 0),
            resource_categories=(ResourceCategory.UNKNOWN,),
            is_routing_frame=False,
            is_logic_frame=False,
            is_memory_frame=False,
            is_clock_frame=False,
            is_io_frame=False,
            routing_bit_ranges=tuple(),
            logic_bit_ranges=tuple(),
            total_routing_bits=0,
            total_logic_bits=0,
            is_security_critical=False,
            trojan_risk_level=TrojanRiskLevel.LOW,
            attack_vectors=tuple(),
            column_descriptor=None,  # type: ignore
            is_valid=False,
            validation_warnings=(error,)
        )
    
    # ========================================================================
    # Convenience Query Methods
    # ========================================================================
    
    def get_tiles_for_frame(self, far_value: int) -> List[str]:
        """
        Quick lookup: FAR → tile names
        
        Args:
            far_value: Frame address
            
        Returns:
            List of tile names
        """
        coverage = self.map_frame(far_value)
        return list(coverage.tiles_affected)
    
    def get_resource_type(self, far_value: int) -> ResourceCategory:
        """
        Quick lookup: FAR → primary resource type
        
        Args:
            far_value: Frame address
            
        Returns:
            Primary resource category
        """
        coverage = self.map_frame(far_value)
        if coverage.is_routing_frame:
            return ResourceCategory.ROUTING
        elif coverage.is_logic_frame:
            return ResourceCategory.LOGIC
        elif coverage.is_memory_frame:
            return ResourceCategory.MEMORY
        elif coverage.is_clock_frame:
            return ResourceCategory.CLOCK
        else:
            return ResourceCategory.UNKNOWN
    
    def is_security_critical_frame(self, far_value: int) -> bool:
        """
        Check if frame is security-critical
        
        Args:
            far_value: Frame address
            
        Returns:
            True if frame is high-value Trojan target
        """
        coverage = self.map_frame(far_value)
        return coverage.is_security_critical
    
    def get_neighboring_frames(self, far_value: int, distance: int = 1) -> List[int]:
        """
        Get frames near this one (spatially adjacent)
        
        Useful for analyzing Trojan propagation patterns.
        
        Args:
            far_value: Center frame
            distance: Manhattan distance in frames
            
        Returns:
            List of neighboring FAR values
        """
        fields = FrameAddress.decode(far_value)
        neighbors = []
        
        # Neighbors in same column (different minors)
        for minor_offset in range(-distance, distance + 1):
            if minor_offset == 0:
                continue
            new_minor = fields['minor'] + minor_offset
            if new_minor >= 0:
                new_far = FrameAddress.encode(
                    fields['block_type'],
                    fields['top_bottom'],
                    fields['major'],
                    new_minor
                )
                # Validate
                if FrameAddress.validate(new_far)[0]:
                    neighbors.append(new_far)
        
        # Neighbors in adjacent columns (same minor)
        for col_offset in [-1, 1]:
            new_col = fields['major'] + col_offset
            if 0 <= new_col < DeviceConstants.TOTAL_COLUMNS:
                # Get block type for new column
                col_desc = self.column_mapper.get_column_descriptor(new_col)
                if col_desc:
                    new_block = col_desc.get_block_type_for_minor(fields['minor'])
                    new_far = FrameAddress.encode(
                        new_block,
                        fields['top_bottom'],
                        new_col,
                        fields['minor']
                    )
                    if FrameAddress.validate(new_far)[0]:
                        neighbors.append(new_far)
        
        return neighbors
    
    def analyze_frame_batch(self, far_list: List[int]) -> Dict:
        """
        Analyze a batch of frames and return statistics
        
        Useful for understanding configuration coverage.
        
        Args:
            far_list: List of frame addresses
            
        Returns:
            Dictionary with batch statistics
        """
        stats = {
            'total_frames': len(far_list),
            'routing_frames': 0,
            'logic_frames': 0,
            'memory_frames': 0,
            'security_critical': 0,
            'risk_distribution': {level.value: 0 for level in TrojanRiskLevel},
            'block_types': {},
            'columns_covered': set(),
            'tiles_covered': set()
        }
        
        for far in far_list:
            coverage = self.map_frame(far)
            
            if coverage.is_routing_frame:
                stats['routing_frames'] += 1
            if coverage.is_logic_frame:
                stats['logic_frames'] += 1
            if coverage.is_memory_frame:
                stats['memory_frames'] += 1
            if coverage.is_security_critical:
                stats['security_critical'] += 1
            
            stats['risk_distribution'][coverage.trojan_risk_level.value] += 1
            
            bt_name = coverage.block_type_name
            stats['block_types'][bt_name] = stats['block_types'].get(bt_name, 0) + 1
            
            stats['columns_covered'].add(coverage.column)
            stats['tiles_covered'].update(coverage.tiles_affected)
        
        # Convert sets to counts
        stats['unique_columns'] = len(stats['columns_covered'])
        stats['unique_tiles'] = len(stats['tiles_covered'])
        stats['columns_covered'] = sorted(list(stats['columns_covered']))
        stats['tiles_covered'] = len(stats['tiles_covered'])
        
        return stats


# ============================================================================
# Module-level convenience functions
# ============================================================================

_global_frame_mapper: Optional[FrameMapper] = None

def get_global_frame_mapper() -> FrameMapper:
    """Get or create the global FrameMapper singleton"""
    global _global_frame_mapper
    if _global_frame_mapper is None:
        _global_frame_mapper = FrameMapper()
    return _global_frame_mapper


def map_frame(far_value: int) -> FrameCoverage:
    """Convenience function for quick frame mapping"""
    return get_global_frame_mapper().map_frame(far_value)


# ============================================================================
# Export main classes and functions
# ============================================================================

__all__ = [
    'ResourceCategory',
    'TrojanRiskLevel',
    'FrameCoverage',
    'TileRange',
    'FrameMapper',
    'get_global_frame_mapper',
    'map_frame'
]