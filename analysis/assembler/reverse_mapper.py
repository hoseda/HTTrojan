# reverse_mapper.py
# Reverse mapping: Tile/Resource → Frame Addresses
# Critical for Trojan localization and targeted bitstream inspection
# Part of: "Turning the Table: Using Bitstream Reverse Engineering to Detect FPGA Trojans"

import re
from dataclasses import dataclass
from typing import List, Set, Tuple, Optional, Dict
from functools import lru_cache


# Import from frame_rules.py
from analysis.frame_rules import (
    DeviceConstants,
    FrameAddress,
    BlockType
)


# Import from column_mapper.py
from analysis.assembler.column_mapper import (
    ColumnMapper,
    ColumnType,
    get_global_mapper as get_global_column_mapper
)

# Import from frame_mapper.py
from analysis.assembler.frame_mapper import (
    FrameMapper,
    ResourceCategory,
    get_global_frame_mapper
)




# ============================================================================
# Frame Reference Data Classes
# ============================================================================

@dataclass(frozen=True)
class FrameReference:
    """
    Reference to a frame with optional bit-level information
    
    Used when we know not just which frame, but which bits within it
    are relevant to a specific resource.
    """
    far_value: int
    frame_type: str  # "routing", "logic", "memory", etc.
    bit_ranges: Optional[Tuple[Tuple[int, int], ...]] = None
    confidence: float = 1.0  # How certain we are about this mapping
    
    def __str__(self) -> str:
        return f"FAR 0x{self.far_value:08X} ({self.frame_type})"


@dataclass
class ResourceLocation:
    """
    Physical location of a resource in the FPGA
    """
    tile_name: str
    tile_type: str
    x_coordinate: int
    y_coordinate: int
    resource_type: ResourceCategory
    
    @staticmethod
    def from_tile_name(tile_name: str, resource_type: ResourceCategory = ResourceCategory.UNKNOWN) -> Optional['ResourceLocation']:
        """
        Parse a tile name into a ResourceLocation
        
        Args:
            tile_name: Tile name like "CLBLL_X23Y45"
            resource_type: Type of resource
            
        Returns:
            ResourceLocation or None if invalid
        """
        match = re.match(r'([A-Z_]+)_X(\d+)Y(\d+)', tile_name)
        if not match:
            return None
        
        tile_type, x_str, y_str = match.groups()
        return ResourceLocation(
            tile_name=tile_name,
            tile_type=tile_type,
            x_coordinate=int(x_str),
            y_coordinate=int(y_str),
            resource_type=resource_type
        )


# ============================================================================
# Reverse Mapper - Main Engine
# ============================================================================

class ReverseMapper:
    """
    Reverse mapping engine: Resources → Frame Addresses
    
    This class solves the inverse problem: given a tile, wire, or site,
    find which frame(s) configure it. Essential for:
    - Trojan localization
    - Selective bitstream inspection
    - Differential analysis
    
    Implementation uses multiple index strategies:
    1. Tile-to-frame index (pre-computed)
    2. Coordinate-to-frame index (on-demand with cache)
    3. Column-to-frame-list index (pre-computed)
    
    Usage:
        mapper = ReverseMapper()
        frames = mapper.get_frames_for_tile("CLBLL_X23Y45")
        print(f"Tile configured by {len(frames)} frames")
    """
    
    def __init__(self, 
                 column_mapper: Optional[ColumnMapper] = None,
                 frame_mapper: Optional[FrameMapper] = None):
        """
        Initialize the reverse mapper
        
        Args:
            column_mapper: Optional ColumnMapper instance
            frame_mapper: Optional FrameMapper instance
        """
        self.column_mapper = column_mapper or get_global_column_mapper()
        self.frame_mapper = frame_mapper or get_global_frame_mapper()
        
        # Indices for fast lookups
        self._tile_to_frames: Dict[str, List[int]] = {}
        self._coordinate_to_frames: Dict[Tuple[int, int], List[int]] = {}
        self._column_to_frames: Dict[int, List[int]] = {}
        
        # Index build status
        self._indices_built = False
        self._build_strategy = "hybrid"  # "full", "lazy", or "hybrid"
    
    # ========================================================================
    # Index Building
    # ========================================================================
    
    def build_indices(self, strategy: str = "hybrid"):
        """
        Build reverse lookup indices
        
        Strategies:
        - "full": Pre-compute everything (memory-intensive, fast queries)
        - "lazy": Compute on-demand (memory-efficient, slower first queries)
        - "hybrid": Pre-compute structure, cache hot paths (balanced)
        
        Args:
            strategy: Index building strategy
        """
        self._build_strategy = strategy
        
        if strategy == "full":
            self._build_full_indices()
        elif strategy == "hybrid":
            self._build_hybrid_indices()
        # lazy strategy builds indices on-demand
        
        self._indices_built = True
    
    def _build_full_indices(self):
        """
        Pre-compute all tile→frame mappings
        
        Iterates through all valid frames and builds complete index.
        Memory-intensive but provides fastest queries.
        """
        print("Building full tile→frame indices...")
        
        # For each column
        for col_idx in range(DeviceConstants.TOTAL_COLUMNS):
            col_desc = self.column_mapper.get_column_descriptor(col_idx)
            if not col_desc:
                continue
            
            frames_in_column = []
            
            # For each possible frame in this column
            for minor in range(col_desc.frames_per_column):
                # Get block type for this minor
                block_type = col_desc.get_block_type_for_minor(minor)
                
                # Try both top and bottom halves
                for top_bottom in [0, 1]:
                    far = FrameAddress.encode(block_type, top_bottom, col_idx, minor)
                    
                    # Validate
                    if not FrameAddress.validate(far)[0]:
                        continue
                    
                    frames_in_column.append(far)
                    
                    # Get tiles for this frame
                    coverage = self.frame_mapper.map_frame(far)
                    for tile in coverage.tiles_affected:
                        if tile not in self._tile_to_frames:
                            self._tile_to_frames[tile] = []
                        self._tile_to_frames[tile].append(far)
            
            # Store column→frames mapping
            self._column_to_frames[col_idx] = frames_in_column
        
        print(f"Indexed {len(self._tile_to_frames)} tiles")
    
    def _build_hybrid_indices(self):
        """
        Build skeleton indices with on-demand caching
        
        Pre-computes column structure but calculates specific
        frames on-demand. Good balance of memory and speed.
        """
        print("Building hybrid indices...")
        
        # Pre-compute column→frame structure
        for col_idx in range(DeviceConstants.TOTAL_COLUMNS):
            col_desc = self.column_mapper.get_column_descriptor(col_idx)
            if col_desc:
                self._column_to_frames[col_idx] = []
                # We'll populate this lazily as needed
        
        print("Skeleton indices ready (lazy loading enabled)")
    
    # ========================================================================
    # Core Reverse Lookup Methods
    # ========================================================================
    
    @lru_cache(maxsize=2048)
    def get_frames_for_tile(self, tile_name: str) -> List[FrameReference]:
        """
        Get all frames that configure a specific tile
        
        A single tile is configured by MULTIPLE frames:
        - Routing frames (interconnect configuration)
        - Logic frames (LUT/FF configuration)
        - Control frames (clock enables, resets)
        
        Args:
            tile_name: Tile name like "CLBLL_X23Y45"
            
        Returns:
            List of FrameReference objects
            
        Example:
            frames = mapper.get_frames_for_tile("CLBLL_X23Y45")
            for frame_ref in frames:
                print(f"Frame {frame_ref.far_value:08X} ({frame_ref.frame_type})")
        """
        # Check cache first
        if self._indices_built and tile_name in self._tile_to_frames:
            far_list = self._tile_to_frames[tile_name]
            return self._convert_to_frame_references(far_list)
        
        # Parse tile name
        location = ResourceLocation.from_tile_name(tile_name)
        if not location:
            return []
        
        # Calculate frames
        frames = self._calculate_frames_for_coordinate(
            location.x_coordinate,
            location.y_coordinate,
            location.tile_type
        )
        
        # Cache result
        if self._build_strategy in ["hybrid", "lazy"]:
            self._tile_to_frames[tile_name] = [ref.far_value for ref in frames]
        
        return frames
    
    @lru_cache(maxsize=2048)
    def get_frames_for_coordinate(self, x: int, y: int) -> List[FrameReference]:
        """
        Get frames for a coordinate (X, Y)
        
        Args:
            x: Column index
            y: Row index
            
        Returns:
            List of FrameReference objects
        """
        # Check cache
        coord = (x, y)
        if self._indices_built and coord in self._coordinate_to_frames:
            far_list = self._coordinate_to_frames[coord]
            return self._convert_to_frame_references(far_list)
        
        # Get column descriptor
        col_desc = self.column_mapper.get_column_descriptor(x)
        if not col_desc:
            return []
        
        # Calculate frames for all tile types at this coordinate
        all_frames = []
        for tile_type in col_desc.tile_types:
            frames = self._calculate_frames_for_coordinate(x, y, tile_type)
            all_frames.extend(frames)
        
        # Deduplicate
        seen = set()
        unique_frames = []
        for ref in all_frames:
            if ref.far_value not in seen:
                seen.add(ref.far_value)
                unique_frames.append(ref)
        
        return unique_frames
    
    def _calculate_frames_for_coordinate(self, x: int, y: int, tile_type: str) -> List[FrameReference]:
        """
        Calculate which frames affect a specific coordinate
        
        This is the core algorithm for reverse lookup.
        
        Algorithm:
        1. Determine top/bottom half from Y coordinate
        2. Calculate minor address from Y offset within half
        3. Get block type from column and tile type
        4. Encode FAR and validate
        5. Return all relevant frames (routing + logic)
        
        Args:
            x: Column coordinate
            y: Row coordinate
            tile_type: Type of tile at this location
            
        Returns:
            List of FrameReference objects
        """
        frames = []
        
        # Get column descriptor
        col_desc = self.column_mapper.get_column_descriptor(x)
        if not col_desc:
            return frames
        
        # Determine top/bottom half
        if y >= 80:
            top_bottom = 1
            y_in_half = y - 80
        else:
            top_bottom = 0
            y_in_half = y
        
        # Calculate minor address
        # Each frame covers 20 tile rows
        minor = y_in_half // DeviceConstants.TILES_PER_ROW
        
        # Verify minor is valid for this column
        if not col_desc.is_minor_valid(minor):
            return frames
        
        # Get block type from tile type and column
        try:
            block_type = BlockType.get_block_type_from_tile(tile_type)
        except ValueError:
            # If tile type doesn't directly map, use column default
            block_type = col_desc.get_block_type_for_minor(minor)
        
        # For CLB tiles, we need BOTH routing and logic frames
        if col_desc.column_type == ColumnType.CLB:
            # Routing frames (first N frames in column)
            routing_count = col_desc.routing_frame_count
            for routing_minor in range(routing_count):
                if routing_minor * 20 <= y_in_half < (routing_minor + 1) * 20:
                    far = FrameAddress.encode(BlockType.CLB, top_bottom, x, routing_minor)
                    if FrameAddress.validate(far)[0]:
                        frames.append(FrameReference(
                            far_value=far,
                            frame_type="routing",
                            confidence=1.0
                        ))
            
            # Logic frames (remaining frames in column)
            logic_minor_start = routing_count
            for logic_minor in range(logic_minor_start, col_desc.frames_per_column):
                if logic_minor * 20 <= y_in_half < (logic_minor + 1) * 20:
                    far = FrameAddress.encode(BlockType.CLB, top_bottom, x, logic_minor)
                    if FrameAddress.validate(far)[0]:
                        frames.append(FrameReference(
                            far_value=far,
                            frame_type="logic",
                            confidence=1.0
                        ))
        
        # For BRAM columns, need both content and interconnect
        elif col_desc.column_type == ColumnType.BRAM:
            # BRAM interconnect frames (minors 0-27)
            if minor < 28:
                far = FrameAddress.encode(BlockType.BRAM_INT, top_bottom, x, minor)
                if FrameAddress.validate(far)[0]:
                    frames.append(FrameReference(
                        far_value=far,
                        frame_type="bram_interconnect",
                        confidence=1.0
                    ))
            
            # BRAM content frames (minors 28+)
            content_minor = minor + 28  # Offset for content frames
            if content_minor < col_desc.frames_per_column:
                far = FrameAddress.encode(BlockType.BRAM_CONTENT, top_bottom, x, content_minor)
                if FrameAddress.validate(far)[0]:
                    frames.append(FrameReference(
                        far_value=far,
                        frame_type="bram_content",
                        confidence=1.0
                    ))
        
        # For other column types (IOB, CLK), single frame type
        else:
            far = FrameAddress.encode(block_type, top_bottom, x, minor)
            if FrameAddress.validate(far)[0]:
                frame_type = "io" if col_desc.column_type == ColumnType.IOB else "clock"
                frames.append(FrameReference(
                    far_value=far,
                    frame_type=frame_type,
                    confidence=1.0
                ))
        
        return frames
    
    def _convert_to_frame_references(self, far_list: List[int]) -> List[FrameReference]:
        """
        Convert list of FAR values to FrameReference objects
        
        Args:
            far_list: List of frame addresses
            
        Returns:
            List of FrameReference objects with type information
        """
        references = []
        for far in far_list:
            coverage = self.frame_mapper.map_frame(far)
            
            # Determine primary frame type
            if coverage.is_routing_frame:
                frame_type = "routing"
            elif coverage.is_logic_frame:
                frame_type = "logic"
            elif coverage.is_memory_frame:
                frame_type = "memory"
            elif coverage.is_clock_frame:
                frame_type = "clock"
            else:
                frame_type = "unknown"
            
            references.append(FrameReference(
                far_value=far,
                frame_type=frame_type,
                bit_ranges=coverage.routing_bit_ranges if coverage.is_routing_frame else coverage.logic_bit_ranges,
                confidence=1.0
            ))
        
        return references
    
    # ========================================================================
    # Advanced Reverse Lookup Methods
    # ========================================================================
    
    def get_frames_for_site(self, site_name: str) -> List[FrameReference]:
        """
        Get frames that configure a site (SLICE, IOB, BRAM, etc.)
        
        Sites are named like "SLICE_X12Y34" or "RAMB16_X2Y10"
        
        Args:
            site_name: Site name
            
        Returns:
            List of FrameReference objects
        """
        # Parse site name to extract coordinates
        match = re.match(r'[A-Z0-9_]+_X(\d+)Y(\d+)', site_name)
        if not match:
            return []
        
        x = int(match.group(1))
        y = int(match.group(2))
        
        # For now, treat site same as coordinate
        # In a full implementation, would use site-specific mappings
        return self.get_frames_for_coordinate(x, y)
    
    def get_frames_in_region(self, x_range: Tuple[int, int], 
                            y_range: Tuple[int, int]) -> Set[int]:
        """
        Get all frames that affect a rectangular region
        
        Useful for analyzing a design region or unused area detection.
        
        Args:
            x_range: (x_min, x_max) inclusive
            y_range: (y_min, y_max) inclusive
            
        Returns:
            Set of FAR values
            
        Example:
            # Get all frames in bottom-left quadrant
            frames = mapper.get_frames_in_region((0, 23), (0, 79))
        """
        frames = set()
        
        x_min, x_max = x_range
        y_min, y_max = y_range
        
        for x in range(x_min, x_max + 1):
            for y in range(y_min, y_max + 1):
                frame_refs = self.get_frames_for_coordinate(x, y)
                for ref in frame_refs:
                    frames.add(ref.far_value)
        
        return frames
    
    def get_frames_for_column(self, column_index: int) -> List[int]:
        """
        Get all frames in a specific column
        
        Args:
            column_index: Column index
            
        Returns:
            List of FAR values
        """
        # Check cache
        if column_index in self._column_to_frames and self._column_to_frames[column_index]:
            return self._column_to_frames[column_index].copy()
        
        # Calculate all frames for this column
        col_desc = self.column_mapper.get_column_descriptor(column_index)
        if not col_desc:
            return []
        
        frames = []
        
        for minor in range(col_desc.frames_per_column):
            block_type = col_desc.get_block_type_for_minor(minor)
            
            for top_bottom in [0, 1]:
                far = FrameAddress.encode(block_type, top_bottom, column_index, minor)
                if FrameAddress.validate(far)[0]:
                    frames.append(far)
        
        # Cache result
        self._column_to_frames[column_index] = frames
        
        return frames.copy()
    
    def get_routing_frames_for_tile(self, tile_name: str) -> List[FrameReference]:
        """
        Get only routing frames for a tile (filter out logic)
        
        Critical for Trojan detection focusing on routing modifications.
        
        Args:
            tile_name: Tile name
            
        Returns:
            List of FrameReference objects (routing only)
        """
        all_frames = self.get_frames_for_tile(tile_name)
        return [ref for ref in all_frames if ref.frame_type == "routing"]
    
    def get_logic_frames_for_tile(self, tile_name: str) -> List[FrameReference]:
        """
        Get only logic frames for a tile (filter out routing)
        
        Args:
            tile_name: Tile name
            
        Returns:
            List of FrameReference objects (logic only)
        """
        all_frames = self.get_frames_for_tile(tile_name)
        return [ref for ref in all_frames if ref.frame_type == "logic"]
    
    # ========================================================================
    # Trojan Detection Support Methods
    # ========================================================================
    
    def get_frames_for_used_tiles(self, used_tiles: Set[str]) -> Set[int]:
        """
        Get all frames that configure used tiles in a design
        
        This defines the "expected configuration footprint" for
        Trojan detection. Frames outside this set are suspicious.
        
        Args:
            used_tiles: Set of tile names used by legitimate design
            
        Returns:
            Set of FAR values that should be configured
            
        Example:
            # Get expected frames from netlist analysis
            used_tiles = {"CLBLL_X23Y45", "CLBLL_X23Y46", ...}
            expected_frames = mapper.get_frames_for_used_tiles(used_tiles)
            
            # Compare with actual configured frames
            suspicious = actual_frames - expected_frames
        """
        expected_frames = set()
        
        for tile in used_tiles:
            frame_refs = self.get_frames_for_tile(tile)
            for ref in frame_refs:
                expected_frames.add(ref.far_value)
        
        return expected_frames
    
    def find_unused_region_frames(self, used_tiles: Set[str]) -> Set[int]:
        """
        Find frames in unused regions (prime Trojan hiding spots)
        
        Args:
            used_tiles: Set of tiles used by legitimate design
            
        Returns:
            Set of FAR values in unused regions
        """
        # Get all possible frames
        all_frames = set()
        for col_idx in range(DeviceConstants.TOTAL_COLUMNS):
            all_frames.update(self.get_frames_for_column(col_idx))
        
        # Get expected frames
        expected_frames = self.get_frames_for_used_tiles(used_tiles)
        
        # Unused = all - expected
        unused_frames = all_frames - expected_frames
        
        return unused_frames
    
    def localize_suspicious_modification(self, modified_frame: int,
                                        used_tiles: Set[str]) -> Dict:
        """
        Analyze a modified frame to determine if it's suspicious
        
        This implements the paper's localization strategy.
        
        Args:
            modified_frame: FAR value that was modified
            used_tiles: Set of tiles used by legitimate design
            
        Returns:
            Dictionary with localization analysis
        """
        # Get frame coverage
        coverage = self.frame_mapper.map_frame(modified_frame)
        
        # Check if frame affects used tiles
        frame_tiles = set(coverage.tiles_affected)
        used_intersection = frame_tiles.intersection(used_tiles)
        unused_intersection = frame_tiles - used_tiles
        
        # Assess suspicion level
        if len(unused_intersection) > 0 and coverage.is_routing_frame:
            suspicion = "HIGH"
            reason = "Routing modifications in unused region"
        elif len(used_intersection) > 0 and coverage.is_routing_frame:
            suspicion = "MEDIUM"
            reason = "Routing modifications in used region (possible detour)"
        elif len(unused_intersection) > 0 and coverage.is_logic_frame:
            suspicion = "MEDIUM"
            reason = "Logic configuration in unused region"
        else:
            suspicion = "LOW"
            reason = "Modification in expected location"
        
        return {
            'far_value': modified_frame,
            'far_hex': coverage.far_hex,
            'block_type': coverage.block_type_name,
            'column': coverage.column,
            'tiles_affected': list(coverage.tiles_affected),
            'tiles_used': list(used_intersection),
            'tiles_unused': list(unused_intersection),
            'is_routing': coverage.is_routing_frame,
            'is_logic': coverage.is_logic_frame,
            'suspicion_level': suspicion,
            'reason': reason,
            'trojan_risk': coverage.trojan_risk_level.value,
            'attack_vectors': list(coverage.attack_vectors)
        }
    
    # ========================================================================
    # Bidirectional Consistency Checking
    # ========================================================================
    
    def verify_bidirectional_consistency(self, sample_size: int = 100) -> Dict:
        """
        Test bidirectional consistency: tile → frame → tile
        
        This verifies the correctness of forward and reverse mappings.
        Essential for debugging and validation.
        
        Args:
            sample_size: Number of random frames to test
            
        Returns:
            Dictionary with test results
        """
        import random
        
        results = {
            'tests_run': 0,
            'successes': 0,
            'failures': 0,
            'failed_cases': []
        }
        
        # Get random sample of frames
        all_columns = list(range(DeviceConstants.TOTAL_COLUMNS))
        random.shuffle(all_columns)
        
        for col in all_columns[:min(sample_size // 10, len(all_columns))]:
            col_frames = self.get_frames_for_column(col)
            sample_frames = random.sample(col_frames, min(10, len(col_frames)))
            
            for far in sample_frames:
                results['tests_run'] += 1
                
                # Forward: frame → tiles
                coverage = self.frame_mapper.map_frame(far)
                if not coverage.tiles_affected:
                    continue
                
                # Pick a tile
                test_tile = coverage.tiles_affected[0]
                
                # Reverse: tile → frames
                reverse_frames = self.get_frames_for_tile(test_tile)
                reverse_fars = [ref.far_value for ref in reverse_frames]
                
                # Check if original frame is in reverse lookup result
                if far in reverse_fars:
                    results['successes'] += 1
                else:
                    results['failures'] += 1
                    results['failed_cases'].append({
                        'far': hex(far),
                        'tile': test_tile,
                        'found_frames': [hex(f) for f in reverse_fars]
                    })
        
        results['success_rate'] = (results['successes'] / results['tests_run'] * 100
                                  if results['tests_run'] > 0 else 0)
        
        return results
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """
        Get reverse mapper statistics
        
        Returns:
            Dictionary with cache and index statistics
        """
        return {
            'indices_built': self._indices_built,
            'build_strategy': self._build_strategy,
            'tiles_indexed': len(self._tile_to_frames),
            'coordinates_cached': len(self._coordinate_to_frames),
            'columns_indexed': len(self._column_to_frames)
        }
    
    def clear_caches(self):
        """Clear all cached data (useful for memory management)"""
        self._tile_to_frames.clear()
        self._coordinate_to_frames.clear()
        # Keep column index as it's relatively small
        
        # Clear LRU caches
        self.get_frames_for_tile.cache_clear()
        self.get_frames_for_coordinate.cache_clear()


# ============================================================================
# Module-level convenience functions
# ============================================================================

_global_reverse_mapper: Optional[ReverseMapper] = None

def get_global_reverse_mapper() -> ReverseMapper:
    """Get or create the global ReverseMapper singleton"""
    global _global_reverse_mapper
    if _global_reverse_mapper is None:
        _global_reverse_mapper = ReverseMapper()
        _global_reverse_mapper.build_indices("hybrid")
    return _global_reverse_mapper


def get_frames_for_tile(tile_name: str) -> List[FrameReference]:
    """Convenience function for quick tile→frame lookup"""
    return get_global_reverse_mapper().get_frames_for_tile(tile_name)


def get_frames_for_region(x_range: Tuple[int, int], y_range: Tuple[int, int]) -> Set[int]:
    """Convenience function for region frame lookup"""
    return get_global_reverse_mapper().get_frames_in_region(x_range, y_range)


# ============================================================================
# Export main classes and functions
# ============================================================================

__all__ = [
    'FrameReference',
    'ResourceLocation',
    'ReverseMapper',
    'get_global_reverse_mapper',
    'get_frames_for_tile',
    'get_frames_for_region'
]