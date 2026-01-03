# routing_reconstructor.py
"""
Routing State Reconstructor
Reconstructs active routing configuration from bitstream frames

Phase 2.2: Convert frame bits to active routing paths
Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

# Import device model
from analysis.device_model import DeviceModel
from analysis.tile_grid import DeviceGraph, RoutingNode, RoutingEdge

# Import semantic extraction
from src.detector.semantic.bit_semantics import (
    FrameBitExtractor,
    BitLayoutDatabase
)

# Import integration layer
from src.mapping.integration.bitstream_loader import LoadedBitstream
from src.mapping.integration.frame_obj_adapter import AdaptedFrame

# Import analysis infrastructure
from analysis.assembler.frame_mapper import FrameMapper
from analysis.assembler.reverse_mapper import ReverseMapper


@dataclass
class ActivePIP:
    """
    Represents an active (enabled) programmable interconnect point
    """
    tile_name: str
    start_wire_id: int
    end_wire_id: int
    frame_address: int
    bit_offset: int
    
    def __hash__(self):
        return hash((self.tile_name, self.start_wire_id, self.end_wire_id))
    
    def __eq__(self, other):
        if not isinstance(other, ActivePIP):
            return False
        return (self.tile_name == other.tile_name and
                self.start_wire_id == other.start_wire_id and
                self.end_wire_id == other.end_wire_id)
    
    def __str__(self):
        return f"PIP({self.tile_name}: {self.start_wire_id}→{self.end_wire_id})"


@dataclass
class RoutingPath:
    """
    Represents a complete routing path through the device
    """
    path_id: str
    nodes: List[RoutingNode] = field(default_factory=list)
    edges: List[ActivePIP] = field(default_factory=list)
    source_tile: Optional[str] = None
    sink_tile: Optional[str] = None
    
    def length(self) -> int:
        """Get path length (number of hops)"""
        return len(self.edges)
    
    def tiles_traversed(self) -> Set[str]:
        """Get set of all tiles this path touches"""
        tiles = set()
        for node in self.nodes:
            tiles.add(node.tile_name)
        return tiles


@dataclass
class RoutingConfiguration:
    """
    Complete routing configuration state from a bitstream
    
    This is the "active routing graph" - showing which PIPs are ON.
    """
    bitstream_id: str
    active_pips: Set[ActivePIP] = field(default_factory=set)
    pip_by_tile: Dict[str, Set[ActivePIP]] = field(default_factory=lambda: defaultdict(set))
    pip_by_frame: Dict[int, Set[ActivePIP]] = field(default_factory=lambda: defaultdict(set))
    
    # Routing paths (computed on-demand)
    _paths_cache: Optional[List[RoutingPath]] = None
    
    def add_pip(self, pip: ActivePIP):
        """Add an active PIP to the configuration"""
        self.active_pips.add(pip)
        self.pip_by_tile[pip.tile_name].add(pip)
        self.pip_by_frame[pip.frame_address].add(pip)
    
    def get_pips_in_tile(self, tile_name: str) -> Set[ActivePIP]:
        """Get all active PIPs in a tile"""
        return self.pip_by_tile.get(tile_name, set()).copy()
    
    def get_pips_in_frame(self, far_value: int) -> Set[ActivePIP]:
        """Get all active PIPs configured by a frame"""
        return self.pip_by_frame.get(far_value, set()).copy()
    
    def is_pip_active(self, tile_name: str, start_wire: int, end_wire: int) -> bool:
        """Check if a specific PIP is active"""
        test_pip = ActivePIP(tile_name, start_wire, end_wire, 0, 0)
        return test_pip in self.active_pips
    
    def get_statistics(self) -> Dict:
        """Get routing statistics"""
        return {
            'total_active_pips': len(self.active_pips),
            'tiles_with_routing': len(self.pip_by_tile),
            'frames_with_routing': len(self.pip_by_frame),
            'avg_pips_per_tile': (len(self.active_pips) / len(self.pip_by_tile)
                                 if self.pip_by_tile else 0)
        }


class PIPFrameMapper:
    """
    Maps PIPs to their controlling frame bits
    
    This is critical - we need to know which bits control which PIPs
    to extract routing configuration from frames.
    """
    
    def __init__(self, device_model: DeviceModel,
                 reverse_mapper: Optional[ReverseMapper] = None):
        """
        Initialize PIP-to-frame mapper
        
        Args:
            device_model: Device model with PIP definitions
            reverse_mapper: Reverse mapper for tile→frame lookups
        """
        self.device_model = device_model
        self.reverse_mapper = reverse_mapper or ReverseMapper()
        
        # Cache: (tile, start_wire, end_wire) -> (far, bit_offset)
        self._pip_to_bit: Dict[Tuple[str, int, int], Tuple[int, int]] = {}
        self._build_pip_mappings()
    
    def _build_pip_mappings(self):
        """
        Build PIP → (frame, bit) mappings
        
        This is approximate - real implementation needs detailed
        Xilinx bitstream documentation for exact bit positions.
        """
        print("Building PIP→frame mappings (this may take a moment)...")
        
        tiles = self.device_model.tiles.get_all_tiles()
        pip_count = 0
        
        for tile in tiles[:100]:  # Limit for performance
            pips = self.device_model.get_pips_of_tile(tile.name)
            if not pips:
                continue
            
            # Get frames for this tile
            frame_refs = self.reverse_mapper.get_routing_frames_for_tile(tile.name)
            if not frame_refs:
                continue
            
            # Distribute PIPs across routing frames
            # This is simplified - real distribution is complex
            for idx, pip in enumerate(pips[:50]):  # Limit PIPs per tile
                frame_ref = frame_refs[idx % len(frame_refs)]
                bit_offset = (idx * 4) % 704  # Approximate bit position
                
                key = (tile.name, pip.startWireId, pip.endWireId)
                self._pip_to_bit[key] = (frame_ref.far_value, bit_offset)
                pip_count += 1
        
        print(f"Mapped {pip_count} PIPs to frame bits")
    
    def get_pip_bit_location(self, tile_name: str,
                            start_wire: int,
                            end_wire: int) -> Optional[Tuple[int, int]]:
        """
        Get (frame_address, bit_offset) for a PIP
        
        Args:
            tile_name: Tile containing PIP
            start_wire: Start wire ID
            end_wire: End wire ID
            
        Returns:
            (far_value, bit_offset) or None if not found
        """
        key = (tile_name, start_wire, end_wire)
        return self._pip_to_bit.get(key)


class RoutingReconstructor:
    """
    Routing State Reconstruction Engine
    
    Reads bitstream frames and reconstructs the active routing configuration.
    This tells us which PIPs are ON and what paths exist through the device.
    
    Usage:
        reconstructor = RoutingReconstructor()
        routing = reconstructor.reconstruct(loaded_bitstream)
        print(f"Found {len(routing.active_pips)} active PIPs")
    """
    
    def __init__(self, device_model: Optional[DeviceModel] = None):
        """
        Initialize routing reconstructor
        
        Args:
            device_model: Device model (creates one if None)
        """
        self.device_model = device_model or DeviceModel()
        self.device_graph = DeviceGraph(self.device_model)
        
        self.frame_mapper = FrameMapper()
        self.reverse_mapper = ReverseMapper()
        self.bit_extractor = FrameBitExtractor()
        
        self.pip_mapper = PIPFrameMapper(self.device_model, self.reverse_mapper)
    
    def reconstruct(self, bitstream: LoadedBitstream,
                   verbose: bool = True) -> RoutingConfiguration:
        """
        Reconstruct routing configuration from bitstream
        
        Args:
            bitstream: Loaded bitstream to analyze
            verbose: Print progress messages
            
        Returns:
            RoutingConfiguration with all active PIPs
        """
        if verbose:
            print(f"\nReconstructing routing configuration from {bitstream.info.filename}")
        
        routing_config = RoutingConfiguration(
            bitstream_id=bitstream.info.filename
        )
        
        # Process all frames
        frame_count = 0
        routing_frame_count = 0
        
        for frame in bitstream:
            frame_count += 1
            
            # Get frame coverage
            coverage = self.frame_mapper.map_frame(frame.far_value)
            
            # Only process routing frames
            if not coverage.is_routing_frame:
                continue
            
            routing_frame_count += 1
            
            # Extract PIPs from this frame
            pips = self._extract_pips_from_frame(frame, coverage)
            for pip in pips:
                routing_config.add_pip(pip)
            
            if verbose and frame_count % 100 == 0:
                print(f"  Processed {frame_count} frames, found {len(routing_config.active_pips)} PIPs...")
        
        if verbose:
            stats = routing_config.get_statistics()
            print(f"\nRouting reconstruction complete:")
            print(f"  Total frames: {frame_count}")
            print(f"  Routing frames: {routing_frame_count}")
            print(f"  Active PIPs: {stats['total_active_pips']}")
            print(f"  Tiles with routing: {stats['tiles_with_routing']}")
        
        return routing_config
    
    def _extract_pips_from_frame(self, frame: AdaptedFrame,
                                 coverage) -> List[ActivePIP]:
        """
        Extract active PIPs from a single frame
        
        Args:
            frame: Frame to analyze
            coverage: Frame coverage information
            
        Returns:
            List of active PIPs
        """
        active_pips = []
        
        # Get routing bits for this frame
        routing_bits = self.bit_extractor.bit_db.get_routing_bits(frame.far_value)
        
        # For each tile affected by this frame
        for tile_name in coverage.tiles_affected:
            # Get PIPs in this tile
            tile_pips = self.device_model.get_pips_of_tile(tile_name)
            if not tile_pips:
                continue
            
            # Check each PIP's bit
            for pip in tile_pips[:20]:  # Limit for performance
                bit_location = self.pip_mapper.get_pip_bit_location(
                    tile_name, pip.startWireId, pip.endWireId
                )
                
                if not bit_location:
                    continue
                
                far, bit_offset = bit_location
                
                # Check if this frame controls this PIP
                if far != frame.far_value:
                    continue
                
                # Extract bit value
                try:
                    is_active = self.bit_extractor.extract_bit(
                        frame.frame_data, bit_offset
                    )
                    
                    if is_active:
                        active_pips.append(ActivePIP(
                            tile_name=tile_name,
                            start_wire_id=pip.startWireId,
                            end_wire_id=pip.endWireId,
                            frame_address=frame.far_value,
                            bit_offset=bit_offset
                        ))
                except:
                    continue
        
        return active_pips
    
    def compare_routing(self, golden_routing: RoutingConfiguration,
                       suspect_routing: RoutingConfiguration) -> Dict:
        """
        Compare two routing configurations
        
        Finds PIPs that differ - key for Trojan detection.
        
        Args:
            golden_routing: Golden reference routing
            suspect_routing: Suspect routing to analyze
            
        Returns:
            Dictionary with comparison results
        """
        golden_pips = golden_routing.active_pips
        suspect_pips = suspect_routing.active_pips
        
        # Find differences
        added_pips = suspect_pips - golden_pips
        removed_pips = golden_pips - suspect_pips
        common_pips = golden_pips.intersection(suspect_pips)
        
        # Group by tile
        added_by_tile = defaultdict(set)
        removed_by_tile = defaultdict(set)
        
        for pip in added_pips:
            added_by_tile[pip.tile_name].add(pip)
        
        for pip in removed_pips:
            removed_by_tile[pip.tile_name].add(pip)
        
        return {
            'golden_pip_count': len(golden_pips),
            'suspect_pip_count': len(suspect_pips),
            'common_pips': len(common_pips),
            'added_pips': len(added_pips),
            'removed_pips': len(removed_pips),
            'tiles_with_changes': len(set(added_by_tile.keys()) | set(removed_by_tile.keys())),
            'added_by_tile': dict(added_by_tile),
            'removed_by_tile': dict(removed_by_tile),
            'suspicious_additions': [
                pip for pip in added_pips 
                if self._is_suspicious_pip(pip, golden_routing)
            ]
        }
    
    def _is_suspicious_pip(self, pip: ActivePIP,
                          golden_routing: RoutingConfiguration) -> bool:
        """
        Determine if a PIP addition is suspicious
        
        Suspicious = creates routing in unexpected area
        """
        # Check if tile was completely unused in golden
        golden_pips_in_tile = golden_routing.get_pips_in_tile(pip.tile_name)
        
        # New routing in previously unused tile = suspicious
        if len(golden_pips_in_tile) == 0:
            return True
        
        # Single new PIP in tile with existing routing = less suspicious
        return False
    
    def visualize_routing_diff(self, golden_routing: RoutingConfiguration,
                              suspect_routing: RoutingConfiguration,
                              max_show: int = 20):
        """
        Print visual diff of routing changes
        
        Args:
            golden_routing: Golden routing
            suspect_routing: Suspect routing
            max_show: Maximum changes to display
        """
        comparison = self.compare_routing(golden_routing, suspect_routing)
        
        print("\n" + "="*70)
        print("Routing Configuration Comparison")
        print("="*70)
        print(f"Golden PIPs:   {comparison['golden_pip_count']}")
        print(f"Suspect PIPs:  {comparison['suspect_pip_count']}")
        print(f"Common:        {comparison['common_pips']}")
        print(f"Added:         {comparison['added_pips']}")
        print(f"Removed:       {comparison['removed_pips']}")
        print(f"")
        
        if comparison['added_pips'] > 0:
            print(f"Added PIPs (showing first {max_show}):")
            shown = 0
            for tile, pips in comparison['added_by_tile'].items():
                if shown >= max_show:
                    break
                for pip in pips:
                    if shown >= max_show:
                        break
                    print(f"  + {pip}")
                    shown += 1
        
        if comparison['suspicious_additions']:
            print(f"\nâš ï¸  SUSPICIOUS: {len(comparison['suspicious_additions'])} PIPs in unused areas")
            for pip in comparison['suspicious_additions'][:5]:
                print(f"  ⚠️  {pip}")
        
        print("="*70 + "\n")


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'ActivePIP',
    'RoutingPath',
    'RoutingConfiguration',
    'PIPFrameMapper',
    'RoutingReconstructor'
]