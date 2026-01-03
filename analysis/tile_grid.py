# tile_grid.py
"""
Tile Grid and Routing Graph
Builds device-wide routing graph from DeviceModel

Fixed version - removed executable code at bottom
Part of: Turning the Table - FPGA Trojan Detection
"""

from collections import deque
from typing import List, Optional
from analysis.device_model import DeviceModel


class RoutingNode:
    """
    Instantiate a routing Node 
    """
    def __init__(self, tile_name: str, wire_id: int) -> None:
        self.tile_name = tile_name
        self.wire_id = wire_id

    def __repr__(self) -> str:
        return f"RoutingNode(tile:{self.tile_name},wire:{self.wire_id})"
    
    def __hash__(self):
        return hash((self.tile_name, self.wire_id))
    
    def __eq__(self, other):
        if not isinstance(other, RoutingNode):
            return False
        return self.tile_name == other.tile_name and self.wire_id == other.wire_id


class RoutingEdge:
    """
    Routing Edge representing a PIP (programmable interconnect point)
    """
    def __init__(self, start_tile: str, start_wire: int, end_wire: int) -> None:
        self.start_tile = start_tile
        self.start_wire = start_wire
        self.end_wire = end_wire

    def __repr__(self) -> str:
        return f"RoutingEdge(start_tile:{self.start_tile},start_wire:{self.start_wire},end_wire:{self.end_wire})"


class TileRoutingGraph:
    """
    Routing graph for a single tile
    """
    def __init__(self, tile_name: str) -> None:
        self.tile_name = tile_name
        self.nodes = {}
        self.edges = []
    
    def add_node(self, wire_id: int):
        """
        Add a wire as node
        """
        if wire_id not in self.nodes:
            self.nodes[wire_id] = RoutingNode(self.tile_name, wire_id)

    def add_edge(self, start_wire: int, end_wire: int):
        """
        Add PIP as an edge
        """
        self.add_node(start_wire)
        self.add_node(end_wire)

        edge = RoutingEdge(self.tile_name, start_wire, end_wire)
        self.edges.append(edge)

    def get_neighbors(self, wire_id: int) -> List[int]:
        """
        Get all wires reachable from this wire via PIPs
        """
        neighbors = []
        for edge in self.edges:
            if edge.start_wire == wire_id:
                neighbors.append(edge.end_wire)
        return neighbors
    
    def __repr__(self) -> str:
        return f"TileRoutingGraph(name:{self.tile_name},nodes:{len(self.nodes)},edges:{len(self.edges)})"


class DeviceGraph:
    """
    Device-wide collection of tile-local routing graphs
    """
    def __init__(self, device_model: DeviceModel) -> None:
        self.device_model = device_model
        self.tile_graphs = {}

    def build_tile_graphs(self, verbose: bool = False):
        """
        Build routing graph for each tile
        
        Args:
            verbose: Print progress messages
        """
        tiles = self.device_model.tiles.get_all_tiles()
        tile_count = 0

        for tile in tiles:
            graph = TileRoutingGraph(tile.name)
           
            wires = self.device_model.get_all_wires_of_tile(tile.name)
            if wires:
                for wire in wires:
                    graph.add_node(wire.wireId)
            
            pips = self.device_model.get_pips_of_tile(tile.name)
            if pips:
                for pip in pips:
                    graph.add_edge(pip.startWireId, pip.endWireId)

            self.tile_graphs[tile.name] = graph
            tile_count += 1
            
            if verbose and tile_count % 100 == 0:
                print(f"Built graphs for {tile_count} tiles...")
        
        if verbose:
            print(f"Completed: Built routing graphs for {tile_count} tiles")

    def get_tile_graph(self, tile_name: str) -> Optional[TileRoutingGraph]:
        """
        Get routing graph for a specific tile
        """
        return self.tile_graphs.get(tile_name)
    
    def get_routing_path(self, tile_name: str, start_wire: int, end_wire: int) -> Optional[List[int]]:
        """
        Find routing path within a tile with simple BFS.
        
        Args:
            tile_name: Tile to search in
            start_wire: Starting wire ID
            end_wire: Target wire ID
            
        Returns:
            List of wire IDs forming path, or None if no path exists
        """
        graph = self.get_tile_graph(tile_name)
        if not graph:
            return None
        
        queue = deque([(start_wire, [start_wire])])
        visited = {start_wire}

        while queue:
            current, path = queue.popleft()

            if current == end_wire:
                return path
                
            for neighbor in graph.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    def get_statistics(self) -> dict:
        """
        Get device graph statistics
        
        Returns:
            Dictionary with graph statistics
        """
        total_nodes = sum(len(g.nodes) for g in self.tile_graphs.values())
        total_edges = sum(len(g.edges) for g in self.tile_graphs.values())
        
        return {
            'tiles': len(self.tile_graphs),
            'total_routing_nodes': total_nodes,
            'total_routing_edges': total_edges,
            'avg_nodes_per_tile': total_nodes / len(self.tile_graphs) if self.tile_graphs else 0,
            'avg_edges_per_tile': total_edges / len(self.tile_graphs) if self.tile_graphs else 0
        }


# ============================================================================
# Convenience function for creating device graph
# ============================================================================

def create_device_graph(device_model: Optional[DeviceModel] = None, 
                       build_immediately: bool = True,
                       verbose: bool = False) -> DeviceGraph:
    """
    Create and optionally build a device graph
    
    Args:
        device_model: Device model (creates one if None)
        build_immediately: Build tile graphs immediately
        verbose: Print progress
        
    Returns:
        DeviceGraph instance
    """
    if device_model is None:
        device_model = DeviceModel()
    
    graph = DeviceGraph(device_model)
    
    if build_immediately:
        graph.build_tile_graphs(verbose=verbose)
    
    return graph


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'RoutingNode',
    'RoutingEdge',
    'TileRoutingGraph',
    'DeviceGraph',
    'create_device_graph'
]