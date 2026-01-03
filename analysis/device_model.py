# load json + builds DeviceModel Object

from typing import Tuple,List
from analysis.util.visualizers import DEVICE_INFO,TILES_TYPE,TILES,WIRES,SITES,PIPS
from analysis.util.validators import Tile,Wire,Site,PIP

class DeviceModel:
    """
    Device Model
    """
    def __init__(self):
        self.device_info = DEVICE_INFO
        self.tiles_type = TILES_TYPE
        self.tiles = TILES
        self.sites = SITES
        self.wires = WIRES
        self.pips = PIPS

    def get_part_name(self) -> str:
        """
        return part name of the device
        """
        return self.device_info.part

    def get_family(self) -> str:
        """
        return family of device
        """
        return self.device_info.familyType
    
    def get_dimensions(self) -> Tuple[int,int]:
        """
        return dimensions of device , (col,row)
        """
        return (self.device_info.cols,self.device_info.rows)
    
    def is_valid_coordinate(self,col:int,row:int) -> bool:
        """
        check if the given coordinate is in dimension of device
        """
        if col <= self.device_info.cols and row <= self.device_info.rows:
            return True
        return False
    
    def get_tile_by_name(self,name:str) -> Tile | None:
        """
        return Tile with name
        """
        return self.tiles.get_tile_by_name(name)
    
    def get_tile(self,col:int,row:int) -> Tile | None:
        """
        return tile by coordinate
        """
        if self.is_valid_coordinate(col,row):
            return self.tiles.get_tile(col,row)
        return None
    
    def get_tiles_by_type(self,tile_type:str) -> List[Tile]:
        """
        return tiles with the same type
        """
        return self.tiles.list_tiles_by_type(tile_type)
    
    def get_tiles_in_row(self,row) -> List[Tile] | None:
        """
        return tiles in a row
        """
        _row , _ = self.get_dimensions()
        if row <= _row:
            return self.tiles.get_all_tiles_in_row(row)
        return None
    
    def get_tiles_in_column(self,col) -> List[Tile] | None:
        """
        return tiles in a column
        """
        _ , _col = self.get_dimensions()
        if col <= _col:
            return self.tiles.get_all_tiles_in_column(col)
        return None
    
    def get_all_wires_of_tile(self,tile_name:str) -> List[Wire] | None:
        """
        return all wires of physically in that tile
        """
        _is_there_tile = self.tiles.is_there_tile_by_name(tile_name)
        if _is_there_tile:
            return self.wires.get_wires_by_tile_name(tile_name)
        return None
    
    def get_pips_of_tile(self,tile_name:str) -> List[PIP] | None:
        """
        return all programmable connections in tile
        """
        _is_there_tile = self.tiles.is_there_tile_by_name(tile_name)
        if _is_there_tile:
            return self.pips.get_pips_of_tile(tile_name)
        return None
    
    def get_sites_of_tile(self,tile_name:str) -> List[Site] | None:
        """
        return all sites of the tile
        """
        _is_there_tile = self.tiles.is_there_tile_by_name(tile_name)
        if _is_there_tile:
            return self.sites.get_sites_of_tile(tile_name)
        return None
    
    def get_neighbor_tiles(self,tile:Tile) -> List:
        """
        return neighbot tiles of a tile
        """
        col , row = self.get_dimensions()
        left = None
        right = None
        up = None
        bottom = None

        if tile.col > 0 and tile.col <= col:
            left = self.get_tile(tile.col-1,tile.row)
        if tile.col < col:
            right = self.get_tile(tile.col+1,tile.row)
        if tile.row > 0 and tile.row <= row:
            bottom = self.get_tile(tile.col,tile.row-1)
        if tile.row < row:
            up = self.get_tile(tile.col,tile.row+1)
        
        return [left,right,bottom,up]
    
    def get_wire_connections(self,tile_name:str,wire_id:int) -> List:
        """
        return each wire connections
        """
        _wire = self.wires.get_wire(tile_name,wire_id)
        _pips = self.pips.get_pips_by_start_wire_id(wire_id)
        connections = []
        if _wire:
            _from = {"tile" : _wire.tile , "wireId" : _wire.wireId}
            for pip in _pips:
                _to = {"tile" : pip.tile, "wireId" : pip.endWireId}
                res = {"from" : _from, "to" : _to}
                connections.append(res)      
        return connections
    
    def get_pip_endpoints(self,pip:PIP) -> Tuple[Wire|None,Wire|None] | None:
        """
        return A structured description of the connection this PIP represents
        """
        _pip = self.pips.is_there_pip(pip.tile,pip.startWireId,pip.endWireId)
        if _pip:
            _start = self.wires.get_wire_by_id(pip.startWireId)
            _end = self.wires.get_wire_by_id(pip.endWireId)
            return (_start,_end)
        return None
    
    def iter_routing_nodes(self) -> List[Tuple[str,int]]:
        """
        return a collection of routing nodes, (tile_name,wire_id)
        """
        wires = self.wires.get_all_wires()
        res = []
        for i in wires:
            res.append((i.tile,i.wireId))
        return res
    
    def iter_routing_edges(self,tile_name:str,wire_id:int) -> List[Tuple[str,int]]:
        """
        return a list of nodes reachable via PIPs
        """
        _pips = self.pips.get_pips_by_tile_name_and_start_wire_id(tile_name,wire_id)
        res = []
        for pip in _pips:
            res.append((pip.tile,pip.endWireId))
        return res
    
    def is_routing_tile(self,tile:Tile) -> bool:
        """
        checks if a tile mainly exist to route signal 
        """
        return any(x in tile.type for x in ["INT","INTERCONNECT"])
        
    def is_logic_tile(self,tile:Tile) -> bool:
        """
        checks if a tile contains login resources
        """
        return any(x in tile.type for x in ["CLB","SLICE","LOGIC"])

    
    def is_clock_tile(self,tile:Tile) -> bool:
        """
        checks if tile is a part of clock network
        """  
        return any(x in tile.type for x in ["HCLK","CLK","BUFG","CMT"])
    
    
    def validate_tile_references(self):
        """
        checks that every object that claims to belong to a tile actually points to a real tile.
        """
        tiles = self.tiles.get_all_tiles()
        for tile in tiles:
            if not self.pips.is_there_pip_by_tile_name(tile.name):
                raise ValueError(f"inconsistancy between tile : {tile.name} and pips")
            if not self.wires.is_there_wire_by_tile_name(tile.name):
                raise ValueError(f"inconsistancy between tile : {tile.name} and wires")
            if not self.sites.is_there_sites_by_tile_name(tile.name):
                raise ValueError(f"inconsistancy between tile : {tile.name} and sites")
    
    def validate_wire_ids(self):
        """
        checks that wire IDs are valid for the tile type they belong to.
        """
        _wires = self.wires.get_all_wires()
        for wire in _wires:
            if not self.tiles.is_there_tile_by_name(wire.tile):
                raise ValueError(f"inconsistancy between wire : {wire.wireId} and tiles")
            
    
    def get_tile_signature(self,tile:Tile) -> Tuple[str,int,int,List[Site]]:
        """
        Create a compact identity fingerprint for a tile.
        """
        _sites = self.sites.get_sites_of_tile(tile.name)
        _wires = self.wires.get_wires_by_tile_name(tile.name)
        _pips = self.pips.get_pips_of_tile(tile.name)
        return (tile.type,len(_wires),len(_pips),_sites)
    
    def get_tile_routing_resources(self,tile:Tile) -> Tuple[List[Wire],List[PIP]]:
        """
        Return everything inside the tile that affects routing.
        """
        _wires = self.wires.get_wires_by_tile_name(tile.name)
        _pips = self.pips.get_pips_of_tile(tile.name)
        return (_wires,_pips)