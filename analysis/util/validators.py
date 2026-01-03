#Model Validators

from typing import List ,Tuple
from pydantic import BaseModel , RootModel


class DeviceInfo(BaseModel):
    """Model of DeviceInfo"""
    part:   str
    partName:   str
    familyType: str
    rows:   int
    cols:   int

    def device_demensions(self) -> Tuple[int,int]:
        """
        return (max_col,max_row)
        """
        return (self.cols,self.rows)
    

class TileType(BaseModel):
    """Model of Tile's Type"""
    name:   str


class TilesType(RootModel[List[TileType]]):
    """
    List of Tile's Type
    """

    def get_all_tile_types(self) -> List[TileType]:
        """
        return all tile types
        """
        return self.root
    
    def is_there_type_by_name(self,type_name:str) -> bool:
        """
        checks if there is type with the type_name
        """
        return any(x.name == type_name for x in self.root)

class Wire(BaseModel):
    """
    Model of Wire
    """
    tile: str
    wireId: int


class ListWires(RootModel[List[Wire]]):
    """
    List of Wires
    """

    def get_all_wires(self) -> List[Wire]:
        """
        return all wires
        """
        return self.root

    def get_wire(self,tile_name:str,wire_id:int) -> Wire | None:
        """
        return a wire by name and id
        """
        return next((wire for wire in self.root if wire.tile == tile_name and wire.wireId == wire_id),None)

    def get_wires_by_tile_name(self,tile_name:str) -> List[Wire]:
        """
        return all wires of physically in that tile
        """
        return [wire for wire in self.root if wire.tile == tile_name]
    
    def get_wire_by_id(self,wire_id) -> Wire | None:
        """
        return wire by id
        """
        return next((wire for wire in self.root if wire.wireId == wire_id),None)
    
    def is_there_wire_by_tile_name(self,tile_name:str) -> bool:
        """
        checks if there is wire with the tile_name
        """
        return any(x.tile == tile_name for x in self.root)
    
    def is_there_wire_by_id(self,wire_id:str) -> bool:
        """
        checks if there is wire with the tile_name
        """
        return any(x.wireId == wire_id for x in self.root)

class Tile(BaseModel):
    """
    Model of Tile
    """
    name:   str
    row:    int
    col:    int
    type:   str

    def get_type(self) -> str:
        """
        return the tile's type
        """
        return self.type

    def get_coordinates(self) -> Tuple[int,int]:
        """
        return the tile's coordinate
        """
        return (self.col,self.row)
    

class ListTiles(RootModel[List[Tile]]):
    """
    List of Tiles
    """

    def __len__(self):
        return len(self.root)

    def get_tile(self,col:int,row:int) -> Tile | None:
        """
        return tile by (col,row)
        """
        return next((tile for tile in self.root if tile.col == col and tile.row == row),None)

    def get_tile_by_name(self,name:str) -> Tile | None:
        """
        return tile by name
        """
        return next((tile for tile in self.root if tile.name == name),None)
    
    def is_there_tile_by_name(self,name:str) -> bool:
        """
        check if there is a tile with the given name
        """
        _name = self.get_tile_by_name(name)
        if _name:
            return True
        return False
    
    def get_all_tiles(self) -> List[Tile]:
        """
        return a falt list of all tiles
        """
        return self.root
    
    def get_all_tiles_in_column(self,col:int) -> List[Tile]:
        """
        return all tiles in a column `col` 
        """
        return [tile for tile in self.root if tile.col == col]
    
    def get_all_tiles_in_row(self,row:int) -> List[Tile]:
        """
        return all tiles in a row `row` 
        """
        return [tile for tile in self.root if tile.row == row]
    
    def list_tiles_by_type(self,type_name:str) -> List[Tile]:
        """
        return list of tiles with the same type 
        """
        return [tile for tile in self.root if tile.type == type_name]
    

class PIP(BaseModel):
    """
    Model of PIP
    """
    tile:   str
    startWireId:    int
    endWireId:  int


class ListPIPs(RootModel[List[PIP]]):
    """
    List of PIPS
    """

    
    def get_pips_of_tile(self,tile_name:str) -> List[PIP]:
        """
        return all programmable connections in tile
        """
        return [pip for pip in self.root if pip.tile == tile_name]
    
    def is_there_pip_by_tile_name(self,tile_name:str) -> bool:
        """
        checks if there is pip with the tile_name
        """
        return any(x.tile == tile_name for x in self.root)
    
    def get_pips_by_tile_name_and_start_wire_id(self,tile_name:str,wire_id:int) -> List[PIP]:
        """
        return list of pips with tile_name and start_wire_id
        """
        return [pip for pip in self.root if pip.tile == tile_name and pip.startWireId == wire_id]
    
    def get_pips_by_start_wire_id(self,start_id:int) -> List[PIP]:
        """
        return all programmable connections by start_id
        """
        return [pip for pip in self.root if pip.startWireId == start_id]
    
    def is_there_pip(self,tile_name,start_wire,end_wire) -> bool:
        """
        check if the given pip is exist
        """
        _pip = self.get_pips_of_tile(tile_name)
        for pip in _pip:
            if pip.startWireId == start_wire and pip.endWireId == end_wire:
                return True
        return False



class Site(BaseModel):
    """
    Model of Site
    """
    name:   str
    type:   str
    tile:   str

    def get_type(self) -> str:
        """
        return the site's type
        """
        return self.type


class ListSites(RootModel[List[Site]]):
    """
    List of Sites
    """

    def get_sites_of_tile(self,tile_name:str) -> List[Site]:
        """
        return all sites of the tile
        """
        return [site for site in self.root if site.tile == tile_name]
    
    def is_there_sites_by_tile_name(self,tile_name:str) -> bool:
        """
        checks if there is site with the tile_name
        """
        return any(x.tile == tile_name for x in self.root)
