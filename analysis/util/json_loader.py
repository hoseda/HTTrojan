#Load json files

from analysis.util.validators import DeviceInfo , TilesType , ListTiles , ListSites , ListWires , ListPIPs

class JsonLoader:
    """
    Load Json Files
    """
    @staticmethod
    def load_device_info(path:str) -> DeviceInfo:
        """
        Load Device Info
        """
        return DeviceInfo.model_validate_json(open(path).read())
    
    @staticmethod
    def load_tile_types(path:str) -> TilesType:
        """
        Load Tile Types
        """
        return TilesType.model_validate_json(open(path).read())
    
    @staticmethod
    def load_tiles(path:str) -> ListTiles:
        """
        Load Tiles
        """
        return ListTiles.model_validate_json(open(path).read())
    
    @staticmethod
    def load_wires(path:str) -> ListWires:
        """
        Load Wires
        """
        return ListWires.model_validate_json(open(path).read())
    
    @staticmethod
    def load_sites(path:str) -> ListSites:
        """
        Load Sites
        """
        return ListSites.model_validate_json(open(path).read())
    
    @staticmethod
    def load_pips(path:str) -> ListPIPs:
        """
        Load PIPs
        """
        return ListPIPs.model_validate_json(open(path).read())
