from analysis.util.json_loader import JsonLoader
from configs.raw_data_path import DEVICE_INFO_PATH,TILES_TYPE_PATH,TILES_PATH,WIRES_PATH,SITES_PATH,PIPS_PATH


Loader = JsonLoader()

DEVICE_INFO = Loader.load_device_info(DEVICE_INFO_PATH.as_posix())
TILES_TYPE = Loader.load_tile_types(TILES_TYPE_PATH.as_posix())
TILES = Loader.load_tiles(TILES_PATH.as_posix())
WIRES = Loader.load_wires(WIRES_PATH.as_posix())
SITES = Loader.load_sites(SITES_PATH.as_posix())
PIPS = Loader.load_pips(PIPS_PATH.as_posix())