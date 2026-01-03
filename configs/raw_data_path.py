from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = (BASE_DIR / "../data/raw_device").resolve()

DEVICE_INFO_PATH = DATA_DIR / "deviceInfo.json"
TILES_TYPE_PATH = DATA_DIR / "tileTypes.json"
TILES_PATH = DATA_DIR / "tiles.json"
WIRES_PATH = DATA_DIR / "wires.json"
SITES_PATH = DATA_DIR / "sites.json"
PIPS_PATH = DATA_DIR / "pips.json"