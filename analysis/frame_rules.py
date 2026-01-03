# frame_rules.py
# Complete frame address and bitstream rules for Virtex-5 VLX50T
# Based on: "Turning the Table: Using Bitstream Reverse Engineering to Detect FPGA Trojans"
# Target Device: xc5vlx50tff1136-2

import re
from typing import List, Dict, Tuple, Optional, Set

# ============================================================================
# Section A — Device Constants
# ============================================================================

class DeviceConstants:
    """
    Unchanging facts about Virtex5 VLX50T device
    Fixed typos: DEVICE_FULL_NAME, LUTSS_PER_SLICE
    """
    # Device identification
    DEVICE_FAMILY = "Virtex5"
    DEVICE_PART = "xc5vlx50t"
    DEVICE_PACKAGE = "ff1136"
    DEVICE_SPEED = "-2"
    DEVICE_FULL_NAME = "xc5vlx50tff1136-2"  # Fixed: was xc55vlx50t

    # Frame structure constants
    WORDS_PER_FRAME = 41
    FRAME_WORD_SIZE = 32  # bits
    BITS_PER_FRAME = WORDS_PER_FRAME * FRAME_WORD_SIZE  # 1312 bits
    BYTES_PER_FRAME = BITS_PER_FRAME // 8  # 164 bytes

    # Device architecture info
    TOTAL_ROWS = 2  # Top and Bottom
    TOTAL_COLUMNS = 48
    TOTAL_SLICES = 7200
    TOTAL_LUTS = TOTAL_SLICES * 4
    TOTAL_BRAMS = 48
    TOTAL_DSP48S = 48
    TOTAL_IOS = 480
    
    # Column type counts
    CLB_COLUMNS = 32
    IOB_COLUMNS = 2  # Left and right edges
    BRAM_COLUMNS = 10
    DSP_COLUMNS = 0  # VLX50T doesn't have separate DSP columns
    CLK_COLUMNS = 2
    
    # Slice organization
    SLICES_PER_CLB = 2
    LUTS_PER_SLICE = 4  # Fixed: was LUTSS_PER_SLICE
    FFS_PER_SLICE = 4
    LUT_SIZE = 6  # 6-input LUTs
    LUT_TRUTH_TABLE_SIZE = 2 ** LUT_SIZE  # 64 bits
    
    # Vertical tile organization
    TILES_PER_ROW = 20  # Each frame covers 20 tile rows vertically
    TOTAL_TILE_ROWS = 160  # Total vertical tiles in device


# ============================================================================
# Section B — Frame Address Field Definitions
# ============================================================================

class FrameAddress:
    """
    Frame Address Register (FAR) definition for Virtex-5
    
    FAR Format (32-bit):
    [31:29] Block Type (3 bits - actually 2 bits used)
    [28:23] Major (Column) (6 bits)
    [22]    Top/Bottom (1 bit)
    [21:17] Minor (Frame within column) (5 bits)
    [16:0]  Reserved (17 bits)
    """
    
    # Field positions (bit ranges)
    BLOCK_TYPE_START = 23  # Bits [25:23]
    BLOCK_TYPE_END = 25
    BLOCK_TYPE_WIDTH = 3
    
    TOP_BIT = 22
    
    ROW_START = 17  # Bits [21:17] - Row address
    ROW_END = 21
    ROW_WIDTH = 5
    
    MAJOR_START = 17  # Bits [22:17] for major address
    MAJOR_END = 22
    MAJOR_WIDTH = 6
    
    MINOR_START = 0  # Bits [16:0] for minor
    MINOR_END = 16
    MINOR_WIDTH = 17
    
    # Field meanings
    FIELD_DESCRIPTIONS = {
        'block_type': 'Type of FPGA resource (CLB, BRAM, IOB, etc.)',
        'top_bottom': 'Top Half (1) or Bottom Half (0) of the device',
        'row': 'Row index within top/bottom half',
        'major': 'Column Index (X coordinate)',
        'minor': 'Frame Number within a column (minor address)'
    }
    
    # Valid ranges
    MAX_BLOCK_TYPE = 7
    MAX_TOP_BOTTOM = 1
    MAX_ROW = DeviceConstants.TOTAL_ROWS - 1
    MAX_MAJOR = DeviceConstants.TOTAL_COLUMNS - 1
    MAX_MINOR = 127  # 5 bits for minor in most block types
    
    @staticmethod
    def decode(far_value: int) -> Dict[str, int]:
        """
        Decode FAR value into its constituent fields
        
        Args:
            far_value: 32-bit Frame Address Register value
            
        Returns:
            Dictionary with decoded fields
        """
        return {
            'block_type': (far_value >> FrameAddress.BLOCK_TYPE_START) & 0x7,
            'top_bottom': (far_value >> FrameAddress.TOP_BIT) & 0x1,
            'major': (far_value >> FrameAddress.MAJOR_START) & 0x3F,
            'minor': (far_value >> FrameAddress.MINOR_START) & 0x1FFFF
        }
    
    @staticmethod
    def encode(block_type: int, top_bottom: int, major: int, minor: int) -> int:
        """
        Encode fields into FAR value
        
        Args:
            block_type: Block type identifier (0-7)
            top_bottom: 0=bottom, 1=top
            major: Column index (0-47)
            minor: Frame within column (0-127)
            
        Returns:
            32-bit FAR value
        """
        far_value = 0
        far_value |= (block_type & 0x7) << FrameAddress.BLOCK_TYPE_START
        far_value |= (top_bottom & 0x1) << FrameAddress.TOP_BIT
        far_value |= (major & 0x3F) << FrameAddress.MAJOR_START
        far_value |= (minor & 0x1FFFF) << FrameAddress.MINOR_START
        return far_value
    
    @staticmethod
    def validate(far_value: int) -> Tuple[bool, Optional[str]]:
        """
        Validate if a FAR value is legal for this device
        
        Returns:
            (is_valid, error_message)
        """
        fields = FrameAddress.decode(far_value)
        
        if fields['block_type'] > FrameAddress.MAX_BLOCK_TYPE:
            return False, f"Invalid block type: {fields['block_type']}"
        
        if fields['major'] > FrameAddress.MAX_MAJOR:
            return False, f"Invalid major (column) address: {fields['major']}"
        
        # Check if this block type exists in this column
        col_type = ColumnClassification.get_column_type(fields['major'])
        if col_type == "UNKNOWN":
            return False, f"Column {fields['major']} does not exist"
        
        # Check minor address against column's frame count
        max_frames = ColumnClassification.get_frames_per_column(fields['major'])
        if fields['minor'] >= max_frames:
            return False, f"Minor {fields['minor']} exceeds column frame count {max_frames}"
        
        return True, None


# ============================================================================
# Section C — Block Type Definitions
# ============================================================================

class BlockType:
    """
    FPGA Block Types and Their Characteristics
    Maps to different hardware resources and configuration semantics
    """
    
    # Block type enumeration (matches Virtex-5 configuration)
    CLB = 0          # Configurable Logic Blocks
    IOB = 1          # Input/Output Blocks
    BRAM_CONTENT = 2 # Block RAM Content
    BRAM_INT = 3     # Block RAM Interconnect
    DSP = 4          # DSP48E blocks (not present in VLX50T as separate type)
    CLK = 5          # Clock distribution
    CFG = 6          # Configuration logic
    RESERVED = 7     # Reserved/unused
    
    # Block type properties
    PROPERTIES = {
        CLB: {
            'name': 'CLB',
            'description': 'Configurable Logic Block',
            'contains_routing': True,
            'contains_logic': True,
            'affects_security_critical': True,  # Can hide Trojans
            'tile_types': ['CLBLL', 'CLBLM', 'INT'],
            'frames_per_column': 36,
            'configures': [
                'LUT configuration (truth tables)',
                'Flip-flop initialization',
                'Carry chain routing',
                'Multiplexer configuration',
                'Local routing (within CLB)',
                'Interconnect routing (between CLBs)'
            ],
            'routing_bit_regions': [(0, 800)],  # Approximate routing bit ranges
            'logic_bit_regions': [(800, 1312)],  # Approximate logic bit ranges
        },
        IOB: {
            'name': 'IOB',
            'description': 'Input/Output Block',
            'contains_routing': True,
            'contains_logic': False,
            'affects_security_critical': True,  # Can exfiltrate data
            'tile_types': ['IOI', 'LIOI', 'RIOI'],
            'frames_per_column': 54,
            'configures': [
                'IO Standards (LVTTL, LVCMOS, etc.)',
                'Slew Rate',
                'Drive Strength',
                'Pull-up/Pull-down',
                'IODELAY configuration',
                'IOB routing to/from device core'
            ],
            'routing_bit_regions': [(0, 1100)],
            'logic_bit_regions': [(1100, 1312)],
        },
        BRAM_CONTENT: {
            'name': 'BRAM',
            'description': 'Block RAM Content',
            'contains_routing': False,
            'contains_logic': True,
            'affects_security_critical': True,  # Can store malicious payloads
            'tile_types': ['BRAM'],
            'frames_per_column': 64,  # BRAM content frames
            'configures': [
                'RAM contents (initialization data)',
                'RAM mode (Single/Dual port, SDP, TDP)',
                'Width/Depth configuration',
                'Output registers',
                'Write mode (READ_FIRST, WRITE_FIRST, NO_CHANGE)'
            ],
            'routing_bit_regions': [],  # No routing in content frames
            'logic_bit_regions': [(0, 1312)],  # All bits are content
        },
        BRAM_INT: {
            'name': 'BRAM_INT',
            'description': 'Block RAM Interconnect',
            'contains_routing': True,
            'contains_logic': False,
            'affects_security_critical': True,  # Routing to/from BRAM
            'tile_types': ['BRAM_INT'],
            'frames_per_column': 28,  # Interconnect frames
            'configures': [
                'Routing to BRAM address pins',
                'Routing to BRAM data pins',
                'Routing to BRAM control signals',
                'Routing from BRAM outputs',
                'Clock routing to BRAM'
            ],
            'routing_bit_regions': [(0, 1312)],  # All routing
            'logic_bit_regions': [],
        },
        CLK: {
            'name': 'CLK',
            'description': 'Clock Management Tile',
            'contains_routing': True,
            'contains_logic': False,
            'affects_security_critical': True,  # Clock manipulation = common attack
            'tile_types': ['HCLK', 'HCLK_CLB'],
            'frames_per_column': 4,
            'configures': [
                'BUFG (global buffer) configuration',
                'Clock multiplexers',
                'Clock enables',
                'Global clock routing',
                'Regional clock routing',
                'Clock domain crossing'
            ],
            'routing_bit_regions': [(0, 1312)],
            'logic_bit_regions': [],
        },
    }
    
    @staticmethod
    def get_name(block_type: int) -> str:
        """Get block type name from enumeration"""
        if block_type in BlockType.PROPERTIES:
            return BlockType.PROPERTIES[block_type]['name']
        return "UNKNOWN"
    
    @staticmethod
    def get_properties(block_type: int) -> Dict:
        """Get all properties for a block type"""
        return BlockType.PROPERTIES.get(block_type, {})
    
    @staticmethod
    def contains_routing(block_type: int) -> bool:
        """Check if this block type contains routing configuration"""
        props = BlockType.get_properties(block_type)
        return props.get('contains_routing', False)
    
    @staticmethod
    def contains_logic(block_type: int) -> bool:
        """Check if this block type contains logic configuration"""
        props = BlockType.get_properties(block_type)
        return props.get('contains_logic', False)
   
    @staticmethod
    def is_security_critical(block_type: int) -> bool:
        """
        Determine if modifications to this block type are security-critical
        Important for Trojan detection
        """
        props = BlockType.get_properties(block_type)
        return props.get('affects_security_critical', False)
    
    @staticmethod
    def get_block_type_from_tile(tile_type: str) -> int:
        """
        Infer block type from tile type string
        Used in reverse mapping
        """
        tile_upper = tile_type.upper()
        
        if 'CLBLL' in tile_upper or 'CLBLM' in tile_upper:
            return BlockType.CLB
        elif 'INT' in tile_upper and 'BRAM' not in tile_upper:
            return BlockType.CLB  # Interconnect tiles associated with CLB
        elif 'IOI' in tile_upper or 'LIOI' in tile_upper or 'RIOI' in tile_upper:
            return BlockType.IOB
        elif 'BRAM_INT' in tile_upper:
            return BlockType.BRAM_INT
        elif 'BRAM' in tile_upper:
            return BlockType.BRAM_CONTENT
        elif 'HCLK' in tile_upper or 'CLK' in tile_upper:
            return BlockType.CLK
        else:
            raise ValueError(f"Cannot determine block type for tile: {tile_type}")


# ============================================================================
# Section D — Column Classification Rules
# ============================================================================

class ColumnClassification:
    """
    Map FPGA columns to their types and behaviors
    Critical for understanding frame → resource mapping
    """
    
    # Column type enumeration
    COL_TYPE_CLB = "CLB"
    COL_TYPE_IOB = "IOB"
    COL_TYPE_BRAM = "BRAM"
    COL_TYPE_CLK = "CLK"
    COL_TYPE_UNKNOWN = "UNKNOWN"
    
    # Virtex-5 VLX50T column mapping
    # Format: column_index: (column_type, tile_types, frames_per_column, routing_frames, logic_frames)
    COLUMN_MAP = {
        0: ('IOB', ['LIOI', 'INT'], 54, 54, 0),
        1: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        2: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        3: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        4: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),  # 64 content + 28 interconnect
        5: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        6: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        7: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        8: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        9: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        10: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        11: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        12: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        13: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        14: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        15: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        16: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        17: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        18: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        19: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        20: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        21: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        22: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        23: ('CLK', ['HCLK', 'INT'], 4, 4, 0),  # Center clock column
        24: ('CLK', ['HCLK', 'INT'], 4, 4, 0),  # Center clock column
        25: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        26: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        27: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        28: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        29: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        30: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        31: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        32: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        33: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        34: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        35: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        36: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        37: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        38: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        39: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        40: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        41: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        42: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        43: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        44: ('BRAM', ['BRAM', 'BRAM_INT'], 92, 28, 64),
        45: ('CLB', ['CLBLL', 'INT'], 36, 22, 14),
        46: ('CLB', ['CLBLM', 'INT'], 36, 22, 14),
        47: ('IOB', ['RIOI', 'INT'], 54, 54, 0),
    }
    
    @staticmethod
    def get_column_type(major: int) -> str:
        """Get column type from major (column) index"""
        if major in ColumnClassification.COLUMN_MAP:
            return ColumnClassification.COLUMN_MAP[major][0]
        return ColumnClassification.COL_TYPE_UNKNOWN
    
    @staticmethod
    def get_tile_types_in_column(major: int) -> List[str]:
        """Get tile types present in a given column"""
        if major in ColumnClassification.COLUMN_MAP:
            return ColumnClassification.COLUMN_MAP[major][1]
        return []
    
    @staticmethod
    def get_frames_per_column(major: int) -> int:
        """Get total number of frames in a column"""
        if major in ColumnClassification.COLUMN_MAP:
            return ColumnClassification.COLUMN_MAP[major][2]
        return 0
    
    @staticmethod
    def get_routing_frames_count(major: int) -> int:
        """Get number of routing frames in a column"""
        if major in ColumnClassification.COLUMN_MAP:
            return ColumnClassification.COLUMN_MAP[major][3]
        return 0
    
    @staticmethod
    def get_logic_frames_count(major: int) -> int:
        """Get number of logic configuration frames in a column"""
        if major in ColumnClassification.COLUMN_MAP:
            return ColumnClassification.COLUMN_MAP[major][4]
        return 0
    
    @staticmethod
    def is_routing_frame(major: int, minor: int) -> bool:
        """
        Determine if a frame is primarily a routing frame
        Critical for Trojan detection focusing on routing modifications
        """
        routing_count = ColumnClassification.get_routing_frames_count(major)
        return minor < routing_count
    
    @staticmethod
    def get_all_clb_columns() -> List[int]:
        """Get list of all CLB column indices"""
        return [col for col, data in ColumnClassification.COLUMN_MAP.items() 
                if data[0] == ColumnClassification.COL_TYPE_CLB]
    
    @staticmethod
    def get_all_bram_columns() -> List[int]:
        """Get list of all BRAM column indices"""
        return [col for col, data in ColumnClassification.COLUMN_MAP.items() 
                if data[0] == ColumnClassification.COL_TYPE_BRAM]
    
    @staticmethod
    def get_all_iob_columns() -> List[int]:
        """Get list of all IOB column indices"""
        return [col for col, data in ColumnClassification.COLUMN_MAP.items() 
                if data[0] == ColumnClassification.COL_TYPE_IOB]


# ============================================================================
# Section E — Frame Coverage Rules (Frame → Tiles Mapping)
# ============================================================================

class FrameCoverage:
    """
    Map frames to physical tile locations
    This is THE KEY for bitstream → netlist reverse mapping
    """
    
    # Each frame configures a vertical slice of tiles
    TILES_PER_FRAME_HEIGHT = 20  # Virtex-5 specific
    
    # Device has top and bottom halves
    TILES_PER_HALF = 80  # 20 tiles × 4 clock regions
    TOTAL_TILE_ROWS = 160
    
    @staticmethod
    def get_tiles_configured_by_frame(far_value: int) -> List[str]:
        """
        Get list of tile names configured by this frame
        
        Args:
            far_value: Frame Address Register value
            
        Returns:
            List of tile names in format "TILETYPE_X#Y#"
        """
        fields = FrameAddress.decode(far_value)
        block_type = fields['block_type']
        top_bottom = fields['top_bottom']
        major = fields['major']
        minor = fields['minor']
        
        # Get column properties
        col_type = ColumnClassification.get_column_type(major)
        tile_types = ColumnClassification.get_tile_types_in_column(major)
        
        if not tile_types:
            return []
        
        # Calculate vertical tile range
        # Each frame covers TILES_PER_FRAME_HEIGHT vertical tiles
        tiles_per_frame = FrameCoverage.TILES_PER_FRAME_HEIGHT
        
        # Base Y depends on top/bottom half
        if top_bottom == 1:  # Top half
            y_base = FrameCoverage.TILES_PER_HALF
        else:  # Bottom half
            y_base = 0
        
        y_start = y_base + (minor * tiles_per_frame)
        y_end = y_start + tiles_per_frame
        
        # Generate tile names
        tiles = []
        for tile_type in tile_types:
            for y in range(y_start, min(y_end, FrameCoverage.TOTAL_TILE_ROWS)):
                tile_name = f"{tile_type}_X{major}Y{y}"
                tiles.append(tile_name)
        
        return tiles
    
    @staticmethod
    def get_frame_for_tile(tile_name: str) -> Optional[int]:
        """
        Reverse lookup: given a tile name, find its frame address
        
        Args:
            tile_name: Tile name in format "TILETYPE_X#Y#"
            
        Returns:
            FAR value or None if invalid
        """
        # Parse tile name
        match = re.match(r'([A-Z_]+)_X(\d+)Y(\d+)', tile_name)
        if not match:
            return None
        
        tile_type, x_str, y_str = match.groups()
        major = int(x_str)
        y = int(y_str)
        
        # Determine top/bottom half
        if y >= FrameCoverage.TILES_PER_HALF:
            top_bottom = 1
            y_in_half = y - FrameCoverage.TILES_PER_HALF
        else:
            top_bottom = 0
            y_in_half = y
        
        # Calculate minor address
        minor = y_in_half // FrameCoverage.TILES_PER_FRAME_HEIGHT
        
        # Infer block type from tile type
        try:
            block_type = BlockType.get_block_type_from_tile(tile_type)
        except ValueError:
            return None
        
        # Encode FAR
        return FrameAddress.encode(block_type, top_bottom, major, minor)
    
    @staticmethod
    def get_tile_coordinates(tile_name: str) -> Optional[Tuple[int, int]]:
        """
        Extract (X, Y) coordinates from tile name
        
        Returns:
            (x, y) tuple or None
        """
        match = re.match(r'[A-Z_]+_X(\d+)Y(\d+)', tile_name)
        if match:
            return (int(match.group(1)), int(match.group(2)))
        return None
    
    @staticmethod
    def get_neighboring_tiles(tile_name: str, distance: int = 1) -> List[str]:
        """
        Get tiles within Manhattan distance from given tile
        Useful for analyzing routing patterns
        """
        coords = FrameCoverage.get_tile_coordinates(tile_name)
        if not coords:
            return []
        
        x, y = coords
        tile_type_match = re.match(r'([A-Z_]+)_X', tile_name)
        if not tile_type_match:
            return []
        
        tile_type = tile_type_match.group(1)
        neighbors = []
        
        for dx in range(-distance, distance + 1):
            for dy in range(-distance, distance + 1):
                if dx == 0 and dy == 0:
                    continue
                if abs(dx) + abs(dy) > distance:
                    continue
                
                nx, ny = x + dx, y + dy
                if 0 <= nx < DeviceConstants.TOTAL_COLUMNS and 0 <= ny < FrameCoverage.TOTAL_TILE_ROWS:
                    neighbors.append(f"{tile_type}_X{nx}Y{ny}")
        
        return neighbors


# ============================================================================
# Section F — Bit Region Semantics (What Each Bit Does)
# ============================================================================

class BitRegions:
    """
    Define what each bit position in a frame configures
    Critical for identifying routing vs logic modifications
    """
    
    # Bit region types
    REGION_TYPE_ROUTING = "routing"
    REGION_TYPE_LOGIC = "logic"
    REGION_TYPE_CONTROL = "control"
    REGION_TYPE_RESERVED = "reserved"
    REGION_TYPE_UNKNOWN = "unknown"
    
    # CLB frame bit regions (approximate - device-specific details needed)
    CLB_BIT_REGIONS = {
        'interconnect_routing': (0, 704),      # INT tile routing bits
        'clb_routing': (704, 832),             # Local CLB routing
        'lut_init': (832, 1088),               # LUT truth tables (64 bits × 4 LUTs)
        'ff_init': (1088, 1120),               # Flip-flop initialization
        'mux_config': (1120, 1200),            # Multiplexer configuration
        'carry_config': (1200, 1250),          # Carry chain configuration
        'control_signals': (1250, 1312),       # Clock enables, resets, etc.
    }
    
    # IOB frame bit regions
    IOB_BIT_REGIONS = {
        'io_routing': (0, 800),                # Routing to/from IOBs
        'io_standard': (800, 850),             # IOSTANDARD configuration
        'drive_strength': (850, 900),          # Drive strength, slew rate
        'iodelay_config': (900, 1100),         # IODELAY tap values
        'io_registers': (1100, 1200),          # IOB registers
        'control': (1200, 1312),               # Pull-up/down, termination
    }
    
    # BRAM content frame bit regions
    BRAM_CONTENT_BIT_REGIONS = {
        'memory_content': (0, 1312),           # All bits are RAM initialization
    }
    
    # BRAM interconnect frame bit regions
    BRAM_INT_BIT_REGIONS = {
        'address_routing': (0, 400),           # Address pin routing
        'data_routing': (400, 900),            # Data pin routing
        'control_routing': (900, 1200),        # Control signal routing
        'clock_routing': (1200, 1312),         # Clock routing
    }
    
    # Clock frame bit regions
    CLK_BIT_REGIONS = {
        'bufg_config': (0, 200),               # BUFG configurations
        'clock_mux': (200, 600),               # Clock multiplexers
        'clock_routing': (600, 1200),          # Global/regional clock nets
        'clock_enable': (1200, 1312),          # Clock enable logic
    }
    
    @staticmethod
    def get_bit_region_type(far_value: int, bit_offset: int) -> str:
        """
        Determine what type of configuration a specific bit controls
        
        Args:
            far_value: Frame address
            bit_offset: Bit position within frame (0-1311)
            
        Returns:
            Region type string
        """
        fields = FrameAddress.decode(far_value)
        block_type = fields['block_type']
        major = fields['major']
        
        # Get block type properties
        props = BlockType.get_properties(block_type)
        
        # Check if this is a routing frame in this column
        is_routing = ColumnClassification.is_routing_frame(major, fields['minor'])
        
        if block_type == BlockType.CLB:
            for region_name, (start, end) in BitRegions.CLB_BIT_REGIONS.items():
                if start <= bit_offset < end:
                    if 'routing' in region_name:
                        return BitRegions.REGION_TYPE_ROUTING
                    elif 'lut' in region_name or 'ff' in region_name:
                        return BitRegions.REGION_TYPE_LOGIC
                    else:
                        return BitRegions.REGION_TYPE_CONTROL
        
        elif block_type == BlockType.IOB:
            for region_name, (start, end) in BitRegions.IOB_BIT_REGIONS.items():
                if start <= bit_offset < end:
                    if 'routing' in region_name:
                        return BitRegions.REGION_TYPE_ROUTING
                    else:
                        return BitRegions.REGION_TYPE_LOGIC
        
        elif block_type == BlockType.BRAM_CONTENT:
            return BitRegions.REGION_TYPE_LOGIC  # All content
        
        elif block_type == BlockType.BRAM_INT:
            return BitRegions.REGION_TYPE_ROUTING  # All routing
        
        elif block_type == BlockType.CLK:
            return BitRegions.REGION_TYPE_ROUTING  # Clock routing
        
        return BitRegions.REGION_TYPE_UNKNOWN
    
    @staticmethod
    def get_routing_bits_in_frame(far_value: int) -> List[int]:
        """
        Get list of bit offsets that control routing in this frame
        CRITICAL for Trojan detection
        
        Returns:
            List of bit indices that affect routing
        """
        fields = FrameAddress.decode(far_value)
        block_type = fields['block_type']
        
        routing_bits = []
        
        if block_type == BlockType.CLB:
            # Add interconnect and CLB routing bits
            routing_bits.extend(range(0, 832))  # Both INT and CLB routing
        
        elif block_type == BlockType.IOB:
            # IO routing bits
            routing_bits.extend(range(0, 800))
        
        elif block_type == BlockType.BRAM_INT:
            # All BRAM interconnect is routing
            routing_bits.extend(range(0, 1312))
        
        elif block_type == BlockType.CLK:
            # All clock configuration affects routing
            routing_bits.extend(range(0, 1312))
        
        return routing_bits
    
    @staticmethod
    def get_logic_bits_in_frame(far_value: int) -> List[int]:
        """
        Get list of bit offsets that control logic configuration
        
        Returns:
            List of bit indices that affect logic (LUTs, FFs, etc.)
        """
        fields = FrameAddress.decode(far_value)
        block_type = fields['block_type']
        
        logic_bits = []
        
        if block_type == BlockType.CLB:
            # LUT and FF configuration bits
            logic_bits.extend(range(832, 1200))
        
        elif block_type == BlockType.BRAM_CONTENT:
            # All BRAM content is logic
            logic_bits.extend(range(0, 1312))
        
        return logic_bits


# ============================================================================
# Section G — Validation Rules (Anomaly Detection)
# ============================================================================

class ValidationRules:
    """
    Rules for detecting illegal or suspicious frame configurations
    Used by Trojan detection system
    """
    
    @staticmethod
    def validate_frame_address(far_value: int) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive validation of frame address
        
        Returns:
            (is_valid, error_message)
        """
        return FrameAddress.validate(far_value)
    
    @staticmethod
    def validate_frame_content(far_value: int, frame_data: bytes) -> Tuple[bool, List[str]]:
        """
        Validate frame content for anomalies
        
        Args:
            far_value: Frame address
            frame_data: Frame data (164 bytes = 1312 bits)
            
        Returns:
            (is_valid, list_of_warnings)
        """
        warnings = []
        
        # Check frame data length
        if len(frame_data) != DeviceConstants.BYTES_PER_FRAME:
            return False, [f"Invalid frame length: {len(frame_data)} bytes, expected {DeviceConstants.BYTES_PER_FRAME}"]
        
        # Decode frame address
        fields = FrameAddress.decode(far_value)
        block_type = fields['block_type']
        major = fields['major']
        minor = fields['minor']
        
        # Check if block type matches column type
        col_type = ColumnClassification.get_column_type(major)
        expected_block = None
        
        if col_type == "CLB":
            expected_block = BlockType.CLB
        elif col_type == "IOB":
            expected_block = BlockType.IOB
        elif col_type == "BRAM":
            # BRAM columns have both content and interconnect frames
            if minor < 28:
                expected_block = BlockType.BRAM_INT
            else:
                expected_block = BlockType.BRAM_CONTENT
        elif col_type == "CLK":
            expected_block = BlockType.CLK
        
        if expected_block is not None and block_type != expected_block:
            warnings.append(f"Block type {block_type} unexpected for column type {col_type}")
        
        # Check for all-zero frames (might be suspicious if in active region)
        if frame_data == b'\x00' * DeviceConstants.BYTES_PER_FRAME:
            warnings.append("Frame contains all zeros - may indicate unused or cleared region")
        
        # Check for all-one frames (suspicious)
        if frame_data == b'\xff' * DeviceConstants.BYTES_PER_FRAME:
            warnings.append("Frame contains all ones - highly suspicious pattern")
        
        return len(warnings) == 0, warnings
    
    @staticmethod
    def detect_routing_modification(original_frame: bytes, modified_frame: bytes, far_value: int) -> Dict:
        """
        Detect and analyze routing modifications between two frame versions
        CORE FUNCTION for Trojan detection based on the paper
        
        Args:
            original_frame: Original (golden) frame data
            modified_frame: Potentially trojaned frame data
            far_value: Frame address
            
        Returns:
            Dictionary with modification analysis
        """
        if len(original_frame) != len(modified_frame):
            return {'error': 'Frame length mismatch'}
        
        # Get routing bit positions for this frame
        routing_bits = BitRegions.get_routing_bits_in_frame(far_value)
        logic_bits = BitRegions.get_logic_bits_in_frame(far_value)
        
        # Convert bytes to bit arrays
        orig_bits = [int(b) for byte in original_frame for b in f'{byte:08b}']
        mod_bits = [int(b) for byte in modified_frame for b in f'{byte:08b}']
        
        # Count differences
        routing_diffs = []
        logic_diffs = []
        other_diffs = []
        
        for i in range(min(len(orig_bits), len(mod_bits))):
            if orig_bits[i] != mod_bits[i]:
                if i in routing_bits:
                    routing_diffs.append(i)
                elif i in logic_bits:
                    logic_diffs.append(i)
                else:
                    other_diffs.append(i)
        
        # Calculate severity score (routing mods are most suspicious)
        severity = len(routing_diffs) * 10 + len(logic_diffs) * 5 + len(other_diffs) * 1
        
        # Determine if this looks like a Trojan
        is_suspicious = len(routing_diffs) > 0 and len(routing_diffs) < 20  # Small targeted changes
        
        fields = FrameAddress.decode(far_value)
        
        return {
            'far_value': far_value,
            'block_type': BlockType.get_name(fields['block_type']),
            'column': fields['major'],
            'minor': fields['minor'],
            'routing_bits_modified': len(routing_diffs),
            'logic_bits_modified': len(logic_diffs),
            'other_bits_modified': len(other_diffs),
            'total_bits_modified': len(routing_diffs) + len(logic_diffs) + len(other_diffs),
            'routing_bit_positions': routing_diffs[:50],  # Limit output
            'logic_bit_positions': logic_diffs[:50],
            'severity_score': severity,
            'is_suspicious': is_suspicious,
            'suspicion_reason': 'Targeted routing modifications detected' if is_suspicious else 'Normal modification pattern',
            'tiles_affected': FrameCoverage.get_tiles_configured_by_frame(far_value)
        }
    
    @staticmethod
    def is_frame_in_used_region(far_value: int, used_tiles: Set[str]) -> bool:
        """
        Check if frame configures tiles that are actually used in the design
        Unused region modifications are highly suspicious
        
        Args:
            far_value: Frame address
            used_tiles: Set of tile names used by the legitimate design
            
        Returns:
            True if frame affects used tiles
        """
        frame_tiles = set(FrameCoverage.get_tiles_configured_by_frame(far_value))
        return bool(frame_tiles.intersection(used_tiles))
    
    @staticmethod
    def get_suspicious_frame_patterns() -> List[Dict]:
        """
        Return known suspicious patterns for Trojan detection
        Based on "Turning the Table" paper insights
        """
        return [
            {
                'name': 'Unused Region Routing',
                'description': 'Routing modifications in unused device regions',
                'detection': 'Check if modified routing frames affect tiles outside used region',
                'severity': 'HIGH'
            },
            {
                'name': 'Clock Network Tampering',
                'description': 'Unauthorized clock routing changes',
                'detection': 'Monitor CLK block type frames for unexpected modifications',
                'severity': 'CRITICAL'
            },
            {
                'name': 'IO Exfiltration Path',
                'description': 'New routing paths to IO pins not in original design',
                'detection': 'Trace routing changes that lead to IOB frames',
                'severity': 'HIGH'
            },
            {
                'name': 'Hidden Logic Insertion',
                'description': 'LUT configurations in supposedly unused CLBs',
                'detection': 'Check logic bits in frames outside used tile set',
                'severity': 'MEDIUM'
            },
            {
                'name': 'BRAM Payload',
                'description': 'Suspicious data patterns in BRAM initialization',
                'detection': 'Analyze BRAM content frames for unexpected patterns',
                'severity': 'MEDIUM'
            },
            {
                'name': 'Minimal Routing Detour',
                'description': 'Small routing changes that create covert channels',
                'detection': '1-5 routing bit changes in critical paths',
                'severity': 'HIGH'
            }
        ]


# ============================================================================
# Helper Functions for Analysis
# ============================================================================

def get_frame_info(far_value: int) -> Dict:
    """
    Get comprehensive information about a frame
    Useful debugging and analysis function
    """
    fields = FrameAddress.decode(far_value)
    
    return {
        'far_value': hex(far_value),
        'far_decimal': far_value,
        'block_type': BlockType.get_name(fields['block_type']),
        'block_type_id': fields['block_type'],
        'top_bottom': 'Top' if fields['top_bottom'] == 1 else 'Bottom',
        'column': fields['major'],
        'column_type': ColumnClassification.get_column_type(fields['major']),
        'minor': fields['minor'],
        'is_routing_frame': ColumnClassification.is_routing_frame(fields['major'], fields['minor']),
        'tiles_configured': FrameCoverage.get_tiles_configured_by_frame(far_value),
        'tile_count': len(FrameCoverage.get_tiles_configured_by_frame(far_value)),
        'contains_routing': BlockType.contains_routing(fields['block_type']),
        'contains_logic': BlockType.contains_logic(fields['block_type']),
        'security_critical': BlockType.is_security_critical(fields['block_type'])
    }


def analyze_bitstream_region(start_far: int, end_far: int) -> Dict:
    """
    Analyze a region of the bitstream
    Returns statistics useful for Trojan detection
    """
    analysis = {
        'total_frames': end_far - start_far + 1,
        'routing_frames': 0,
        'logic_frames': 0,
        'block_types': {},
        'columns_covered': set(),
        'tiles_covered': set()
    }
    
    for far in range(start_far, end_far + 1):
        fields = FrameAddress.decode(far)
        
        # Count by block type
        bt_name = BlockType.get_name(fields['block_type'])
        analysis['block_types'][bt_name] = analysis['block_types'].get(bt_name, 0) + 1
        
        # Count routing vs logic
        if ColumnClassification.is_routing_frame(fields['major'], fields['minor']):
            analysis['routing_frames'] += 1
        else:
            analysis['logic_frames'] += 1
        
        # Track columns and tiles
        analysis['columns_covered'].add(fields['major'])
        analysis['tiles_covered'].update(FrameCoverage.get_tiles_configured_by_frame(far))
    
    # Convert sets to counts
    analysis['unique_columns'] = len(analysis['columns_covered'])
    analysis['unique_tiles'] = len(analysis['tiles_covered'])
    analysis['columns_covered'] = sorted(list(analysis['columns_covered']))
    analysis['tiles_covered'] = len(analysis['tiles_covered'])  # Just count
    
    return analysis


# ============================================================================
# Export Main Classes
# ============================================================================

__all__ = [
    'DeviceConstants',
    'FrameAddress',
    'BlockType',
    'ColumnClassification',
    'FrameCoverage',
    'BitRegions',
    'ValidationRules',
    'get_frame_info',
    'analyze_bitstream_region'
]