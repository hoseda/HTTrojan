# bit_semantics.py
"""
Bit-Level Semantics Extractor
Maps individual bits in configuration frames to their semantic meaning

Phase 2.1: Detailed bit position mappings for PIPs, LUTs, and FFs
Part of: Turning the Table - FPGA Trojan Detection
"""

from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum

from analysis.frame_rules import BlockType, FrameAddress


class BitFunction(Enum):
    """Classification of what a bit controls"""
    PIP = "pip"                          # Programmable interconnect point
    LUT_INIT = "lut_init"               # LUT truth table bit
    FF_INIT = "ff_init"                 # Flip-flop initialization
    FF_CTRL = "ff_ctrl"                 # FF control (CE, SR, clock)
    MUX_SEL = "mux_select"              # Multiplexer selection
    CARRY = "carry_chain"               # Carry chain configuration
    CLOCK_MUX = "clock_mux"             # Clock multiplexer
    IO_STANDARD = "io_standard"         # IO standard selection
    DRIVE_STRENGTH = "drive_strength"   # Output drive strength
    SLEW_RATE = "slew_rate"            # Slew rate control
    PULL = "pull_resistor"              # Pull-up/down
    BRAM_INIT = "bram_init"            # BRAM initialization data
    BRAM_MODE = "bram_mode"            # BRAM operating mode
    RESERVED = "reserved"               # Reserved/unused
    UNKNOWN = "unknown"                 # Unknown function


@dataclass(frozen=True)
class BitDescriptor:
    """
    Complete description of a configuration bit
    
    Describes what a specific bit position controls in a frame.
    """
    bit_offset: int                     # Position within 1312-bit frame
    function: BitFunction               # What this bit does
    resource_name: str                  # Name of resource (e.g., "LUT_A" or "PIP_123")
    subfield: Optional[str] = None      # Subfield within resource (e.g., "INIT[15]")
    frame_relative: bool = True         # Offset relative to frame start
    
    # Additional context
    tile_type: Optional[str] = None     # Tile type this applies to
    site_name: Optional[str] = None     # Site within tile (e.g., "SLICE_X0")
    
    # Trojans love to flip these
    is_routing_critical: bool = False   # Affects signal routing
    is_security_sensitive: bool = False # Changing could enable attacks
    
    def __str__(self) -> str:
        return f"Bit[{self.bit_offset}]: {self.function.value} - {self.resource_name}"


class BitLayoutDatabase:
    """
    Database of bit position semantics for Virtex-5
    
    This is the "Rosetta Stone" that translates bit positions to meanings.
    Built from Xilinx documentation and reverse engineering.
    """
    
    def __init__(self):
        """Initialize bit layout database"""
        self._clb_layout: Dict[int, BitDescriptor] = {}
        self._iob_layout: Dict[int, BitDescriptor] = {}
        self._bram_layout: Dict[int, BitDescriptor] = {}
        self._clk_layout: Dict[int, BitDescriptor] = {}
        
        # Build layouts
        self._build_clb_layout()
        self._build_iob_layout()
        self._build_bram_layout()
        self._build_clk_layout()
    
    def _build_clb_layout(self):
        """
        Build CLB frame bit layout
        
        CLB frames contain:
        - Interconnect routing (bits 0-703)
        - CLB local routing (bits 704-831)
        - LUT initialization (bits 832-1087)
        - FF configuration (bits 1088-1199)
        - Control signals (bits 1200-1311)
        """
        # Interconnect PIPs (approximate - actual layout is complex)
        for bit in range(0, 704):
            pip_id = bit // 4  # Each PIP roughly 4 bits
            self._clb_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.PIP,
                resource_name=f"INT_PIP_{pip_id}",
                is_routing_critical=True,
                is_security_sensitive=True  # Routing mods = Trojan vector
            )
        
        # CLB local routing
        for bit in range(704, 832):
            pip_id = (bit - 704) // 2
            self._clb_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.PIP,
                resource_name=f"CLB_PIP_{pip_id}",
                is_routing_critical=True
            )
        
        # LUT initialization (4 LUTs × 64 bits each)
        lut_names = ['A', 'B', 'C', 'D']
        for lut_idx, lut_name in enumerate(lut_names):
            lut_base = 832 + (lut_idx * 64)
            for bit_in_lut in range(64):
                bit = lut_base + bit_in_lut
                self._clb_layout[bit] = BitDescriptor(
                    bit_offset=bit,
                    function=BitFunction.LUT_INIT,
                    resource_name=f"LUT_{lut_name}",
                    subfield=f"INIT[{bit_in_lut}]",
                    is_security_sensitive=True  # LUT mods = logic Trojans
                )
        
        # FF configuration (4 FFs × 8 bits control each)
        for ff_idx in range(4):
            ff_base = 1088 + (ff_idx * 8)
            self._clb_layout[ff_base] = BitDescriptor(
                bit_offset=ff_base,
                function=BitFunction.FF_INIT,
                resource_name=f"FF_{ff_idx}",
                subfield="INIT"
            )
            self._clb_layout[ff_base + 1] = BitDescriptor(
                bit_offset=ff_base + 1,
                function=BitFunction.FF_CTRL,
                resource_name=f"FF_{ff_idx}",
                subfield="CLOCK_ENABLE"
            )
            self._clb_layout[ff_base + 2] = BitDescriptor(
                bit_offset=ff_base + 2,
                function=BitFunction.FF_CTRL,
                resource_name=f"FF_{ff_idx}",
                subfield="SET_RESET"
            )
        
        # Multiplexers
        for bit in range(1120, 1200):
            mux_id = (bit - 1120) // 4
            self._clb_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.MUX_SEL,
                resource_name=f"MUX_{mux_id}"
            )
        
        # Carry chain
        for bit in range(1200, 1250):
            self._clb_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.CARRY,
                resource_name=f"CARRY_BIT_{bit-1200}"
            )
        
        # Control signals
        for bit in range(1250, 1312):
            self._clb_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.FF_CTRL,
                resource_name=f"CTRL_{bit-1250}"
            )
    
    def _build_iob_layout(self):
        """Build IOB frame bit layout"""
        # IO routing
        for bit in range(0, 800):
            self._iob_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.PIP,
                resource_name=f"IOB_ROUTE_{bit}",
                is_routing_critical=True,
                is_security_sensitive=True  # IO = exfiltration risk
            )
        
        # IO standards
        for bit in range(800, 850):
            self._iob_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.IO_STANDARD,
                resource_name=f"IOSTANDARD_BIT_{bit-800}"
            )
        
        # Drive/slew
        for bit in range(850, 900):
            self._iob_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.DRIVE_STRENGTH,
                resource_name=f"DRIVE_{bit-850}"
            )
        
        # Pull resistors
        for bit in range(1200, 1312):
            self._iob_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.PULL,
                resource_name=f"PULL_{bit-1200}"
            )
    
    def _build_bram_layout(self):
        """Build BRAM frame bit layout"""
        # All BRAM content bits
        for bit in range(0, 1312):
            word = bit // 32
            bit_in_word = bit % 32
            self._bram_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.BRAM_INIT,
                resource_name=f"BRAM_WORD_{word}",
                subfield=f"BIT[{bit_in_word}]",
                is_security_sensitive=True  # Can store payloads
            )
    
    def _build_clk_layout(self):
        """Build clock frame bit layout"""
        # Clock routing
        for bit in range(0, 1312):
            self._clk_layout[bit] = BitDescriptor(
                bit_offset=bit,
                function=BitFunction.CLOCK_MUX,
                resource_name=f"CLK_ROUTE_{bit}",
                is_routing_critical=True,
                is_security_sensitive=True  # Clock = timing attacks
            )
    
    def get_bit_descriptor(self, far_value: int, bit_offset: int) -> Optional[BitDescriptor]:
        """
        Get semantic description of a bit
        
        Args:
            far_value: Frame address
            bit_offset: Bit position in frame (0-1311)
            
        Returns:
            BitDescriptor or None if unknown
        """
        if not 0 <= bit_offset < 1312:
            return None
        
        fields = FrameAddress.decode(far_value)
        block_type = fields['block_type']
        
        # Select appropriate layout
        if block_type == BlockType.CLB:
            return self._clb_layout.get(bit_offset)
        elif block_type == BlockType.IOB:
            return self._iob_layout.get(bit_offset)
        elif block_type == BlockType.BRAM_CONTENT:
            return self._bram_layout.get(bit_offset)
        elif block_type == BlockType.CLK:
            return self._clk_layout.get(bit_offset)
        
        return None
    
    def get_routing_bits(self, far_value: int) -> List[BitDescriptor]:
        """Get all routing-related bits in a frame"""
        routing_bits = []
        
        for bit in range(1312):
            descriptor = self.get_bit_descriptor(far_value, bit)
            if descriptor and descriptor.is_routing_critical:
                routing_bits.append(descriptor)
        
        return routing_bits
    
    def get_security_sensitive_bits(self, far_value: int) -> List[BitDescriptor]:
        """Get all security-sensitive bits in a frame"""
        sensitive_bits = []
        
        for bit in range(1312):
            descriptor = self.get_bit_descriptor(far_value, bit)
            if descriptor and descriptor.is_security_sensitive:
                sensitive_bits.append(descriptor)
        
        return sensitive_bits


class FrameBitExtractor:
    """
    Extract and manipulate bits from configuration frames
    
    Provides bit-level access to frame data with semantic awareness.
    """
    
    def __init__(self):
        """Initialize bit extractor"""
        self.bit_db = BitLayoutDatabase()
    
    def extract_bit(self, frame_data: bytes, bit_offset: int) -> bool:
        """
        Extract a single bit from frame data
        
        Args:
            frame_data: 164-byte frame
            bit_offset: Bit position (0-1311)
            
        Returns:
            Bit value as boolean
        """
        if not 0 <= bit_offset < 1312:
            raise ValueError(f"Bit offset {bit_offset} out of range")
        
        byte_idx = bit_offset // 8
        bit_in_byte = 7 - (bit_offset % 8)  # MSB first
        
        return bool((frame_data[byte_idx] >> bit_in_byte) & 1)
    
    def extract_bits_range(self, frame_data: bytes, start: int, end: int) -> int:
        """
        Extract a range of bits as integer
        
        Args:
            frame_data: Frame data
            start: Start bit (inclusive)
            end: End bit (exclusive)
            
        Returns:
            Integer value of bit range
        """
        value = 0
        for bit_offset in range(start, end):
            if self.extract_bit(frame_data, bit_offset):
                value |= (1 << (end - bit_offset - 1))
        return value
    
    def extract_lut_truth_table(self, frame_data: bytes, 
                                lut_name: str) -> int:
        """
        Extract LUT truth table (64-bit value)
        
        Args:
            frame_data: CLB frame data
            lut_name: LUT name ('A', 'B', 'C', or 'D')
            
        Returns:
            64-bit LUT initialization value
        """
        lut_map = {'A': 0, 'B': 1, 'C': 2, 'D': 3}
        if lut_name not in lut_map:
            raise ValueError(f"Invalid LUT name: {lut_name}")
        
        lut_idx = lut_map[lut_name]
        start_bit = 832 + (lut_idx * 64)
        end_bit = start_bit + 64
        
        return self.extract_bits_range(frame_data, start_bit, end_bit)
    
    def extract_pip_states(self, frame_data: bytes, far_value: int) -> Dict[str, bool]:
        """
        Extract PIP (routing switch) states from frame
        
        Args:
            frame_data: Frame data
            far_value: Frame address
            
        Returns:
            Dictionary mapping PIP name to enabled state
        """
        pip_states = {}
        
        # Get routing bits
        routing_bits = self.bit_db.get_routing_bits(far_value)
        
        for descriptor in routing_bits:
            bit_value = self.extract_bit(frame_data, descriptor.bit_offset)
            pip_states[descriptor.resource_name] = bit_value
        
        return pip_states
    
    def compare_bits(self, frame1: bytes, frame2: bytes) -> Dict[int, Tuple[bool, bool]]:
        """
        Compare two frames bit-by-bit
        
        Args:
            frame1: First frame
            frame2: Second frame
            
        Returns:
            Dictionary of changed bits: bit_offset -> (old_value, new_value)
        """
        changes = {}
        
        for bit_offset in range(1312):
            bit1 = self.extract_bit(frame1, bit_offset)
            bit2 = self.extract_bit(frame2, bit_offset)
            
            if bit1 != bit2:
                changes[bit_offset] = (bit1, bit2)
        
        return changes
    
    def analyze_bit_change(self, far_value: int, bit_offset: int,
                          old_value: bool, new_value: bool) -> Dict:
        """
        Analyze what a bit change means semantically
        
        Args:
            far_value: Frame address
            bit_offset: Bit that changed
            old_value: Original value
            new_value: New value
            
        Returns:
            Dictionary with semantic analysis
        """
        descriptor = self.bit_db.get_bit_descriptor(far_value, bit_offset)
        
        if not descriptor:
            return {
                'bit_offset': bit_offset,
                'function': 'unknown',
                'impact': 'unknown',
                'severity': 'low'
            }
        
        # Determine impact
        if descriptor.function == BitFunction.PIP:
            impact = "routing_modification"
            severity = "critical" if descriptor.is_security_sensitive else "high"
        elif descriptor.function == BitFunction.LUT_INIT:
            impact = "logic_modification"
            severity = "high"
        elif descriptor.function == BitFunction.CLOCK_MUX:
            impact = "clock_modification"
            severity = "critical"
        else:
            impact = "configuration_change"
            severity = "medium"
        
        return {
            'bit_offset': bit_offset,
            'function': descriptor.function.value,
            'resource': descriptor.resource_name,
            'subfield': descriptor.subfield,
            'old_value': old_value,
            'new_value': new_value,
            'impact': impact,
            'severity': severity,
            'is_routing': descriptor.is_routing_critical,
            'is_sensitive': descriptor.is_security_sensitive
        }


class SemanticBitDiff:
    """
    Semantic differential analysis of bit changes
    
    Takes two frames and produces human-readable analysis of differences.
    """
    
    def __init__(self):
        """Initialize semantic diff analyzer"""
        self.extractor = FrameBitExtractor()
    
    def analyze_frame_diff(self, far_value: int,
                          golden_data: bytes,
                          suspect_data: bytes) -> Dict:
        """
        Perform semantic analysis of frame differences
        
        Args:
            far_value: Frame address
            golden_data: Golden frame data
            suspect_data: Suspect frame data
            
        Returns:
            Comprehensive analysis dictionary
        """
        # Get bit changes
        bit_changes = self.extractor.compare_bits(golden_data, suspect_data)
        
        if not bit_changes:
            return {
                'has_changes': False,
                'total_bits_changed': 0
            }
        
        # Analyze each change
        analyzed_changes = []
        for bit_offset, (old_val, new_val) in bit_changes.items():
            analysis = self.extractor.analyze_bit_change(
                far_value, bit_offset, old_val, new_val
            )
            analyzed_changes.append(analysis)
        
        # Categorize changes
        routing_changes = [c for c in analyzed_changes if c['is_routing']]
        logic_changes = [c for c in analyzed_changes if c['function'] == 'lut_init']
        security_changes = [c for c in analyzed_changes if c['is_sensitive']]
        
        # Assess severity
        max_severity = 'low'
        if any(c['severity'] == 'critical' for c in analyzed_changes):
            max_severity = 'critical'
        elif any(c['severity'] == 'high' for c in analyzed_changes):
            max_severity = 'high'
        elif any(c['severity'] == 'medium' for c in analyzed_changes):
            max_severity = 'medium'
        
        return {
            'has_changes': True,
            'total_bits_changed': len(bit_changes),
            'routing_bits_changed': len(routing_changes),
            'logic_bits_changed': len(logic_changes),
            'security_bits_changed': len(security_changes),
            'max_severity': max_severity,
            'detailed_changes': analyzed_changes[:50],  # Limit output
            'summary': self._generate_summary(analyzed_changes)
        }
    
    def _generate_summary(self, changes: List[Dict]) -> str:
        """Generate human-readable summary of changes"""
        if not changes:
            return "No changes detected"
        
        routing = sum(1 for c in changes if c['is_routing'])
        logic = sum(1 for c in changes if c['function'] == 'lut_init')
        critical = sum(1 for c in changes if c['severity'] == 'critical')
        
        parts = []
        if critical > 0:
            parts.append(f"{critical} CRITICAL modifications")
        if routing > 0:
            parts.append(f"{routing} routing changes")
        if logic > 0:
            parts.append(f"{logic} logic changes")
        
        return ", ".join(parts) if parts else f"{len(changes)} changes"


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'BitFunction',
    'BitDescriptor',
    'BitLayoutDatabase',
    'FrameBitExtractor',
    'SemanticBitDiff'
]