# src/mapping/integration/frame_obj_adapter.py
"""
Frame Object Adapter - Integration Layer

Adapts FrameObj from parser to the analysis framework.
Provides clean interface between parser and detection system.

Part of: Turning the Table - FPGA Trojan Detection
Author: Based on your existing parser infrastructure
"""

from typing import Tuple, Optional, Dict, List
from dataclasses import dataclass
import struct

# Import your existing parser types
# Assuming these are importable from src.parser.payload_lexer
from src.parser.payload_lexer import FrameObj

@dataclass
class AdaptedFrame:
    """
    Standardized frame representation for analysis
    
    This bridges your parser's FrameObj to the detection framework.
    Contains both raw data and decoded fields.
    """
    # Frame address information
    far_value: int              # FAR as integer (for fast comparison)
    far_hex: str               # FAR as hex string (for display)
    
    # Decoded FAR fields
    block_type: int            # 0=CLB, 1=BRAM, 3=DSP, 4=IO
    top_bottom: int            # 0=bottom, 1=top
    column: int                # X coordinate (major address)
    major: int                 # Full major field
    minor: int                 # Frame index within column
    
    # Raw frame data (164 bytes)
    frame_data: bytes          # Complete frame content
    
    # Metadata
    frame_index: int           # Original index from parser
    data_word_count: int       # Should be 41 for Virtex-5
    
    def __hash__(self):
        """Make AdaptedFrame hashable for sets/dicts"""
        return hash(self.far_value)
    
    def __eq__(self, other):
        """Equality based on FAR value"""
        if not isinstance(other, AdaptedFrame):
            return False
        return self.far_value == other.far_value


class FrameObjAdapter:
    """
    Adapter for your existing FrameObj format
    
    Converts FrameObj from payload_lexer.py into AdaptedFrame
    for use by the detection framework.
    
    Usage:
        adapter = FrameObjAdapter()
        frame_obj = ... # From your parser
        adapted = adapter.adapt(frame_obj)
        print(f"FAR: {adapted.far_hex}, Data: {len(adapted.frame_data)} bytes")
    """
    
    def __init__(self):
        """Initialize the adapter"""
        self.adaptation_count = 0
        self.errors = []
    
    def adapt(self, frame_obj: FrameObj) -> Optional[AdaptedFrame]:
        """
        Convert FrameObj to AdaptedFrame
        
        Args:
            frame_obj: FrameObj from your parser
            
        Returns:
            AdaptedFrame or None if conversion fails
        """
        try:
            # Extract FAR value
            far_hex_str = frame_obj.far_raw  # e.g., "00234000"
            far_value = int(far_hex_str, 16)
            
            # Extract decoded fields
            block_type = frame_obj.block_type
            top_bottom = frame_obj.top_bottom
            column = frame_obj.column
            major = frame_obj.major
            minor = frame_obj.minor
            
            # Extract frame data (convert data_words to bytes)
            frame_data = self._extract_frame_data(frame_obj.data_words)
            
            # Create adapted frame
            adapted = AdaptedFrame(
                far_value=far_value,
                far_hex=f"0x{far_hex_str.upper()}",
                block_type=block_type,
                top_bottom=top_bottom,
                column=column,
                major=major,
                minor=minor,
                frame_data=frame_data,
                frame_index=frame_obj.idx,
                data_word_count=len(frame_obj.data_words)
            )
            
            self.adaptation_count += 1
            return adapted
            
        except Exception as e:
            error_msg = f"Failed to adapt FrameObj {frame_obj.idx}: {str(e)}"
            self.errors.append(error_msg)
            return None
    
    def adapt_batch(self, frame_objs: List[FrameObj]) -> List[AdaptedFrame]:
        """
        Convert multiple FrameObj instances
        
        Args:
            frame_objs: List of FrameObj from parser
            
        Returns:
            List of successfully adapted frames
        """
        adapted_frames = []
        
        for frame_obj in frame_objs:
            adapted = self.adapt(frame_obj)
            if adapted:
                adapted_frames.append(adapted)
        
        return adapted_frames
    
    def _extract_frame_data(self, data_words: List) -> bytes:
        """
        Convert data_words to flat byte array
        Handle multiple formats robustly
        """
        frame_bytes = bytearray()
        
        for word in data_words:
            if isinstance(word, (bytes, bytearray)):
                # Already bytes
                frame_bytes.extend(word)
            elif isinstance(word, memoryview):
                # Memoryview
                frame_bytes.extend(bytes(word))
            elif isinstance(word, int):
                # Integer - convert to 4 bytes big-endian
                try:
                    frame_bytes.extend(word.to_bytes(4, byteorder='big'))
                except:
                    # If integer is too large, truncate
                    frame_bytes.extend((word & 0xFFFFFFFF).to_bytes(4, byteorder='big'))
            else:
                # Unknown type - try to convert
                try:
                    frame_bytes.extend(bytes(word))
                except:
                    # Last resort - convert to bytes any way possible
                    frame_bytes.extend(str(word).encode()[:4].ljust(4, b'\x00'))
        
        # Validate length
        if len(frame_bytes) != 164:
            raise ValueError(f"Frame data must be 164 bytes, got {len(frame_bytes)}")
        
        return bytes(frame_bytes)
        
    def get_statistics(self) -> Dict:
        """
        Get adapter statistics
        
        Returns:
            Dictionary with adaptation statistics
        """
        return {
            'frames_adapted': self.adaptation_count,
            'errors': len(self.errors),
            'error_messages': self.errors[-10:]  # Last 10 errors
        }
    
    def validate_frame_data(self, adapted: AdaptedFrame) -> Tuple[bool, Optional[str]]:
        """
        Validate that adapted frame is correct
        
        Args:
            adapted: AdaptedFrame to validate
            
        Returns:
            (is_valid, error_message)
        """
        # Check frame data length
        if len(adapted.frame_data) != 164:
            return False, f"Invalid frame data length: {len(adapted.frame_data)}"
        
        # Check data word count
        if adapted.data_word_count != 41:
            return False, f"Invalid word count: {adapted.data_word_count}"
        
        # Check FAR fields are in valid ranges
        if adapted.block_type > 7:
            return False, f"Invalid block type: {adapted.block_type}"
        
        if adapted.top_bottom not in (0, 1):
            return False, f"Invalid top_bottom: {adapted.top_bottom}"
        
        if adapted.column > 47:  # Virtex-5 VLX50T has 48 columns
            return False, f"Invalid column: {adapted.column}"
        
        return True, None


class FrameDataExtractor:
    """
    Low-level frame data manipulation utilities
    
    Provides methods for extracting specific bits, words, and
    byte ranges from frame data.
    """
    
    @staticmethod
    def extract_word(frame_data: bytes, word_index: int) -> int:
        """
        Extract a 32-bit word from frame data
        
        Args:
            frame_data: 164-byte frame data
            word_index: Word index (0-40)
            
        Returns:
            32-bit word as integer
        """
        if not 0 <= word_index < 41:
            raise ValueError(f"Word index must be 0-40, got {word_index}")
        
        offset = word_index * 4
        word_bytes = frame_data[offset:offset+4]
        return struct.unpack('>I', word_bytes)[0]  # Big-endian
    
    @staticmethod
    def extract_bit(frame_data: bytes, bit_offset: int) -> bool:
        """
        Extract a single bit from frame data
        
        Args:
            frame_data: 164-byte frame data
            bit_offset: Bit position (0-1311)
            
        Returns:
            Bit value as boolean
        """
        if not 0 <= bit_offset < 1312:
            raise ValueError(f"Bit offset must be 0-1311, got {bit_offset}")
        
        byte_index = bit_offset // 8
        bit_in_byte = 7 - (bit_offset % 8)  # MSB first
        
        byte_val = frame_data[byte_index]
        return bool((byte_val >> bit_in_byte) & 1)
    
    @staticmethod
    def extract_bits(frame_data: bytes, start_bit: int, end_bit: int) -> int:
        """
        Extract a range of bits as integer
        
        Args:
            frame_data: 164-byte frame data
            start_bit: Start bit offset (inclusive)
            end_bit: End bit offset (exclusive)
            
        Returns:
            Bits as integer value
        """
        if start_bit >= end_bit:
            raise ValueError(f"Invalid bit range: {start_bit}-{end_bit}")
        
        result = 0
        for bit_offset in range(start_bit, end_bit):
            bit_val = FrameDataExtractor.extract_bit(frame_data, bit_offset)
            if bit_val:
                result |= (1 << (end_bit - bit_offset - 1))
        
        return result
    
    @staticmethod
    def compare_frames(frame1: bytes, frame2: bytes) -> List[int]:
        """
        Find all bit positions that differ between two frames
        
        Args:
            frame1: First frame data
            frame2: Second frame data
            
        Returns:
            List of bit offsets where frames differ
        """
        if len(frame1) != len(frame2):
            raise ValueError("Frames must be same length")
        
        differences = []
        
        for bit_offset in range(1312):  # 164 bytes * 8 bits
            bit1 = FrameDataExtractor.extract_bit(frame1, bit_offset)
            bit2 = FrameDataExtractor.extract_bit(frame2, bit_offset)
            
            if bit1 != bit2:
                differences.append(bit_offset)
        
        return differences
    
    @staticmethod
    def count_set_bits(frame_data: bytes) -> int:
        """
        Count number of '1' bits in frame data
        
        Args:
            frame_data: Frame data
            
        Returns:
            Count of set bits
        """
        return sum(bin(byte).count('1') for byte in frame_data)
    
    @staticmethod
    def is_default_frame(frame_data: bytes) -> bool:
        """
        Check if frame is in default/reset state (all zeros)
        
        Args:
            frame_data: Frame data
            
        Returns:
            True if frame is all zeros
        """
        return frame_data == b'\x00' * 164


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'AdaptedFrame',
    'FrameObjAdapter',
    'FrameDataExtractor'
]