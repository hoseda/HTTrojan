"""
Bitstream Mapping and Integration

Bridges parser output to analysis framework.
"""

from .integration import (
    AdaptedFrame,
    FrameObjAdapter,
    BitstreamLoader,
    load_bitstream
)

__all__ = [
    'AdaptedFrame',
    'FrameObjAdapter',
    'BitstreamLoader',
    'load_bitstream'
]