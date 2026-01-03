"""
Integration Layer - Parser to Framework Bridge

Adapts existing parser output to the detection framework.
"""

from .frame_obj_adapter import (
    AdaptedFrame,
    FrameObjAdapter,
    FrameDataExtractor
)

from .bitstream_loader import (
    BitstreamInfo,
    LoadedBitstream,
    BitstreamLoader,
    load_bitstream,
    quick_compare
)

__all__ = [
    'AdaptedFrame',
    'FrameObjAdapter',
    'FrameDataExtractor',
    'BitstreamInfo',
    'LoadedBitstream',
    'BitstreamLoader',
    'load_bitstream',
    'quick_compare'
]
