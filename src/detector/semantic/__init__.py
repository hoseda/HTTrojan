"""
Semantic Analysis Module
Phase 2: Bit-level semantics, routing, and logic extraction
"""

from .bit_semantics import (
    BitFunction,
    BitDescriptor,
    BitLayoutDatabase,
    FrameBitExtractor,
    SemanticBitDiff
)

from .routing_reconstructor import (
    ActivePIP,
    RoutingPath,
    RoutingConfiguration,
    PIPFrameMapper,
    RoutingReconstructor
)

from .logic_reconstructor import (
    LUTConfiguration,
    FFConfiguration,
    SliceConfiguration,
    LogicConfiguration,
    LogicReconstructor,
    SemanticLogicAnalyzer
)

__all__ = [
    # Bit semantics
    'BitFunction',
    'BitDescriptor',
    'BitLayoutDatabase',
    'FrameBitExtractor',
    'SemanticBitDiff',
    
    # Routing reconstruction
    'ActivePIP',
    'RoutingPath',
    'RoutingConfiguration',
    'PIPFrameMapper',
    'RoutingReconstructor',
    
    # Logic reconstruction
    'LUTConfiguration',
    'FFConfiguration',
    'SliceConfiguration',
    'LogicConfiguration',
    'LogicReconstructor',
    'SemanticLogicAnalyzer',
]