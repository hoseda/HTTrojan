# Analysis Toolkit

The `analysis/` directory contains reusable utilities that map low-level frame data onto the physical structure of the FPGA. These modules are essential for interpreting anomalies flagged by the detector.

## Key Modules
- **`analysis/assembler/`** – Houses frame assemblers and mapping utilities. `frame_mapper.py` is particularly important because it converts frame addresses into tile/site references, often caching lookups with `functools.lru_cache` for speed.
- **`analysis/frame_rules.py`** – Defines `FrameAddress` and helper functions to encode/decode the location of a frame within the device column/row scheme.
- **`analysis/device_model.py`** – Describes the target FPGA fabric, including columns, rows, and tile resource types.

## Responsibilities
1. Provide deterministic translations between frame indices and physical resources.
2. Enforce device-specific rules (e.g., valid column ranges, configuration word sizes).
3. Supply metadata that the detector uses to classify anomalies (e.g., “this frame touches a BRAM column”).

## Data Dependencies
- Uses JSON metadata stored under `data/raw_device/`. Paths are centralized in `configs/raw_data_path.py` so you can relocate the cache if needed.

## Extension Points
- Add new device families by expanding the JSON metadata and extending `device_model.py` logic.
- Customize risk heuristics in `frame_mapper.py` to flag particular tiles/sites as more critical based on project requirements.

The analysis toolkit is the bridge between raw frame differences and meaningful hardware insights. Pair it with the documentation in `docs/detection_stack.md` to understand how anomalies are contextualized.