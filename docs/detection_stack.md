# Detection Stack

The detection layer lives under `src/detector/` and contains three major capabilities: baseline construction, differential comparison, and higher-level semantic reasoning.

## Baseline Builder (`src/detector/baseline/`)
- **`baseline_builder.py`** – Provides `GoldenBaselineBuilder`, responsible for creating baselines from parsed bitstreams.
- Captures:
  - Frame payloads and indices.
  - Tile usage metadata to understand which regions of the FPGA are active.
  - Optional history for frames that have multiple writes.
- Saves baselines as `.pkl` and/or JSON using methods on `GoldenBaseline`.

## Differential Detector (`src/detector/differential/`)
- **`frame_differential_detector.py`** – Implements `FrameDifferentialDetector` and the `quick_detect()` helper.
- Core logic:
  1. Aligns frames between golden and suspect bitstreams.
  2. Computes per-frame differences and tags anomalies with severity levels (critical/high/medium/low).
  3. Produces a report object exposing counts and summary flags (`trojan_detected`).
- Designed to be deterministic and extensible with new heuristics or scoring rules.

## Semantic Layer (`src/detector/semantic/`)
- Hosts advanced reasoning components that look beyond raw frame differences to infer possible payload intent or resource misuse.
- Works in tandem with the analysis toolkit to determine which tiles or functional blocks were affected.

## Supporting Utilities
- Shared dataclasses, statistics helpers, and optional caching to accelerate repeated detection runs.

Once the detector finishes, the resulting report is passed to the reporting layer described in `docs/reporting_and_cli.md`.