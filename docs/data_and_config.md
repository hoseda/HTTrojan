# Data & Configuration Requirements

HTTrojan relies on several auxiliary assets that describe the target FPGA and store analysis artifacts. Understanding these resources helps ensure reliable detection runs.

## Metadata Paths
- **`configs/raw_data_path.py`** centralizes the absolute path to device metadata. Update this file if you relocate `data/raw_device/`.
- **`data/raw_device/`** contains JSON bundles that describe the FPGA fabric (columns, tiles, wires, etc.). These files are consumed by the analysis toolkit and mapping layer.

## Sample Bitstreams
- Located under `example/` (see `docs/examples.md` for details).
- Include trusted golden designs and intentionally Trojaned variants for regression testing.

## Generated Artifacts
- **Baselines (`baselines/`)** – Created automatically when running `--create-baseline`. Each subdirectory contains:
  - `golden_baseline.pkl` – Pickled `GoldenBaseline` object.
  - `golden_baseline_info.json` – Human-readable metadata and statistics.
- **Reports (`detection_reports/`)** – Produced during detection runs. Each timestamped folder includes text, JSON, and Markdown summaries.

## Environment Variables
- `LEXER_PROGRESS` – When set to a truthy value, enables a progress bar during payload lexing in the parser.

## Storage & Security Considerations
- Baselines capture detailed frame histories that may leak IP. Store `baselines/` and `detection_reports/` in secure locations.
- Ensure the user running detection has write access to the repository root so directories can be created as needed.

Configure these resources properly before attempting large-scale detection workflows.