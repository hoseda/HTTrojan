# Project Structure

The repository is organized around distinct layers that parse bitstreams, build baselines, analyze anomalies, and generate reports. Below is a directory-by-directory guide.

## Top-Level Files
- `run_detection.py` – automation script for tests, baseline creation, and detection.
- `interactive_cli.py` – interactive console experience for running detections and browsing reports.
- `AGENTS.md` – notes used by Qodo agents (not part of runtime logic).
- `__init__.py` – enables the repo to be imported as a package in tooling.

## Core Directories
### `src/`
Primary Python packages grouped by domain:
- `parser/` – low-level bitstream parsing (`file_loader.py`, `header_lexer.py`, `payload_lexer.py`).
- `mapping/` – integration layer turning parser output into reusable objects (`integration/bitstream_loader.py`).
- `detector/` – baseline construction, differential detector, and semantic layers.
- `report/` – simple text/JSON/Markdown report generator and helpers.

### `analysis/`
Device-specific assemblers, frame rules, and FPGA layout abstractions that map raw frames to physical resources.

### `configs/`
Helpers that point to metadata bundles (e.g., `configs/raw_data_path.py`).

### `data/`
Contains cached device metadata consumed by the analysis and mapping layers (`data/raw_device/*.json`).

### `example/`
Reference bitstreams for regression, organized by design family (see `docs/examples.md`).

### Generated Artifacts
- `baselines/` – created at runtime to store golden baselines (`golden_baseline.pkl` + JSON metadata).
- `detection_reports/` – created at runtime to store report outputs per detection run.

Refer to `docs/workflows.md` to see how each of these directories participates in the main automation flows.