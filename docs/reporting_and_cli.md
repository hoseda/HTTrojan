# Reporting & Interactive CLI

HTTrojan provides both automated report generation and an interactive console experience to help engineers inspect results efficiently.

## Report Generation (`src/report/`)
- **`simple_report_generator.py`** – Central class responsible for serializing detection results.
- Generates multiple formats in a single call via `generate_all_formats()`:
  - Plain text summary (`.txt`).
  - Machine-readable JSON (`.json`).
  - Markdown report suitable for documentation or ticket attachments (`.md`).
- Files are saved under a timestamped directory inside `detection_reports/`, created with `run_detection.create_unique_output_dir()`.

### Report Contents
- Overall anomaly counts with severity split (critical/high/medium/low).
- Boolean flag indicating whether a Trojan is likely present.
- Optional per-anomaly details depending on detector configuration (frame address, tile, notes).

## Interactive CLI (`interactive_cli.py`)
- Presents a menu-driven interface with colorful output (via `colorama` when available).
- Typical features include:
  - Running infrastructure tests.
  - Creating or listing baselines.
  - Launching new detection runs (quick or full).
  - Browsing previously generated reports and cleaning artifact directories.

## Workflow Integration
1. Run `python run_detection.py --golden ... --suspect ...` for automated pipelines or CI/CD contexts.
2. Use the interactive CLI when you need guided execution, incremental troubleshooting, or a more visual overview.
3. Share report artifacts located in `detection_reports/<timestamped>/trojan_detection_report.*` with stakeholders.

For CLI-friendly automation patterns, revisit `docs/workflows.md`.