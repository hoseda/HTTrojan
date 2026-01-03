# Core Workflows

HTTrojan exposes a set of scripted workflows through `run_detection.py` and the interactive console. This guide explains when and how to use each flow.

## 1. Infrastructure Smoke Test
```
python run_detection.py --test
```
- Imports essential modules (`BitstreamLoader`, `GoldenBaselineBuilder`, `FrameDifferentialDetector`, `SimpleReportGenerator`, parser & analysis helpers).
- Returns a pass/fail summary so you can verify environment readiness before longer runs.

## 2. Create a Golden Baseline
```
python run_detection.py --create-baseline path/to/golden.bit
```
Steps:
1. `BitstreamLoader` parses the `.bit` file and normalizes frames.
2. `GoldenBaselineBuilder` extracts tile usage and history, creating a `GoldenBaseline` object.
3. Results are saved under `baselines/<timestamped>/` as both `golden_baseline.pkl` and `golden_baseline_info.json`.

Tips:
- Provide an optional `baseline_id` by editing `create_golden_baseline()` call if you embed this in a script.
- Secure the generated directory because it reflects trusted configuration data.

## 3. Full Differential Detection
```
python run_detection.py --golden baselines/.../golden_baseline.pkl --suspect example/.../trojan.bit
```
Workflow:
1. Loads the golden reference (from pickle or directly from another `.bit`).
2. Parses the suspect bitstream.
3. `FrameDifferentialDetector.detect()` compares frames, classifies anomalies, and sets severity flags.
4. `SimpleReportGenerator.generate_all_formats()` writes report artifacts under `detection_reports/<timestamped>/` (text, JSON, Markdown).
5. Console summary lists counts by severity and whether a Trojan was detected.

## 4. Quick Detection
```
python run_detection.py --golden golden.bit --suspect suspect.bit --quick
```
- Calls `quick_detect()` for a rapid assessment without generating full artifacts.
- Useful for triage when you only need an immediate summary.

## 5. Interactive CLI
```
python interactive_cli.py
```
- Presents a guided dashboard with menus for tests, baseline management, detection runs, and report browsing.
- Ideal for analysts who prefer an operator-style experience.

Refer to `docs/reporting_and_cli.md` for more details on output formats and UI capabilities.