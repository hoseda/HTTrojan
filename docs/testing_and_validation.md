# Testing & Validation

Although HTTrojan does not ship with a traditional `tests/` directory, it provides infrastructure-level checks and recommended workflows to validate functionality.

## Infrastructure Tests
```
python run_detection.py --test
```
- Verifies that critical modules can be imported (`BitstreamLoader`, `GoldenBaselineBuilder`, `FrameDifferentialDetector`, `SimpleReportGenerator`, parser/analysis helpers).
- Outputs a pass/fail table for quick diagnostics.

## Regression Using Sample Bitstreams
1. Create a baseline from a known-good sample, e.g.:
   ```
   python run_detection.py --create-baseline example/aes/aes_encrypt_golden.bit
   ```
2. Run detection against its Trojan counterpart:
   ```
   python run_detection.py --golden baselines/.../golden_baseline.pkl --suspect example/aes/aes_encrypt_trojan.bit
   ```
3. Inspect the generated report under `detection_reports/` to confirm anomalies are detected and severity ratings look reasonable.

## Manual Validation Checklist
- **Parser sanity** – Confirm frame counts and headers match expectations for the target FPGA.
- **Baseline integrity** – Inspect `golden_baseline_info.json` to ensure tile usage aligns with the design.
- **Detector output** – Review severity breakdowns and sample anomalies for correctness.
- **Report artifacts** – Check that text/JSON/Markdown outputs are present and readable.

## Additional Recommendations
- Run `--quick` detections during development for fast feedback, then run full detections before releasing results.
- When modifying analysis heuristics, rerun detections across multiple designs in `example/` to avoid regressions.

By following these validation steps, you can maintain confidence in the detection stack as the project evolves.