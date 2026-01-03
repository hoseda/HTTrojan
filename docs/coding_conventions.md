# Coding Conventions & Contribution Notes

To keep the codebase consistent and approachable, follow these guidelines when contributing to HTTrojan.

## Style Guidelines
- **Language**: Python 3.10+ – leverage structural pattern matching and modern typing features when helpful.
- **Indentation**: 4 spaces, no tabs.
- **Naming**:
  - Modules and files use `snake_case` (e.g., `frame_differential_detector.py`).
  - Functions and variables use descriptive `snake_case` names.
  - Classes follow CapWords (e.g., `GoldenBaselineBuilder`).
- **Imports**: Prefer explicit relative imports within packages to keep dependencies clear.
- **Type Hints**: Maintain type annotations consistently across new code for readability and tooling support.

## Documentation
- Update relevant Markdown files under `docs/` when adding new subsystems or workflows.
- Keep inline comments focused on non-obvious logic; avoid repeating what the code already expresses.

## Testing Expectations
- Run `python run_detection.py --test` before submitting changes to ensure core modules import successfully.
- Provide evidence of baseline creation and detection runs (ideally referencing sample bitstreams) when proposing major changes.

## Version Control & PRs
- When Git is initialized, follow Conventional Commits (e.g., `feat: add semantic routing reconstructor`).
- Branch naming convention: `{feature|bugfix|docs}/short-description`.
- Include report samples or CLI output in pull requests to demonstrate behavior when possible.

## Security & Data Handling
- Treat `baselines/` and `detection_reports/` as sensitive; do not commit generated artifacts containing proprietary designs.
- Verify that device metadata (`data/raw_device/`) matches the FPGA family under investigation to avoid false positives/negatives.

Adhering to these conventions keeps the project maintainable and ready for future collaborators.