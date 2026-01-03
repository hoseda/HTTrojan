#!/usr/bin/env python3
"""HTTrojan detection workflows and reusable helpers."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.detector.baseline.baseline_builder import GoldenBaselineBuilder
from src.detector.baseline.golden_baseline import GoldenBaseline
from src.detector.differential.frame_differential_detector import (
    FrameDifferentialDetector,
    quick_detect,
)
from src.mapping.integration.bitstream_loader import BitstreamLoader
from src.report.simple_report_generator import SimpleReportGenerator


@dataclass
class DetectionResult:
    """Detailed information about a detection run."""

    report: object
    output_dir: Path
    saved_files: Dict[str, Path]
    golden_source: str
    suspect_source: str


@dataclass
class BaselineResult:
    """Information about a newly created baseline."""

    baseline: GoldenBaseline
    output_dir: Path
    pickle_path: Path
    metadata_path: Path


@dataclass
class QuickDetectionResult:
    """Summary from the quick detection helper."""

    report: object
    summary: str


@dataclass
class InfrastructureTestResult:
    """Status of required modules and subsystems."""

    passed: bool
    modules: Dict[str, bool]


def create_unique_output_dir(parent: Path, prefix: str) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_prefix = prefix.replace(os.sep, "_").replace(" ", "_") or "artifact"
    candidate = parent / f"{safe_prefix}_{timestamp}"
    counter = 1
    while candidate.exists():
        candidate = parent / f"{safe_prefix}_{timestamp}_{counter:02d}"
        counter += 1
    candidate.mkdir(parents=True, exist_ok=False)
    return candidate


def _load_golden(golden_path: str, loader: BitstreamLoader) -> GoldenBaseline:
    if golden_path.lower().endswith(".pkl"):
        golden = GoldenBaseline.load(golden_path)
        if not golden:
            raise ValueError(f"Failed to load golden baseline: {golden_path}")
        return golden

    golden_bs = loader.load(golden_path)
    if not golden_bs:
        raise ValueError(f"Failed to load golden bitstream: {golden_path}")

    builder = GoldenBaselineBuilder()
    baseline = builder.build_from_loaded(golden_bs)
    if not baseline:
        raise ValueError("Unable to build baseline from provided golden bitstream")
    return baseline


def _load_suspect(suspect_path: str, loader: BitstreamLoader):
    suspect_bs = loader.load(suspect_path)
    if not suspect_bs:
        raise ValueError(f"Failed to load suspect bitstream: {suspect_path}")
    return suspect_bs


def run_basic_detection(golden_path: str, suspect_path: str) -> DetectionResult:
    loader = BitstreamLoader()
    golden = _load_golden(golden_path, loader)
    suspect = _load_suspect(suspect_path, loader)

    detector = FrameDifferentialDetector()
    report = detector.detect(golden, suspect, verbose=False)

    report_gen = SimpleReportGenerator()
    reports_root = PROJECT_ROOT / "detection_reports"
    report_subdir = create_unique_output_dir(
        reports_root, prefix=f"report_{Path(suspect_path).stem or 'suspect'}"
    )
    saved = report_gen.generate_all_formats(
        report,
        output_dir=str(report_subdir),
        base_name="trojan_detection_report",
    )

    saved_paths = {fmt: Path(path) for fmt, path in saved.items()}
    return DetectionResult(
        report=report,
        output_dir=report_subdir,
        saved_files=saved_paths,
        golden_source=golden_path,
        suspect_source=suspect_path,
    )


def create_golden_baseline(
    golden_path: str,
    *,
    baseline_id: Optional[str] = None,
) -> BaselineResult:
    builder = GoldenBaselineBuilder()
    baseline = builder.build_from_bitstream(
        golden_path,
        baseline_id=baseline_id or Path(golden_path).stem or "golden",
        auto_detect_usage=True,
    )
    if not baseline:
        raise ValueError(f"Failed to build baseline from {golden_path}")

    baseline_root = PROJECT_ROOT / "baselines"
    baseline_dir = create_unique_output_dir(
        baseline_root, prefix=f"baseline_{baseline.baseline_id}"
    )
    pickle_path = baseline_dir / "golden_baseline.pkl"
    metadata_path = baseline_dir / "golden_baseline_info.json"

    baseline.save(str(pickle_path))
    baseline.save(str(metadata_path), format="json")

    return BaselineResult(
        baseline=baseline,
        output_dir=baseline_dir,
        pickle_path=pickle_path,
        metadata_path=metadata_path,
    )


def run_quick_detection(golden_path: str, suspect_path: str) -> QuickDetectionResult:
    report = quick_detect(golden_path, suspect_path)
    summary = getattr(report, "summary", "")
    return QuickDetectionResult(report=report, summary=summary)


def run_infrastructure_tests() -> InfrastructureTestResult:
    modules = {}
    checks = {
        "BitstreamLoader": "src.mapping.integration.bitstream_loader.BitstreamLoader",
        "GoldenBaselineBuilder": "src.detector.baseline.baseline_builder.GoldenBaselineBuilder",
        "FrameDifferentialDetector": "src.detector.differential.frame_differential_detector.FrameDifferentialDetector",
        "SimpleReportGenerator": "src.report.simple_report_generator.SimpleReportGenerator",
        "Parser": "src.parser.file_loader.Parser",
        "FrameAddress": "analysis.frame_rules.FrameAddress",
        "FrameMapper": "analysis.assembler.frame_mapper.FrameMapper",
    }

    for name, path in checks.items():
        try:
            module_path, attr = path.rsplit(".", 1)
            module = __import__(module_path, fromlist=[attr])
            getattr(module, attr)
            modules[name] = True
        except Exception:
            modules[name] = False

    return InfrastructureTestResult(passed=all(modules.values()), modules=modules)


AVAILABLE_WORKFLOWS: Dict[str, callable] = {
    "infrastructure": run_infrastructure_tests,
    "create_baseline": create_golden_baseline,
    "basic_detection": run_basic_detection,
    "quick_detection": run_quick_detection,
}

__all__ = [
    "run_basic_detection",
    "create_golden_baseline",
    "run_quick_detection",
    "run_infrastructure_tests",
    "AVAILABLE_WORKFLOWS",
]


def _print_detection_summary(result: DetectionResult):
    report = result.report
    print("\nDetection Summary")
    print("-" * 60)
    print(f"Output directory: {result.output_dir}")
    print(f"Anomalies: {len(report)}")
    if hasattr(report, "critical_count"):
        print(f"Critical: {report.critical_count}")
        print(f"High:     {report.high_count}")
        print(f"Medium:   {report.medium_count}")
        print(f"Low:      {report.low_count}")
    print(f"Trojan detected: {'Yes' if getattr(report, 'trojan_detected', False) else 'No'}")


def main():
    parser = argparse.ArgumentParser(
        description="HTTrojan detection workflows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_detection.py --test
  python run_detection.py --create-baseline golden.bit
  python run_detection.py --golden golden.bit --suspect suspect.bit
        """,
    )

    parser.add_argument("--test", action="store_true", help="Run infrastructure tests")
    parser.add_argument(
        "--create-baseline", metavar="GOLDEN_BIT", help="Create and save a golden baseline"
    )
    parser.add_argument("--golden", metavar="PATH", help="Path to golden bitstream (.bit/.pkl)")
    parser.add_argument("--suspect", metavar="PATH", help="Path to suspect bitstream (.bit)")
    parser.add_argument(
        "--quick", action="store_true", help="Use quick detection instead of full workflow"
    )

    args = parser.parse_args()

    if args.test:
        result = run_infrastructure_tests()
        print("Infrastructure test result:", "PASSED" if result.passed else "FAILED")
        for name, status in result.modules.items():
            print(f"  {name:28} {'OK' if status else 'ERROR'}")
        return 0

    if args.create_baseline:
        result = create_golden_baseline(args.create_baseline)
        print("Baseline created:")
        print(f"  Directory : {result.output_dir}")
        print(f"  Pickle    : {result.pickle_path}")
        print(f"  Metadata  : {result.metadata_path}")
        return 0

    if args.golden and args.suspect:
        if args.quick:
            result = run_quick_detection(args.golden, args.suspect)
            print(result.summary or "Quick detection finished.")
            return 0

        detection_result = run_basic_detection(args.golden, args.suspect)
        _print_detection_summary(detection_result)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
