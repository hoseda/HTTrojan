"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    HTTrojan Detection Report Generator                    ║
║                  Professional Multi-Format Report System                  ║
╚═══════════════════════════════════════════════════════════════════════════╝

Generates beautiful, human-readable reports from anomaly detection results.
Supports text, JSON, and Markdown formats with rich formatting.

Part of: Turning the Table - FPGA Trojan Detection
"""

from __future__ import annotations

import re
import sys
import json
import unicodedata
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

# Optional color support -----------------------------------------------------
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except Exception:
    class _Plain:
        def __getattr__(self, _name: str) -> str:
            return ""
    Fore = Back = Style = _Plain()  # type: ignore
    HAS_COLOR = False

# Import anomaly structures --------------------------------------------------
from src.detector.differential.frame_anomaly import (
    AnomalyReport,
    FrameAnomaly,
    SeverityLevel,
    AnomalyType
)


# ============================================================================
# Constants & Configuration
# ============================================================================

class Colors:
    """Color palette for consistent theming"""
    PRIMARY = Fore.CYAN
    SECONDARY = Fore.BLUE
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    CRITICAL = Fore.MAGENTA
    INFO = Fore.WHITE
    DIM = Style.DIM
    BRIGHT = Style.BRIGHT
    RESET = Style.RESET_ALL


class Icons:
    """Unicode icons for visual enhancement"""
    CHECKMARK = "✓"
    CROSS = "✗"
    ARROW_RIGHT = "→"
    BULLET = "•"
    WARNING = "⚠"
    SHIELD = "🛡"
    ALERT = "🚨"
    CHECK_CIRCLE = "✅"
    RED_CIRCLE = "🔴"
    YELLOW_CIRCLE = "🟡"
    BLUE_CIRCLE = "🔵"
    WHITE_CIRCLE = "⚪"
    CHART = "📊"
    FILE = "📄"
    CLOCK = "🕐"
    GEAR = "⚙"
    TARGET = "🎯"


class BoxChars:
    """Box-drawing characters for borders"""
    H_LINE = "─"
    V_LINE = "│"
    TL_CORNER = "╭"
    TR_CORNER = "╮"
    BL_CORNER = "╰"
    BR_CORNER = "╯"
    T_DOWN = "┬"
    T_UP = "┴"
    T_RIGHT = "├"
    T_LEFT = "┤"
    
    # Double lines
    H_DOUBLE = "═"
    V_DOUBLE = "║"
    TL_DOUBLE = "╔"
    TR_DOUBLE = "╗"
    BL_DOUBLE = "╚"
    BR_DOUBLE = "╝"


SEVERITY_ICONS = {
    "CRITICAL": f"{Icons.RED_CIRCLE} CRITICAL",
    "HIGH": f"{Icons.YELLOW_CIRCLE} HIGH",
    "MEDIUM": f"{Icons.BLUE_CIRCLE} MEDIUM",
    "LOW": f"{Icons.WHITE_CIRCLE} LOW",
}

SEVERITY_COLORS = {
    "CRITICAL": Colors.ERROR + Colors.BRIGHT,
    "HIGH": Colors.WARNING + Colors.BRIGHT,
    "MEDIUM": Colors.PRIMARY + Colors.BRIGHT,
    "LOW": Colors.DIM,
}


# ============================================================================
# Formatting Utilities
# ============================================================================

def colorize(text: str, color: str = "") -> str:
    """Apply color to text if terminal supports it"""
    if sys.stdout.isatty() and HAS_COLOR:
        return f"{color}{text}{Style.RESET_ALL}"
    return text


def visible_width(text: str) -> int:
    """Calculate printable width accounting for ANSI codes"""
    if not text:
        return 0
    ansi_clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    width = 0
    for char in ansi_clean:
        width += 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
    return width


def pad_text(text: str, width: int, *, align: str = "left") -> str:
    """Pad text using visual width awareness"""
    current = visible_width(text)
    padding = max(0, width - current)
    if align == "right":
        return " " * padding + text
    if align == "center":
        left = padding // 2
        right = padding - left
        return (" " * left) + text + (" " * right)
    return text + (" " * padding)


def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate text to max length with suffix"""
    if visible_width(text) <= max_length:
        return text
    max_body = max(0, max_length - visible_width(suffix))
    trimmed = ""
    current = 0
    for char in text:
        char_width = 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
        if current + char_width > max_body:
            break
        trimmed += char
        current += char_width
    return trimmed + suffix


def draw_header(title: str, width: int = 80, double: bool = True) -> str:
    """Draw formatted header"""
    if double:
        top = colorize(BoxChars.TL_DOUBLE + BoxChars.H_DOUBLE * (width - 2) + BoxChars.TR_DOUBLE,
                       Colors.PRIMARY + Colors.BRIGHT)
        bottom = colorize(BoxChars.BL_DOUBLE + BoxChars.H_DOUBLE * (width - 2) + BoxChars.BR_DOUBLE,
                          Colors.PRIMARY + Colors.BRIGHT)
        v = colorize(BoxChars.V_DOUBLE, Colors.PRIMARY + Colors.BRIGHT)
    else:
        top = colorize(BoxChars.TL_CORNER + BoxChars.H_LINE * (width - 2) + BoxChars.TR_CORNER,
                       Colors.PRIMARY + Colors.BRIGHT)
        bottom = colorize(BoxChars.BL_CORNER + BoxChars.H_LINE * (width - 2) + BoxChars.BR_CORNER,
                          Colors.PRIMARY + Colors.BRIGHT)
        v = colorize(BoxChars.V_LINE, Colors.PRIMARY + Colors.BRIGHT)
    
    title_padded = pad_text(title, width - 4, align="center")
    middle = f"{v} {colorize(title_padded, Colors.PRIMARY + Colors.BRIGHT)} {v}"
    
    return f"{top}\n{middle}\n{bottom}"


def draw_section(title: str, icon: str = "") -> str:
    """Draw section header"""
    if icon:
        title = f"{icon} {title}"
    return f"\n{BoxChars.TL_CORNER}{BoxChars.H_LINE} {title}\n"


def draw_separator(width: int = 80, char: str = "-") -> str:
    """Draw separator line"""
    return char * width


def format_table(headers: List[str], rows: List[List[str]], 
                col_widths: Optional[List[int]] = None) -> List[str]:
    """Format data as table"""
    lines = []
    
    if not col_widths:
        col_widths = []
        for i in range(len(headers)):
            max_len = visible_width(str(headers[i]))
            for row in rows:
                if i < len(row):
                    max_len = max(max_len, visible_width(str(row[i])))
            col_widths.append(min(max_len + 2, 50))
    
    # Top border
    border_top = "┌" + "┬".join("─" * w for w in col_widths) + "┐"
    lines.append(border_top)
    
    # Headers
    header_parts = []
    for i in range(len(headers)):
        header_text = truncate_text(str(headers[i]), col_widths[i])
        header_parts.append(pad_text(header_text, col_widths[i], align="center"))
    lines.append("│" + "│".join(header_parts) + "│")
    
    # Separator
    separator = "├" + "┼".join("─" * w for w in col_widths) + "┤"
    lines.append(separator)
    
    # Rows
    for row in rows:
        row_parts = []
        for i in range(len(headers)):
            if i < len(row):
                cell_text = truncate_text(str(row[i]), col_widths[i])
            else:
                cell_text = ""
            row_parts.append(pad_text(cell_text, col_widths[i]))
        lines.append("│" + "│".join(row_parts) + "│")
    
    # Bottom border
    border_bottom = "└" + "┴".join("─" * w for w in col_widths) + "┘"
    lines.append(border_bottom)
    
    return lines


def format_metric(label: str, value: str, width: int = 80) -> str:
    """Format a key-value metric line"""
    label_width = 30
    value_width = width - label_width - 4
    label_padded = pad_text(label, label_width)
    value_padded = pad_text(str(value), value_width)
    return f"  {label_padded}  {value_padded}"


# ============================================================================
# Simple Report Generator
# ============================================================================

class SimpleReportGenerator:
    """
    Professional Report Generator for Detection Results
    
    Generates visually appealing reports in multiple formats:
    - Text (human-readable console output with colors)
    - JSON (machine-readable structured data)
    - Markdown (documentation and archival)
    
    Features:
    - Rich color coding and icons
    - Responsive table formatting
    - Severity-based highlighting
    - Detailed and summary views
    - Attack vector analysis
    - Recommendations engine
    
    Usage:
        generator = SimpleReportGenerator()
        
        # Generate colorized text report
        text = generator.generate_text_report(report)
        print(text)
        
        # Save in all formats
        files = generator.generate_all_formats(report, "output_dir")
    """
    
    def __init__(self, use_colors: bool = True):
        """
        Initialize the report generator
        
        Args:
            use_colors: Enable terminal colors in text reports
        """
        self.use_colors = use_colors and HAS_COLOR
        self.reports_generated = 0
    
    # ========================================================================
    # Text Report Generation
    # ========================================================================
    
    def generate_text_report(self, 
                            report: AnomalyReport,
                            detail_level: str = "summary",
                            width: int = 80) -> str:
        """
        Generate professional text report with colors and formatting
        
        Args:
            report: AnomalyReport to format
            detail_level: "summary", "detailed", or "full"
            width: Report width in characters
            
        Returns:
            Formatted text report with ANSI colors
        """
        lines = []
        
        # Header
        lines.append(colorize(draw_header("FPGA TROJAN DETECTION REPORT", width), 
                             Colors.PRIMARY + Colors.BRIGHT))
        lines.append("")
        
        # Verdict Banner
        lines.append(self._format_verdict(report))
        lines.append("")
        
        # Detection Metadata
        lines.append(colorize(draw_section("Detection Metadata", Icons.CLOCK), 
                             Colors.SECONDARY + Colors.BRIGHT))
        lines.extend(self._format_metadata(report, width))
        lines.append("")
        
        # Statistics Overview
        lines.append(colorize(draw_section("Statistics Overview", Icons.CHART), 
                             Colors.SECONDARY + Colors.BRIGHT))
        lines.extend(self._format_statistics(report, width))
        lines.append("")
        
        # Severity Breakdown
        lines.append(colorize(draw_section("Anomaly Severity Distribution", Icons.TARGET), 
                             Colors.SECONDARY + Colors.BRIGHT))
        lines.extend(self._format_severity_breakdown(report))
        lines.append("")
        
        # Type Breakdown
        if report.type_counts:
            lines.append(colorize(draw_section("Anomaly Types", Icons.GEAR), 
                                 Colors.SECONDARY + Colors.BRIGHT))
            lines.extend(self._format_type_breakdown(report))
            lines.append("")
        
        # Critical Findings
        if report.critical_count > 0:
            lines.append(colorize(draw_section("Critical Findings", Icons.ALERT), 
                                 Colors.ERROR + Colors.BRIGHT))
            lines.extend(self._format_critical_findings(report, detail_level))
            lines.append("")
        
        # High Severity Findings
        if report.high_count > 0 and detail_level in ["detailed", "full"]:
            lines.append(colorize(draw_section("High Severity Findings", Icons.WARNING), 
                                 Colors.WARNING + Colors.BRIGHT))
            lines.extend(self._format_high_findings(report, detail_level))
            lines.append("")
        
        # Unused Region Analysis
        unused_anomalies = report.get_unused_region_anomalies()
        if unused_anomalies:
            lines.append(colorize(draw_section("Unused Region Modifications", Icons.SHIELD), 
                                 Colors.CRITICAL + Colors.BRIGHT))
            lines.append(colorize("  ⚠ Prime locations for hardware Trojan insertion", 
                                 Colors.WARNING))
            lines.append("")
            lines.extend(self._format_unused_regions(report, unused_anomalies, detail_level))
            lines.append("")
        
        # Routing Analysis
        routing_anomalies = report.get_routing_anomalies()
        if routing_anomalies and detail_level in ["detailed", "full"]:
            lines.append(colorize(draw_section("Routing Modifications", Icons.TARGET), 
                                 Colors.WARNING + Colors.BRIGHT))
            lines.extend(self._format_routing_analysis(routing_anomalies))
            lines.append("")
        
        # Recommendations
        lines.append(colorize(draw_section("Security Recommendations", Icons.SHIELD), 
                             Colors.PRIMARY + Colors.BRIGHT))
        lines.extend(self._format_recommendations(report))
        lines.append("")
        
        # Summary Narrative
        if report.summary:
            lines.append(colorize(draw_section("Analysis Summary", Icons.FILE), 
                                 Colors.SECONDARY + Colors.BRIGHT))
            lines.extend(self._format_summary_narrative(report.summary))
            lines.append("")
        
        # Footer
        lines.append(colorize(draw_separator(width, "═"), Colors.DIM))
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        footer = pad_text(f"Report generated: {timestamp}", width, align="center")
        lines.append(colorize(footer, Colors.DIM))
        lines.append(colorize(draw_separator(width, "═"), Colors.DIM))
        
        self.reports_generated += 1
        
        return "\n".join(lines)
    
    def _format_verdict(self, report: AnomalyReport) -> str:
        """Format verdict banner with appropriate styling"""
        routing_mods = len(report.get_routing_anomalies())
        
        if report.trojan_detected:
            verdict = f"{Icons.ALERT}  VERDICT: TROJAN DETECTED  {Icons.ALERT}"
            return colorize(pad_text(verdict, 80, align="center"), 
                          Colors.ERROR + Colors.BRIGHT + Back.BLACK)
        elif report.critical_count > 0 or report.high_count > 0:
            verdict = f"{Icons.WARNING} VERDICT: SUSPICIOUS MODIFICATIONS FOUND"
            return colorize(pad_text(verdict, 80, align="center"), 
                          Colors.WARNING + Colors.BRIGHT)
        elif len(report) > 0 or routing_mods > 0 or report.total_bits_changed > 0:
            verdict = f"{Icons.WARNING} VERDICT: MODIFICATIONS DETECTED"
            return colorize(pad_text(verdict, 80, align="center"), 
                          Colors.WARNING)
        else:
            verdict = f"{Icons.CHECK_CIRCLE} VERDICT: NO SIGNIFICANT ANOMALIES"
            return colorize(pad_text(verdict, 80, align="center"), 
                          Colors.SUCCESS + Colors.BRIGHT)
    
    def _format_metadata(self, report: AnomalyReport, width: int) -> List[str]:
        """Format detection metadata"""
        lines = []
        
        metrics = [
            (f"{Icons.FILE} Golden Baseline", report.golden_id),
            (f"{Icons.FILE} Suspect Bitstream", report.suspect_id),
            (f"{Icons.CLOCK} Detection Time", 
             report.detection_timestamp.strftime("%Y-%m-%d %H:%M:%S")),
            (f"{Icons.TARGET} Confidence", f"{report.confidence:.1%}"),
        ]
        
        for label, value in metrics:
            lines.append(format_metric(
                colorize(label, Colors.PRIMARY),
                colorize(str(value), Colors.BRIGHT)
            ))
        
        return lines
    
    def _format_statistics(self, report: AnomalyReport, width: int) -> List[str]:
        """Format statistics overview"""
        lines = []
        
        # Frame statistics
        frame_pct = (report.frames_with_differences / max(1, report.total_frames_compared)) * 100
        
        stats = [
            ("Frames Compared", f"{report.total_frames_compared:,}"),
            ("Frames Modified", 
             f"{report.frames_with_differences:,} ({frame_pct:.2f}%)"),
            ("Total Bits Changed", f"{report.total_bits_changed:,}"),
            ("Total Anomalies", f"{len(report):,}"),
        ]
        
        for label, value in stats:
            color = Colors.BRIGHT if "Modified" in label or "Changed" in label else Colors.INFO
            lines.append(format_metric(
                colorize(label, Colors.DIM),
                colorize(value, color)
            ))
        
        return lines
    
    def _format_severity_breakdown(self, report: AnomalyReport) -> List[str]:
        """Format severity distribution with visual bars"""
        lines = []
        
        total = len(report)
        severities = [
            ("CRITICAL", report.critical_count, Colors.ERROR),
            ("HIGH", report.high_count, Colors.WARNING),
            ("MEDIUM", report.medium_count, Colors.PRIMARY),
            ("LOW", report.low_count, Colors.DIM),
        ]
        
        max_count = max((count for _, count, _ in severities), default=1)
        
        for severity, count, color in severities:
            icon = SEVERITY_ICONS.get(severity, severity)
            pct = (count / max(1, total)) * 100
            
            # Visual bar
            bar_width = 40
            filled = int((count / max(1, max_count)) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            
            label = colorize(icon, color)
            count_str = colorize(str(count).rjust(5), color)
            pct_str = colorize(f"({pct:5.1f}%)", Colors.DIM)
            line = f"  {pad_text(label, 30)} {count_str} {pad_text(pct_str, 10)} {colorize(bar, color)}"
            
            lines.append(line)
        
        return lines
    
    def _format_type_breakdown(self, report: AnomalyReport) -> List[str]:
        """Format anomaly type distribution"""
        lines = []
        
        # Sort by count descending
        sorted_types = sorted(report.type_counts.items(), 
                            key=lambda x: x[1], reverse=True)
        
        headers = ["Type", "Count"]
        rows = []
        
        for atype, count in sorted_types[:10]:  # Top 10
            rows.append([
                truncate_text(atype, 40),
                colorize(str(count), Colors.BRIGHT)
            ])
        
        if len(sorted_types) > 10:
            remaining = sum(count for _, count in sorted_types[10:])
            rows.append([
                colorize("... others", Colors.DIM),
                colorize(str(remaining), Colors.DIM)
            ])
        
        table_lines = format_table(headers, rows, col_widths=[42, 10])
        lines.extend([f"  {line}" for line in table_lines])
        
        return lines
    
    def _format_critical_findings(self, report: AnomalyReport, 
                                  detail_level: str) -> List[str]:
        """Format critical anomalies"""
        lines = []
        
        for i, anomaly in enumerate(report.get_critical_anomalies(), 1):
            lines.append(colorize(f"  {i}. {anomaly.far_hex} - {anomaly.block_type_name}", 
                                 Colors.ERROR + Colors.BRIGHT))
            lines.extend(self._format_anomaly_details(anomaly, detail_level, indent=5))
            lines.append("")
        
        return lines
    
    def _format_high_findings(self, report: AnomalyReport, 
                             detail_level: str) -> List[str]:
        """Format high severity anomalies"""
        lines = []
        
        high_anomalies = report.get_high_severity_anomalies()[:10]  # Top 10
        
        for i, anomaly in enumerate(high_anomalies, 1):
            lines.append(colorize(f"  {i}. {anomaly.far_hex} - {anomaly.block_type_name}", 
                                 Colors.WARNING + Colors.BRIGHT))
            lines.extend(self._format_anomaly_details(anomaly, "summary", indent=5))
            lines.append("")
        
        if report.high_count > 10:
            remaining = report.high_count - 10
            lines.append(colorize(f"  ... and {remaining} more HIGH severity anomalies", 
                                 Colors.DIM))
            lines.append("")
        
        return lines
    
    def _format_unused_regions(self, report: AnomalyReport, 
                              unused_anomalies: List[FrameAnomaly],
                              detail_level: str) -> List[str]:
        """Format unused region anomalies"""
        lines = []
        
        lines.append(colorize(f"  Total: {len(unused_anomalies)} anomalies in unused regions", 
                             Colors.WARNING))
        lines.append("")
        
        for i, anomaly in enumerate(unused_anomalies[:5], 1):  # Top 5
            lines.append(colorize(f"  {i}. {anomaly.far_hex} - {anomaly.block_type_name}", 
                                 Colors.WARNING + Colors.BRIGHT))
            lines.extend(self._format_anomaly_details(anomaly, detail_level, indent=5))
            lines.append("")
        
        if len(unused_anomalies) > 5:
            lines.append(colorize(f"  ... and {len(unused_anomalies) - 5} more", 
                                 Colors.DIM))
            lines.append("")
        
        return lines
    
    def _format_routing_analysis(self, routing_anomalies: List[FrameAnomaly]) -> List[str]:
        """Format routing modification analysis"""
        lines = []
        
        lines.append(colorize(f"  Total: {len(routing_anomalies)} routing modifications", 
                             Colors.WARNING))
        lines.append(colorize("  ⚠ May indicate routing detours or covert channels", 
                             Colors.DIM))
        lines.append("")
        
        for i, anomaly in enumerate(routing_anomalies[:3], 1):  # Top 3
            lines.append(colorize(f"  {i}. {anomaly.far_hex}", 
                                 Colors.WARNING))
            lines.append(colorize(f"     {Icons.BULLET} {anomaly.suspicion_reason}", 
                                 Colors.DIM))
            lines.append("")
        
        return lines
    
    def _format_anomaly_details(self, anomaly: FrameAnomaly, 
                               detail_level: str, indent: int = 3) -> List[str]:
        """Format details for a single anomaly"""
        lines = []
        prefix = " " * indent
        
        # Basic details
        severity_color = SEVERITY_COLORS.get(anomaly.severity.value, Colors.INFO)
        lines.append(colorize(f"{prefix}{Icons.BULLET} Severity: {anomaly.severity.value}", 
                             severity_color))
        lines.append(colorize(f"{prefix}{Icons.BULLET} Type: {anomaly.anomaly_type.value}", 
                             Colors.INFO))
        lines.append(colorize(f"{prefix}{Icons.BULLET} Location: Column {anomaly.column}, Minor {anomaly.minor}", 
                             Colors.DIM))
        lines.append(colorize(f"{prefix}{Icons.BULLET} Bits Changed: {anomaly.bits_changed}", 
                             Colors.BRIGHT))
        
        if detail_level in ["detailed", "full"]:
            lines.append(colorize(f"{prefix}{Icons.BULLET} Tiles Affected: {len(anomaly.tiles_affected)}", 
                                 Colors.DIM))
            if anomaly.tiles_unused:
                lines.append(colorize(f"{prefix}  {Icons.ARROW_RIGHT} {len(anomaly.tiles_unused)} in unused region", 
                                     Colors.WARNING))
            
            if anomaly.suspicion_reason:
                lines.append(colorize(f"{prefix}{Icons.BULLET} Reason: {anomaly.suspicion_reason}", 
                                     Colors.DIM))
            
            if anomaly.attack_vectors:
                vectors = ", ".join(anomaly.attack_vectors)
                lines.append(colorize(f"{prefix}{Icons.BULLET} Attack Vectors: {vectors}", 
                                     Colors.WARNING))
        
        if detail_level == "full":
            if anomaly.tiles_affected:
                tiles_display = ", ".join(anomaly.tiles_affected[:5])
                if len(anomaly.tiles_affected) > 5:
                    tiles_display += f", ... (+{len(anomaly.tiles_affected)-5} more)"
                lines.append(colorize(f"{prefix}{Icons.BULLET} Affected Tiles: {tiles_display}", 
                                     Colors.DIM))
        
        return lines
    
    def _format_recommendations(self, report: AnomalyReport) -> List[str]:
        """Generate security recommendations"""
        lines = []
        
        if report.trojan_detected:
            lines.append(colorize(f"  {Icons.ALERT} IMMEDIATE ACTION REQUIRED:", 
                                 Colors.ERROR + Colors.BRIGHT))
            lines.append(colorize(f"  {Icons.CROSS} DO NOT deploy this bitstream to production", 
                                 Colors.ERROR))
            lines.append(colorize(f"  {Icons.BULLET} Investigate bitstream source and provenance", 
                                 Colors.WARNING))
            lines.append(colorize(f"  {Icons.BULLET} Review synthesis/build toolchain for compromise", 
                                 Colors.WARNING))
            lines.append(colorize(f"  {Icons.BULLET} Conduct detailed manual inspection of critical findings", 
                                 Colors.WARNING))
            lines.append("")
        
        recs = []
        
        if report.critical_count > 0:
            recs.append((Icons.WARNING, 
                        "Critical anomalies detected - manual inspection required",
                        Colors.ERROR))
        
        unused_anomalies = report.get_unused_region_anomalies()
        if unused_anomalies:
            recs.append((Icons.SHIELD, 
                        f"{len(unused_anomalies)} modifications in unused regions (high Trojan risk)",
                        Colors.WARNING))
        
        routing_anomalies = report.get_routing_anomalies()
        if routing_anomalies:
            recs.append((Icons.TARGET, 
                        f"{len(routing_anomalies)} routing modifications (check for detours/covert channels)",
                        Colors.WARNING))
        
        if report.high_count > 10:
            recs.append((Icons.CHART, 
                        f"{report.high_count} high-severity anomalies require comprehensive analysis",
                        Colors.WARNING))
        
        if not report.trojan_detected and not recs:
            recs.append((Icons.CHECK_CIRCLE, 
                        "No significant anomalies detected",
                        Colors.SUCCESS))
            recs.append((Icons.CHECKMARK, 
                        "Bitstream appears to match golden baseline",
                        Colors.SUCCESS))
            recs.append((Icons.CLOCK, 
                        "Consider periodic re-verification",
                        Colors.INFO))
        
        for icon, text, color in recs:
            lines.append(colorize(f"  {icon} {text}", color))
        
        return lines
    
    def _format_summary_narrative(self, summary: str) -> List[str]:
        """Format summary narrative"""
        lines = []
        
        for line in summary.splitlines():
            if line.strip():
                lines.append(colorize(f"  {line}", Colors.INFO))
        
        return lines
    
    # ========================================================================
    # JSON Report Generation
    # ========================================================================
    
    def generate_json_report(self, report: AnomalyReport) -> str:
        """
        Generate JSON report for machine processing
        
        Args:
            report: AnomalyReport to serialize
            
        Returns:
            Pretty-printed JSON string
        """
        report_dict = report.to_json()
        return json.dumps(report_dict, indent=2, sort_keys=True)
    
    def save_json_report(self, report: AnomalyReport, filepath: str) -> bool:
        """
        Save JSON report to file
        
        Args:
            report: AnomalyReport
            filepath: Output file path
            
        Returns:
            True on success, False on error
        """
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.generate_json_report(report))
            
            return True
        except Exception as e:
            print(colorize(f"{Icons.CROSS} Error saving JSON report: {str(e)}", 
                          Colors.ERROR))
            return False
    
    # ========================================================================
    # Markdown Report Generation
    # ========================================================================
    
    def generate_markdown_report(self, report: AnomalyReport) -> str:
        """
        Generate Markdown report for documentation
        
        Ideal for archival, sharing, and rendering in documentation systems.
        
        Args:
            report: AnomalyReport
            
        Returns:
            Markdown formatted report
        """
        lines = []
        
        # Title
        lines.append("# 🛡 FPGA Trojan Detection Report")
        lines.append("")
        
        # Verdict badge
        routing_mods = len(report.get_routing_anomalies())
        if report.trojan_detected:
            lines.append("🚨 **VERDICT: TROJAN DETECTED** 🚨")
        elif report.critical_count > 0 or report.high_count > 0:
            lines.append("⚠️ **VERDICT: SUSPICIOUS MODIFICATIONS FOUND**")
        elif len(report) > 0 or routing_mods > 0 or report.total_bits_changed > 0:
            lines.append("⚠️ **VERDICT: MODIFICATIONS DETECTED**")
        else:
            lines.append("✅ **VERDICT: NO SIGNIFICANT ANOMALIES**")
        
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # Metadata
        lines.append("## 📋 Detection Metadata")
        lines.append("")
        lines.append(f"- **Golden Baseline:** `{report.golden_id}`")
        lines.append(f"- **Suspect Bitstream:** `{report.suspect_id}`")
        lines.append(f"- **Detection Time:** {report.detection_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **Confidence:** {report.confidence:.1%}")
        lines.append("")
        
        # Statistics
        lines.append("## 📊 Statistics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Frames Compared | {report.total_frames_compared:,} |")
        lines.append(f"| Frames Modified | {report.frames_with_differences:,} |")
        lines.append(f"| Total Bits Changed | {report.total_bits_changed:,} |")
        lines.append(f"| Total Anomalies | {len(report):,} |")
        lines.append("")
        
        # Severity breakdown
        lines.append("### Severity Distribution")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| 🔴 CRITICAL | {report.critical_count} |")
        lines.append(f"| 🟡 HIGH | {report.high_count} |")
        lines.append(f"| 🔵 MEDIUM | {report.medium_count} |")
        lines.append(f"| ⚪ LOW | {report.low_count} |")
        lines.append("")
        
        # Type breakdown
        if report.type_counts:
            lines.append("### Anomaly Types")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for atype, count in sorted(report.type_counts.items(), 
                                      key=lambda x: x[1], reverse=True)[:10]:
                lines.append(f"| {atype} | {count} |")
            lines.append("")
        
        # Critical findings
        if report.critical_count > 0:
            lines.append("## 🚨 Critical Findings")
            lines.append("")
            for i, anomaly in enumerate(report.get_critical_anomalies(), 1):
                lines.append(f"### {i}. {anomaly.far_hex} - {anomaly.block_type_name}")
                lines.append("")
                lines.append(f"- **Type:** {anomaly.anomaly_type.value}")
                lines.append(f"- **Bits Changed:** {anomaly.bits_changed}")
                lines.append(f"- **Location:** Column {anomaly.column}, Minor {anomaly.minor}")
                lines.append(f"- **Reason:** {anomaly.suspicion_reason}")
                if anomaly.attack_vectors:
                    lines.append(f"- **Attack Vectors:** {', '.join(anomaly.attack_vectors)}")
                lines.append("")
        
        # Unused regions
        unused_anomalies = report.get_unused_region_anomalies()
        if unused_anomalies:
            lines.append("## 🛡 Unused Region Analysis")
            lines.append("")
            lines.append(f"Found **{len(unused_anomalies)} modifications** in unused regions.")
            lines.append("")
            lines.append("> ⚠️ **Note:** Unused regions are prime locations for hardware Trojan insertion.")
            lines.append("")
        
        # Summary
        if report.summary:
            lines.append("## 📝 Analysis Summary")
            lines.append("")
            for line in report.summary.splitlines():
                if line.strip():
                    lines.append(line)
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        lines.append("")
        
        return "\n".join(lines)
    
    def save_markdown_report(self, report: AnomalyReport, filepath: str) -> bool:
        """
        Save Markdown report to file
        
        Args:
            report: AnomalyReport
            filepath: Output file path
            
        Returns:
            True on success, False on error
        """
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.generate_markdown_report(report))
            
            return True
        except Exception as e:
            print(colorize(f"{Icons.CROSS} Error saving Markdown report: {str(e)}", 
                          Colors.ERROR))
            return False
    
    # ========================================================================
    # File Operations
    # ========================================================================
    
    def save_text_report(self, report: AnomalyReport, filepath: str,
                        detail_level: str = "detailed") -> bool:
        """
        Save text report to file
        
        Args:
            report: AnomalyReport
            filepath: Output file path
            detail_level: Detail level for report
            
        Returns:
            True on success, False on error
        """
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            text = self.generate_text_report(report, detail_level)
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            return True
        except Exception as e:
            print(colorize(f"{Icons.CROSS} Error saving text report: {str(e)}", 
                          Colors.ERROR))
            return False
    
    def generate_all_formats(self, report: AnomalyReport, output_dir: str,
                           base_name: str = "trojan_detection_report") -> Dict[str, str]:
        """
        Generate report in all formats
        
        Creates text, JSON, and Markdown versions of the report.
        
        Args:
            report: AnomalyReport
            output_dir: Output directory
            base_name: Base filename (without extension)
            
        Returns:
            Dictionary mapping format to filepath
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        # Text report
        text_path = output_path / f"{base_name}.txt"
        if self.save_text_report(report, str(text_path), detail_level="detailed"):
            results['text'] = str(text_path)
            print(colorize(f"  {Icons.CHECKMARK} Saved text report: {text_path.name}", 
                          Colors.SUCCESS))
        
        # JSON report
        json_path = output_path / f"{base_name}.json"
        if self.save_json_report(report, str(json_path)):
            results['json'] = str(json_path)
            print(colorize(f"  {Icons.CHECKMARK} Saved JSON report: {json_path.name}", 
                          Colors.SUCCESS))
        
        # Markdown report
        md_path = output_path / f"{base_name}.md"
        if self.save_markdown_report(report, str(md_path)):
            results['markdown'] = str(md_path)
            print(colorize(f"  {Icons.CHECKMARK} Saved Markdown report: {md_path.name}", 
                          Colors.SUCCESS))
        
        return results


# ============================================================================
# Convenience Functions
# ============================================================================

def quick_report(report: AnomalyReport, format: str = "text") -> str:
    """
    Quick report generation helper
    
    Args:
        report: AnomalyReport
        format: "text", "json", or "markdown"
        
    Returns:
        Formatted report string
        
    Raises:
        ValueError: If format is unknown
    """
    generator = SimpleReportGenerator()
    
    if format == "text":
        return generator.generate_text_report(report)
    elif format == "json":
        return generator.generate_json_report(report)
    elif format == "markdown":
        return generator.generate_markdown_report(report)
    else:
        raise ValueError(f"Unknown format: {format}. Use 'text', 'json', or 'markdown'")


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'SimpleReportGenerator',
    'quick_report',
    'Colors',
    'Icons',
    'SEVERITY_ICONS',
    'SEVERITY_COLORS',
]
