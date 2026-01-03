#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    HTTrojan Detection Console                             ║
║                  Enhanced Interactive Terminal Interface                  ║
╚═══════════════════════════════════════════════════════════════════════════╝

A beautiful, feature-rich terminal UI for HTTrojan detection workflows.
Includes dashboard, progress tracking, enhanced reports, and more.
"""

from __future__ import annotations

import os
import re
import sys
import time
import json
import shutil
import hashlib
import unicodedata
import threading
import random
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

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

# Optional readline for tab completion ---------------------------------------
try:
    import readline
    HAS_READLINE = True
except Exception:
    readline = None  # type: ignore
    HAS_READLINE = False

# Domain imports -------------------------------------------------------------
from run_detection import (
    create_golden_baseline,
    run_basic_detection,
    run_infrastructure_tests,
    run_quick_detection,
)
from src.report.simple_report_generator import SimpleReportGenerator


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
    ARROW_LEFT = "←"
    BULLET = "•"
    STAR = "★"
    WARNING = "⚠"
    INFO = "ℹ"
    FOLDER = "📁"
    FILE = "📄"
    SHIELD = "🛡"
    SEARCH = "🔍"
    CHART = "📊"
    GEAR = "⚙"
    ROCKET = "🚀"
    LOCK = "🔒"
    BACK = "↩"


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
    CROSS = "┼"
    
    # Double lines
    H_DOUBLE = "═"
    V_DOUBLE = "║"
    TL_DOUBLE = "╔"
    TR_DOUBLE = "╗"
    BL_DOUBLE = "╚"
    BR_DOUBLE = "╝"


# ============================================================================
# Terminal Utilities
# ============================================================================

def get_terminal_size() -> Tuple[int, int]:
    """Get terminal dimensions (width, height)"""
    try:
        size = os.get_terminal_size()
        return max(80, size.columns), max(24, size.lines)
    except OSError:
        return 80, 24


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def move_cursor(x: int, y: int):
    """Move cursor to position (x, y)"""
    print(f"\033[{y};{x}H", end='')


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


# ============================================================================
# UI Components
# ============================================================================

class Box:
    """Drawable box with borders and content"""
    
    def __init__(self, width: int = 70, double_line: bool = False):
        self.width = width
        self.double = double_line
        
        if double_line:
            self.tl, self.tr = BoxChars.TL_DOUBLE, BoxChars.TR_DOUBLE
            self.bl, self.br = BoxChars.BL_DOUBLE, BoxChars.BR_DOUBLE
            self.h, self.v = BoxChars.H_DOUBLE, BoxChars.V_DOUBLE
        else:
            self.tl, self.tr = BoxChars.TL_CORNER, BoxChars.TR_CORNER
            self.bl, self.br = BoxChars.BL_CORNER, BoxChars.BR_CORNER
            self.h, self.v = BoxChars.H_LINE, BoxChars.V_LINE
    
    def top(self, title: str = "", color: str = Colors.PRIMARY) -> str:
        """Top border with optional title"""
        if title:
            max_title_length = self.width - 6
            title_str = f" {truncate_text(title, max_title_length)} "
            inner_space = self.width - 2 - visible_width(title_str)
            left_pad = max(0, inner_space // 2)
            right_pad = max(0, inner_space - left_pad)
            return (colorize(self.tl, color) + 
                   colorize(self.h * left_pad, color) + 
                   title_str + 
                   colorize(self.h * right_pad, color) + 
                   colorize(self.tr, color))
        return (colorize(self.tl, color) + 
               colorize(self.h * (self.width - 2), color) + 
               colorize(self.tr, color))
    
    def bottom(self, color: str = Colors.PRIMARY) -> str:
        """Bottom border"""
        return (colorize(self.bl, color) + 
               colorize(self.h * (self.width - 2), color) + 
               colorize(self.br, color))
    
    def middle(self, content: str = "", align: str = "left", border_color: str = Colors.PRIMARY) -> str:
        """Middle line with content and colored borders"""
        available = self.width - 4  # 2 for borders, 2 for padding
        content = truncate_text(content, available)
        if align == "center":
            content_body = pad_text(content, available, align="center")
        elif align == "right":
            content_body = pad_text(content, available, align="right")
        else:
            content_body = pad_text(content, available, align="left")
        return f"{colorize(self.v, border_color)} {content_body} {colorize(self.v, border_color)}"
    
    def separator(self, color: str = Colors.PRIMARY) -> str:
        """Horizontal separator line"""
        return (colorize(BoxChars.T_RIGHT, color) + 
               colorize(self.h * (self.width - 2), color) + 
               colorize(BoxChars.T_LEFT, color))

def draw_logo():
    """Draw ASCII art logo - compact and properly centered"""
    logo_lines = [
"██╗  ██╗████████╗████████╗██████╗  ██████╗      ██╗ █████╗ ███╗   ██╗",
"██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔═══██╗     ██║██╔══██╗████╗  ██║",
"███████║   ██║      ██║   ██████╔╝██║   ██║     ██║███████║██╔██╗ ██║",
"██╔══██║   ██║      ██║   ██╔══██╗██║   ██║██   ██║██╔══██║██║╚██╗██║",
"██║  ██║   ██║      ██║   ██║  ██║╚██████╔╝╚█████╔╝██║  ██║██║ ╚████║",
"╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝"
    ]
    
    term_width, _ = get_terminal_size()
    print()
    
    for line in logo_lines:
        # Calculate proper centering
        line_len = len(line)
        if line_len < term_width:
            padding = (term_width - line_len) // 2
            centered = " " * padding + line
        else:
            centered = line[:term_width]
        print(colorize(centered, Colors.PRIMARY + Colors.BRIGHT))


def draw_banner(title: str, subtitle: str = "", icon: str = ""):
    """Draw fancy banner with title - FIXED VERSION with proper centering and colors"""
    term_width, _ = get_terminal_size()
    
    # Create box that fits nicely in terminal
    box_width = min(term_width - 4, 96)
    box = Box(width=box_width, double_line=True)
    
    # Calculate left padding to center the entire box
    left_padding = (term_width - box_width) // 2
    left_pad_str = " " * left_padding
    
    print()
    
    # Top border - centered and colored
    print(left_pad_str + box.top(color=Colors.PRIMARY))
    
    # Empty line with colored borders
    print(left_pad_str + box.middle("", align="center", border_color=Colors.PRIMARY))
    
    # Title line
    max_title_len = box_width - 10
    if icon:
        title_with_icon = f"{icon}  {title}"
    else:
        title_with_icon = title
    
    title_display = truncate_text(title_with_icon, max_title_len)
    title_colored = colorize(title_display, Colors.PRIMARY + Colors.BRIGHT)
    print(left_pad_str + box.middle(title_colored, align="center", border_color=Colors.PRIMARY))
    
    # Subtitle line if present
    if subtitle:
        subtitle_display = truncate_text(subtitle, max_title_len)
        subtitle_colored = colorize(subtitle_display, Colors.DIM)
        print(left_pad_str + box.middle(subtitle_colored, align="center", border_color=Colors.PRIMARY))
    
    # Empty line with colored borders
    print(left_pad_str + box.middle("", align="center", border_color=Colors.PRIMARY))
    
    # Bottom border - centered and colored
    print(left_pad_str + box.bottom(color=Colors.PRIMARY))
    print()

def draw_section_header(title: str, icon: str = ""):
    """Draw section header"""
    width, _ = get_terminal_size()
    if icon:
        title = f"{icon} {title}"
    
    # Truncate if too long
    title = truncate_text(title, width - 10)
    
    print()
    print(colorize(f"╭─ {title} ", Colors.SECONDARY + Colors.BRIGHT))


def format_progress_bar(current: int, total: int, width: int = 40,
                        label: str = "", color: str = Colors.SUCCESS) -> str:
    """Format a progress bar line"""
    if total <= 0:
        total = 1
    percentage = min(100, int((current / total) * 100))
    term_width, _ = get_terminal_size()
    max_bar_width = max(10, min(width, term_width - 30))
    filled = min(max_bar_width, int((max_bar_width * current) / total))
    bar = "█" * filled + "░" * (max_bar_width - filled)
    progress_text = f"{label:<22} [{bar}] {percentage:3d}% ({current}/{total})"
    return colorize(progress_text, color)


def draw_progress_bar(current: int, total: int, width: int = 40, 
                      label: str = "", color: str = Colors.SUCCESS):
    """Draw progress bar"""
    line = format_progress_bar(current, total, width=width, label=label, color=color)
    print(line, end='\r', flush=True)
    return line


def animate_progress(label: str, duration: float = 1.5, steps: int = 30,
                     color: str = Colors.PRIMARY):
    """Animate a single progress bar"""
    delay = max(0.02, duration / max(1, steps))
    for step in range(steps + 1):
        draw_progress_bar(step, steps, label=label, color=color)
        time.sleep(delay)
    print()  # finalize line


def run_progress_group(labels: List[str], *, base_duration: float = 1.6, width: int = 48):
    """Animate multiple progress bars with slight async behavior"""
    if not labels:
        return
    colors = [Colors.PRIMARY, Colors.SECONDARY, Colors.SUCCESS, Colors.WARNING]
    totals = [random.randint(24, 42) for _ in labels]
    max_total = max(totals)
    delay = max(0.03, base_duration / max(1, max_total))
    term_width, _ = get_terminal_size()
    # Ensure clean area for animation
    placeholder = "".ljust(term_width)
    for _ in labels:
        print(placeholder)
    for step in range(max_total + 1):
        print(f"\033[{len(labels)}F", end='')
        for idx, label in enumerate(labels):
            total = totals[idx]
            current = min(step, total)
            line = format_progress_bar(
                current,
                total,
                width=width,
                label=label,
                color=colors[idx % len(colors)]
            )
            print(line.ljust(term_width))
        time.sleep(delay)
    print()


def draw_table(headers: List[str], rows: List[List[str]], 
              col_widths: Optional[List[int]] = None):
    """Draw formatted table with responsive width"""
    term_width, _ = get_terminal_size()
    
    if not col_widths:
        col_widths = []
        for i in range(len(headers)):
            max_len = visible_width(str(headers[i]))
            for row in rows:
                if i < len(row):
                    max_len = max(max_len, visible_width(str(row[i])))
            col_widths.append(min(max_len + 2, 50))  # Cap at 50
    
    total_width = sum(col_widths) + len(col_widths) + 1
    if total_width > term_width - 4:
        scale = (term_width - len(col_widths) - 5) / sum(col_widths)
        col_widths = [max(8, int(w * scale)) for w in col_widths]
    
    border_top = "┌" + "┬".join("─" * w for w in col_widths) + "┐"
    print(colorize(border_top, Colors.DIM))
    vertical = colorize("│", Colors.DIM)
    
    header_parts = []
    for i in range(len(headers)):
        header_text = truncate_text(str(headers[i]), col_widths[i])
        header_parts.append(colorize(pad_text(header_text, col_widths[i], align="center"), Colors.BRIGHT))
    header_row = vertical + vertical.join(header_parts) + vertical
    print(header_row)
    
    separator = "├" + "┼".join("─" * w for w in col_widths) + "┤"
    print(colorize(separator, Colors.DIM))
    
    for row in rows:
        row_parts = []
        for i in range(len(headers)):
            if i < len(row):
                cell_text = truncate_text(str(row[i]), col_widths[i])
            else:
                cell_text = ""
            row_parts.append(pad_text(cell_text, col_widths[i]))
        row_str = vertical + vertical.join(row_parts) + vertical
        print(row_str)
    
    border_bottom = "└" + "┴".join("─" * w for w in col_widths) + "┘"
    print(colorize(border_bottom, Colors.DIM))


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class SystemStats:
    """System statistics"""
    total_baselines: int = 0
    total_reports: int = 0
    total_detections: int = 0
    trojans_found: int = 0
    last_scan: Optional[str] = None
    disk_usage: str = "0 B"


# ============================================================================
# Report Rendering Helpers
# ============================================================================

def render_report_summary(report, *, highlight_top: int = 3):
    """Pretty-print structured summary of a detection report"""
    print(colorize("\nDetection Report Summary", Colors.PRIMARY + Colors.BRIGHT))
    print(colorize("=" * 80, Colors.DIM))
    
    verdict_line = ""
    if getattr(report, "trojan_detected", False):
        verdict_line = colorize("🚨 TROJAN DETECTED 🚨", Colors.ERROR + Colors.BRIGHT)
    elif getattr(report, "critical_count", 0) > 0 or getattr(report, "high_count", 0) > 0:
        verdict_line = colorize("⚠️  Suspicious modifications detected", Colors.WARNING + Colors.BRIGHT)
    else:
        verdict_line = colorize("✅ No significant anomalies", Colors.SUCCESS + Colors.BRIGHT)
    print(verdict_line)
    print()
    
    info_rows = []
    if hasattr(report, "golden_id"):
        info_rows.append([colorize("Golden", Colors.DIM), getattr(report, "golden_id", "-")])
    if hasattr(report, "suspect_id"):
        info_rows.append([colorize("Suspect", Colors.DIM), getattr(report, "suspect_id", "-")])
    if hasattr(report, "detection_timestamp"):
        ts = report.detection_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        info_rows.append([colorize("Detected", Colors.DIM), ts])
    info_rows.append([colorize("Confidence", Colors.DIM), f"{getattr(report, 'confidence', 0):.1%}"])
    info_rows.append([colorize("Frames Compared", Colors.DIM), f"{getattr(report, 'total_frames_compared', 0):,}"])
    info_rows.append([colorize("Frames Modified", Colors.DIM), f"{getattr(report, 'frames_with_differences', 0):,}"])
    info_rows.append([colorize("Bits Changed", Colors.DIM), f"{getattr(report, 'total_bits_changed', 0):,}"])
    draw_table(["Field", "Value"], info_rows, col_widths=[18, 40])
    print()
    
    severity_rows = [
        [colorize("CRITICAL", Colors.ERROR + Colors.BRIGHT), getattr(report, "critical_count", 0)],
        [colorize("HIGH", Colors.WARNING + Colors.BRIGHT), getattr(report, "high_count", 0)],
        [colorize("MEDIUM", Colors.PRIMARY + Colors.BRIGHT), getattr(report, "medium_count", 0)],
        [colorize("LOW", Colors.DIM), getattr(report, "low_count", 0)],
    ]
    draw_table(["Severity", "Count"], severity_rows, col_widths=[16, 10])
    print()
    
    type_counts = getattr(report, "type_counts", {}) or {}
    if type_counts:
        rows = []
        for name, count in sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]:
            rows.append([truncate_text(name, 32), count])
        draw_table(["Anomaly Type", "Count"], rows, col_widths=[34, 10])
        print()
    
    anomalies = []
    if hasattr(report, "get_critical_anomalies"):
        anomalies.extend(report.get_critical_anomalies())
    if len(anomalies) < highlight_top and hasattr(report, "get_high_severity_anomalies"):
        anomalies.extend(report.get_high_severity_anomalies())
    seen = set()
    highlighted = 0
    if anomalies:
        print(colorize("Highlighted Findings", Colors.SECONDARY + Colors.BRIGHT))
        for anomaly in anomalies:
            key = getattr(anomaly, "far_hex", None)
            if key in seen:
                continue
            seen.add(key)
            severity = getattr(anomaly, "severity", None)
            severity_text = severity.value if severity else ""
            header = f"[{severity_text}] {getattr(anomaly, 'far_hex', 'N/A')} - {getattr(anomaly, 'block_type_name', '')}"
            color = Colors.ERROR + Colors.BRIGHT if severity_text == "CRITICAL" else Colors.WARNING
            print(colorize(f"  {header}", color))
            reason = getattr(anomaly, "suspicion_reason", "")
            if reason:
                print(colorize(f"    ↳ {reason}", Colors.DIM))
            highlighted += 1
            if highlighted >= highlight_top:
                break
        print()
    
    summary_text = getattr(report, "summary", "")
    if summary_text:
        print(colorize("Narrative Summary", Colors.SECONDARY + Colors.BRIGHT))
        for line in summary_text.splitlines():
            print(colorize(f"  {line}", Colors.DIM))
        print()


# ============================================================================
# Enhanced Workflows
# ============================================================================

class ProgressIndicator:
    """Animated progress indicator"""
    
    SPINNERS = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
        'line': ['─', '\\', '│', '/'],
        'arrow': ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        'box': ['◰', '◳', '◲', '◱'],
    }
    
    def __init__(self, message: str = "Working", style: str = 'dots'):
        self.message = message
        self.frames = self.SPINNERS.get(style, self.SPINNERS['dots'])
        self.running = False
        self.idx = 0
    
    def __enter__(self):
        self.running = True
        return self
    
    def __exit__(self, *args):
        self.running = False
        print("\r" + " " * 80 + "\r", end='', flush=True)
    
    def update(self, message: str = ""):
        if message:
            self.message = message
        
        if self.running:
            frame = self.frames[self.idx % len(self.frames)]
            print(f"\r{colorize(frame, Colors.PRIMARY)} {self.message}...", 
                  end='', flush=True)
            self.idx += 1
            time.sleep(0.1)


def get_system_stats() -> SystemStats:
    """Gather system statistics"""
    stats = SystemStats()
    
    baselines_dir = PROJECT_ROOT / "baselines"
    reports_dir = PROJECT_ROOT / "detection_reports"
    
    try:
        if baselines_dir.exists():
            stats.total_baselines = len(list(baselines_dir.glob("*.pkl")))
        
        if reports_dir.exists():
            reports = list(reports_dir.iterdir())
            stats.total_reports = len(reports)
            
            # Count trojans found
            for report_dir in reports:
                if report_dir.is_dir():
                    report_file = report_dir / "trojan_detection_report.txt"
                    if report_file.exists():
                        try:
                            content = report_file.read_text()
                            if "TROJAN DETECTED" in content or "CRITICAL" in content:
                                stats.trojans_found += 1
                        except Exception:
                            pass
            
            # Last scan time
            if reports:
                try:
                    latest = max(reports, key=lambda p: p.stat().st_mtime)
                    stats.last_scan = datetime.fromtimestamp(
                        latest.stat().st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
        
        # Calculate disk usage
        total_size = 0
        for directory in [baselines_dir, reports_dir]:
            if directory.exists():
                for path in directory.rglob("*"):
                    if path.is_file():
                        try:
                            total_size += path.stat().st_size
                        except Exception:
                            pass
        
        stats.disk_usage = human_size(total_size)
    except Exception:
        pass
    
    return stats


def draw_dashboard():
    """Draw system dashboard"""
    clear_screen()
    draw_logo()
    
    stats = get_system_stats()
    
    draw_banner(
        "System Dashboard",
        "Hardware Security Monitoring & Analysis",
        Icons.CHART
    )
    
    width, _ = get_terminal_size()
    box = Box(width=min(width - 4, 90))
    
    # Statistics section
    draw_section_header("System Statistics", Icons.INFO)
    print()
    
    # Color-coded statistics
    trojans_color = Colors.ERROR if stats.trojans_found > 0 else Colors.SUCCESS
    trojans_value = colorize(f" ■ {stats.trojans_found}", trojans_color + Colors.BRIGHT)
    
    baselines_value = colorize(f"■ {stats.total_baselines}", Colors.SUCCESS + Colors.BRIGHT)
    reports_value = colorize(f"■ {stats.total_reports}", Colors.INFO + Colors.BRIGHT)
    disk_value = colorize(f"■ {stats.disk_usage}", Colors.SECONDARY + Colors.BRIGHT)
    
    stats_data = [
        [colorize("📊 Total Baselines", Colors.PRIMARY), baselines_value, colorize("Trusted references", Colors.DIM)],
        [colorize("📋 Detection Reports", Colors.PRIMARY), reports_value, colorize("Completed scans", Colors.DIM)],
        [colorize("⚠️  Trojans Found", Colors.PRIMARY), trojans_value, colorize(" Security threats", Colors.DIM)],
        [colorize("💾 Disk Usage", Colors.PRIMARY), disk_value, colorize("Storage consumed", Colors.DIM)],
        [colorize("🕐 Last Scan", Colors.PRIMARY), colorize(stats.last_scan or "Never", Colors.BRIGHT), colorize("Most recent activity", Colors.DIM)],
    ]
    
    # Draw as formatted table
    for row in stats_data:
        label, value, description = row
        label_text = truncate_text(label, 40)
        value_text = truncate_text(value, 25)
        print(f"  {pad_text(label_text, 40)} {pad_text(value_text, 25)} {description}")
    
    print()
    
    # Quick status
    draw_section_header("System Status", Icons.SHIELD)
    print()
    
    # Test infrastructure
    print(f"  {colorize('Checking system components...', Colors.DIM)}")
    time.sleep(0.3)
    
    components = [
        ("Parser Module", True),
        ("Frame Mapper", True),
        ("Detection Engine", True),
        ("Semantic Analyzer", True),
        ("Report Generator", True),
    ]
    
    all_ok = True
    for component, status in components:
        icon = colorize("●", Colors.SUCCESS + Colors.BRIGHT) if status else colorize("●", Colors.ERROR + Colors.BRIGHT)
        status_text = colorize("ONLINE", Colors.SUCCESS + Colors.BRIGHT) if status else colorize("OFFLINE", Colors.ERROR + Colors.BRIGHT)
        component_label = truncate_text(colorize(component, Colors.BRIGHT), 35)
        print(f"  {icon} {pad_text(component_label, 35)} [{status_text}]")
        all_ok = all_ok and status
    
    print()
    
    if all_ok:
        print(f"  {colorize('✓ All systems operational', Colors.SUCCESS + Colors.BRIGHT)}")
    else:
        print(f"  {colorize('✗ Some components failed', Colors.ERROR + Colors.BRIGHT)}")
    
    print()
    
    # IMPORTANT: Add pause so dashboard doesn't flash
    pause(colorize("Press Enter to return to main menu...", Colors.PRIMARY))


def workflow_infrastructure():
    """Enhanced infrastructure check"""
    clear_screen()
    draw_banner("Infrastructure Self-Test", "Validating system components", Icons.GEAR)
    
    print(f"{colorize('Running comprehensive system checks...', Colors.INFO + Colors.BRIGHT)}\n")
    
    with ProgressIndicator("Initializing") as progress:
        for _ in range(5):
            progress.update()
    
    print(f"\n{colorize('Component Status:', Colors.BRIGHT)}\n")
    
    # Run actual test
    try:
        result = run_infrastructure_tests()
    except Exception as exc:
        print(colorize(f"  {Icons.CROSS} Error: {exc}", Colors.ERROR))
        result = None
    
    print()
    if isinstance(result, bool):
        ok = result
        modules = {}
    elif result is None:
        ok = False
        modules = {}
    else:
        ok = result.passed
        modules = result.modules
    
    if modules:
        headers = ["Module", "Status"]
        rows = []
        for name, status in modules.items():
            status_text = colorize("OK", Colors.SUCCESS + Colors.BRIGHT) if status else colorize("FAIL", Colors.ERROR + Colors.BRIGHT)
            rows.append([name, status_text])
        draw_table(headers, rows, col_widths=[32, 10])
        print()
    
    if ok:
        print(colorize(f"  {Icons.CHECKMARK} All systems operational!", Colors.SUCCESS + Colors.BRIGHT))
        print(colorize(f"  {Icons.ROCKET} Ready for Trojan detection", Colors.SUCCESS))
    else:
        print(colorize(f"  {Icons.CROSS} System check failed", Colors.ERROR + Colors.BRIGHT))
        print(colorize(f"  {Icons.INFO} Review module status above", Colors.WARNING))
    
    print()
    pause()


def workflow_create_baseline():
    """Enhanced baseline creation"""
    clear_screen()
    draw_banner("Create Golden Baseline", "Establish trusted reference", Icons.LOCK)
    
    print(colorize("This will create a trusted baseline from a known-good bitstream.\n", Colors.INFO))
    print(colorize(f"  {Icons.BACK} Type 'back' to return to main menu\n", Colors.DIM))
    
    golden_path = prompt_path(
        f"{Icons.FILE} Enter path to golden .bit file",
        must_exist=True,
        allow_back=True
    )
    
    if golden_path == "back":
        return
    
    print()
    draw_section_header("Building Baseline", Icons.GEAR)
    print()
    
    try:
        print(f"  {colorize('[*]', Colors.PRIMARY + Colors.BRIGHT)} Generating baseline...")
        result = create_golden_baseline(golden_path)
        print(colorize(f"  {Icons.CHECKMARK} Complete", Colors.SUCCESS + Colors.BRIGHT))
        
        print()
        print(colorize(f"\n  {Icons.CHECKMARK} Baseline created successfully!", Colors.SUCCESS + Colors.BRIGHT))
        print(colorize(f"  {Icons.INFO} Saved to: {result.output_dir}", Colors.INFO))
        
    except Exception as exc:
        print()
        print(colorize(f"\n  {Icons.CROSS} Baseline creation failed", Colors.ERROR + Colors.BRIGHT))
        print(colorize(f"  {Icons.WARNING} Error: {str(exc)}", Colors.ERROR))
    
    print()
    pause()


def workflow_basic_detection():
    """Enhanced guided detection"""
    clear_screen()
    draw_banner("Guided Trojan Detection", "Comprehensive security analysis", Icons.SEARCH)
    
    print(colorize("This performs deep analysis comparing golden vs suspect bitstreams.\n", Colors.INFO))
    print(colorize(f"  {Icons.BACK} Type 'back' to return to main menu\n", Colors.DIM))
    
    golden = prompt_path(
        f"{Icons.LOCK} Enter path to golden bitstream (.bit or .pkl)",
        must_exist=True,
        allow_back=True
    )
    
    if golden == "back":
        return
    
    suspect = prompt_path(
        f"{Icons.FILE} Enter path to suspect bitstream (.bit)",
        must_exist=True,
        allow_back=True
    )
    
    if suspect == "back":
        return
    
    print()
    draw_section_header("Detection Pipeline", Icons.SEARCH)
    print()
    
    progress_labels = [
        "Preparing Inputs",
        "Loading Bitstreams",
        "Differential Analysis",
        "Generating Report"
    ]
    run_progress_group(progress_labels)
    
    try:
        report_result = run_basic_detection(golden, suspect)
        
        print(colorize(f"\n  {Icons.CHECKMARK} Detection complete!", Colors.SUCCESS + Colors.BRIGHT))
        print(colorize(f"  {Icons.FILE} Report directory: {report_result.output_dir}", Colors.INFO))
        if report_result.saved_files:
            print(colorize("  Saved artifacts:", Colors.DIM))
            for fmt, path in report_result.saved_files.items():
                print(colorize(f"    • {fmt.upper():8} {path}", Colors.DIM))
        
        render_report_summary(report_result.report)
        
    except Exception as exc:
        print()
        print(colorize(f"\n  {Icons.CROSS} Detection failed", Colors.ERROR + Colors.BRIGHT))
        print(colorize(f"  {Icons.WARNING} Error: {str(exc)}", Colors.ERROR))
    
    print()
    pause()


def workflow_quick_detection():
    """Enhanced quick detection"""
    clear_screen()
    draw_banner("Quick Detection", "Fast security scan", Icons.ROCKET)
    
    print(colorize("Rapid analysis for quick threat assessment.\n", Colors.INFO))
    print(colorize(f"  {Icons.BACK} Type 'back' to return to main menu\n", Colors.DIM))
    
    golden = prompt_path(
        f"{Icons.LOCK} Enter path to golden (.bit or .pkl)",
        must_exist=True,
        allow_back=True
    )
    
    if golden == "back":
        return
    
    suspect = prompt_path(
        f"{Icons.FILE} Enter path to suspect (.bit)",
        must_exist=True,
        allow_back=True
    )
    
    if suspect == "back":
        return
    
    print()
    run_progress_group(["Parsing", "Frame Mapping", "Quick Scan"], base_duration=1.2)
    print()
    
    try:
        result = run_quick_detection(golden, suspect)
        print()
        print(colorize(f"  {Icons.CHECKMARK} Quick scan complete", Colors.SUCCESS + Colors.BRIGHT))
        if result and result.summary:
            print(colorize(result.summary, Colors.INFO))
        if result and result.report:
            render_report_summary(result.report, highlight_top=2)
    except Exception as exc:
        print()
        print(colorize(f"  {Icons.CROSS} Scan failed: {str(exc)}", Colors.ERROR))
    
    print()
    pause()


def workflow_report_viewer():
    """Enhanced report browser"""
    clear_screen()
    draw_banner("Detection Reports", "Browse analysis results", Icons.CHART)
    
    reports_dir = PROJECT_ROOT / "detection_reports"
    artifacts = list_artifact_dirs(reports_dir)
    
    if not artifacts:
        print(colorize(f"  {Icons.INFO} No reports found yet.", Colors.WARNING + Colors.BRIGHT))
        print(colorize(f"  {Icons.ARROW_RIGHT} Run a detection first to generate reports.\n", Colors.DIM))
        pause()
        return
    
    # Display reports table
    print(colorize(f"Found {len(artifacts)} reports:\n", Colors.INFO + Colors.BRIGHT))
    
    headers = ["#", "Report", "Size", "Date", "Status"]
    rows = []
    
    for idx, path in enumerate(artifacts[:20], start=1):
        stat = path.stat()
        timestamp = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        size = human_size(stat.st_size) if path.is_file() else "dir"
        
        # Check for trojans
        status = "⚪ Clean"
        if path.is_dir():
            report_file = path / "trojan_detection_report.txt"
            if report_file.exists():
                try:
                    content = report_file.read_text()
                    if "TROJAN DETECTED" in content or "CRITICAL" in content:
                        status = colorize("🔴 Trojan", Colors.ERROR + Colors.BRIGHT)
                    else:
                        status = colorize("🟢 Clean", Colors.SUCCESS + Colors.BRIGHT)
                except Exception:
                    pass
        
        name = truncate_text(path.name, 40)
        rows.append([colorize(str(idx), Colors.BRIGHT), name, size, timestamp, status])
    
    draw_table(headers, rows)
    
    print()
    print(colorize(f"  {Icons.BACK} Press Enter to return to main menu", Colors.DIM))
    choice = prompt_input(
        f"\n{Icons.ARROW_RIGHT} Select report number to view",
        required=False
    )
    
    if not choice:
        return
    
    try:
        idx = int(choice) - 1
        selected = artifacts[idx]
    except (ValueError, IndexError):
        print(colorize(f"  {Icons.CROSS} Invalid selection", Colors.ERROR))
        pause()
        return
    
    # Find viewable file
    if selected.is_dir():
        view_file = selected / "trojan_detection_report.txt"
        if not view_file.exists():
            view_file = next((f for f in selected.iterdir() if f.suffix in {'.txt', '.log'}), None)
    else:
        view_file = selected
    
    if not view_file or not view_file.exists():
        print(colorize(f"  {Icons.CROSS} No viewable content", Colors.ERROR))
        pause()
        return
    
    # Display report
    clear_screen()
    draw_banner(f"Report: {truncate_text(view_file.name, 60)}", "", Icons.FILE)
    
    try:
        content = view_file.read_text(errors='replace')
        
        # Syntax highlighting for reports
        for line in content.split('\n'):
            if 'CRITICAL' in line or 'TROJAN DETECTED' in line:
                print(colorize(line, Colors.ERROR + Colors.BRIGHT))
            elif 'HIGH' in line or 'WARNING' in line:
                print(colorize(line, Colors.WARNING + Colors.BRIGHT))
            elif 'SUCCESS' in line or '✓' in line:
                print(colorize(line, Colors.SUCCESS + Colors.BRIGHT))
            elif line.startswith('=') or line.startswith('-'):
                print(colorize(line, Colors.DIM))
            elif line.startswith('#') or 'Summary' in line:
                print(colorize(line, Colors.PRIMARY + Colors.BRIGHT))
            else:
                print(line)
    except Exception as exc:
        print(colorize(f"  {Icons.CROSS} Error reading file: {exc}", Colors.ERROR))
    
    print()
    pause()


def workflow_cleanup():
    """Enhanced artifact management"""
    clear_screen()
    draw_banner("Artifact Management", "Clean up generated files", Icons.GEAR)
    
    categories = {
        "1": ("Baselines", PROJECT_ROOT / "baselines", Icons.LOCK),
        "2": ("Detection Reports", PROJECT_ROOT / "detection_reports", Icons.FILE),
    }
    
    print(colorize("Select category to manage:\n", Colors.INFO + Colors.BRIGHT))
    
    for key, (label, root, icon) in categories.items():
        try:
            count = len(list_artifact_dirs(root))
            size_total = sum(
                f.stat().st_size for f in root.rglob("*") if f.is_file()
            ) if root.exists() else 0
        except Exception:
            count = 0
            size_total = 0
        
        count_str = colorize(f"{count} items", Colors.BRIGHT)
        size_str = colorize(human_size(size_total), Colors.DIM)
        label_text = truncate_text(label, 25)
        print(f"  [{colorize(key, Colors.PRIMARY + Colors.BRIGHT)}] {icon} {pad_text(label_text, 25)} ({count_str}, {size_str})")
    
    print(f"  [{colorize('0', Colors.PRIMARY + Colors.BRIGHT)}] {Icons.BACK} Return to menu")
    
    choice = prompt_input(f"\n{Icons.ARROW_RIGHT} Select category", required=False)
    
    if not choice or choice == "0":
        return
    
    if choice not in categories:
        print(colorize(f"  {Icons.CROSS} Invalid selection", Colors.ERROR))
        pause()
        return
    
    label, root, icon = categories[choice]
    entries = list_artifact_dirs(root)
    
    if not entries:
        print(colorize(f"\n  {Icons.INFO} No artifacts in {label}", Colors.WARNING))
        pause()
        return
    
    clear_screen()
    draw_banner(f"Manage {label}", f"{len(entries)} items", icon)
    
    # Show items
    headers = ["#", "Name", "Size", "Modified"]
    rows = []
    
    for idx, path in enumerate(entries, start=1):
        try:
            stat = path.stat()
            ts = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            size = human_size(stat.st_size) if path.is_file() else "dir"
            rows.append([colorize(str(idx), Colors.BRIGHT), truncate_text(path.name, 50), size, ts])
        except Exception:
            pass
    
    draw_table(headers, rows)
    
    print()
    print(colorize(f"  {Icons.BACK} Press Enter to cancel", Colors.DIM))
    selection = prompt_input(
        f"{Icons.ARROW_RIGHT} Enter numbers to delete (comma-separated) or 'all'",
        required=False
    )
    
    if not selection:
        return
    
    # Parse selection
    if selection.strip().lower() == 'all':
        targets = entries
    else:
        targets = []
        for token in selection.split(','):
            try:
                idx = int(token.strip())
                if 1 <= idx <= len(entries):
                    targets.append(entries[idx - 1])
            except ValueError:
                pass
    
    if not targets:
        print(colorize(f"  {Icons.CROSS} No valid selection", Colors.ERROR))
        pause()
        return
    
    # Confirm
    print(colorize(f"\n  {Icons.WARNING} Will delete {len(targets)} items:", Colors.WARNING + Colors.BRIGHT))
    for path in targets[:10]:
        print(f"    {Icons.BULLET} {path.name}")
    if len(targets) > 10:
        print(f"    {Icons.BULLET} ... and {len(targets) - 10} more")
    
    if not prompt_confirmation(f"\n{Icons.WARNING} Proceed with deletion? (y/N)"):
        print(colorize(f"  {Icons.INFO} Cancelled", Colors.INFO))
        pause()
        return
    
    # Delete
    print()
    deleted = 0
    for path in targets:
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            print(colorize(f"  {Icons.CHECKMARK} Deleted {truncate_text(path.name, 60)}", Colors.SUCCESS))
            deleted += 1
        except Exception as exc:
            print(colorize(f"  {Icons.CROSS} Failed: {truncate_text(path.name, 50)} - {exc}", Colors.ERROR))
    
    print()
    print(colorize(f"  {Icons.CHECKMARK} Deleted {deleted}/{len(targets)} items", Colors.SUCCESS + Colors.BRIGHT))
    pause()


# ============================================================================
# Input Utilities
# ============================================================================

@contextmanager
def _completion_context(completer):
    """Context manager for readline completion"""
    if not HAS_READLINE:
        yield
        return
    
    old_completer = readline.get_completer()
    old_delims = readline.get_completer_delims()
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n\"'`")
    try:
        yield
    finally:
        readline.set_completer(old_completer)
        readline.set_completer_delims(old_delims)


def _path_completions(text: str, state: int) -> Optional[str]:
    """Path completion for readline"""
    expanded = os.path.expanduser(text)
    directory, partial = os.path.split(expanded)
    search_dir = directory or "."
    
    try:
        entries = os.listdir(search_dir)
    except OSError:
        return None
    
    matches = []
    for entry in entries:
        if entry.startswith(partial):
            candidate = os.path.join(directory, entry) if directory else entry
            full_path = os.path.join(search_dir, entry)
            if os.path.isdir(full_path):
                candidate = candidate + os.sep
            matches.append(candidate)
    
    matches.sort()
    return matches[state] if state < len(matches) else None


def prompt_input(prompt_text: str, *, required: bool = True, 
                enable_tab: bool = False) -> str:
    """Enhanced input prompt"""
    while True:
        prompt = f"  {colorize(prompt_text, Colors.PRIMARY + Colors.BRIGHT)}: "
        
        if enable_tab and HAS_READLINE:
            with _completion_context(_path_completions):
                value = input(prompt).strip()
        else:
            value = input(prompt).strip()
        
        if value or not required:
            return value
        
        print(colorize(f"  {Icons.CROSS} Input required", Colors.ERROR))


def prompt_path(prompt_text: str, *, must_exist: bool = True, allow_back: bool = False) -> str:
    """Enhanced path prompt with validation"""
    while True:
        value = prompt_input(prompt_text, enable_tab=True, required=not allow_back)
        
        if allow_back and value.lower() == "back":
            return "back"
        
        if not value:
            if allow_back:
                print(colorize(f"  {Icons.INFO} Returning to menu...", Colors.INFO))
                return "back"
            print(colorize(f"  {Icons.CROSS} Path cannot be empty", Colors.ERROR))
            continue
        
        path = Path(value).expanduser()
        
        if must_exist and not path.exists():
            print(colorize(f"  {Icons.CROSS} Path not found: {path}", Colors.ERROR))
            print(colorize(f"  {Icons.INFO} Check the path and try again (or type 'back')", Colors.DIM))
            continue
        
        return str(path)


def prompt_confirmation(message: str) -> bool:
    """Enhanced confirmation prompt"""
    response = prompt_input(f"{message}", required=False).lower()
    return response in {'y', 'yes'}


def pause(message: str = "Press Enter to continue..."):
    """Enhanced pause"""
    input(colorize(f"\n  {Icons.INFO} {message}", Colors.DIM))


# ============================================================================
# Utility Functions
# ============================================================================

def list_artifact_dirs(root: Path) -> List[Path]:
    """List artifacts in directory"""
    if not root.exists():
        return []
    try:
        items = [p for p in root.iterdir() if p.is_dir() or p.is_file()]
        return sorted(items, key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return []


def human_size(num_bytes: float) -> str:
    """Convert bytes to human-readable size"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024 or unit == "TB":
            return f"{num_bytes:0.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} B"


# ============================================================================
# Main Menu
# ============================================================================

MENU = {
    "0": {
        "title": "System Dashboard",
        "icon": Icons.CHART,
        "handler": draw_dashboard,
        "color": Colors.INFO
    },
    "1": {
        "title": "Infrastructure Self-Test",
        "icon": Icons.GEAR,
        "handler": workflow_infrastructure,
        "color": Colors.SECONDARY
    },
    "2": {
        "title": "Create Golden Baseline",
        "icon": Icons.LOCK,
        "handler": workflow_create_baseline,
        "color": Colors.SUCCESS
    },
    "3": {
        "title": "Run Guided Detection",
        "icon": Icons.SEARCH,
        "handler": workflow_basic_detection,
        "color": Colors.PRIMARY
    },
    "4": {
        "title": "Quick Detection Scan",
        "icon": Icons.ROCKET,
        "handler": workflow_quick_detection,
        "color": Colors.WARNING
    },
    "5": {
        "title": "Browse Detection Reports",
        "icon": Icons.FILE,
        "handler": workflow_report_viewer,
        "color": Colors.INFO
    },
    "6": {
        "title": "Manage Artifacts",
        "icon": Icons.FOLDER,
        "handler": workflow_cleanup,
        "color": Colors.SECONDARY
    },
}


def render_menu():
    """Render main menu"""
    clear_screen()
    draw_logo()
    
    draw_banner(
        "Interactive Console",
        "Hardware Security Analysis Platform",
        Icons.SHIELD
    )
    
    print(colorize("Choose a workflow:\n", Colors.INFO + Colors.BRIGHT))
    
    for key, meta in MENU.items():
        icon = meta['icon']
        title = truncate_text(meta['title'], 44)
        color = meta.get('color', Colors.INFO)
        
        key_display = colorize(f"[{key}]", Colors.PRIMARY + Colors.BRIGHT)
        icon_display = colorize(icon, color)
        title_display = colorize(title, Colors.BRIGHT)
        
        print(f"  {pad_text(key_display, 6)} {pad_text(icon_display, 3)} {title_display}")
    
    print(f"\n  {colorize('[q]', Colors.ERROR + Colors.BRIGHT)} {colorize(Icons.CROSS, Colors.ERROR)} {colorize('Exit', Colors.BRIGHT)}")
    print()


def main():
    """Main application loop"""
    try:
        while True:
            render_menu()
            
            choice = prompt_input(
                f"{Icons.ARROW_RIGHT} Select option",
                required=False
            ).lower()
            
            if choice in {'q', 'quit', 'exit'}:
                clear_screen()
                print()
                print(colorize(f"  {Icons.CHECKMARK} Thank you for using HTTrojan Detection!", Colors.SUCCESS + Colors.BRIGHT))
                print(colorize(f"  {Icons.SHIELD} Stay secure!", Colors.PRIMARY))
                print()
                return
            
            action = MENU.get(choice)
            if not action:
                print(colorize(f"  {Icons.CROSS} Invalid option. Try again.", Colors.ERROR))
                time.sleep(1)
                continue
            
            try:
                action['handler']()
            except KeyboardInterrupt:
                print()
                print(colorize(f"\n  {Icons.INFO} Operation cancelled. Returning to menu...", Colors.WARNING))
                time.sleep(1)
            except Exception as exc:
                print()
                print(colorize(f"\n  {Icons.CROSS} Unexpected error: {exc}", Colors.ERROR))
                pause("Press Enter to return to menu...")
    
    except KeyboardInterrupt:
        print()
        print(colorize(f"\n  {Icons.INFO} Interrupted by user. Goodbye!", Colors.WARNING))
        return
    except Exception as exc:
        print()
        print(colorize(f"\n  {Icons.CROSS} Fatal error: {exc}", Colors.ERROR))
        return


if __name__ == "__main__":
    main()
