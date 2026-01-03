# HTTrojan Overview

HTTrojan is a Python-based framework for detecting malicious hardware Trojans hidden inside FPGA bitstreams. The project ingests a trusted "golden" configuration, compares it with a suspect design, and produces human-readable reports that highlight anomalies at the frame and tile level.

## Goals
- **Automate Trojan detection** by normalizing vendor `.bit` files and comparing their frame payloads.
- **Preserve engineer trust** by storing reproducible baselines with tile usage metadata.
- **Provide actionable insights** through textual, JSON, and Markdown reports plus an interactive console UI.

## High-Level Architecture
1. **Parser & Integration Layer** – Converts raw `.bit` payloads into structured frame objects (`src/parser`, `src/mapping/integration`).
2. **Detection Stack** – Builds golden baselines, runs differential analysis, and adds semantic reasoning (`src/detector`).
3. **Analysis Toolkit** – Maps frames to physical FPGA resources and applies risk heuristics (`analysis/*`).
4. **Reporting & UX** – Generates multi-format reports and exposes workflows via CLI scripts (`src/report`, `run_detection.py`, `interactive_cli.py`).

## Primary Entry Points
- `run_detection.py` – scriptable workflows for testing, baseline creation, and full/quick detection.
- `interactive_cli.py` – guided console dashboard for operators who prefer an interactive flow.

Use this document as the starting point before diving into subtopics covered in the rest of the `docs/` folder.