# Parser & Integration Layer

Located under `src/parser/` and `src/mapping/integration/`, this layer converts raw `.bit` files into structured representations that downstream detectors consume.

## Parser (`src/parser`)
- **`file_loader.py`** – Entry point exposing `Parser` with helper methods to load files, split headers, and iterate frames.
- **`header_lexer.py`** – Recognizes vendor-specific header markers and records metadata such as FPGA part, date, and configuration options.
- **`payload_lexer.py`** – Reads the frame payload bitstream, handles sync words, and exposes frame-level byte arrays.

### Key Responsibilities
1. Ensure `.bit` files are parsed deterministically regardless of extraneous padding or metadata.
2. Provide reusable iterators for frame payloads and header sections.
3. Surface validation errors early so suspect/golden comparisons do not operate on corrupt data.

## Integration (`src/mapping/integration`)
- **`bitstream_loader.py`** – Wraps the parser to produce `LoadedBitstream` objects with:
  - Indexed frames and addresses.
  - Statistics (frame count, word count, modified frame history if enabled).
  - Optional capture of write history for later semantic analysis.

### Configuration Options
- `capture_history` flag allows skipping history for faster/lighter scans.
- Uses device metadata from `configs/raw_data_path.py` and `data/raw_device/` to interpret addresses consistently with the analysis layer.

## Data Flow Summary
```
.bit file → Parser → frames + header metadata → BitstreamLoader → LoadedBitstream
```
These `LoadedBitstream` objects feed directly into the baseline builder and differential detector, ensuring a single source of truth for parsed data.

For details on how frames are mapped into FPGA resources, see `docs/analysis_toolkit.md`.