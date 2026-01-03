# Example Bitstreams

The `example/` directory contains curated golden and Trojanized bitstreams for multiple hardware designs. Use these files for regression testing, demonstrations, and validating changes to the detection stack.

## Directory Layout
Each subdirectory focuses on a specific design or subsystem:

| Subdirectory | Golden File | Trojan File(s) | Notes |
|--------------|-------------|----------------|-------|
| `aes/` | `aes_encrypt_golden.bit` | `aes_encrypt_trojan.bit` | AES encryption core used to verify baseline vs Trojan detection end-to-end. |
| `alu/` | `alu_golden.bit` | `alu_trojan.bit` | Arithmetic logic unit showcasing control-flow tampering. |
| `cach/` | `cache_controller_golden.bit` | `cache_controller_trojan.bit` | Cache controller frames with altered replacement logic. |
| `cpu_branch/` | `cpu_branch_predictor_golden.bit` | `cpu_branch_predictor_trojan.bit` | Branch predictor example highlighting subtle control anomalies. |
| `crypto/` | `crypto_accelerator_golden.bit` | `crypto_accelerator_trojan_type1.bit` | Crypto accelerator variant demonstrating partial-frame manipulation. |
| `mem/` | `mem_controller_golden.bit` | `mem_controller_trojan.bit` | Memory controller configuration changes affecting arbitration. |
| `network/` | `network_router_golden.bit` | `network_router_trojan.bit` | Network-on-chip router with injected covert channel. |
| `uart/` | `uart_tx_golden.bit` | `uart_tx_trojan.bit` | UART transmitter showing small payload modifications. |

## Usage Tips
1. **Baseline Creation** – Point `--create-baseline` at the golden file to generate a trusted reference for that design.
2. **Detection Runs** – Compare the generated baseline (or original golden `.bit`) against the Trojan file to confirm anomalies are detected.
3. **Regression Suites** – Run detections across multiple subdirectories after modifying parser/detector logic to ensure no unintended regressions.

## Naming Conventions
- Golden files consistently include `_golden.bit` to make CLI commands predictable.
- Trojan files include `_trojan.bit` (or `_trojan_typeX.bit`) to denote the malicious variant.

These fixtures allow you to replicate typical workflows quickly and provide concrete evidence of algorithmic improvements.