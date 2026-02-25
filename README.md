# RDS Analyzer

[![CI](https://github.com/openshift-kni/rds-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/openshift-kni/rds-analyzer/actions/workflows/ci.yml)

A rule-based analyzer for OpenShift cluster comparisons. This tool evaluates [kube-compare](https://github.com/openshift/kube-compare) JSON reports against a configurable set of rules to determine the impact of configuration deviations from the reference configuration.

## Overview

- Evaluates configuration differences against YAML-defined rules.
- Determines impact levels: Impacting, Not Impacting, Not a Deviation, or Needs Review.
- Supports version-specific rule evaluation for different OCP versions.
- Generates text or HTML reports with detailed analysis.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/openshift-kni/rds-analyzer.git
cd rds-analyzer

# Build
make build

# Or install directly to GOBIN
make install
```

### Binary Releases

Download pre-built binaries from the [Releases](https://github.com/openshift-kni/rds-analyzer/releases) page.

### Container Image

Container images are available on Quay.io:

```bash
podman pull quay.io/rhsysdeseng/rds-analyzer:latest
```

## Usage

### Basic Usage

```bash
# Analyze from stdin with text output and using custom rules file
cat results.json | rds-analyzer -r /path/to/custom-rules.yaml

# Analyze from file with HTML output (using default rules file ./rules.yaml)
rds-analyzer -i results.json -o html > report.html

# Analyze using 4.19 OCP release for rules evaluation (using default rules file ./rules.yaml)
rds-analyzer -i results.json -t 4.19

# Use custom rules file and input file
rds-analyzer -i results.json -r /path/to/rules.yaml

# Generate reporting format
rds-analyzer -i results.json -m reporting
```

### Container Usage

```bash
# Analyze from file
podman run --rm -v $(pwd):/data:Z quay.io/rhsysdeseng/rds-analyzer:latest \
  -i /data/results.json -r /data/rules.yaml

# Generate HTML report
podman run --rm -v $(pwd):/data:Z quay.io/rhsysdeseng/rds-analyzer:latest \
  -i /data/results.json -r /data/rules.yaml -o html > report.html

# Analyze from stdin
cat results.json | podman run --rm -i -v $(pwd):/data:Z quay.io/rhsysdeseng/rds-analyzer:latest \
  -r /data/rules.yaml
```

### Command-Line Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Input file path (reads from stdin if not specified) | stdin |
| `--output` | `-o` | Output format: `text` or `html` | `text` |
| `--output-mode` | `-m` | Output mode: `simple` or `reporting` | `simple` |
| `--target` | `-t` | Target OCP version for rules evaluation (e.g., 4.19) | highest in rules |
| `--rules` | `-r` | Path to rules.yaml file | `./rules.yaml` |
| `--version` | `-v` | Show version information | - |
| `--help` | `-h` | Show help | - |

## Output Modes

| Mode | Description |
|------|-------------|
| `simple` | Default output showing all deviations and impacts |
| `reporting` | Structured output optimized for reporting workflows and consumption by LLMs |

## Impact Levels

| Level | Symbol | Description |
|-------|--------|-------------|
| Impacting | Red | Deviation must be corrected |
| Not Impacting | Yellow | Deviation requires attention (RDS expansion) or support exception |
| Not a Deviation | Green | Configuration is compliant |
| Needs Review | Gray | No matching rule; requires review by the Telco Team |

## Development

### Building

```bash
make build          # Build binary release for current platform
make image-build    # Build for container release for current platform
```

## Contributing

See [AGENTS.md](AGENTS.md) for development guidelines and code conventions.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
