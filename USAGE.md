# RDS Analyzer — Usage Guide

This document explains how documentation is organized and where to find step-by-step instructions.

## Documentation Overview

### Getting started: README

**Initial tool documentation lives in the project's [README](README.md).** The README is intended for people unfamiliar with the project and covers:

- **Overview** — What RDS Analyzer does (evaluate kube-compare JSON reports against rules).
- **Installation** — Building from source or using the binary so you can get the tool up and running quickly.
- **Basic usage** — Running the analyzer with input file or stdin, and generating text or HTML output.
- **Command-line options** — All flags (`--input`, `--output`, `--target`, `--rules`, etc.).
- **Configuration** — Rules file format, condition types, matching, and version-specific impacts.
- **Output formats** — Text (terminal) and HTML report behavior.
- **Impact levels** — Impacting, Not Impacting, Not a Deviation, Needs Review.
- **Development** — Build, test, lint, and project structure.

Start there to install the tool and run your first analysis.

### Full workflow: docs/

A **more thorough, end-to-end example** is in the docs folder. It walks through the complete process from having cluster data to producing deviation reports and using them to drive remediation.

| Document | Purpose |
|----------|--------|
| [docs/full-workflow.md](docs/full-workflow.md) | Full workflow: must-gather → cluster compare plugin → telco reference → run RDS Analyzer for deviation reporting → use the report to open and track issues. |

That doc assumes a must-gather has been collected and covers:

1. **Prerequisites** — Must-gather collected from the cluster.
2. **Install the cluster compare plugin** — With pointers to the official cluster compare / kube-compare documentation.
3. **Obtain the telco reference** — Where and how to get the reference configuration (official docs).
4. **Run the tool** — Running the comparison with the option to output deviation reportings (JSON in → text/HTML out).
5. **Use the report** — How to use the deviation report to open and track Jira tickets (or your issue tracker).

## Quick reference

- **New to the project?** → [README](README.md)  
- **End-to-end workflow (must-gather → cluster compare → telco reference → deviation report → drive remediation)?** → [docs/full-workflow.md](docs/full-workflow.md)  
- **Rule engine and development details?** → [AGENTS.md](AGENTS.md)
