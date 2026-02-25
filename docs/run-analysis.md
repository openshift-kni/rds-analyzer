# Run RDS Analysis

To run RDS Analyzer, provide kube-compare JSON (from file or stdin) and optional flags:

```bash
# From file, text output (default)
rds-analyzer -i comparison-results.json

# HTML report
rds-analyzer -i comparison-results.json -o html > report.html

# With target OCP version and custom rules
rds-analyzer -i comparison-results.json -t 4.21 -r /path/to/rules.yaml
```

For the **full workflow** from must-gather and cluster compare through to deviation reportings and Jiras, see [full-workflow.md](full-workflow.md).

For all options and rules format, see the [README](../README.md).
