# Full Workflow: Cluster Compare to Deviation Report and Jiras

This document walks through the complete workflow from having cluster data to producing deviation reportings and using them to open and track Jira tickets. It assumes you have already collected a must-gather from your OpenShift cluster.

## Overview

1. **Prerequisites** — Must-gather collected.
2. **Install the cluster compare plugin** — So you can compare cluster CRs to a reference.
3. **Obtain the telco reference** — Reference configuration to compare against.
4. **Run the comparison and produce deviation reportings** — JSON from cluster compare → RDS Analyzer → text/HTML report.
5. **Use the report to open Jiras** — Turn deviations into tracked issues.

---

## 1. Prerequisites: Must-Gather Collected

This workflow assumes you have already run a **must-gather** on the cluster you want to analyze. Must-gather captures cluster state (resource definitions, logs, etc.) needed for comparison.

- **OpenShift / OKD:** Use `oc adm must-gather` or `oc adm must-gather --all-images` and, if required, the appropriate must-gather image for your product.  
  See the official documentation for your version, for example: [Gathering data about your cluster](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/support/gathering-cluster-data) (Red Hat) or the [must-gather repository](https://github.com/openshift/must-gather).
- Ensure the must-gather output is available on the machine where you will run the cluster compare plugin and RDS Analyzer.

---

## 2. Install the Cluster Compare Plugin

You need the **cluster compare** (kube-compare) plugin to compare your cluster’s configuration against a reference and produce the JSON report that RDS Analyzer consumes.

- **Install and usage:** Follow the official documentation for your environment:
  - [Installing the cluster-compare plugin](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/scalability_and_performance/comparing-cluster-configurations#installing-cluster-compare_installing-cluster-compare-plugin).
  - [kube-compare](https://github.com/openshift/kube-compare) — upstream plugin and usage.
- Confirm you can run the plugin and that it produces JSON output (e.g. `--output json` or equivalent as per the plugin’s docs).

---

## 3. Grab the Telco Reference

To compare your cluster against the **telco reference** (reference configuration), you must obtain and use the correct reference data as expected by the cluster compare plugin.

- **Where to get it and how to use it:** Refer to the **official documentation** for your product or project that describes:
  - Where the telco reference is published or how to generate it.
  - How to point the cluster compare plugin at this reference (paths, env vars, or flags).
- Use that reference when running the cluster compare step below.

---

## 4. Run the Tool with the Option to Output Deviation Reportings

### 4.1 Run cluster compare

Using the cluster compare plugin, run a comparison of your cluster (e.g. using the live cluster) against the telco reference, and **output the result as JSON**. Exact command depends on the plugin; typically something like:

```bash
# Example (adapt to your plugin’s actual CLI and paths)
export KUBECTL_EXTERNAL_DIFF="diff --color -N -y"
export KUBECONFIG=~/.kube/kubeadmin 
oc cluster-compare -r /path/to/the/metadata.yaml >> comparison-results.json
```

Using the cluster compare plugin, run a comparison of your cluster (e.g. using the must-gather data) against the telco reference, and **output the result as JSON**. Exact command depends on the plugin; typically something like:

```bash
# Example (adapt to your plugin’s actual CLI and paths)
export KUBECTL_EXTERNAL_DIFF="diff --color -N -y" 
oc cluster-compare -r /path/to/the/metadata.yaml -f "must-gather*/*/cluster-scoped-resources","must-gather*/*/namespaces" -R >> comparison-results.json
```

Refer to the cluster compare / kube-compare official docs for the exact command and options for your setup.

### 4.2 Run RDS Analyzer on the JSON

Feed the comparison JSON into RDS Analyzer to get a **deviation report** (text or HTML).

**Text report (terminal):**

```bash
rds-analyzer -i comparison-results.json
```

**HTML report (for sharing or printing):**

```bash
rds-analyzer -i comparison-results.json -o html > deviation-report.html
```

**With a specific OCP version and custom rules:**

```bash
rds-analyzer -i comparison-results.json -o html -t 4.21 -r /path/to/rules.yaml > deviation-report.html
```

The output is your **deviation report**: it lists differences, classifies them by impact (Impacting, Not Impacting, Not a Deviation, Needs Review), and ties them to rules. Use this report in the next step.

---

## 5. Use the Deviation Report to Open Jiras

The deviation report (text or HTML) is the source of truth for what needs to be fixed or reviewed. Use it to create and link Jira tickets (or issues in your own tracker).

- **Impacting** — Create Jira tickets for each item (or per CR/rule as your process dictates). These are deviations that must be corrected.
- **Not Impacting** — Decide per your process whether to create Jiras for support exceptions or RDS expansion; the report gives you the list.
- **Needs Review** — Create Jiras or tasks for manual review where no rule matched.
- **Not a Deviation** — No action required; useful for audit trail.

**Suggested workflow:**

1. Open the HTML report (or use the text output) and go through each section.
2. For each deviation you want to track, create a Jira issue and copy the relevant rule ID, CR name, description, and impact from the report into the ticket.
3. Optionally, attach the HTML report to an epic or parent Jira so all deviations are traceable.

This keeps remediation tracked and linked to the same deviation report you produced from cluster compare and RDS Analyzer.

---

## Summary

| Step | Action |
|------|--------|
| 1 | Ensure must-gather has been collected from the cluster. |
| 2 | Install the cluster compare plugin (see official docs). |
| 3 | Obtain the telco reference and configure the plugin to use it (see official docs). |
| 4 | Run cluster compare with JSON output; run `rds-analyzer` to produce the deviation report (text or HTML). |
| 5 | Use the deviation report to open and track Jiras (or other issues) for remediation and review. |

For installation and CLI options of RDS Analyzer, see the [README](../README.md). For a short map of all documentation, see [USAGE.md](../USAGE.md).
