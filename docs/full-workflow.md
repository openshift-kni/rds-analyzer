# Full Workflow: Cluster Compare to Deviation Report and Jiras

This document walks through the complete workflow from having cluster data to producing deviation reportings and using them to open and track Jira tickets. It assumes you have already collected a must-gather from your OpenShift cluster or that you have access to the cluster directly (via a kubeconfig file).

## Overview

1. **Prerequisites** — Must-gather collected.
2. **Install the cluster compare plugin** — So you can compare cluster CRs to a reference.
3. **Obtain the telco reference** — Reference configuration to compare against.
4. **Run the comparison and produce deviation reportings** — JSON from cluster compare → RDS Analyzer → text/HTML report.
5. **Use the report to open Jiras** — Turn deviations into tracked issues.

---

## 1. Prerequisites: Must-Gather Collected

> **NOTE**: You can skip this step if you have access to the cluster (via a kubeconfig file) where you want to run the comparison.

This workflow assumes you have already run a **must-gather** on the cluster you want to analyze. Must-gather captures cluster state (resource definitions, logs, etc.) needed for comparison.

- **OpenShift / OKD:** Use `oc adm must-gather` or `oc adm must-gather --all-images` and, if required, the appropriate must-gather image for your product.  
  See the official documentation for your version, for example: [Gathering data about your cluster](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/support/gathering-cluster-data) (Red Hat) or the [must-gather repository](https://github.com/openshift/must-gather).
- Ensure the must-gather output is available on the machine where you will run the cluster compare plugin and RDS Analyzer.

---

## 2. Install the Cluster Compare Plugin

You need the **cluster compare** (kube-compare) plugin to compare your cluster’s configuration against a reference and produce the JSON report that RDS Analyzer consumes.

- **Install and usage:** Follow the official documentation for your environment:
  - [Installing the cluster-compare plugin](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/scalability_and_performance/comparing-cluster-configurations#installing-cluster-compare-plugin).
  - [kube-compare](https://github.com/openshift/kube-compare) — upstream plugin and usage.
- Confirm you can run the plugin and that it produces JSON output (e.g. `--output json` or equivalent as per the plugin’s docs).

---

## 3. Run cluster compare against the different telco references

The docs below are refences to the official docs on how to run cluster comparisons using the different references:

- [Telco RAN DU](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/scalability_and_performance/telco-ran-du-ref-design-specs#using-cluster-compare-telco-ran_ran-ref-design-crs)
- [Telco Core](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/scalability_and_performance/telco-core-ref-design-specs#using-cluster-compare-telco_core_telco-core)
- [Telco Hub](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/scalability_and_performance/telco-hub-ref-design-specs#telco-hub-rds-container_telco-hub)


## 4. Run RDS Analyzer on the JSON

Before running the RDS Analyzer we need two things:

1. The JSON output from the cluster compare tool (previous step - section 3).
2. The rules file (example can be found [here](../examples/example-ran-du-rules.yaml))

**Text report (terminal):**

```bash
rds-analyzer -i comparison-results.json -r example-ran-du-rules.yaml
```

**HTML report (for sharing or printing):**

```bash
rds-analyzer -i comparison-results.json -r example-ran-du-rules.yaml -o html > deviation-report.html
```

**Targetting a specific OCP version and rules file:**

```bash
rds-analyzer -i comparison-results.json -o html -t 4.21 -r /path/to/rules.yaml > deviation-report.html
```

The output is your **deviation report**: it lists differences, classifies them by impact (Impacting, Not Impacting, Not a Deviation, Needs Review), and ties them to rules.

---

## 5. Use the LLM-oriented Deviation Report

The RDS Analyzer tool has a `reporting` mode that changes the output formatting a bit to ease consumption by LLMs.

You can access this mode by running the tool as follows:

```bash
rds-analyzer -i comparison-results.json -r example-ran-du-rules.yaml -m reporting
```

The reporting mode divides the report in two sections:

1. Must be addressed: Information in this section requires the user to make changes.
2. Required guidance: Information in this section requires the user to interact with the telco team.

You can send this report with an LLM and have it do things for you. For example, you could open deviation jira tickets to the Telco Team automatically.

The deviation report (text or HTML) is the source of truth for what needs to be fixed or reviewed. Use it to create and link Jira tickets (or issues in your own tracker).