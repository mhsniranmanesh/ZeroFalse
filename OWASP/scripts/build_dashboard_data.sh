#!/bin/bash
# Populate dashboard-data/ from the per-alert evaluation CSVs in results/.
# Layout expected by streamlit_dashboard.py:
#   dashboard-data/<prompt_version>_owasp_<CWE>_<model>/evaluation_<CWE>_<model>.csv
# Run from the OWASP/ directory.

set -e
RESULTS_DIR="${RESULTS_DIR:-results}"
DASHBOARD_DIR="${DASHBOARD_DIR:-dashboard-data}"

for csv in "$RESULTS_DIR"/*/CWE-*/*/evaluation_*.csv; do
    model_dir=$(dirname "$csv")
    model=$(basename "$model_dir")
    cwe=$(basename "$(dirname "$model_dir")")
    version=$(basename "$(dirname "$(dirname "$model_dir")")")
    target="$DASHBOARD_DIR/${version}_owasp_${cwe}_${model}"
    mkdir -p "$target"
    cp "$csv" "$target/"
done

echo "Dashboard data written to $DASHBOARD_DIR/"
