#!/bin/bash

# Configuration - Update these paths according to your setup
# Base directory of all CWE folders (CodeQL queries)
CWE_DIR="${CODEQL_CWE_DIR:-../codeql/qlpacks/codeql/java-queries/1.4.0/Security/CWE}"
# CodeQL executable path
CODEQL_PATH="${CODEQL_PATH:-../codeql/codeql}"
# Output directory
OUTPUT_DIR="${OUTPUT_DIR:-../output}"
# Create output directory
mkdir -p "$OUTPUT_DIR/owasp-benchmark"

# Check if CodeQL path exists
if [ ! -f "$CODEQL_PATH" ]; then
    echo "Error: CodeQL executable not found at $CODEQL_PATH"
    echo "Please set the CODEQL_PATH environment variable or update the default path in the script"
    exit 1
fi

# Check if CWE directory exists
if [ ! -d "$CWE_DIR" ]; then
    echo "Error: CWE directory not found at $CWE_DIR"
    echo "Please set the CODEQL_CWE_DIR environment variable or update the default path in the script"
    exit 1
fi

echo "Starting CWE analysis..."
echo "CWE Directory: $CWE_DIR"
echo "CodeQL Path: $CODEQL_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo ""

# Loop through all subdirectories (each CWE)
for cwe_path in "$CWE_DIR"/*; do
  if [ -d "$cwe_path" ]; then
    cwe_name=$(basename "$cwe_path")
    echo "Analyzing $cwe_name..."

    $CODEQL_PATH database analyze codeql-dbs/owasp-benchmark "$cwe_path" \
      --format=sarif-latest \
      --output="$OUTPUT_DIR/owasp-benchmark/owasp-benchmark-$cwe_name.sarif" \
      --verbosity=progress
  fi
done

echo ""
echo "Analysis completed. Results saved to: $OUTPUT_DIR/owasp-benchmark/"