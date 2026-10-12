#!/usr/bin/env python3
"""
SARIF Code Context Extractor

This script processes SARIF files to extract vulnerability code context.
It uses the MethodLocator tool to determine method boundaries and extracts
code snippets along with intermediate context between data flow steps.
"""

import json
import os
import subprocess
import sys
import shutil
from typing import Dict, Tuple
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class MethodInfo:
    """Represents information about a method from MethodLocator"""
    def __init__(self, found: bool, method_name: str = "", start_line: int = 0, 
                 end_line: int = 0, method_signature: str = "", method_body: str = ""):
        self.found = found
        self.method_name = method_name
        self.start_line = start_line
        self.end_line = end_line
        self.method_signature = method_signature
        self.method_body = method_body


class CodeExtractor:
    """Main class for extracting code context from SARIF files"""
    
    def __init__(self, sarif_file: str, source_root: str, method_finder_path: str, output_dir: str = "vulnerability_outputs", max_workers: int = 4):
        self.sarif_file = sarif_file
        self.source_root = source_root
        self.method_finder_path = method_finder_path
        self.output_dir = output_dir
        self.max_workers = max_workers
        
        # Thread lock for safe printing
        self.print_lock = threading.Lock()
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Load SARIF data
        with open(sarif_file, 'r') as f:
            self.sarif_data = json.load(f)
    
    def thread_safe_print(self, message: str):
        """Thread-safe printing function"""
        with self.print_lock:
            print(message)
    
    def resolve_uri(self, uri: str, uri_base_id: str = None) -> str:
        """Resolve relative URI to absolute path"""
        if uri_base_id == "%SRCROOT%":
            return os.path.join(self.source_root, uri)
        elif os.path.isabs(uri):
            return uri
        else:
            return os.path.join(self.source_root, uri)
    
    def get_method_info(self, file_path: str, line_number: int) -> MethodInfo:
        """Use MethodLocator to get method information for a specific line"""
        try:
            # Convert to absolute paths to ensure Maven can find everything
            abs_method_finder_path = os.path.abspath(self.method_finder_path)
            abs_pom_path = os.path.join(abs_method_finder_path, "pom.xml")
            
            # Use the exact same command format as in command.txt
            cmd = [
                "mvn", "-q", "-f", abs_pom_path,
                "exec:java", 
                f"-Dexec.mainClass=MethodLocator", 
                f"-Dexec.args={file_path} {line_number}"
            ]
            
            # Run the command and capture output, redirecting stderr to devnull
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            
            if result.returncode == 0:
                try:
                    output = result.stdout.strip()
                    
                    # Filter out Maven warnings that pollute the JSON output
                    lines = output.split('\n')
                    json_lines = []
                    json_started = False
                    
                    for line in lines:
                        # Skip Maven warning lines
                        if (line.startswith('WARNING:') or 
                            line.startswith('[INFO]') or 
                            line.startswith('[WARNING]') or
                            'sun.misc.Unsafe' in line or
                            'AbstractFuture$UnsafeAtomicHelper' in line or
                            'will be removed in a future release' in line):
                            continue
                        
                        # Look for JSON start
                        if line.strip().startswith('{'):
                            json_started = True
                        
                        if json_started:
                            json_lines.append(line)
                    
                    # Join the cleaned JSON lines
                    clean_output = '\n'.join(json_lines).strip()
                    
                    if not clean_output:
                        return MethodInfo(found=False)
                    
                    # Parse the cleaned JSON
                    method_data = json.loads(clean_output)
                    
                    if method_data.get("found", False):
                        return MethodInfo(
                            found=True,
                            method_name=method_data.get("methodName", ""),
                            start_line=method_data.get("startLine", 0),
                            end_line=method_data.get("endLine", 0),
                            method_signature=method_data.get("methodSignature", ""),
                            method_body=method_data.get("methodBody", "")
                        )
                    else:
                        return MethodInfo(found=False)
                except json.JSONDecodeError as e:
                    # Show the problematic output for debugging
                    self.thread_safe_print(f"Warning: Could not parse MethodLocator JSON for {file_path}:{line_number}")
                    self.thread_safe_print(f"  JSON Error: {str(e)}")
                    self.thread_safe_print(f"  Raw output: {repr(clean_output[:200])}")  # Show first 200 chars
                    return MethodInfo(found=False)
            else:
                self.thread_safe_print(f"Warning: MethodLocator command failed for {file_path}:{line_number}")
                self.thread_safe_print(f"  Return code: {result.returncode}")
                if result.stdout:
                    self.thread_safe_print(f"  Stdout: {result.stdout[:200]}")
                return MethodInfo(found=False)
                
        except Exception as e:
            self.thread_safe_print(f"Error running MethodLocator for {file_path}:{line_number}: {e}")
            return MethodInfo(found=False)
    
    def extract_code_snippet(self, file_path: str, line: int, context_lines: int = 0) -> str:
        """Extract the exact line for data flow step (no context)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            if line <= 0 or line > len(lines):
                return f"Line {line} is out of range (file has {len(lines)} lines)"
            
            # Only show the exact line
            line_content = lines[line - 1].rstrip()
            return f">>> {line:4d}: {line_content}"
            
        except Exception as e:
            return f"Error reading file {file_path}: {e}"
    
    def extract_intermediate_code(self, file_path: str, start_line: int, end_line: int) -> str:
        """Extract all code between two lines in the same file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Ensure we don't go out of bounds
            start_idx = max(0, start_line - 1)
            end_idx = min(len(lines), end_line)
            
            intermediate_lines = []
            for i in range(start_idx, end_idx):
                line_num = i + 1
                intermediate_lines.append(f"    {line_num:4d}: {lines[i].rstrip()}")
            
            return "\n".join(intermediate_lines)
            
        except Exception as e:
            return f"Error reading intermediate code from {file_path}: {e}"
    
    def process_thread_flow(self, thread_flow: Dict, vulnerability_id: str) -> str:
        """Process a single thread flow and extract code context"""
        output_lines = []
        locations = thread_flow.get("locations", [])
        
        if not locations:
            return "No locations found in thread flow"
        
        for i, location_data in enumerate(locations):
            location = location_data.get("location", {})
            physical_location = location.get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            region = physical_location.get("region", {})
            
            uri = artifact_location.get("uri", "")
            uri_base_id = artifact_location.get("uriBaseId", "")
            line_number = region.get("startLine", 0)
            column_number = region.get("startColumn", 0)
            
            if not uri or not line_number:
                output_lines.append(f"### Data Flow Step {i+1}: Invalid location data")
                continue
            
            # Resolve file path
            file_path = self.resolve_uri(uri, uri_base_id)
            
            output_lines.append(f"### Data Flow Step {i+1}: {uri}, Line {line_number}, Column {column_number}")
            output_lines.append(f"File: {file_path}")
            
            # Check if file exists
            if not os.path.exists(file_path):
                output_lines.append(f"Warning: Source file not found: {file_path}")
                output_lines.append("")
                continue
            
            # Extract code snippet for this step
            code_snippet = self.extract_code_snippet(file_path, line_number)
            output_lines.append("```java")
            output_lines.append(code_snippet)
            output_lines.append("```")
            output_lines.append("")
            
            # Check if we need intermediate code
            if i < len(locations) - 1:
                next_location_data = locations[i + 1]
                next_location = next_location_data.get("location", {})
                next_physical_location = next_location.get("physicalLocation", {})
                next_artifact_location = next_physical_location.get("artifactLocation", {})
                next_region = next_physical_location.get("region", {})
                
                next_uri = next_artifact_location.get("uri", "")
                next_uri_base_id = next_artifact_location.get("uriBaseId", "")
                next_line_number = next_region.get("startLine", 0)
                
                next_file_path = self.resolve_uri(next_uri, next_uri_base_id)
                
                # Check if both locations are in the same file
                if file_path == next_file_path and os.path.exists(file_path):
                    # Get method info for both locations
                    current_method = self.get_method_info(file_path, line_number)
                    next_method = self.get_method_info(next_file_path, next_line_number)
                    
                    # Check if both are in the same method
                    if (current_method.found and next_method.found and 
                        current_method.method_name == next_method.method_name and
                        current_method.method_signature == next_method.method_signature):
                        
                        # Extract intermediate code
                        start_extraction = line_number + 1
                        end_extraction = next_line_number - 1
                        
                        if end_extraction >= start_extraction:
                            output_lines.append(f"**Intermediate code within method `{current_method.method_name}` (lines {start_extraction}-{end_extraction}):**")
                            intermediate_code = self.extract_intermediate_code(file_path, start_extraction, end_extraction + 1)
                            output_lines.append("```java")
                            output_lines.append(intermediate_code)
                            output_lines.append("```")
                            output_lines.append("")
        
        return "\n".join(output_lines)
    
    def process_single_vulnerability(self, result_data: Tuple[int, Dict]) -> str:
        """Process a single vulnerability result and return the filename"""
        i, result = result_data
        rule_id = result.get("ruleId", f"rule_{i}")
        message = result.get("message", {}).get("text", "No message")
        
        # Create output for this vulnerability
        output_lines = []
        output_lines.append(f"# Vulnerability: {rule_id}")
        output_lines.append(f"## Message: {message}")
        output_lines.append("")
        
        # Process code flows
        code_flows = result.get("codeFlows", [])
        
        if not code_flows:
            output_lines.append("No code flows found for this vulnerability.")
        else:
            for j, code_flow in enumerate(code_flows):
                output_lines.append(f"## Code Flow {j+1}")
                output_lines.append("")
                
                thread_flows = code_flow.get("threadFlows", [])
                for k, thread_flow in enumerate(thread_flows):
                    output_lines.append(f"### Thread Flow {k+1}")
                    output_lines.append("")
                    
                    thread_output = self.process_thread_flow(thread_flow, f"{rule_id}_{i}")
                    output_lines.append(thread_output)
        
        # Write to file
        filename = f"vulnerability_{rule_id}_{i+1}.txt"
        # Sanitize filename
        filename = filename.replace("/", "_").replace("\\", "_")
        output_file = os.path.join(self.output_dir, filename)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(output_lines))
        
        return filename
    
    def process_sarif(self):
        """Process the SARIF file and extract all vulnerabilities using multithreading"""
        runs = self.sarif_data.get("runs", [])
        
        if not runs:
            print("No runs found in SARIF file")
            return
        
        run = runs[0]  # Assuming single run
        results = run.get("results", [])
        
        print(f"Processing {len(results)} vulnerability results using {self.max_workers} threads...")
        
        # Prepare data for multithreading - enumerate results to maintain index
        result_data = list(enumerate(results))
        
        completed_count = 0
        
        # Process vulnerabilities in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all vulnerability processing tasks
            future_to_index = {
                executor.submit(self.process_single_vulnerability, data): data[0] 
                for data in result_data
            }
            
            # Process completed tasks as they finish
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    filename = future.result()
                    completed_count += 1
                    self.thread_safe_print(f"Completed vulnerability {completed_count}/{len(results)}: {filename}")
                except Exception as e:
                    self.thread_safe_print(f"Error processing vulnerability {index + 1}: {e}")
        
        print(f"\nProcessing complete! {completed_count}/{len(results)} vulnerabilities processed successfully.")


def process_single_project(sarif_file: str, project_source: str, method_finder: str, output_dir: str, max_workers: int):
    """Process a single project"""
    if not os.path.exists(sarif_file):
        print(f"Error: SARIF file not found: {sarif_file}")
        return False
    
    if not os.path.exists(project_source):
        print(f"Error: Source root not found: {project_source}")
        return False
    
    extractor = CodeExtractor(sarif_file, project_source, method_finder, output_dir, max_workers)
    extractor.process_sarif()
    
    print(f"\nCheck the '{output_dir}' directory for results.")
    return True


def process_projects_directory(codeql_dbs_dir: str, sarif_files_dir: str, method_finder: str, max_workers: int):
    """Process all projects in codeql-dbs directory"""
    if not os.path.exists(codeql_dbs_dir):
        print(f"Error: CodeQL databases directory not found: {codeql_dbs_dir}")
        return
    
    if not os.path.exists(sarif_files_dir):
        print(f"Error: SARIF files directory not found: {sarif_files_dir}")
        return
    
    # Find all project directories in codeql-dbs
    project_dirs = []
    for item in os.listdir(codeql_dbs_dir):
        item_path = os.path.join(codeql_dbs_dir, item)
        if os.path.isdir(item_path):
            project_dirs.append(item)
    
    if not project_dirs:
        print(f"No project directories found in: {codeql_dbs_dir}")
        return
    
    print(f"Found {len(project_dirs)} project directories:")
    for project_dir in project_dirs:
        print(f"  - {project_dir}")
    print()
    
    successful_count = 0
    
    for project_dir in project_dirs:
        print(f"\n{'='*60}")
        print(f"Processing project: {project_dir}")
        print(f"{'='*60}")
        
        # Construct paths
        project_path = os.path.join(codeql_dbs_dir, project_dir)
        src_zip_path = os.path.join(project_path, "src.zip")
        sarif_file = os.path.join(sarif_files_dir, f"{project_dir}.sarif")
        
        # Check if SARIF file exists
        if not os.path.exists(sarif_file):
            print(f"Warning: SARIF file not found: {sarif_file}")
            continue
        
        # Check if src.zip exists
        if not os.path.exists(src_zip_path):
            print(f"Warning: src.zip not found in project directory: {src_zip_path}")
            continue
        
        # Unzip src.zip in the project directory
        print(f"  Unzipping src.zip in {project_path}...")
        try:
            result = subprocess.run(
                ["unzip", "-o", "src.zip"], 
                cwd=project_path, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            if result.returncode != 0:
                print(f"Warning: Failed to unzip src.zip for {project_dir}")
                print(f"  Error: {result.stderr}")
                continue
        except Exception as e:
            print(f"Warning: Exception while unzipping src.zip for {project_dir}: {e}")
            continue
        
        # Construct the expected source path after unzipping
        # Structure: {project_dir}/root/cwe-bench-java/project-sources/{project_name}/
        project_source_path = os.path.join(project_path, "root", "cwe-bench-java", "project-sources", project_dir)
        
        if not os.path.exists(project_source_path):
            print(f"  Could not find valid source directory for {project_dir}")
            continue
        
        # Generate output directory name
        base_output_dir = "code-contexts-output"
        os.makedirs(base_output_dir, exist_ok=True)
        output_dir = os.path.join(base_output_dir, project_dir)
        
        print(f"  SARIF file: {sarif_file}")
        print(f"  Source root: {project_source_path}")
        print(f"  Output directory: {output_dir}")
        
        # Process the project
        success = process_single_project(sarif_file, project_source_path, method_finder, output_dir, max_workers)
        
        # Clean up the unzipped root directory
        root_cleanup_path = os.path.join(project_path, "root")
        if os.path.exists(root_cleanup_path):
            print(f"  Cleaning up unzipped directory: {root_cleanup_path}")
            try:
                shutil.rmtree(root_cleanup_path)
                print(f"  Successfully removed {root_cleanup_path}")
            except Exception as e:
                print(f"  Warning: Could not remove {root_cleanup_path}: {e}")
        
        if success:
            successful_count += 1
    
    print(f"\n{'='*60}")
    print(f"Processing complete! {successful_count}/{len(project_dirs)} projects processed successfully.")


def main():
    parser = argparse.ArgumentParser(description="Extract vulnerability code context from SARIF files")
    parser.add_argument("sarif_file", nargs='?', help="Path to SARIF file (required if --codeql-dbs not used)")
    parser.add_argument("--project-source", help="Root directory of source code (required if --codeql-dbs not used)")
    parser.add_argument("--codeql-dbs", help="Directory containing CodeQL database projects (each with src.zip)")
    parser.add_argument("--sarif-files", help="Directory containing SARIF files (required when using --codeql-dbs)")
    parser.add_argument("--method-finder", default="MethodFinder", help="Path to MethodFinder project")
    parser.add_argument("--output-dir", default="vulnerability_outputs", help="Output directory for vulnerability files (ignored when using --codeql-dbs)")
    parser.add_argument("--max-workers", type=int, default=4, help="Maximum number of worker threads (default: 4)")
    
    args = parser.parse_args()
    
    # Check if we're processing multiple projects or a single project
    if args.codeql_dbs:
        # Process multiple projects automatically
        if not args.sarif_files:
            print("Error: --sarif-files is required when using --codeql-dbs")
            parser.print_help()
            sys.exit(1)
        
        if not os.path.exists(args.method_finder):
            print(f"Error: MethodFinder path not found: {args.method_finder}")
            sys.exit(1)
        
        if args.max_workers < 1:
            print(f"Error: max-workers must be at least 1")
            sys.exit(1)
        
        process_projects_directory(args.codeql_dbs, args.sarif_files, args.method_finder, args.max_workers)
    else:
        # Process single project (original behavior)
        if not args.sarif_file:
            print("Error: sarif_file is required when --codeql-dbs is not used")
            parser.print_help()
            sys.exit(1)
        
        if not args.project_source:
            print("Error: --project-source is required when --codeql-dbs is not used")
            parser.print_help()
            sys.exit(1)
        
        if not os.path.exists(args.method_finder):
            print(f"Error: MethodFinder path not found: {args.method_finder}")
            sys.exit(1)
        
        if args.max_workers < 1:
            print(f"Error: max-workers must be at least 1")
            sys.exit(1)
        
        process_single_project(args.sarif_file, args.project_source, args.method_finder, args.output_dir, args.max_workers)


if __name__ == "__main__":
    main()
