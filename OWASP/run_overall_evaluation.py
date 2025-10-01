#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import json
from pathlib import Path
from typing import List, Tuple, Dict

def extract_run_info_from_folder(folder_path: str) -> Tuple[str, str, str, str]:
    """
    Extract prompt_version, dataset, CWE, and model from folder name.
    Expected format: {promptversion}_{dataset}_{CWE}_{model}
    """
    folder_name = os.path.basename(folder_path)
    parts = folder_name.split('_')
    
    if len(parts) < 4:
        raise ValueError(f"Invalid folder format: {folder_name}. Expected: {{promptversion}}_{{dataset}}_{{CWE}}_{{model}}")
    
    # Parse the new format: {promptversion}_{dataset}_{CWE}_{model}
    prompt_version = parts[0]
    dataset = parts[1]
    
    # Find CWE part (should contain "CWE-")
    cwe_part = None
    model_parts = []
    
    for i, part in enumerate(parts[2:], 2):
        if part.startswith("CWE-"):
            cwe_part = part
            # Everything after CWE is model parts
            model_parts = parts[i+1:]
            break
    
    if not cwe_part:
        raise ValueError(f"No CWE found in folder name: {folder_name}")
    
    model = "_".join(model_parts)
    
    return prompt_version, dataset, cwe_part, model

def is_benchmark_file(filename: str) -> bool:
    """
    Check if a file is a benchmark test file (BenchmarkTest###).
    """
    return re.match(r'BenchmarkTest\d+', filename) is not None

def filter_benchmark_files(prompts_dir: str, responses_dir: str) -> Tuple[List[str], List[str]]:
    """
    Filter files to keep only benchmark test files.
    Returns lists of valid prompt and response files.
    """
    valid_prompts = []
    valid_responses = []
    
    # Get all prompt files
    if os.path.exists(prompts_dir):
        for filename in os.listdir(prompts_dir):
            if filename.endswith('.txt'):
                # Extract the base name without extension
                base_name = filename[:-4]  # Remove .txt
                
                # Check if it contains BenchmarkTest
                if is_benchmark_file(base_name):
                    valid_prompts.append(filename)
                else:
                    print(f"  Filtering out non-benchmark prompt: {filename}")
    
    # Get all response files
    if os.path.exists(responses_dir):
        for filename in os.listdir(responses_dir):
            if filename.endswith('.txt'):
                # Extract the base name without extension
                base_name = filename[:-4]  # Remove .txt
                
                # Check if it contains BenchmarkTest
                if is_benchmark_file(base_name):
                    valid_responses.append(filename)
                else:
                    print(f"  Filtering out non-benchmark response: {filename}")
    
    return valid_prompts, valid_responses

def remove_non_benchmark_files(prompts_dir: str, responses_dir: str) -> None:
    """
    Remove non-benchmark files from prompts and responses directories.
    """
    print("  Filtering files to keep only benchmark tests...")
    
    # Remove non-benchmark prompt files
    if os.path.exists(prompts_dir):
        for filename in os.listdir(prompts_dir):
            if filename.endswith('.txt'):
                base_name = filename[:-4]
                if not is_benchmark_file(base_name):
                    file_path = os.path.join(prompts_dir, filename)
                    os.remove(file_path)
                    print(f"    Removed: {filename}")
    
    # Remove non-benchmark response files
    if os.path.exists(responses_dir):
        for filename in os.listdir(responses_dir):
            if filename.endswith('.txt'):
                base_name = filename[:-4]
                if not is_benchmark_file(base_name):
                    file_path = os.path.join(responses_dir, filename)
                    os.remove(file_path)
                    print(f"    Removed: {filename}")

def run_evaluation(run_folder: str, cwe: str, model: str, dataset: str) -> bool:
    """
    Run the evaluation script for a specific run folder.
    """
    if dataset == "owasp":
        cmd = [
            "python", "evaluate_results.py",
            "--ground_truth", "input_files/ground_truth/expectedresults-1.2.csv",
            "--cwe", cwe,
            "--run_folder", run_folder,
            "--model", model
        ]
    else:
        print(f"  ✗ Unknown dataset: {dataset}")
        return False
    
    print(f"  Running evaluation: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"  ✓ Evaluation completed successfully")
            if result.stdout:
                print(f"    Output: {result.stdout.strip()}")
            return True
        else:
            print(f"  ✗ Evaluation failed with return code {result.returncode}")
            if result.stderr:
                print(f"    Error: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"  ✗ Evaluation timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"  ✗ Evaluation failed with exception: {e}")
        return False

def process_run_folder(run_folder: str) -> bool:
    """
    Process a single run folder: automatically filter files based on dataset type and run evaluation.
    
    Args:
        run_folder: Path to the run folder
    """
    print(f"\nProcessing run folder: {run_folder}")
    
    try:
        # Extract run information
        prompt_version, dataset, cwe, model = extract_run_info_from_folder(run_folder)
        print(f"  Prompt Version: {prompt_version}")
        print(f"  Dataset: {dataset}")
        print(f"  CWE: {cwe}")
        print(f"  Model: {model}")
        
        # Define subdirectories
        prompts_dir = os.path.join(run_folder, "prompts")
        responses_dir = os.path.join(run_folder, "responses")
        
        # Check if directories exist
        if not os.path.exists(prompts_dir):
            print(f"  ✗ Prompts directory not found: {prompts_dir}")
            return False
        
        if not os.path.exists(responses_dir):
            print(f"  ✗ Responses directory not found: {responses_dir}")
            return False
        
        # Count files before filtering
        prompt_files_before = len([f for f in os.listdir(prompts_dir) if f.endswith('.txt')])
        response_files_before = len([f for f in os.listdir(responses_dir) if f.endswith('.txt')])
        
        print(f"  Files before filtering: {prompt_files_before} prompts, {response_files_before} responses")
        
        # Apply automatic dataset-specific filtering logic
        if dataset == "owasp":
            # For OWASP dataset: Automatically filter and remove non-benchmark files
            print(f"  🔧 [OWASP] Automatically removing non-benchmark files...")
            remove_non_benchmark_files(prompts_dir, responses_dir)
            
            # Count files after filtering
            valid_prompts, valid_responses = filter_benchmark_files(prompts_dir, responses_dir)
            print(f"  Files after filtering: {len(valid_prompts)} prompts, {len(valid_responses)} responses")
            
            if len(valid_prompts) == 0:
                print(f"  ✗ No valid benchmark prompt files found")
                return False
            
            if len(valid_responses) == 0:
                print(f"  ✗ No valid benchmark response files found")
                return False
            
        else:
            # For other datasets: Keep all files
            print(f"  🔧 [Other] Keeping all files (no filtering applied)")
            valid_prompts = [f for f in os.listdir(prompts_dir) if f.endswith('.txt')]
            valid_responses = [f for f in os.listdir(responses_dir) if f.endswith('.txt')]
            print(f"  Files after filtering: {len(valid_prompts)} prompts, {len(valid_responses)} responses")
        
        # Run evaluation
        success = run_evaluation(run_folder, cwe, model, dataset)
        
        return success
        
    except Exception as e:
        print(f"  ✗ Error processing run folder: {e}")
        return False

def main():
    """
    Main function to process all run folders with automatic dataset-specific filtering.
    """
    results_dir = "results"
    
    if not os.path.exists(results_dir):
        print(f"Results directory not found: {results_dir}")
        return
    
    print("Starting overall evaluation of all run folders...")
    print(f"Results directory: {results_dir}")
    print(f"Automatic filtering: OWASP datasets → remove non-benchmark files")
    
    # Get all run folders
    run_folders = []
    for item in os.listdir(results_dir):
        item_path = os.path.join(results_dir, item)
        if os.path.isdir(item_path):
            # Check if it has the expected structure (promptversion_dataset_CWE_model)
            if '_' in item and 'CWE-' in item and len(item.split('_')) >= 4:
                run_folders.append(item_path)
    
    if not run_folders:
        print("No run folders found in results directory")
        return
    
    print(f"Found {len(run_folders)} run folders to process")
    
    # Process each run folder
    successful_runs = 0
    failed_runs = 0
    
    for run_folder in sorted(run_folders):
        success = process_run_folder(run_folder)
        if success:
            successful_runs += 1
        else:
            failed_runs += 1
    
    # Summary
    print(f"\n{'='*60}")
    print("EVALUATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total run folders processed: {len(run_folders)}")
    print(f"Successful evaluations: {successful_runs}")
    print(f"Failed evaluations: {failed_runs}")
    print(f"Success rate: {(successful_runs/len(run_folders)*100):.1f}%")
    
    if failed_runs > 0:
        print(f"\nFailed runs may need manual investigation.")
    
    print(f"\nEvaluation completed!")

if __name__ == "__main__":
    main() 