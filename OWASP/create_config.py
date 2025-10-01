#!/usr/bin/env python3
"""
Configuration Generator for Parallel Analysis Runner

This script helps create configuration files for the parallel analysis runner.
"""

import json
import argparse
from typing import List, Dict, Any

def create_config(
    datasets: List[str],
    prompt_versions: List[str],
    models: List[str],
    cwes: List[str],
    threads: int = 4
) -> Dict[str, Any]:
    """Create a configuration dictionary."""
    return {
        "datasets": datasets,
        "prompt_versions": prompt_versions,
        "models": models,
        "cwes": cwes,
        "threads": threads
    }

def get_available_cwes():
    return {
        "owasp": [
            "CWE-022", "CWE-078", "CWE-079", "CWE-089", "CWE-090", "CWE-113", 
            "CWE-134", "CWE-209", "CWE-327", "CWE-330", "CWE-501", "CWE-614", 
            "CWE-643"
        ]
    }

def get_common_models():
    """Get list of common models."""
    return [
        "o4-mini",
        "google/gemini-2.5-pro",
        "deepseek/deepseek-r1"
    ]

def main():
    parser = argparse.ArgumentParser(description='Create configuration files for parallel analysis')
    parser.add_argument('--output', '-o', required=True, help='Output configuration file path')
    parser.add_argument('--datasets', nargs='+', default=['owasp'], help='Datasets to use (owasp)')
    parser.add_argument('--prompt-versions', nargs='+', default=['optimized'], help='Prompt versions to use (baseline, optimized)')
    parser.add_argument('--models', nargs='+', default=['o4-mini'], help='Models to use')
    parser.add_argument('--cwes', nargs='+', help='Specific CWEs to use (if not specified, uses all available)')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads')
    parser.add_argument('--list-available', action='store_true', help='List available options and exit')
    
    args = parser.parse_args()
    
    if args.list_available:
        print("Available options:")
        print("\nDatasets:")
        print("  owasp")
        
        print("\nPrompt versions:")
        print("  baseline, optimized")
        
        print("\nCommon models:")
        for model in get_common_models():
            print(f"  {model}")
        
        print("\nAvailable CWEs by dataset:")
        available_cwes = get_available_cwes()
        for dataset, cwes in available_cwes.items():
            print(f"\n  {dataset}:")
            for cwe in cwes:
                print(f"    {cwe}")
        return
    
    # Validate datasets
    valid_datasets = ['owasp']
    for dataset in args.datasets:
        if dataset not in valid_datasets:
            print(f"Error: Invalid dataset '{dataset}'. Valid options: {valid_datasets}")
            return
    
    # Determine CWEs to use
    if args.cwes:
        cwes = args.cwes
    else:
        # Use all available CWEs for the selected datasets
        available_cwes = get_available_cwes()
        cwes = []
        for dataset in args.datasets:
            cwes.extend(available_cwes.get(dataset, []))
        # Remove duplicates while preserving order
        seen = set()
        cwes = [cwe for cwe in cwes if not (cwe in seen or seen.add(cwe))]
    
    # Create configuration
    config = create_config(
        datasets=args.datasets,
        prompt_versions=args.prompt_versions,
        models=args.models,
        cwes=cwes,
        threads=args.threads
    )
    
    # Calculate total jobs
    total_jobs = len(args.datasets) * len(args.prompt_versions) * len(args.models) * len(cwes)
    
    # Save configuration
    with open(args.output, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"Configuration saved to {args.output}")
    print(f"Total jobs: {total_jobs}")
    print(f"Estimated time with {args.threads} threads: {total_jobs * 10 / args.threads:.1f} minutes (assuming 10 min per job)")

if __name__ == '__main__':
    main() 