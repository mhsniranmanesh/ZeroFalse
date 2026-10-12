#!/usr/bin/env python3
"""
Multi-model analysis runner for CWE vulnerability analysis.
This script runs analyze_specific_projects.py with multiple models in parallel or sequential mode.
"""

import os
import sys
import subprocess
import time
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of OpenVuln models to run (10 specific models)
MODELS = [
    "x-ai/grok-4",
    "google/gemini-2.5-pro",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "openai/o4-mini",
    "qwen/qwen3-235b-a22b",
    "openai/gpt-5",
    "deepseek/deepseek-r1",
    "deepseek/deepseek-r1-distill-llama-70b",
    "mistralai/mixtral-8x7b-instruct"
]

def run_single_model_analysis(model, api_key, delay=2.0, max_retries=3):
    """Run analysis for a single model."""
    logger.info(f"🚀 Starting analysis for model: {model}")
    
    for attempt in range(max_retries):
        try:
            # Build command for OpenVuln analysis
            cmd = [
                sys.executable, "./analyze_specific_projects.py",
                "--model", model,
                "--delay", str(delay)
            ]
            
            if api_key:
                cmd.extend(["--api-key", api_key])
            
            # Run the analysis
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Successfully completed analysis for {model}")
                return {
                    "model": model,
                    "status": "success",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            else:
                logger.warning(f"⚠️  Analysis failed for {model} (attempt {attempt + 1}/{max_retries})")
                logger.warning(f"Error: {result.stderr}")
                
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 30  # Exponential backoff
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    return {
                        "model": model,
                        "status": "failed",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "error": f"Failed after {max_retries} attempts"
                    }
                    
        except subprocess.TimeoutExpired:
            logger.error(f"⏰ Analysis timed out for {model}")
            return {
                "model": model,
                "status": "timeout",
                "error": "Analysis timed out after 1 hour"
            }
        except Exception as e:
            logger.error(f"❌ Unexpected error for {model}: {e}")
            return {
                "model": model,
                "status": "error",
                "error": str(e)
            }
    
    return {
        "model": model,
        "status": "failed",
        "error": f"Failed after {max_retries} attempts"
    }

def run_sequential_analysis(models, api_key, delay=2.0):
    """Run analysis sequentially for all models."""
    logger.info("🔄 Running analysis sequentially...")
    
    results = []
    total_models = len(models)
    
    for i, model in enumerate(models, 1):
        logger.info(f"📊 Progress: {i}/{total_models} - {model}")
        
        result = run_single_model_analysis(model, api_key, delay)
        results.append(result)
        
        # Add delay between models to avoid rate limiting
        if i < total_models:
            logger.info("⏳ Waiting 30 seconds before next model...")
            time.sleep(30)
    
    return results

def run_parallel_analysis(models, api_key, delay=2.0, max_workers=3):
    """Run analysis in parallel for multiple models."""
    logger.info(f"⚡ Running analysis in parallel (max {max_workers} workers)...")
    
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_model = {
            executor.submit(run_single_model_analysis, model, api_key, delay): model 
            for model in models
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_model):
            model = future_to_model[future]
            try:
                result = future.result()
                results.append(result)
                logger.info(f"✅ Completed: {model} - Status: {result['status']}")
            except Exception as e:
                logger.error(f"❌ Exception for {model}: {e}")
                results.append({
                    "model": model,
                    "status": "error",
                    "error": str(e)
                })
    
    return results

def generate_summary_report(results):
    """Generate a summary report of all analysis results."""
    logger.info("📋 Generating summary report...")
    
    successful = [r for r in results if r['status'] == 'success']
    failed = [r for r in results if r['status'] in ['failed', 'error', 'timeout']]
    
    report = f"""
# Multi-Model Analysis Summary Report
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Overview
- Total models: {len(results)}
- Successful: {len(successful)}
- Failed: {len(failed)}

## Successful Models
"""
    
    for result in successful:
        report += f"- ✅ {result['model']}\n"
    
    if failed:
        report += "\n## Failed Models\n"
        for result in failed:
            report += f"- ❌ {result['model']} ({result['status']})\n"
            if 'error' in result:
                report += f"  Error: {result['error']}\n"
    
    # Save report in OpenVuln directory
    report_path = Path("./multi_model_analysis_report.md")
    with open(report_path, 'w') as f:
        f.write(report)
    
    logger.info(f"📄 Summary report saved to: {report_path}")
    return report

def main():
    """Main function with command line arguments."""
    parser = argparse.ArgumentParser(description="Run multi-model analysis for CWE vulnerability detection")
    parser.add_argument("--api-key", help="OpenRouter API key")
    parser.add_argument("--models", nargs="+", default=MODELS, 
                       help="Models to run (default: all predefined models)")
    parser.add_argument("--delay", type=float, default=2.0,
                       help="Delay between API calls in seconds (default: 2.0)")
    parser.add_argument("--parallel", action="store_true",
                       help="Run models in parallel (default: sequential)")
    parser.add_argument("--max-workers", type=int, default=3,
                       help="Maximum number of parallel workers (default: 3)")
    parser.add_argument("--dry-run", action="store_true",
                       help="Show what would be run without executing")
    
    args = parser.parse_args()
    
    # Get API key
    api_key = args.api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key and not args.dry_run:
        print("❌ OpenRouter API key not found!")
        print("Please provide your API key using one of these methods:")
        print("1. Command line argument: --api-key 'your-api-key-here'")
        print("2. Environment variable: export OPENROUTER_API_KEY='your-api-key-here'")
        print("\nGet your API key from: https://openrouter.ai/keys")
        return
    
    # Show what will be run
    print("🎯 Multi-Model CWE Vulnerability Analysis")
    print("=" * 50)
    print(f"Models to run: {len(args.models)}")
    print(f"Mode: {'Parallel' if args.parallel else 'Sequential'}")
    if args.parallel:
        print(f"Max workers: {args.max_workers}")
    print(f"Delay between calls: {args.delay} seconds")
    print()
    
    print("📋 Models:")
    for i, model in enumerate(args.models, 1):
        print(f"  {i:2d}. {model}")
    print()
    
    if args.dry_run:
        print("🔍 Dry run mode - no analysis will be executed")
        return
    
    # Confirm before running
    if len(args.models) > 5:
        response = input(f"⚠️  You're about to run analysis on {len(args.models)} models. This may take several hours and cost money. Continue? (y/N): ")
        if response.lower() != 'y':
            print("❌ Analysis cancelled")
            return
    
    # Run analysis
    start_time = time.time()
    
    try:
        if args.parallel:
            results = run_parallel_analysis(args.models, api_key, args.delay, args.max_workers)
        else:
            results = run_sequential_analysis(args.models, api_key, args.delay)
        
        # Generate summary
        report = generate_summary_report(results)
        
        # Show final summary
        elapsed_time = time.time() - start_time
        successful = len([r for r in results if r['status'] == 'success'])
        
        print("\n" + "="*50)
        print("🏁 Analysis Complete!")
        print(f"⏱️  Total time: {elapsed_time/60:.1f} minutes")
        print(f"✅ Successful: {successful}/{len(results)} models")
        print(f"📄 Report: ./multi_model_analysis_report.md")
        print("="*50)
        
    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
