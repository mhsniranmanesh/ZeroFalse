#!/usr/bin/env python3
"""
Parallel Analysis Runner for OWASP False Positive Reduction

This script runs multiple analysis jobs in parallel using different combinations of:
- Datasets (owasp)
- Prompt versions (baseline, optimized)
- Models (o4-mini, gemini, claude, ...)
- CWEs (078, 079, 089, ...)

Usage:
    python run_parallel_analysis.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 CWE-079 --threads 4
"""

import os
import sys
import time
import argparse
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parallel_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AnalysisJob:
    """Represents a single analysis job configuration."""
    dataset: str
    prompt_version: str
    model: str
    cwe: str
    job_id: str = ""
    
    def __post_init__(self):
        if not self.job_id:
            self.job_id = f"{self.prompt_version}_{self.dataset}_{self.cwe}_{self.model.replace('/', '_')}"

class ProgressTracker:
    """Tracks progress of parallel jobs."""
    
    def __init__(self, total_jobs: int):
        self.total_jobs = total_jobs
        self.completed_jobs = 0
        self.failed_jobs = 0
        self.running_jobs = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        
    def job_started(self, job_id: str):
        with self.lock:
            self.running_jobs += 1
            logger.info(f"🚀 Started job: {job_id} (Running: {self.running_jobs}/{self.total_jobs})")
    
    def job_completed(self, job_id: str, success: bool = True):
        with self.lock:
            self.running_jobs -= 1
            if success:
                self.completed_jobs += 1
                logger.info(f"✅ Completed job: {job_id} (Completed: {self.completed_jobs}/{self.total_jobs})")
            else:
                self.failed_jobs += 1
                logger.error(f"❌ Failed job: {job_id} (Failed: {self.failed_jobs}/{self.total_jobs})")
            
            self._print_progress()
    
    def _print_progress(self):
        elapsed = time.time() - self.start_time
        progress = (self.completed_jobs + self.failed_jobs) / self.total_jobs * 100
        eta = (elapsed / (self.completed_jobs + self.failed_jobs)) * (self.total_jobs - self.completed_jobs - self.failed_jobs) if (self.completed_jobs + self.failed_jobs) > 0 else 0
        
        logger.info(f"📊 Progress: {progress:.1f}% | "
                   f"Completed: {self.completed_jobs} | "
                   f"Failed: {self.failed_jobs} | "
                   f"Running: {self.running_jobs} | "
                   f"Elapsed: {elapsed:.1f}s | "
                   f"ETA: {eta:.1f}s")

def generate_jobs(datasets: List[str], prompt_versions: List[str], models: List[str], cwes: List[str]) -> List[AnalysisJob]:
    """Generate all job combinations from parameters."""
    jobs = []
    
    for dataset in datasets:
        for prompt_version in prompt_versions:
            for model in models:
                for cwe in cwes:
                    job = AnalysisJob(
                        dataset=dataset,
                        prompt_version=prompt_version,
                        model=model,
                        cwe=cwe
                    )
                    jobs.append(job)
    
    logger.info(f"Generated {len(jobs)} analysis jobs")
    return jobs

def get_owasp_paths(cwe: str) -> Dict[str, str]:
    """Get OWASP dataset paths for a given CWE."""
    return {
        'sarif_file': f"input_files/sarif_results/owasp-benchmark/owasp-benchmark-{cwe}.sarif",
        'project_src_root': "input_files/source_code/BenchmarkJava",
        'expected_results_csv': "input_files/ground_truth/expectedresults-1.2.csv"
    }

def check_paths_exist(paths: Dict[str, str], dataset: str) -> bool:
    """Check if all required paths exist for a dataset."""
    for key, path in paths.items():
        if not os.path.exists(path):
            logger.warning(f"Path does not exist for {dataset} {key}: {path}")
            return False
    return True

def run_owasp_analysis(job: AnalysisJob, paths: Dict[str, str], progress: ProgressTracker) -> bool:
    """Run OWASP analysis for a single job."""
    try:
        progress.job_started(job.job_id)
        
        cmd = [
            'python', 'analyze_with_llm.py',
            '--sarif_file', paths['sarif_file'],
            '--project_src_root', paths['project_src_root'],
            '--expected_results_csv', paths['expected_results_csv'],
            '--model', job.model,
            '--prompt_version', job.prompt_version,
            '--enable_token_counting'
        ]
        
        logger.info(f"Running OWASP analysis: {' '.join(cmd)}")
        
        # Use Popen to get real-time output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Stream output in real-time
        stdout_lines = []
        stderr_lines = []
        
        while True:
            stdout_line = process.stdout.readline()
            stderr_line = process.stderr.readline()
            
            if stdout_line:
                stdout_lines.append(stdout_line.strip())
                logger.info(f"[{job.job_id}] {stdout_line.strip()}")
            
            if stderr_line:
                stderr_lines.append(stderr_line.strip())
                logger.warning(f"[{job.job_id}] {stderr_line.strip()}")
            
            # Check if process has finished
            if process.poll() is not None:
                break
        
        # Wait for process to complete
        returncode = process.wait()
        
        if returncode == 0:
            logger.info(f"OWASP analysis completed successfully for {job.job_id}")
            progress.job_completed(job.job_id, success=True)
            return True
        else:
            stderr_output = '\n'.join(stderr_lines)
            logger.error(f"OWASP analysis failed for {job.job_id}: {stderr_output}")
            progress.job_completed(job.job_id, success=False)
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"OWASP analysis timed out for {job.job_id}")
        progress.job_completed(job.job_id, success=False)
        return False
    except Exception as e:
        logger.error(f"OWASP analysis error for {job.job_id}: {e}")
        progress.job_completed(job.job_id, success=False)
        return False

def run_single_job(job: AnalysisJob, progress: ProgressTracker) -> bool:
    """Run a single analysis job."""
    logger.info(f"Starting job: {job.job_id}")
    
    if job.dataset.lower() == 'owasp':
        paths = get_owasp_paths(job.cwe)
        if not check_paths_exist(paths, 'owasp'):
            logger.error(f"Required paths not found for OWASP CWE {job.cwe}")
            progress.job_completed(job.job_id, success=False)
            return False
        return run_owasp_analysis(job, paths, progress)
    
    else:
        logger.error(f"Unknown dataset: {job.dataset}")
        progress.job_completed(job.job_id, success=False)
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Run parallel analysis jobs with direct command line parameters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Medium test with OWASP dataset
  python run_parallel_analysis.py --datasets owasp --prompt-versions optimized --models o4-mini google/gemini-2.5-pro --cwes CWE-078 CWE-079 CWE-089 CWE-090 --threads 4

  # Dry run to see what would be executed
  python run_parallel_analysis.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 --threads 2 --dry-run
        """
    )
    
    # Required arguments
    parser.add_argument('--datasets', nargs='+', required=True, 
                       choices=['owasp'],
                       help='Datasets to analyze (owasp)')
    parser.add_argument('--prompt-versions', nargs='+', required=True,
                       help='Prompt template versions (baseline, optimized)')
    parser.add_argument('--models', nargs='+', required=True,
                       help='LLM models to use')
    parser.add_argument('--cwes', nargs='+', required=True,
                       help='CWE identifiers to analyze (e.g., CWE-078, CWE-079)')
    
    # Optional arguments
    parser.add_argument('--threads', type=int, default=4,
                       help='Number of parallel threads (default: 4)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be run without executing')
    
    args = parser.parse_args()
    
    # Generate all jobs
    jobs = generate_jobs(args.datasets, args.prompt_versions, args.models, args.cwes)
    
    if args.dry_run:
        logger.info("DRY RUN - Would execute the following jobs:")
        for job in jobs:
            logger.info(f"  {job.job_id}")
        logger.info(f"Total: {len(jobs)} jobs with {args.threads} threads")
        return
    
    # Initialize progress tracker
    progress = ProgressTracker(len(jobs))
    
    logger.info(f"Starting parallel analysis with {len(jobs)} jobs using {args.threads} threads")
    logger.info(f"Datasets: {args.datasets}")
    logger.info(f"Prompt versions: {args.prompt_versions}")
    logger.info(f"Models: {args.models}")
    logger.info(f"CWEs: {args.cwes}")
    logger.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run jobs in parallel
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all jobs
        future_to_job = {executor.submit(run_single_job, job, progress): job for job in jobs}
        
        # Wait for completion
        for future in as_completed(future_to_job):
            job = future_to_job[future]
            try:
                success = future.result()
                if not success:
                    logger.warning(f"Job {job.job_id} completed with errors")
            except Exception as e:
                logger.error(f"Job {job.job_id} generated an exception: {e}")
                progress.job_completed(job.job_id, success=False)
    
    # Final summary
    logger.info(f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Final results: {progress.completed_jobs} successful, {progress.failed_jobs} failed")

if __name__ == '__main__':
    main() 