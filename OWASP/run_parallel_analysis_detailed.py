#!/usr/bin/env python3
"""
Parallel Analysis Runner for OWASP False Positive Reduction

This script runs multiple analysis jobs in parallel using different combinations of:
- Datasets (owasp)
- Prompt versions (baseline, optimized)
- Models (o4-mini, gemini, claude, ...)
- CWEs (078, 079, 089, ...)

Usage:
    python run_parallel_analysis_detailed.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 CWE-079 --threads 4
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
        logging.FileHandler('parallel_analysis_detailed.log'),
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
    """Tracks progress of parallel jobs with file-level details."""
    
    def __init__(self, total_jobs: int):
        self.total_jobs = total_jobs
        self.completed_jobs = 0
        self.failed_jobs = 0
        self.running_jobs = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.job_progress = {}  # Track file progress for each job
        
    def job_started(self, job_id: str):
        with self.lock:
            self.running_jobs += 1
            self.job_progress[job_id] = {"files_processed": 0, "files_completed": 0, "files_skipped": 0}
            logger.info(f"🚀 Started job: {job_id} (Running: {self.running_jobs}/{self.total_jobs})")
    
    def update_file_progress(self, job_id: str, file_action: str, filename: str = ""):
        """Update file progress for a specific job."""
        with self.lock:
            if job_id in self.job_progress:
                if file_action == "processing":
                    self.job_progress[job_id]["files_processed"] += 1
                    logger.info(f"[{job_id}] 📄 Processing file #{self.job_progress[job_id]['files_processed']}: {filename}")
                elif file_action == "completed":
                    self.job_progress[job_id]["files_completed"] += 1
                    logger.info(f"[{job_id}] ✅ Completed file #{self.job_progress[job_id]['files_completed']}: {filename}")
                elif file_action == "skipped":
                    self.job_progress[job_id]["files_skipped"] += 1
                    logger.info(f"[{job_id}] ⏭️ Skipped file #{self.job_progress[job_id]['files_skipped']}: {filename}")
    
    def job_completed(self, job_id: str, success: bool = True):
        with self.lock:
            self.running_jobs -= 1
            if success:
                self.completed_jobs += 1
                progress_info = self.job_progress.get(job_id, {})
                logger.info(f"✅ Completed job: {job_id} (Completed: {self.completed_jobs}/{self.total_jobs})")
                logger.info(f"   📊 Files processed: {progress_info.get('files_processed', 0)}, "
                           f"completed: {progress_info.get('files_completed', 0)}, "
                           f"skipped: {progress_info.get('files_skipped', 0)}")
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

def run_owasp_analysis(job: AnalysisJob, paths: Dict[str, str], progress: ProgressTracker, batch_size: int, max_workers: int, verbose: bool = False) -> bool:
    """Run OWASP analysis for a single job with detailed file tracking."""
    try:
        progress.job_started(job.job_id)
        
        cmd = [
            'python', 'analyze_with_llm.py',
            '--sarif_file', paths['sarif_file'],
            '--project_src_root', paths['project_src_root'],
            '--expected_results_csv', paths['expected_results_csv'],
            '--model', job.model,
            '--prompt_version', job.prompt_version,
            '--enable_token_counting',
            '--batch_size', str(batch_size),
            '--max_workers', str(max_workers)
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
        
        # Stream output in real-time with non-blocking reads
        stdout_lines = []
        stderr_lines = []
        
        import select
        import time
        
        # Set non-blocking mode for pipes
        import fcntl
        import os
        
        # Make pipes non-blocking
        fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(process.stderr.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        
        start_time = time.time()
        timeout_seconds = 3600  # 1 hour timeout
        
        while True:
            # Check timeout
            if time.time() - start_time > timeout_seconds:
                logger.error(f"OWASP analysis timed out after {timeout_seconds} seconds for {job.job_id}")
                process.terminate()
                try:
                    process.wait(timeout=10)  # Give it 10 seconds to terminate gracefully
                except subprocess.TimeoutExpired:
                    process.kill()  # Force kill if it doesn't terminate
                progress.job_completed(job.job_id, success=False)
                return False
            # Check if process has finished
            if process.poll() is not None:
                break
            
            # Try to read from stdout (non-blocking)
            try:
                stdout_line = process.stdout.readline()
                if stdout_line:
                    stdout_lines.append(stdout_line.strip())
                    line_content = stdout_line.strip()
                    
                    # Only log important lines, not every single line (performance improvement)
                    if verbose or any(keyword in line_content.lower() for keyword in ['error', 'warning', 'failed', 'completed', 'processing']):
                        logger.info(f"[{job.job_id}] {line_content}")
                    
                    # Track file processing progress for OWASP
                    if "Processing" in line_content and "warning" in line_content.lower():
                        progress.update_file_progress(job.job_id, "processing", "warning")
                    elif "Completed" in line_content and "warning" in line_content.lower():
                        progress.update_file_progress(job.job_id, "completed", "warning")
            except (IOError, OSError):
                # No data available, continue
                pass
            
            # Try to read from stderr (non-blocking)
            try:
                stderr_line = process.stderr.readline()
                if stderr_line:
                    stderr_lines.append(stderr_line.strip())
                    logger.warning(f"[{job.job_id}] {stderr_line.strip()}")
            except (IOError, OSError):
                # No data available, continue
                pass
            
            # Small sleep to prevent busy waiting
            time.sleep(0.1)
        
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

def run_single_job(job: AnalysisJob, progress: ProgressTracker, batch_size: int, max_workers: int, verbose: bool = False) -> bool:
    """Run a single analysis job."""
    try:
        logger.info(f"Starting job: {job.job_id}")
        logger.info(f"Job details: dataset={job.dataset}, model={job.model}, cwe={job.cwe}")
        
        # Run OWASP analysis
        if job.dataset.lower() == 'owasp':
            logger.info(f"Setting up OWASP paths for {job.job_id}")
            paths = get_owasp_paths(job.cwe)
            if not check_paths_exist(paths, 'owasp'):
                logger.error(f"Required paths not found for OWASP CWE {job.cwe}")
                progress.job_completed(job.job_id, success=False)
                return False
            logger.info(f"OWASP paths validated, starting analysis for {job.job_id}")
            return run_owasp_analysis(job, paths, progress, batch_size, max_workers, verbose)
        
        else:
            logger.error(f"Unknown dataset: {job.dataset}")
            progress.job_completed(job.job_id, success=False)
            return False
            
    except Exception as e:
        logger.error(f"Unexpected error in run_single_job for {job.job_id}: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        progress.job_completed(job.job_id, success=False)
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Run parallel analysis jobs with detailed file tracking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Small test with OWASP dataset
  python run_parallel_analysis_detailed.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 CWE-079 --threads 2 --batch-size 5 --max-workers 8

  # Medium test with OWASP dataset
  python run_parallel_analysis_detailed.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 CWE-079 CWE-089 CWE-090 --threads 4 --batch-size 10 --max-workers 15

  # Large test with multiple models
  python run_parallel_analysis_detailed.py --datasets owasp --prompt-versions optimized --models o4-mini google/gemini-2.5-pro  --cwes CWE-078 CWE-079 CWE-089 CWE-090 --threads 8 --batch-size 20 --max-workers 25

  # Dry run to see what would be executed
  python run_parallel_analysis_detailed.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 --threads 2 --batch-size 5 --max-workers 8 --dry-run
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
    parser.add_argument('--batch-size', type=int, default=10,
                       help='Number of prompts to process concurrently in each analysis job (default: 10)')
    parser.add_argument('--max-workers', type=int, default=15,
                       help='Maximum number of concurrent API calls in each analysis job (default: 15)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging (logs every line of output, may slow down processing)')
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
        logger.info(f"Each job will use batch-size={args.batch_size}, max-workers={args.max_workers}")
        return
    
    # Initialize progress tracker
    progress = ProgressTracker(len(jobs))
    
    logger.info(f"Starting parallel analysis with {len(jobs)} jobs using {args.threads} threads")
    logger.info(f"Datasets: {args.datasets}")
    logger.info(f"Prompt versions: {args.prompt_versions}")
    logger.info(f"Models: {args.models}")
    logger.info(f"CWEs: {args.cwes}")
    logger.info(f"Batch settings: batch-size={args.batch_size}, max-workers={args.max_workers}")
    logger.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run jobs in parallel
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all jobs
        future_to_job = {executor.submit(run_single_job, job, progress, args.batch_size, args.max_workers, args.verbose): job for job in jobs}
        
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