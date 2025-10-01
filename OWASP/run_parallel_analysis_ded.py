import argparse
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from analysis_runner import generate_jobs, run_single_job, ProgressTracker

logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(
        description='Run parallel analysis jobs with detailed file tracking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Medium test with both datasets
  python run_parallel_analysis_detailed.py --datasets owasp --prompt-versions optimized --models o4-mini google/gemini-2.5-pro --cwes CWE-078 CWE-079 CWE-089 CWE-090 --threads 4 --batch-size 10 --max-workers 15

  # Large test with multiple models
  python run_parallel_analysis_detailed.py --datasets owasp --prompt-versions optimized --models o4-mini google/gemini-2.5-pro --cwes CWE-078 CWE-079 CWE-089 CWE-090 --threads 8 --batch-size 20 --max-workers 25

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
        future_to_job = {executor.submit(run_single_job, job, progress, args.batch_size, args.max_workers): job for job in jobs}
        
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

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
