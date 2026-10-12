#!/usr/bin/env python3
"""
OpenRouter integration for CWE vulnerability analysis prompt generation.
This version integrates with OpenRouter API to access multiple AI models.
"""

import os
import csv
import json
import pandas as pd
from pathlib import Path
import logging
from typing import Dict, List, Any, Optional
import requests
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OpenRouterPromptGenerator:
    def __init__(self, base_dir: str = ".", api_key: Optional[str] = None, model: str = "openai/gpt-4o-mini"):
        self.base_dir = Path(base_dir)
        self.projects_info_path = self.base_dir / "Projects_info.csv"
        self.code_contexts_path = self.base_dir / "code-context/optimized"
        self.prompt_templates_path = self.base_dir / "prompt_templates" / "optimized"
        self.output_path = self.base_dir / "prompts-responses-openrouter"
        
        # OpenRouter Configuration
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1"
        
        # Load projects info
        self.projects_df = self._load_projects_info()
        
        # Available CWE templates
        self.available_cwe_templates = self._get_available_cwe_templates()
        
        # Available models on OpenRouter
        self.available_models = self._get_available_models()
        
        logger.info(f"Loaded {len(self.projects_df)} projects")
        logger.info(f"Available CWE templates: {list(self.available_cwe_templates.keys())}")
        logger.info(f"Selected model: {self.model}")
        logger.info(f"Available models: {len(self.available_models)}")

    def _load_projects_info(self) -> pd.DataFrame:
        """Load and parse the Projects_info.csv file."""
        try:
            df = pd.read_csv(self.projects_info_path)
            logger.info(f"Successfully loaded {len(df)} projects from {self.projects_info_path}")
            return df
        except Exception as e:
            logger.error(f"Failed to load projects info: {e}")
            raise

    def _get_available_cwe_templates(self) -> Dict[str, str]:
        """Get available CWE template files."""
        templates = {}
        if self.prompt_templates_path.exists():
            for template_file in self.prompt_templates_path.glob("CWE-*.txt"):
                cwe_id = template_file.stem  # e.g., "CWE-022"
                templates[cwe_id] = str(template_file)
        return templates

    def _get_available_models(self) -> List[Dict[str, Any]]:
        """Get available models from OpenRouter."""
        if not self.api_key:
            logger.warning("No OpenRouter API key provided, using default models list")
            return self._get_default_models()
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            response = requests.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            models_data = response.json()
            return models_data.get("data", [])
            
        except Exception as e:
            logger.warning(f"Failed to fetch models from OpenRouter: {e}")
            return self._get_default_models()

    def _get_default_models(self) -> List[Dict[str, Any]]:
        """Get default list of popular models."""
        return [
            {"id": "openai/gpt-4o-mini", "name": "GPT-4o Mini", "pricing": {"prompt": "0.00015", "completion": "0.0006"}},
            {"id": "openai/gpt-4o", "name": "GPT-4o", "pricing": {"prompt": "0.005", "completion": "0.015"}},
            {"id": "anthropic/claude-3-5-sonnet", "name": "Claude 3.5 Sonnet", "pricing": {"prompt": "0.003", "completion": "0.015"}},
            {"id": "google/gemini-pro-1.5", "name": "Gemini Pro 1.5", "pricing": {"prompt": "0.00125", "completion": "0.005"}},
            {"id": "meta-llama/llama-3.1-8b-instruct", "name": "Llama 3.1 8B", "pricing": {"prompt": "0.0002", "completion": "0.0002"}},
            {"id": "mistralai/mistral-7b-instruct", "name": "Mistral 7B", "pricing": {"prompt": "0.0002", "completion": "0.0002"}},
        ]

    def _get_cwe_template(self, cwe_id: str) -> Optional[str]:
        """Get the template content for a specific CWE ID."""
        template_path = self.available_cwe_templates.get(cwe_id)
        if template_path and os.path.exists(template_path):
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        return None

    def _get_code_context_files(self, project_slug: str) -> List[Path]:
        """Get all code context files for a project."""
        project_dir = self.code_contexts_path / project_slug
        if not project_dir.exists():
            logger.warning(f"Project directory not found: {project_dir}")
            return []
        
        # Get all .txt files in the project directory
        context_files = list(project_dir.glob("*.txt"))
        logger.info(f"Found {len(context_files)} context files for {project_slug}")
        return context_files

    def _read_code_context(self, context_file: Path) -> str:
        """Read the content of a code context file."""
        try:
            with open(context_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read {context_file}: {e}")
            return ""

    def _generate_prompt(self, template: str, code_context: str) -> str:
        """Generate a prompt by filling the template with code context."""
        return template.replace("{code_context}", code_context)

    def _call_openrouter_api(self, prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
        """Call OpenRouter API to get AI response."""
        if not self.api_key:
            logger.error("OpenRouter API key not provided")
            return self._generate_fallback_response()
        
        model = model or self.model
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/your-repo/cwe-bench",  # Optional: for analytics
            "X-Title": "CWE Vulnerability Analysis"  # Optional: for analytics
        }
        
        data = {
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=data,
                timeout=60
            )
            
            # Check for HTTP errors and log detailed error information
            if not response.ok:
                error_details = f"HTTP {response.status_code}: {response.reason}"
                try:
                    error_json = response.json()
                    if 'error' in error_json:
                        error_details += f" - {error_json['error']}"
                    if 'message' in error_json:
                        error_details += f" - {error_json['message']}"
                except:
                    error_details += f" - {response.text[:500]}"
                
                logger.error(f"OpenRouter API call failed: {error_details}")
                return self._generate_fallback_response()
            
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            
            # Extract usage information
            usage = result.get("usage", {})
            
            # Try to parse as JSON
            try:
                # First, try to parse the content directly
                parsed_response = json.loads(content)
                parsed_response.update({
                    "model_used": model,
                })
                return parsed_response
            except json.JSONDecodeError:
                # If direct parsing fails, try to extract JSON from markdown code blocks
                try:
                    import re
                    # Look for JSON content within ```json ... ``` blocks
                    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                    if json_match:
                        json_content = json_match.group(1)
                        parsed_response = json.loads(json_content)
                        parsed_response.update({
                            "model_used": model,
                        })
                        return parsed_response
                except (json.JSONDecodeError, AttributeError):
                    pass
                
                # Try to extract JSON from the content even if it's not properly formatted
                try:
                    import re
                    # Look for JSON-like content with proper field names
                    json_pattern = r'\{[^{}]*"False Positive"[^{}]*\}'
                    json_matches = re.findall(json_pattern, content, re.DOTALL)
                    
                    for json_str in json_matches:
                        try:
                            # Clean up the JSON string
                            json_str = json_str.strip()
                            parsed_response = json.loads(json_str)
                            
                            # Validate that we have the required fields
                            required_fields = ["False Positive", "Sanitization Found?", "Attack Feasible?", "Confidence"]
                            if all(field in parsed_response for field in required_fields):
                                parsed_response.update({
                                    "model_used": model,
                                })
                                return parsed_response
                        except json.JSONDecodeError:
                            continue
                except Exception:
                    pass
                
                # If all JSON parsing attempts fail, try to extract individual fields using regex
                try:
                    import re
                    
                    # Extract individual fields using regex patterns
                    false_positive_match = re.search(r'"False Positive"\s*:\s*"([^"]+)"', content)
                    sanitization_match = re.search(r'"Sanitization Found\?"\s*:\s*"([^"]+)"', content)
                    attack_feasible_match = re.search(r'"Attack Feasible\?"\s*:\s*"([^"]+)"', content)
                    confidence_match = re.search(r'"Confidence"\s*:\s*"([^"]+)"', content)
                    
                    if false_positive_match and sanitization_match and attack_feasible_match and confidence_match:
                        parsed_response = {
                            "False Positive": false_positive_match.group(1),
                            "Sanitization Found?": sanitization_match.group(1),
                            "Attack Feasible?": attack_feasible_match.group(1),
                            "Confidence": confidence_match.group(1),
                            "model_used": model,
                        }
                        return parsed_response
                except Exception:
                    pass
                
                # If all JSON parsing attempts fail, wrap in a structured response
                return {
                    "False Positive": "ERROR",
                    "Sanitization Found?": "ERROR",
                    "Attack Feasible?": "ERROR",
                    "Confidence": "ERROR",
                    "model_used": model,
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"OpenRouter API call failed: {e}")
            logger.error(f"Request data: {json.dumps(data, indent=2)}")
            return self._generate_fallback_response()
        except Exception as e:
            logger.error(f"Unexpected error in OpenRouter API call: {e}")
            logger.error(f"Request data: {json.dumps(data, indent=2)}")
            return self._generate_fallback_response()

    def _generate_fallback_response(self) -> Dict[str, Any]:
        """Generate a fallback response when API calls fail."""
        return {
            "False Positive": "ERROR",
            "Sanitization Found?": "ERROR",
            "Attack Feasible?": "ERROR",
            "Confidence": "ERROR",
            "model_used": self.model,
        }

    def _create_project_directory(self, project_slug: str) -> Path:
        """Create directory for a project in the output folder."""
        project_dir = self.output_path / project_slug
        project_dir.mkdir(parents=True, exist_ok=True)
        return project_dir

    def list_available_models(self) -> None:
        """List all available models on OpenRouter."""
        print("Available models on OpenRouter:")
        print("=" * 50)
        
        for model in self.available_models:
            model_id = model.get("id", "Unknown")
            model_name = model.get("name", "Unknown")
            pricing = model.get("pricing", {})
            prompt_price = pricing.get("prompt", "N/A")
            completion_price = pricing.get("completion", "N/A")
            
            print(f"ID: {model_id}")
            print(f"Name: {model_name}")
            print(f"Pricing: ${prompt_price}/1K prompt tokens, ${completion_price}/1K completion tokens")
            print("-" * 30)

    def process_projects_with_openrouter(self, max_projects: Optional[int] = None, 
                                       delay_between_calls: float = 1.0,
                                       model: Optional[str] = None) -> List[Dict[str, Any]]:
        """Process projects and get OpenRouter AI responses."""
        all_results = []
        
        # Create output directory
        self.output_path.mkdir(exist_ok=True)
        
        projects_to_process = self.projects_df.head(max_projects) if max_projects else self.projects_df
        model_to_use = model or self.model
        
        logger.info(f"Using model: {model_to_use}")
        
        for idx, (_, project_row) in enumerate(projects_to_process.iterrows()):
            project_slug = project_row['project_slug']
            cve_id = project_row['cve_id']
            cwe_id = project_row['cwe_id']
            
            logger.info(f"Processing project {idx+1}/{len(projects_to_process)}: {project_slug} (CVE: {cve_id}, CWE: {cwe_id})")
            
            # Get CWE template
            template = self._get_cwe_template(cwe_id)
            if not template:
                logger.warning(f"No template found for {cwe_id}, skipping {project_slug}")
                continue
            
            # Get code context files
            context_files = self._get_code_context_files(project_slug)
            if not context_files:
                logger.warning(f"No context files found for {project_slug}")
                continue
            
            # Create project directory
            project_dir = self._create_project_directory(project_slug)
            
            # Process each context file
            for context_file in context_files:
                alert_name = context_file.stem  # e.g., "vulnerability_java_path-injection_1"
                
                # Read code context
                code_context = self._read_code_context(context_file)
                if not code_context:
                    continue
                
                # Generate prompt
                prompt = self._generate_prompt(template, code_context)
                
                # Get OpenRouter AI response
                logger.info(f"Getting OpenRouter AI response for {alert_name}...")
                response = self._call_openrouter_api(prompt, model_to_use)
                
                # Add metadata
                response.update({
                    "project_slug": project_slug,
                    "CVE": cve_id,
                    "CWE": cwe_id,
                    "alert_name": alert_name,
                    "context_file": str(context_file),
                    "ai_provider": "openrouter",
                    "timestamp": pd.Timestamp.now().isoformat()
                })
                 
                # Add to results for CSV
                all_results.append(response)
                
                logger.info(f"Processed alert: {alert_name} for {project_slug}")
                
                # Add delay to avoid rate limiting
                if delay_between_calls > 0:
                    time.sleep(delay_between_calls)
        
        return all_results

    def save_results_to_csv(self, results: List[Dict[str, Any]]) -> None:
        """Save all results to a CSV file."""
        if not results:
            logger.warning("No results to save")
            return
        
        # Create DataFrame
        df = pd.DataFrame(results)
        
        # Save to CSV
        csv_path = self.output_path / "openrouter_prompts_responses.csv"
        df.to_csv(csv_path, index=False)
        logger.info(f"Saved {len(results)} results to {csv_path}")
        
        # Also save a summary
        summary_path = self.output_path / "openrouter_summary.txt"
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(f"OpenRouter Prompt Generation Summary\n")
            f.write(f"===================================\n\n")
            f.write(f"Model Used: {self.model}\n")
            f.write(f"Total projects processed: {len(self.projects_df)}\n")
            f.write(f"Total alerts processed: {len(results)}\n")
            f.write(f"Unique CWEs: {df['CWE'].nunique()}\n")
            f.write(f"Unique CVEs: {df['CVE'].nunique()}\n\n")
            
            f.write(f"CWE Distribution:\n")
            cwe_counts = df['CWE'].value_counts()
            for cwe, count in cwe_counts.items():
                f.write(f"  {cwe}: {count} alerts\n")
            
            f.write(f"\nProject Distribution:\n")
            project_counts = df['project_slug'].value_counts()
            for project, count in project_counts.head(10).items():
                f.write(f"  {project}: {count} alerts\n")
        
        logger.info(f"Saved summary to {summary_path}")

    def run(self, max_projects: Optional[int] = None, delay_between_calls: float = 1.0, model: Optional[str] = None):
        """Main execution method."""
        logger.info("Starting OpenRouter prompt generation process...")
        
        try:
            # Process projects with OpenRouter
            results = self.process_projects_with_openrouter(max_projects, delay_between_calls, model)
            
            # Save results to CSV
            self.save_results_to_csv(results)
            
            logger.info("OpenRouter prompt generation completed successfully!")
            
        except Exception as e:
            logger.error(f"Error during processing: {e}")
            raise

def main():
    """Main function with command line argument support."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate prompts and get OpenRouter AI responses for CWE analysis")
    parser.add_argument("--api-key", help="OpenRouter API key")
    parser.add_argument("--model", default="openai/gpt-4o-mini", help="Model to use (default: openai/gpt-4o-mini)")
    parser.add_argument("--max-projects", type=int, help="Maximum number of projects to process")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between API calls in seconds")
    parser.add_argument("--list-models", action="store_true", help="List available models and exit")
    
    args = parser.parse_args()
    
    generator = OpenRouterPromptGenerator(api_key=args.api_key, model=args.model)
    
    if args.list_models:
        generator.list_available_models()
        return
    
    generator.run(max_projects=args.max_projects, delay_between_calls=args.delay, model=args.model)

if __name__ == "__main__":
    main()
