#!/usr/bin/env python3
"""
Independent Evaluation Script for OWASP False Positive Reduction

This script evaluates LLM analysis results against ground truth data.
It processes all responses in a run folder and creates a comprehensive evaluation CSV.
"""

import os
import sys
import json
import csv
import argparse
from typing import Dict, List, Tuple, Set


def load_ground_truth(ground_truth_csv: str) -> Dict[str, Dict]:
    """
    Load ground truth data from CSV file.
    
    Args:
        ground_truth_csv: Path to the ground truth CSV file
        
    Returns:
        Dictionary mapping test names to ground truth information
    """
    ground_truth = {}
    
    with open(ground_truth_csv, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith('#'):  # Skip comments and empty rows
                continue
            
            test_name = row[0]
            category = row[1] if len(row) > 1 else ""
            is_vulnerable = row[2] if len(row) > 2 else ""
            cwe = row[3] if len(row) > 3 else ""
            
            ground_truth[test_name] = {
                'category': category,
                'is_vulnerable': is_vulnerable.lower() == 'true',
                'cwe': cwe,
                'expected_result': 'Vulnerable' if is_vulnerable.lower() == 'true' else 'Safe'
            }
    
    return ground_truth


def parse_llm_response(response_file: str) -> Dict:
    """
    Parse LLM response from a text file with flexible JSON extraction.
    
    This function handles various response formats:
    - Pure JSON
    - JSON wrapped in markdown code blocks
    - Mixed content with JSON embedded
    - Responses with explanatory text before/after JSON
    
    Args:
        response_file: Path to the LLM response file
        
    Returns:
        Dictionary containing parsed response data
    """
    try:
        with open(response_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        
        if not content:
            return {'error': 'Empty response file'}
        
        # Method 1: Try to parse the entire content as JSON first
        try:
            response_data = json.loads(content)
            return response_data
        except json.JSONDecodeError:
            pass
        
        # Method 2: Look for JSON wrapped in markdown code blocks
        # Handle ```json ... ``` format
        if '```json' in content:
            start_marker = '```json'
            end_marker = '```'
            start_idx = content.find(start_marker) + len(start_marker)
            end_idx = content.rfind(end_marker)
            if end_idx > start_idx:
                json_content = content[start_idx:end_idx].strip()
                try:
                    response_data = json.loads(json_content)
                    return response_data
                except json.JSONDecodeError:
                    pass
        
        # Method 3: Look for JSON wrapped in generic code blocks
        # Handle ``` ... ``` format (without json specifier)
        if '```' in content:
            # Find all code block markers
            markers = []
            for i, char in enumerate(content):
                if content[i:i+3] == '```':
                    markers.append(i)
            
            # Try each code block as potential JSON
            for i in range(0, len(markers), 2):
                if i + 1 < len(markers):
                    start_idx = markers[i] + 3
                    end_idx = markers[i + 1]
                    if end_idx > start_idx:
                        json_content = content[start_idx:end_idx].strip()
                        try:
                            response_data = json.loads(json_content)
                            return response_data
                        except json.JSONDecodeError:
                            continue
        
        # Method 4: Look for JSON-like content using regex patterns
        import re
        
        # Pattern 1: Look for content between curly braces that might be JSON
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        matches = re.findall(json_pattern, content, re.DOTALL)
        
        for match in matches:
            try:
                response_data = json.loads(match)
                return response_data
            except json.JSONDecodeError:
                continue
        
        # Pattern 2: Look for content that starts with { and ends with }
        # This handles cases where the JSON might be incomplete or have extra content
        brace_start = content.find('{')
        brace_end = content.rfind('}')
        
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            potential_json = content[brace_start:brace_end + 1]
            try:
                response_data = json.loads(potential_json)
                return response_data
            except json.JSONDecodeError:
                pass
        
        # Method 5: Try to clean up common formatting issues and parse
        cleaned_content = content
        
        # Remove common prefixes that might appear before JSON
        prefixes_to_remove = [
            'Here is the analysis:',
            'Analysis:',
            'Response:',
            'The vulnerability analysis:',
            'Based on the code:',
            'Code analysis:',
            'Security assessment:',
            'Vulnerability assessment:',
            'Here is my assessment:',
            'My analysis:',
            'The code analysis reveals:',
            'After analyzing the code:',
            'Based on my analysis:',
            'Here is what I found:',
            'I found:',
            'The result is:',
            'Result:',
            'Answer:',
            'Here is the answer:',
            'The answer is:'
        ]
        
        for prefix in prefixes_to_remove:
            if cleaned_content.startswith(prefix):
                cleaned_content = cleaned_content[len(prefix):].strip()
                break
        
        # Remove common suffixes that might appear after JSON
        suffixes_to_remove = [
            'This concludes the analysis.',
            'End of analysis.',
            'Analysis complete.',
            'That\'s my assessment.',
            'Hope this helps!',
            'Let me know if you need clarification.',
            'Please let me know if you have any questions.',
            'Feel free to ask if you need more details.',
            'I hope this analysis is helpful.',
            'This is my security assessment.',
            'The analysis is complete.',
            'End of security assessment.',
            'That completes my analysis.',
            'This is my finding.',
            'My assessment is complete.'
        ]
        
        for suffix in suffixes_to_remove:
            if cleaned_content.endswith(suffix):
                cleaned_content = cleaned_content[:-len(suffix)].strip()
                break
        
        # Try to parse the cleaned content
        try:
            response_data = json.loads(cleaned_content)
            return response_data
        except json.JSONDecodeError:
            pass
        
        # Method 6: Look for key-value patterns and construct a dict manually
        # This is a fallback for cases where the response has structured content but not valid JSON
        manual_dict = {}
        
        # Common patterns for security analysis responses
        patterns = [
            (r'False Positive[:\s]+(Yes|No)', 'False Positive'),
            (r'Sanitization Found[:\s]+(Yes|No|Unsure)', 'Sanitization Found?'),
            (r'Attack Feasible[:\s]+(Yes|No)', 'Attack Feasible?'),
            (r'Confidence[:\s]+(Low|Medium|High)', 'Confidence'),
            (r'Vulnerability[:\s]+(Yes|No|True|False)', 'Vulnerability'),
            (r'Risk Level[:\s]+(Low|Medium|High|Critical)', 'Risk Level'),
            (r'Severity[:\s]+(Low|Medium|High|Critical)', 'Severity'),
            (r'Impact[:\s]+(Low|Medium|High|Critical)', 'Impact'),
            (r'Exploitability[:\s]+(Low|Medium|High|Critical)', 'Exploitability')
        ]
        
        for pattern, key in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                manual_dict[key] = match.group(1)
        
        if manual_dict:
            return manual_dict
        
        # If all methods fail, return error information
        return {
            'error': 'Could not extract valid JSON from response',
            'content_preview': content[:200] + '...' if len(content) > 200 else content,
            'file': response_file
        }
        
    except Exception as e:
        return {'error': f'Parse error: {e}', 'file': response_file}


def extract_test_name_from_filename(filename: str) -> str:
    """
    Extract test name from response filename.
    
    Args:
        filename: Response filename (e.g., "BenchmarkTest00105_java_java_concatenated-sql-query_0_gpt-4o.txt")
        
    Returns:
        Test name (e.g., "BenchmarkTest00105")
    """
    # Remove file extension
    name = filename.replace('.txt', '')
    
    # Extract the test name (everything before the first underscore after the test number)
    parts = name.split('_')
    if len(parts) >= 1:
        # Find the part that starts with "BenchmarkTest" followed by numbers
        for part in parts:
            if part.startswith('BenchmarkTest') and any(c.isdigit() for c in part):
                return part
    
    return name


def discover_response_keys(responses_dir: str) -> Set[str]:
    """
    Discover all possible JSON keys from LLM responses.
    
    Args:
        responses_dir: Directory containing response files
        
    Returns:
        Set of all unique keys found across responses
    """
    all_keys = set()
    response_files = [f for f in os.listdir(responses_dir) if f.endswith('.txt')]
    
    print(f"Discovering response keys from {len(response_files)} response files...")
    
    for response_file in response_files[:10]:  # Check first 10 files for key discovery
        response_path = os.path.join(responses_dir, response_file)
        try:
            response_data = parse_llm_response(response_path)
            if isinstance(response_data, dict):
                all_keys.update(response_data.keys())
        except Exception as e:
            print(f"Warning: Could not parse {response_file} for key discovery: {e}")
    
    print(f"Discovered {len(all_keys)} unique keys: {sorted(all_keys)}")
    return all_keys


def evaluate_run(ground_truth_csv: str, cwe_number: str, run_folder: str, model: str = None) -> str:
    """
    Evaluate all responses in a run folder against ground truth.
    Args:
        ground_truth_csv: Path to ground truth CSV file
        cwe_number: CWE number (e.g., "CWE-089")
        run_folder: Path to run folder containing responses
        model: Model name (e.g., "gpt-4o")
    Returns:
        Path to the generated filtered evaluation CSV file
    """
    print(f"Starting evaluation for {cwe_number} in {run_folder}")
    if model:
        print(f"Model: {model}")
    
    # Load ground truth data
    print("Loading ground truth data...")
    ground_truth = load_ground_truth(ground_truth_csv)
    print(f"Loaded {len(ground_truth)} ground truth entries")
    
    # Find responses directory
    responses_dir = os.path.join(run_folder, "responses")
    if not os.path.exists(responses_dir):
        raise FileNotFoundError(f"Responses directory not found: {responses_dir}")
    
    # Discover response keys dynamically
    response_keys = discover_response_keys(responses_dir)
    
    # Get all response files
    response_files = [f for f in os.listdir(responses_dir) if f.endswith('.txt')]
    print(f"Found {len(response_files)} response files")
    
    # Process each response
    results = []
    processed_count = 0
    
    for response_file in response_files:
        response_path = os.path.join(responses_dir, response_file)
        test_name = extract_test_name_from_filename(response_file)
        gt_info = ground_truth.get(test_name, {
            'category': 'Unknown',
            'is_vulnerable': False,
            'cwe': 'Unknown',
            'expected_result': 'Unknown'
        })
        llm_response = parse_llm_response(response_path)
        result_row = {
            'test_name': test_name,
            'response_file': response_file,
            'ground_truth_category': gt_info['category'],
            'ground_truth_is_vulnerable': gt_info['is_vulnerable'],
            'ground_truth_cwe': gt_info['cwe'],
            'ground_truth_expected': gt_info['expected_result']
        }
        if isinstance(llm_response, dict):
            for key in response_keys:
                llm_key = f'llm_{key}'
                result_row[llm_key] = llm_response.get(key, '')
        else:
            for key in response_keys:
                llm_key = f'llm_{key}'
                result_row[llm_key] = 'ERROR: Invalid response format'
        results.append(result_row)
        processed_count += 1
        if processed_count % 10 == 0:
            print(f"Processed {processed_count}/{len(response_files)} responses...")
    # Compose base filename
    model_part = f"_{model}" if model else ""
    base_filename = f"evaluation_{cwe_number}{model_part}"
    # Write unfiltered CSV
    import pandas as pd
    ground_truth_columns = [
        'test_name', 'response_file', 'ground_truth_category', 
        'ground_truth_is_vulnerable', 'ground_truth_cwe', 'ground_truth_expected'
    ]
    llm_columns = [f'llm_{key}' for key in sorted(response_keys)]
    all_columns = ground_truth_columns + llm_columns
    unfiltered_csv = os.path.join(run_folder, f"{base_filename}_unfiltered.csv")
    df = pd.DataFrame(results, columns=all_columns)
    df.to_csv(unfiltered_csv, index=False)
    print(f"Unfiltered evaluation saved to: {unfiltered_csv}")
    # Filter rows by CWE (compare numeric part, ignore leading zeros)
    def normalize_cwe(val):
        try:
            return str(int(str(val).replace('CWE-', '').lstrip('0')))
        except Exception:
            return str(val)
    exp_cwe_num = normalize_cwe(cwe_number)
    filtered_df = df[df['ground_truth_cwe'].apply(normalize_cwe) == exp_cwe_num]
    filtered_csv = os.path.join(run_folder, f"{base_filename}.csv")
    filtered_df.to_csv(filtered_csv, index=False)
    print(f"Filtered evaluation saved to: {filtered_csv} (rows with ground_truth_cwe == {cwe_number})")
    return filtered_csv


def main():
    """Main function to run the evaluation."""
    parser = argparse.ArgumentParser(
        description='Evaluate LLM analysis results against ground truth data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python evaluate_results.py --ground_truth input_files/ground_truth/expectedresults-1.2.csv --cwe CWE-089 --run_folder results/exact_location_test_CWE-089_gpt-4o
  python evaluate_results.py -gt input_files/ground_truth/expectedresults-1.2.csv -c CWE-089 -rf results/my_run_CWE-089_gpt-4o
        """
    )
    
    parser.add_argument(
        '--ground_truth', '-gt',
        required=True,
        help='Path to the ground truth CSV file'
    )
    
    parser.add_argument(
        '--cwe', '-c',
        required=True,
        help='CWE number (e.g., CWE-089)'
    )
    
    parser.add_argument(
        '--run_folder', '-rf',
        required=True,
        help='Path to the run folder containing responses'
    )
    
    parser.add_argument(
        '--model', '-m',
        required=False,
        help='Model name (e.g., gpt-4o)'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.ground_truth):
        print(f"Error: Ground truth file not found: {args.ground_truth}")
        sys.exit(1)
    
    if not os.path.exists(args.run_folder):
        print(f"Error: Run folder not found: {args.run_folder}")
        sys.exit(1)
    
    # Run evaluation
    try:
        output_csv = evaluate_run(args.ground_truth, args.cwe, args.run_folder, args.model)
        print(f"\n✅ Evaluation completed successfully!")
        print(f"📊 Results saved to: {output_csv}")
        
    except Exception as e:
        print(f"❌ Evaluation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 