import os
import sys
import json
import tiktoken
import time
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from reusables.argument import Arguments
from llm_api_handler import send_to_llm, test_model_connectivity, validate_api_key

def extract_location_info(location_obj):
    region = location_obj.get("region", {})
    return {
        "file": location_obj["artifactLocation"]["uri"],
        "startLine": region.get("startLine"),
        "endLine": region.get("endLine", region.get("startLine")),
        "startColumn": region.get("startColumn"),
        "endColumn": region.get("endColumn")
    }

def parse_sarif_to_jsonl(sarif_path, output_jsonl_path):
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    parsed_results = []

    for result in sarif_data["runs"][0]["results"]:
        entry = {
            "ruleId": result.get("ruleId"),
            "message": result.get("message", {}).get("text"),
            "locations": [],
            "relatedLocations": []
        }

        for loc in result.get("locations", []):
            pl = loc.get("physicalLocation", {})
            if pl:
                entry["locations"].append(extract_location_info(pl))

        for rloc in result.get("relatedLocations", []):
            pl = rloc.get("physicalLocation", {})
            rentry = extract_location_info(pl)
            rentry["message"] = rloc.get("message", {}).get("text")
            entry["relatedLocations"].append(rentry)

        if "codeFlows" in result:
            entry["codeFlow"] = []
            for codeflow in result["codeFlows"]:
                for threadflow in codeflow.get("threadFlows", []):
                    for loc in threadflow.get("locations", []):
                        loc_entry = {}
                        physical = loc.get("location", {}).get("physicalLocation", {})
                        if physical:
                            loc_entry.update(extract_location_info(physical))
                        message = loc.get("location", {}).get("message", {}).get("text")
                        if message:
                            loc_entry["message"] = message
                        taxa_list = loc.get("taxa", [])
                        for taxa in taxa_list:
                            properties = taxa.get("properties", {})
                            if properties:
                                loc_entry.update(properties)
                        entry["codeFlow"].append(loc_entry)

        parsed_results.append(entry)

    with open(output_jsonl_path, "w", encoding="utf-8") as out_file:
        for result in parsed_results:
            out_file.write(json.dumps(result, ensure_ascii=False) + "\n")

def extract_imports(lines: List[str]) -> str:
    """Extract all import statements from the file."""
    imports = []
    for line in lines:
        if line.strip().startswith("import "):
            imports.append(line)
    return "".join(imports)

def extract_code_snippet(
    file_path: str,
    start_line: int,
    end_line: int = None,
    start_column: int = None,
    end_column: int = None,
    margin_lines: int = 3,
    base_path: str = ".",
    mode: str = "fixed_lines",
    context_level: str = "both",  # "function", "class", or "both"
    is_dataflow_step: bool = False  # New parameter to indicate if this is a dataflow step
) -> str:
    """
    Extracts a code snippet from the given file with surrounding context.

    Parameters:
    - file_path: Relative path to the source file.
    - start_line: Starting line number of the target region.
    - end_line: Ending line number of the target region (optional; defaults to start_line).
    - start_column: Starting column within the first line (optional).
    - end_column: Ending column within the last line (optional).
    - margin_lines: Number of lines of context before and after (used in fixed_lines mode).
    - base_path: Root path to resolve the file.
    - mode: Extraction mode - "fixed_lines", "whole_block", or "function"
    - context_level: Level of context to extract - "function", "class", or "both"
    - is_dataflow_step: Whether this snippet is part of a dataflow step

    Returns:
    - A string of the extracted code snippet.
    """
    try:
        full_path = os.path.join(base_path, file_path)
        with open(full_path, "r") as f:
            lines = f.readlines()

        # Normalize indices
        start_line = max(1, start_line)
        end_line = end_line if end_line else start_line

        if mode == "fixed_lines":
            start_idx = max(0, start_line - 1 - margin_lines)
            end_idx = min(len(lines), end_line + margin_lines)
            snippet_lines = lines[start_idx:end_idx]

            # Highlight region if column info is present and it's a single-line region
            if start_line == end_line and start_column is not None and end_column is not None:
                highlight_idx = start_line - 1 - start_idx
                if 0 <= highlight_idx < len(snippet_lines):
                    line = snippet_lines[highlight_idx]
                    if is_dataflow_step:
                        # Add a comment to mark dataflow step
                        snippet_lines[highlight_idx] = (
                            line[:start_column - 1] +
                            "[[[" + line[start_column - 1:end_column] + "]]]" +
                            line[end_column:] +
                            " // [DATAFLOW STEP]"
                        )
                    else:
                        snippet_lines[highlight_idx] = (
                            line[:start_column - 1] +
                            "[[[" + line[start_column - 1:end_column] + "]]]" +
                            line[end_column:]
                        )

        elif mode in ["whole_block", "function"]:
            # Extract imports first
            imports = extract_imports(lines)
            
            # Find the start of the function
            func_start_idx = 0
            for i in range(start_line - 1, -1, -1):
                line = lines[i].strip()
                if any(keyword in line for keyword in ["public", "private", "protected", "static"]):
                    if line.endswith("{"):
                        func_start_idx = i
                        break
                    elif i + 1 < len(lines) and lines[i + 1].strip().startswith("{"):
                        func_start_idx = i
                        break

            # Find the end of the function
            func_end_idx = len(lines)
            brace_count = 0
            found_start = False
            
            for i in range(func_start_idx, len(lines)):
                line = lines[i]
                if not found_start and "{" in line:
                    found_start = True
                
                if found_start:
                    brace_count += line.count("{") - line.count("}")
                    if brace_count == 0:
                        func_end_idx = i + 1
                        break

            if mode == "function":
                # For function mode, just return the function
                snippet_lines = lines[func_start_idx:func_end_idx]
                if imports:
                    snippet_lines.insert(0, imports)
            else:  # whole_block mode
                # If we want class context, find the containing class
                class_start_idx = 0
                class_end_idx = len(lines)
                
                if context_level in ["class", "both"]:
                    # Find class start
                    for i in range(func_start_idx, -1, -1):
                        line = lines[i].strip()
                        if "class " in line or "interface " in line:
                            class_start_idx = i
                            break

                    # Find class end
                    brace_count = 0
                    found_start = False
                    for i in range(class_start_idx, len(lines)):
                        line = lines[i]
                        if not found_start and "{" in line:
                            found_start = True
                        
                        if found_start:
                            brace_count += line.count("{") - line.count("}")
                            if brace_count == 0:
                                class_end_idx = i + 1
                                break

                # Combine the contexts based on context_level
                if context_level == "function":
                    snippet_lines = lines[func_start_idx:func_end_idx]
                elif context_level == "class":
                    snippet_lines = lines[class_start_idx:class_end_idx]
                else:  # both
                    snippet_lines = lines[min(func_start_idx, class_start_idx):max(func_end_idx, class_end_idx)]

                # Add imports at the beginning
                if imports:
                    snippet_lines.insert(0, imports)

            # Mark dataflow step lines if needed
            if is_dataflow_step:
                for i in range(len(snippet_lines)):
                    if i + func_start_idx == start_line - 1:  # Adjust for the actual line number
                        if start_column is not None and end_column is not None:
                            line = snippet_lines[i]
                            snippet_lines[i] = (
                                line[:start_column - 1] +
                                "[[[" + line[start_column - 1:end_column] + "]]]" +
                                line[end_column:] +
                                " // [DATAFLOW STEP]"
                            )
                        else:
                            snippet_lines[i] = snippet_lines[i].rstrip() + " // [DATAFLOW STEP]\n"
            
            # Check if the block exceeds the maximum size limit
            MAX_BLOCK_SIZE = 500
            if len(snippet_lines) > MAX_BLOCK_SIZE:
                print(f"Warning: Block in {file_path} exceeds maximum size limit of {MAX_BLOCK_SIZE} lines. Truncating to first {MAX_BLOCK_SIZE} lines.")
                snippet_lines = snippet_lines[:MAX_BLOCK_SIZE]
                snippet_lines.append("\n// ... [Block truncated due to size limit] ...\n")

        else:
            raise ValueError(f"Invalid mode: {mode}. Must be 'fixed_lines', 'whole_block', or 'function'")

        return "".join(snippet_lines).strip()

    except Exception as e:
        return f"[Error extracting code from {file_path}: {e}]"


# Load the prompt template from file
def load_prompt_template(template_path):
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()
    
    
# Format dataflow block
def build_dataflow_section(codeflow_list, base_path):
    if not codeflow_list:
        return "No dataflow information is available for this finding."

    steps = []
    for idx, step in enumerate(codeflow_list, start=1):
        # Determine if this is source or sink
        if idx == 1:
            step_type = "SOURCE"
        elif idx == len(codeflow_list):
            step_type = "SINK"
        else:
            step_type = "STEP"
        
        # Extract the actual code snippet for this dataflow step
        snippet = extract_code_snippet(
            file_path=step["file"],
            start_line=step["startLine"],
            end_line=step.get("endLine", step["startLine"]),
            start_column=step.get("startColumn"),
            end_column=step.get("endColumn"),
            margin_lines=0,  # No margin for dataflow steps
            base_path=base_path,
            mode="fixed_lines",
            is_dataflow_step=True  # Mark this as a dataflow step
        )
        
        # Format the step with proper labeling
        steps.append(f"[{idx}] {step_type}:\n{snippet}")
        
        # Add message if available
        if step.get("message"):
            steps.append(f"Message: {step['message']}")

    return "\n\n".join(steps)


def extract_vulnerability_location(json_obj, base_path):
    """Extract the specific vulnerability location from the JSONL data."""
    if not json_obj.get("locations"):
        return "No location information available."
    
    loc = json_obj["locations"][0]
    
    # Read the file to get the exact line
    try:
        full_path = os.path.join(base_path, loc["file"])
        with open(full_path, "r") as f:
            lines = f.readlines()
        
        # Get the vulnerable line (1-indexed to 0-indexed)
        line_number = loc["startLine"]
        if line_number <= len(lines):
            vulnerable_line = lines[line_number - 1].rstrip('\n')
        else:
            vulnerable_line = "Line not found in file"
            
    except Exception as e:
        vulnerable_line = f"Error reading file: {e}"
    
    # Highlight the specific vulnerable part if column information is available
    if loc.get("startColumn") and loc.get("endColumn"):
        start_col = loc["startColumn"] - 1  # Convert to 0-indexed
        end_col = loc["endColumn"] - 1      # Convert to 0-indexed
        
        if start_col < len(vulnerable_line) and end_col <= len(vulnerable_line):
            highlighted_line = (
                vulnerable_line[:start_col] +
                "[[[" + vulnerable_line[start_col:end_col] + "]]]" +
                vulnerable_line[end_col:]
            )
        else:
            highlighted_line = vulnerable_line
    else:
        highlighted_line = vulnerable_line
    
    # Create plain English explanation
    vulnerable_part = vulnerable_line[loc.get("startColumn", 1) - 1:loc.get("endColumn", len(vulnerable_line))]
    explanation = f'"{vulnerable_part}" in the following line of code (line {line_number}) has been detected by CodeQL as the vulnerability location'
    
    return f"{explanation}:\n\n{highlighted_line}"

# Create full prompt from a JSON record
def create_prompt_from_warning(json_obj, prompt_template, base_path):
    """
    Create a prompt from a warning with the whole code snippet and dataflow analysis.
    
    Parameters:
    - json_obj: The warning JSON object
    - prompt_template: The template to use for the prompt
    - base_path: Base path for resolving file paths
    """
    rule_id = json_obj.get("ruleId", "unknown")
    
    # Handle message field which can be either a string or a dictionary
    message_obj = json_obj.get("message", {})
    if isinstance(message_obj, dict):
        message = message_obj.get("text", "No message")
    else:
        message = str(message_obj) if message_obj else "No message"
    
    loc = json_obj["locations"][0]
    
    # Extract the whole code snippet containing the vulnerability
    main_snippet = extract_code_snippet(
        file_path=loc["file"],
        start_line=loc["startLine"],
        end_line=loc.get("endLine"),
        start_column=loc.get("startColumn"),
        end_column=loc.get("endColumn"),
        margin_lines=3,
        base_path=base_path,
        mode="whole_block"
    )
    
    # Extract the specific vulnerability location
    vulnerability_location = extract_vulnerability_location(json_obj, base_path)
    
    # Build dataflow section from the parsed JSONL data
    dataflow_section = build_dataflow_section(json_obj.get("codeFlow", []), base_path)
    
    return prompt_template.format(
        rule_id=rule_id,
        message=message,
        main_snippet=main_snippet,
        vulnerability_location=vulnerability_location,
        dataflow_section=dataflow_section
    )

def extract_cwe_id(sarif_file_path: str) -> str:
    """Extract CWE ID from SARIF file path."""
    filename = os.path.basename(sarif_file_path)
    # Extract CWE number from filename like "owasp-benchmark-CWE-089.sarif"
    if "CWE-" in filename:
        cwe_part = filename.split("CWE-")[1]
        cwe_id = cwe_part.split(".")[0]
        return f"CWE-{cwe_id}"
    return "UNKNOWN"

def create_run_directories(prompt_version: str, dataset: str, cwe_id: str, model: str, base_dir: str = "results") -> tuple:
    """
    Create directories for the current run with naming convention {promptversion}_{dataset}_{CWE}_{model}.
    
    Returns:
    - tuple: (run_dir, prompts_dir, responses_dir, jsonl_file_path)
    """
    # Create the main run directory - replace forward slashes with underscores for safe directory names
    safe_model_name = model.replace("/", "_")
    run_dir_name = f"{prompt_version}_{dataset}_{cwe_id}_{safe_model_name}"
    run_dir = os.path.join(base_dir, run_dir_name)
    
    # Create subdirectories
    prompts_dir = os.path.join(run_dir, "prompts")
    responses_dir = os.path.join(run_dir, "responses")
    
    # Create all directories
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(prompts_dir, exist_ok=True)
    os.makedirs(responses_dir, exist_ok=True)
    
    # JSONL file path within the run directory
    jsonl_file_path = os.path.join(run_dir, "parsed_results.jsonl")
    
    print(f"Created run directory: {run_dir}")
    print(f"  - Prompts: {prompts_dir}")
    print(f"  - Responses: {responses_dir}")
    print(f"  - JSONL: {jsonl_file_path}")
    
    return run_dir, prompts_dir, responses_dir, jsonl_file_path

def process_batch(batch: List[Tuple[str, str, str, str]], model: str, temperature: float, 
                 enable_token_counting: bool, prompts_dir: str, responses_dir: str) -> List[bool]:
    """
    Process a batch of prompts concurrently.
    
    Args:
        batch: List of tuples (filename_stub, prompt, prompt_path, rule_id)
        model: LLM model to use
        temperature: Temperature for LLM
        enable_token_counting: Whether to enable token counting
        prompts_dir: Directory to save prompts
        responses_dir: Directory to save responses
    
    Returns:
        List of boolean success indicators
    """
    results = [False] * len(batch)
    
    def process_single_prompt(idx: int, filename_stub: str, prompt: str, prompt_path: str, rule_id: str):
        try:
            # Save prompt to file
            with open(prompt_path, 'w', encoding='utf-8') as pf:
                pf.write(prompt)
            
            # Send to LLM
            response = send_to_llm(prompt, model, temperature, enable_token_counting)
            
            # Save response to file
            response_path = os.path.join(responses_dir, f"{filename_stub}.txt")
            with open(response_path, 'w', encoding='utf-8') as rf:
                rf.write(response)
            
            results[idx] = True
            print(f"✅ Processed {filename_stub} (Rule: {rule_id})")
            
        except Exception as e:
            print(f"❌ Error processing {filename_stub}: {e}")
            results[idx] = False
    
    # Process all prompts in the batch concurrently
    with ThreadPoolExecutor(max_workers=len(batch)) as executor:
        futures = []
        for idx, (filename_stub, prompt, prompt_path, rule_id) in enumerate(batch):
            future = executor.submit(process_single_prompt, idx, filename_stub, prompt, prompt_path, rule_id)
            futures.append(future)
        
        # Wait for all to complete
        for future in as_completed(futures):
            future.result()
    
    return results

def main():
    # Parse command line arguments
    args = Arguments.parse()
    
    # Validate API key
    if not validate_api_key():
        sys.exit(1)
    
    # Set up paths
    sarif_file_path = os.path.abspath(args.sarif_file)
    project_src_root = os.path.abspath(args.project_src_root)
    CODEBASE_PATH = project_src_root
    
    # Use provided run ID and extract CWE ID
    run_id = args.run_id
    cwe_id = extract_cwe_id(sarif_file_path)
    
    print(f"Starting analysis for {cwe_id} with run ID: {run_id}")
    print(f"Model: {args.model}")
    print(f"Prompt version: {args.prompt_version}")
    print(f"SARIF file: {sarif_file_path}")
    print(f"Source root: {project_src_root}")
    print(f"Token counting: {'Enabled' if args.enable_token_counting else 'Disabled'}")
    
    # Test OpenAI connectivity
    print("Testing OpenAI connectivity...")
    if not test_model_connectivity(args.model):
        sys.exit(1)
    
    # Create run directories with automatic naming
    run_dir, prompts_dir, responses_dir, jsonl_file_path = create_run_directories(
        args.prompt_version, "owasp", cwe_id, args.model
    )
    
    # Parse SARIF to JSONL in the run directory
    parse_sarif_to_jsonl(sarif_file_path, jsonl_file_path)
    
    # Load prompt template based on CWE ID and version
    if args.template_path:
        # Use custom template path if provided
        template_path = args.template_path
        print(f"Using custom template: {template_path}")
    else:
        # Auto-detect template based on CWE ID and version
        prompt_version = args.prompt_version
        template_path = f"input_files/prompt_templates/{prompt_version}/{cwe_id}.txt"
        
        if not os.path.exists(template_path):
            print(f"Warning: Template file {template_path} not found. Trying default version (baseline)...")
            # Fallback to default version (v)
            template_path = f"input_files/prompt_templates/baseline/{cwe_id}.txt"
            
            if not os.path.exists(template_path):
                print(f"Warning: Template file {template_path} not found. Using default CWE-089 template.")
                template_path = f"input_files/prompt_templates/{prompt_version}/CWE-089.txt"
                
                if not os.path.exists(template_path):
                    template_path = "input_files/prompt_templates/baseline/CWE-089.txt"
        else:
            print(f"Using CWE-specific template (version {prompt_version}): {template_path}")
    
    template = load_prompt_template(template_path)

    # Collect all prompts first
    all_prompts = []
    skipped_count = 0
    
    print("Collecting prompts from JSONL file...")
    with open(jsonl_file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            try:
                warning = json.loads(line)
                rule_id = warning["ruleId"].replace("/", "_")
                
                # Get the main source file from the first location
                source_file = warning["locations"][0]["file"]
                source_filename = os.path.basename(source_file).replace(".", "_")  # safe for filenames

                # Create filename for this finding - replace forward slashes with underscores for safe filenames
                safe_model_name = args.model.replace("/", "_")
                filename_stub = f"{source_filename}_{rule_id}_{idx}_{safe_model_name}"

                # Skip if response already exists
                if os.path.exists(os.path.join(responses_dir, filename_stub + ".txt")):
                    print(f"⏭️ Skipping {filename_stub} because response already exists")
                    skipped_count += 1
                    continue
                
                # Generate prompt with whole code snippet and parsed dataflow
                prompt = create_prompt_from_warning(warning, template, base_path=CODEBASE_PATH)
                prompt_path = os.path.join(prompts_dir, filename_stub + ".txt")
                
                all_prompts.append((filename_stub, prompt, prompt_path, rule_id))

            except Exception as e:
                print(f"Error processing line {idx}: {e}")
    
    print(f"Collected {len(all_prompts)} prompts to process, {skipped_count} already exist")

    if not all_prompts:
        print("No prompts to process!")
        print(f"\nResults saved in: {run_dir}")
        return

    # Get batch size from arguments
    batch_size = args.batch_size
    max_workers = args.max_workers
    
    print(f"Batch processing: {batch_size} prompts concurrently, max {max_workers} workers")
    
    # Process prompts in batches
    total_batches = (len(all_prompts) + batch_size - 1) // batch_size
    print(f"Processing {len(all_prompts)} prompts in {total_batches} batches of size {batch_size}")
    
    start_time = time.time()
    successful_count = 0
    failed_count = 0
    
    for batch_idx in range(0, len(all_prompts), batch_size):
        batch = all_prompts[batch_idx:batch_idx + batch_size]
        batch_num = batch_idx // batch_size + 1
        
        print(f"\n🔄 Processing batch {batch_num}/{total_batches} ({len(batch)} prompts)")
        batch_start_time = time.time()
        
        # Process this batch concurrently
        batch_results = process_batch(
            batch, args.model, args.temperature, args.enable_token_counting, 
            prompts_dir, responses_dir
        )
        
        # Update counts
        batch_success = sum(batch_results)
        batch_failed = len(batch_results) - batch_success
        successful_count += batch_success
        failed_count += batch_failed
        
        batch_time = time.time() - batch_start_time
        print(f"✅ Batch {batch_num} completed in {batch_time:.1f}s - "
              f"Success: {batch_success}, Failed: {batch_failed}")
    
    total_time = time.time() - start_time
    print(f"\n🎉 All batches completed in {total_time:.1f}s")
    print(f"📊 Final results: {successful_count} successful, {failed_count} failed, {skipped_count} skipped")
    print(f"⚡ Average time per prompt: {total_time/len(all_prompts):.2f}s")
    print(f"\nResults saved in: {run_dir}")

if __name__ == '__main__':
    main()
