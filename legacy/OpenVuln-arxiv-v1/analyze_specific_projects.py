#!/usr/bin/env python3
"""
Analyze specific projects with OpenRouter.
This script processes only the projects specified by the user.
"""

import os
import pandas as pd
from pathlib import Path
from generate_prompts_with_openrouter import OpenRouterPromptGenerator

def main():
    """Main function to analyze specific projects."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze specific projects with OpenRouter")
    parser.add_argument("--api-key", help="OpenRouter API key")
    parser.add_argument("--model", default="openai/gpt-4o-mini", help="Model to use")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between API calls")
    
    args = parser.parse_args()
    
    # List of OpenVuln projects to analyze (7 specific projects)
    target_projects = [
        "jeremylong__DependencyCheck_CVE-2018-12036_3.1.2",
        "apache__jspwiki_CVE-2022-46907_2.11.3",
        "keycloak__keycloak_CVE-2022-4361_21.1.1",
        "zeroturnaround__zt-zip_CVE-2018-1002201_1.12",
        "undertow-io__undertow_CVE-2014-7816_1.0.16.Final",
        "hapifhir__org.hl7.fhir.core_CVE-2023-28465_5.6.105",
        "perwendel__spark_CVE-2016-9177_2.5.1"
    ]
    
    print("🎯 Analyzing Specific Projects with OpenRouter")
    print("=" * 50)
    print(f"Target projects: {len(target_projects)}")
    print()
    
    # Check for API key (command line argument or environment variable)
    api_key = args.api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("❌ OpenRouter API key not found!")
        print("Please provide your API key using one of these methods:")
        print("1. Command line argument: --api-key 'your-api-key-here'")
        print("2. Environment variable: export OPENROUTER_API_KEY='your-api-key-here'")
        print("\nGet your API key from: https://openrouter.ai/keys")
        return
    
    print("✅ OpenRouter API key found!")
    print()
    
    # Initialize the generator
    generator = OpenRouterPromptGenerator(api_key=api_key, model=args.model)
    
    # Filter the projects dataframe to only include target projects
    original_df = generator.projects_df
    filtered_df = original_df[original_df['project_slug'].isin(target_projects)]
    
    if len(filtered_df) == 0:
        print("❌ No matching projects found in the dataset!")
        print("Please check the project names.")
        return
    
    print(f"📊 Found {len(filtered_df)} matching projects in dataset:")
    for _, row in filtered_df.iterrows():
        print(f"  • {row['project_slug']} (CVE: {row['cve_id']}, CWE: {row['cwe_id']})")
    print()
    
    # Update the generator to use only filtered projects
    generator.projects_df = filtered_df
    
    # Set custom output directory for OpenVuln
    model_name = args.model.replace("/", "_").replace("-", "_")
    p = f"./results/optimized/{model_name}"
    generator.output_path = Path(p)
    
    print("🚀 Starting analysis...")
    print(f"Model: {args.model}")
    print(f"Delay between calls: {args.delay} seconds")
    print()
    
    try:
        # Process the specific projects
        results = generator.process_projects_with_openrouter(
            delay_between_calls=args.delay,
            model=args.model
        )
        
        # Save results
        generator.save_results_to_csv(results)
        
        print("✅ Analysis completed successfully!")
        print(f"📊 Processed {len(results)} alerts from {len(filtered_df)} projects")
        print(f"📁 Results saved to: {generator.output_path}")
        print()
        
        # Show summary
        if results:
            df = pd.DataFrame(results)
            print("📈 Summary:")
            print(f"  • Total alerts: {len(results)}")
            print(f"  • Unique CWEs: {df['CWE'].nunique()}")
            print(f"  • Unique CVEs: {df['CVE'].nunique()}")

            print("\nCWE Distribution:")
            cwe_counts = df['CWE'].value_counts()
            for cwe, count in cwe_counts.items():
                print(f"  • {cwe}: {count} alerts")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        print("Please check your API key and try again.")

if __name__ == "__main__":
    main()
