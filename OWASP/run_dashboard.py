#!/usr/bin/env python3
"""
Launcher script for OWASP Experiment Analysis Dashboard
"""

import subprocess
import sys
import os
from pathlib import Path

def run_dashboard():
    """Run the Streamlit dashboard"""
    print("🚀 Starting OWASP Experiment Analysis Dashboard...")
    print("📊 Dashboard will open in your browser at: http://localhost:8501")
    print("🛑 Press Ctrl+C to stop the dashboard")
    print("-" * 50)
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "streamlit_dashboard.py",
            "--server.port", "8501",
            "--server.address", "localhost"
        ])
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
    except Exception as e:
        print(f"❌ Error running dashboard: {e}")

def check_data():
    """Check if experiment data exists"""
    results_dir = Path("dashboard-data")
    if not results_dir.exists():
        print("⚠️  Warning: 'dashboard-data' directory not found!")
        print("   The dashboard will work but may not display data.")
        print("   Make sure your experiment results are in the 'dashboard-data' folder.")
        return False
    
    csv_files = list(results_dir.glob("**/*.csv"))
    if not csv_files:
        print("⚠️  Warning: No CSV files found in dashboard-data directory!")
        print("   The dashboard will work but may not display data.")
        return False
    
    print(f"✅ Found {len(csv_files)} CSV files in dashboard-data directory")
    return True

def main():
    print("\U0001F52C OWASP Experiment Analysis Dashboard Launcher")
    print("=" * 50)
    
    # Check data
    check_data()
    print()
    
    # Run dashboard
    run_dashboard()

if __name__ == "__main__":
    main() 