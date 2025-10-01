#!/usr/bin/env python3

import os
import pandas as pd
from collections import defaultdict
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def extract_run_info_from_folder(folder_path: str):
    """
    Extract prompt_version, dataset, CWE, and model from folder name.
    Expected format: {promptversion}_{dataset}_{CWE}_{model}
    """
    folder_name = os.path.basename(folder_path)
    parts = folder_name.split('_')
    
    if len(parts) < 4:
        raise ValueError(f"Invalid folder format: {folder_name}. Expected: {{promptversion}}_{{dataset}}_{{CWE}}_{{model}}")
    
    # Parse the new format: {promptversion}_{dataset}_{CWE}_{model}
    prompt_version = parts[0]
    dataset = parts[1]
    
    # Find CWE part (should contain "CWE-")
    cwe_part = None
    model_parts = []
    
    for i, part in enumerate(parts[2:], 2):
        if part.startswith("CWE-"):
            cwe_part = part
            # Everything after CWE is model parts
            model_parts = parts[i+1:]
            break
    
    if not cwe_part:
        raise ValueError(f"No CWE found in folder name: {folder_name}")
    
    model = "_".join(model_parts)
    
    return prompt_version, dataset, cwe_part, model

def find_evaluation_csv(run_folder: str):
    for filename in os.listdir(run_folder):
        if filename.startswith("evaluation_") and filename.endswith(".csv"):
            return os.path.join(run_folder, filename)
    return None

def count_detection_types(df):
    # Normalize columns
    df['gt'] = df['ground_truth_is_vulnerable'].astype(str).str.strip().str.lower()
    df['llm_fp'] = df['llm_False Positive'].astype(str).str.strip().str.lower()
    
    # Real vulnerabilities
    real_vuln = df[df['gt'] == 'true']
    real_vuln_as_vuln = (real_vuln['llm_fp'] == 'no').sum()
    real_vuln_as_fp = (real_vuln['llm_fp'] == 'yes').sum()
    n_real_vuln = len(real_vuln)
    
    # Not vulnerabilities
    not_vuln = df[df['gt'] == 'false']
    not_vuln_as_fp = (not_vuln['llm_fp'] == 'yes').sum()
    not_vuln_as_vuln = (not_vuln['llm_fp'] == 'no').sum()
    n_not_vuln = len(not_vuln)
    
    return {
        'real_vuln_as_vuln': real_vuln_as_vuln,
        'real_vuln_as_fp': real_vuln_as_fp,
        'n_real_vuln': n_real_vuln,
        'not_vuln_as_fp': not_vuln_as_fp,
        'not_vuln_as_vuln': not_vuln_as_vuln,
        'n_not_vuln': n_not_vuln,
        'real_vuln_as_vuln_pct': (real_vuln_as_vuln/n_real_vuln*100) if n_real_vuln > 0 else 0,
        'real_vuln_as_fp_pct': (real_vuln_as_fp/n_real_vuln*100) if n_real_vuln > 0 else 0,
        'not_vuln_as_fp_pct': (not_vuln_as_fp/n_not_vuln*100) if n_not_vuln > 0 else 0,
        'not_vuln_as_vuln_pct': (not_vuln_as_vuln/n_not_vuln*100) if n_not_vuln > 0 else 0
    }

def calculate_metrics(stats):
    """
    Calculate TP, FP, TN, FN and derived metrics based on stats dictionary
    """
    # Define confusion matrix elements based on your specification
    TP = int(stats['not_vuln_as_fp'])  # True Positive: not vulnerable correctly identified as FP
    FP = int(stats['real_vuln_as_fp'])  # False Positive: real vulnerable incorrectly identified as FP
    TN = int(stats['real_vuln_as_vuln'])  # True Negative: real vulnerable correctly identified as vulnerable
    FN = int(stats['not_vuln_as_vuln'])  # False Negative: not vulnerable incorrectly identified as vulnerable
    
    # Calculate derived metrics
    precision = float(TP / (TP + FP) if (TP + FP) > 0 else 0)
    recall = float(TP / (TP + FN) if (TP + FN) > 0 else 0)
    f1_score = float(2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0)
    accuracy = float((TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0)
    fpr = float(FP / (FP + TN) if (FP + TN) > 0 else 0)  # False Positive Rate
    
    return {
        'TP': TP,
        'FP': FP,
        'TN': TN,
        'FN': FN,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'accuracy': accuracy,
        'fpr': fpr
    }

def generate_csv_report(results_data):
    """Generate comprehensive CSV report with metrics"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"📁 Created directory: {reports_dir}")
    
    csv_data = []
    
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        metrics = calculate_metrics(stats)
        
        csv_data.append({
            'Run_ID': run_id,
            'CWE': cwe,
            'Model': model,
            'Total_Real_Vulnerabilities': stats['n_real_vuln'],
            'Real_Vuln_Detected_As_Vuln': stats['real_vuln_as_vuln'],
            'Real_Vuln_Detected_As_Vuln_Pct': round(stats['real_vuln_as_vuln_pct'], 1),
            'Real_Vuln_Mistakenly_As_FP': stats['real_vuln_as_fp'],
            'Real_Vuln_Mistakenly_As_FP_Pct': round(stats['real_vuln_as_fp_pct'], 1),
            'Total_Not_Vulnerabilities': stats['n_not_vuln'],
            'Not_Vuln_Detected_As_FP': stats['not_vuln_as_fp'],
            'Not_Vuln_Detected_As_FP_Pct': round(stats['not_vuln_as_fp_pct'], 1),
            'Not_Vuln_Mistakenly_As_Vuln': stats['not_vuln_as_vuln'],
            'Not_Vuln_Mistakenly_As_Vuln_Pct': round(stats['not_vuln_as_vuln_pct'], 1),
            # Add metrics
            'TP': metrics['TP'],
            'FP': metrics['FP'],
            'TN': metrics['TN'],
            'FN': metrics['FN'],
            'Precision': round(metrics['precision'], 4),
            'Recall': round(metrics['recall'], 4),
            'F1_Score': round(metrics['f1_score'], 4),
            'Accuracy': round(metrics['accuracy'], 4),
            'FPR': round(metrics['fpr'], 4)
        })
    
    df = pd.DataFrame(csv_data)
    csv_path = os.path.join(reports_dir, 'comprehensive_llm_analysis_report.csv')
    df.to_csv(csv_path, index=False)
    print(f"✅ CSV report generated: {csv_path}")
    return df

def make_serializable(d):
    """Recursively convert numpy types in a dict to native Python types for JSON serialization."""
    if isinstance(d, dict):
        return {k: make_serializable(v) for k, v in d.items()}
    elif isinstance(d, list):
        return [make_serializable(v) for v in d]
    elif hasattr(d, 'item') and callable(d.item):
        return d.item()
    elif isinstance(d, (np.integer, np.floating)):
        return d.item()
    else:
        return d

def save_metrics_for_plotting(results_data):
    """Save metrics data in JSON format for later plotting"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    plotting_data = []
    
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        metrics = calculate_metrics(stats)
        
        plotting_data.append({
            'run_id': run_id,
            'cwe': cwe,
            'model': model,
            'metrics': make_serializable(metrics),
            'stats': make_serializable(stats)
        })
    
    # Save to JSON file for later plotting
    json_path = os.path.join(reports_dir, 'metrics_for_plotting.json')
    with open(json_path, 'w') as f:
        json.dump(plotting_data, f, indent=2)
    
    print(f"✅ Metrics data saved for plotting: {json_path}")
    return plotting_data

def create_confusion_matrix_plots(results_data):
    """Create confusion matrix plots for all runs in a single figure"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    if not results_data:
        print("❌ No data available for plotting")
        return
    
    # Calculate number of subplots needed
    n_runs = len(results_data)
    n_cols = min(3, n_runs)  # Maximum 3 columns
    n_rows = (n_runs + n_cols - 1) // n_cols  # Ceiling division
    
    # Create figure with subplots
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 5 * n_rows))
    axes = np.atleast_1d(axes).flatten().tolist()
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    for idx, (run_info, stats) in enumerate(results_data):
        run_id, cwe, model = run_info
        metrics = calculate_metrics(stats)
        
        # Create confusion matrix data
        cm_data = np.array([
            [metrics['TN'], metrics['FP']],  # Top row: TN, FP
            [metrics['FN'], metrics['TP']]   # Bottom row: FN, TP
        ])
        
        # Create subplot
        ax = axes[idx]
        
        # Create heatmap using matplotlib instead of seaborn
        im = ax.imshow(cm_data, cmap='Blues', aspect='equal')
        
        # Add text annotations
        for i in range(cm_data.shape[0]):
            for j in range(cm_data.shape[1]):
                ax.text(j, i, str(cm_data[i, j]), ha='center', va='center', 
                       fontsize=12, fontweight='bold', color='white' if cm_data[i, j] > cm_data.max()/2 else 'black')
        
        # Add colorbar
        plt.colorbar(im, ax=ax)
        
        # Set labels
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_title(f'{run_id}\n{cwe} - {model}', fontsize=10, fontweight='bold')
        
        # Set tick labels and positions
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Vulnerable', 'Not Vulnerable'])
        ax.set_yticklabels(['Vulnerable', 'Not Vulnerable'])
        
        # Add metrics text
        precision = metrics['precision']
        recall = metrics['recall']
        f1 = metrics['f1_score']
        accuracy = metrics['accuracy']
        
        metrics_text = f'Precision: {precision:.3f}\nRecall: {recall:.3f}\nF1: {f1:.3f}\nAccuracy: {accuracy:.3f}'
        ax.text(0.02, 0.98, metrics_text, transform=ax.transAxes, 
               verticalalignment='top', fontsize=8, 
               bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    # Hide empty subplots
    for idx in range(n_runs, len(axes)):
        axes[idx].set_visible(False)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the plot
    plot_path = os.path.join(reports_dir, 'confusion_matrices_all_runs.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    print(f"✅ Confusion matrix plot saved: {plot_path}")
    
    # Close the figure to free memory
    plt.close()

def create_model_confusion_matrix_plots(results_data):
    """Create confusion matrix plots grouped by model"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    if not results_data:
        print("❌ No data available for plotting")
        return
    
    # Group results by model
    model_groups = defaultdict(list)
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        model_groups[model].append((run_info, stats))
    
    # Calculate number of subplots needed
    n_models = len(model_groups)
    n_cols = min(3, n_models)  # Maximum 3 columns
    n_rows = (n_models + n_cols - 1) // n_cols  # Ceiling division
    
    # Create figure with subplots
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 5 * n_rows))
    axes = np.atleast_1d(axes).flatten().tolist()
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    for idx, (model, model_runs) in enumerate(model_groups.items()):
        # Aggregate metrics for this model
        total_TP = sum(calculate_metrics(stats)['TP'] for _, stats in model_runs)
        total_FP = sum(calculate_metrics(stats)['FP'] for _, stats in model_runs)
        total_TN = sum(calculate_metrics(stats)['TN'] for _, stats in model_runs)
        total_FN = sum(calculate_metrics(stats)['FN'] for _, stats in model_runs)
        
        # Create confusion matrix data
        cm_data = np.array([
            [total_TN, total_FP],  # Top row: TN, FP
            [total_FN, total_TP]   # Bottom row: FN, TP
        ])
        
        # Create subplot
        ax = axes[idx]
        
        # Create heatmap using matplotlib instead of seaborn
        im = ax.imshow(cm_data, cmap='Blues', aspect='equal')
        
        # Add text annotations
        for i in range(cm_data.shape[0]):
            for j in range(cm_data.shape[1]):
                ax.text(j, i, str(cm_data[i, j]), ha='center', va='center', 
                       fontsize=12, fontweight='bold', color='white' if cm_data[i, j] > cm_data.max()/2 else 'black')
        
        # Add colorbar
        plt.colorbar(im, ax=ax)
        
        # Set labels
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_title(f'Model: {model.upper()}\n({len(model_runs)} runs)', fontsize=12, fontweight='bold')
        
        # Set tick labels and positions
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Vulnerable', 'Not Vulnerable'])
        ax.set_yticklabels(['Vulnerable', 'Not Vulnerable'])
        
        # Add metrics text
        precision = total_TP / (total_TP + total_FP) if (total_TP + total_FP) > 0 else 0
        recall = total_TP / (total_TP + total_FN) if (total_TP + total_FN) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (total_TP + total_TN) / (total_TP + total_TN + total_FP + total_FN) if (total_TP + total_TN + total_FP + total_FN) > 0 else 0
        
        metrics_text = f'Precision: {precision:.3f}\nRecall: {recall:.3f}\nF1: {f1:.3f}\nAccuracy: {accuracy:.3f}'
        ax.text(0.02, 0.98, metrics_text, transform=ax.transAxes, 
               verticalalignment='top', fontsize=10, 
               bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    # Hide empty subplots
    for idx in range(n_models, len(axes)):
        axes[idx].set_visible(False)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the plot
    plot_path = os.path.join(reports_dir, 'confusion_matrices_by_model.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    print(f"✅ Model confusion matrix plot saved: {plot_path}")
    
    # Close the figure to free memory
    plt.close()

def create_cwe_confusion_matrix_plots(results_data):
    """Create confusion matrix plots grouped by CWE"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    if not results_data:
        print("❌ No data available for plotting")
        return
    
    # Group results by CWE
    cwe_groups = defaultdict(list)
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        cwe_groups[cwe].append((run_info, stats))
    
    # Calculate number of subplots needed
    n_cwes = len(cwe_groups)
    n_cols = min(3, n_cwes)  # Maximum 3 columns
    n_rows = (n_cwes + n_cols - 1) // n_cols  # Ceiling division
    
    # Create figure with subplots
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 5 * n_rows))
    axes = np.atleast_1d(axes).flatten().tolist()
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    for idx, (cwe, cwe_runs) in enumerate(cwe_groups.items()):
        # Aggregate metrics for this CWE
        total_TP = sum(calculate_metrics(stats)['TP'] for _, stats in cwe_runs)
        total_FP = sum(calculate_metrics(stats)['FP'] for _, stats in cwe_runs)
        total_TN = sum(calculate_metrics(stats)['TN'] for _, stats in cwe_runs)
        total_FN = sum(calculate_metrics(stats)['FN'] for _, stats in cwe_runs)
        
        # Create confusion matrix data
        cm_data = np.array([
            [total_TN, total_FP],  # Top row: TN, FP
            [total_FN, total_TP]   # Bottom row: FN, TP
        ])
        
        # Create subplot
        ax = axes[idx]
        
        # Create heatmap using matplotlib instead of seaborn
        im = ax.imshow(cm_data, cmap='Blues', aspect='equal')
        
        # Add text annotations
        for i in range(cm_data.shape[0]):
            for j in range(cm_data.shape[1]):
                ax.text(j, i, str(cm_data[i, j]), ha='center', va='center', 
                       fontsize=12, fontweight='bold', color='white' if cm_data[i, j] > cm_data.max()/2 else 'black')
        
        # Add colorbar
        plt.colorbar(im, ax=ax)
        
        # Set labels
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_title(f'CWE: {cwe}\n({len(cwe_runs)} runs)', fontsize=12, fontweight='bold')
        
        # Set tick labels and positions
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Vulnerable', 'Not Vulnerable'])
        ax.set_yticklabels(['Vulnerable', 'Not Vulnerable'])
        
        # Add metrics text
        precision = total_TP / (total_TP + total_FP) if (total_TP + total_FP) > 0 else 0
        recall = total_TP / (total_TP + total_FN) if (total_TP + total_FN) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (total_TP + total_TN) / (total_TP + total_TN + total_FP + total_FN) if (total_TP + total_TN + total_FP + total_FN) > 0 else 0
        
        metrics_text = f'Precision: {precision:.3f}\nRecall: {recall:.3f}\nF1: {f1:.3f}\nAccuracy: {accuracy:.3f}'
        ax.text(0.02, 0.98, metrics_text, transform=ax.transAxes, 
               verticalalignment='top', fontsize=10, 
               bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    # Hide empty subplots
    for idx in range(n_cwes, len(axes)):
        axes[idx].set_visible(False)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the plot
    plot_path = os.path.join(reports_dir, 'confusion_matrices_by_cwe.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    print(f"✅ CWE confusion matrix plot saved: {plot_path}")
    
    # Close the figure to free memory
    plt.close()

def create_metrics_bar_charts(results_data):
    """Create five bar charts for precision, recall, accuracy, F1-score, and FPR"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    if not results_data:
        print("❌ No data available for plotting")
        return
    
    # Prepare data for plotting
    run_labels = []
    precision_values = []
    recall_values = []
    accuracy_values = []
    f1_values = []
    fpr_values = []
    
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        metrics = calculate_metrics(stats)
        
        # Create run label
        run_label = f"{run_id}\n{cwe}\n{model}"
        run_labels.append(run_label)
        
        # Collect metrics
        precision_values.append(metrics['precision'])
        recall_values.append(metrics['recall'])
        accuracy_values.append(metrics['accuracy'])
        f1_values.append(metrics['f1_score'])
        fpr_values.append(metrics['fpr'])
    
    # Calculate dynamic figure size based on number of bars
    n_bars = len(run_labels)
    # Base width per bar (in inches) - adjust this for desired spacing
    width_per_bar = 1.2
    # Minimum width to ensure readability
    min_width = 12
    # Calculate total width needed
    total_width = max(min_width, n_bars * width_per_bar)
    # Height per chart (5 charts total)
    chart_height = 6
    total_height = chart_height * 5  # 5 charts stacked vertically
    
    # Create figure with 5 subplots arranged vertically
    fig, axes = plt.subplots(5, 1, figsize=(total_width, total_height))
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    # Define colors for bars
    colors = plt.cm.Set3(np.linspace(0, 1, len(run_labels)))
    
    # Calculate dynamic font size based on number of bars
    font_size = max(8, min(14, 30 // n_bars))  # Better font size scaling
    
    # Create charts for each metric
    metrics_data = [
        ('Precision', precision_values, axes[0]),
        ('Recall', recall_values, axes[1]),
        ('Accuracy', accuracy_values, axes[2]),
        ('F1-Score', f1_values, axes[3]),
        ('False Positive Rate', fpr_values, axes[4])
    ]
    
    for metric_name, values, ax in metrics_data:
        # Create bar chart
        bars = ax.bar(range(len(run_labels)), values, color=colors, alpha=0.7)
        ax.set_title(f'{metric_name} by Run', fontsize=14, fontweight='bold')
        ax.set_ylabel(metric_name, fontsize=12)
        ax.set_ylim(0, 1)
        ax.set_xticks(range(len(run_labels)))
        ax.set_xticklabels(run_labels, rotation=45, ha='right', fontsize=font_size)
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{value:.3f}', ha='center', va='bottom', fontsize=8)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the plot
    plot_path = os.path.join(reports_dir, 'metrics_bar_charts.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    print(f"✅ Metrics bar charts saved: {plot_path}")
    
    # Close the figure to free memory
    plt.close()

def create_model_metrics_bar_charts(results_data):
    """Create five bar charts for precision, recall, accuracy, F1-score, and FPR aggregated by model"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    if not results_data:
        print("❌ No data available for plotting")
        return
    
    # Group results by model
    model_groups = defaultdict(list)
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        model_groups[model].append((run_info, stats))
    
    # Prepare data for plotting
    model_labels = []
    precision_values = []
    recall_values = []
    accuracy_values = []
    f1_values = []
    fpr_values = []
    
    for model, model_runs in model_groups.items():
        # Aggregate metrics for this model
        total_TP = sum(calculate_metrics(stats)['TP'] for _, stats in model_runs)
        total_FP = sum(calculate_metrics(stats)['FP'] for _, stats in model_runs)
        total_TN = sum(calculate_metrics(stats)['TN'] for _, stats in model_runs)
        total_FN = sum(calculate_metrics(stats)['FN'] for _, stats in model_runs)
        
        # Calculate aggregated metrics
        precision = total_TP / (total_TP + total_FP) if (total_TP + total_FP) > 0 else 0
        recall = total_TP / (total_TP + total_FN) if (total_TP + total_FN) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (total_TP + total_TN) / (total_TP + total_TN + total_FP + total_FN) if (total_TP + total_TN + total_FP + total_FN) > 0 else 0
        fpr = total_FP / (total_FP + total_TN) if (total_FP + total_TN) > 0 else 0
        
        # Create model label
        model_label = f"{model.upper()}\n({len(model_runs)} runs)"
        model_labels.append(model_label)
        
        # Collect metrics
        precision_values.append(precision)
        recall_values.append(recall)
        accuracy_values.append(accuracy)
        f1_values.append(f1)
        fpr_values.append(fpr)
    
    # Calculate dynamic figure size based on number of bars
    n_bars = len(model_labels)
    # Base width per bar (in inches) - adjust this for desired spacing
    width_per_bar = 1.2
    # Minimum width to ensure readability
    min_width = 12
    # Calculate total width needed
    total_width = max(min_width, n_bars * width_per_bar)
    # Height per chart (5 charts total)
    chart_height = 6
    total_height = chart_height * 5  # 5 charts stacked vertically
    
    # Create figure with 5 subplots arranged vertically
    fig, axes = plt.subplots(5, 1, figsize=(total_width, total_height))
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    # Define colors for bars
    colors = plt.cm.Set3(np.linspace(0, 1, len(model_labels)))
    
    # Calculate dynamic font size based on number of bars
    font_size = max(8, min(14, 30 // n_bars))  # Better font size scaling
    
    # Create charts for each metric
    metrics_data = [
        ('Precision', precision_values, axes[0]),
        ('Recall', recall_values, axes[1]),
        ('Accuracy', accuracy_values, axes[2]),
        ('F1-Score', f1_values, axes[3]),
        ('False Positive Rate', fpr_values, axes[4])
    ]
    
    for metric_name, values, ax in metrics_data:
        # Create bar chart
        bars = ax.bar(range(len(model_labels)), values, color=colors, alpha=0.7)
        ax.set_title(f'{metric_name} by Model', fontsize=14, fontweight='bold')
        ax.set_ylabel(metric_name, fontsize=12)
        ax.set_ylim(0, 1)
        ax.set_xticks(range(len(model_labels)))
        ax.set_xticklabels(model_labels, rotation=45, ha='right', fontsize=font_size)
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{value:.3f}', ha='center', va='bottom', fontsize=8)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the plot
    plot_path = os.path.join(reports_dir, 'model_metrics_bar_charts.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    print(f"✅ Model metrics bar charts saved: {plot_path}")
    
    # Close the figure to free memory
    plt.close()

def create_cwe_metrics_bar_charts(results_data):
    """Create five bar charts for precision, recall, accuracy, F1-score, and FPR aggregated by CWE"""
    # Create evaluation_reports directory if it doesn't exist
    reports_dir = "evaluation_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    if not results_data:
        print("❌ No data available for plotting")
        return
    
    # Group results by CWE
    cwe_groups = defaultdict(list)
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        cwe_groups[cwe].append((run_info, stats))
    
    # Prepare data for plotting
    cwe_labels = []
    precision_values = []
    recall_values = []
    accuracy_values = []
    f1_values = []
    fpr_values = []
    
    for cwe, cwe_runs in cwe_groups.items():
        # Aggregate metrics for this CWE
        total_TP = sum(calculate_metrics(stats)['TP'] for _, stats in cwe_runs)
        total_FP = sum(calculate_metrics(stats)['FP'] for _, stats in cwe_runs)
        total_TN = sum(calculate_metrics(stats)['TN'] for _, stats in cwe_runs)
        total_FN = sum(calculate_metrics(stats)['FN'] for _, stats in cwe_runs)
        
        # Calculate aggregated metrics
        precision = total_TP / (total_TP + total_FP) if (total_TP + total_FP) > 0 else 0
        recall = total_TP / (total_TP + total_FN) if (total_TP + total_FN) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (total_TP + total_TN) / (total_TP + total_TN + total_FP + total_FN) if (total_TP + total_TN + total_FP + total_FN) > 0 else 0
        fpr = total_FP / (total_FP + total_TN) if (total_FP + total_TN) > 0 else 0
        
        # Create CWE label
        cwe_label = f"{cwe}\n({len(cwe_runs)} runs)"
        cwe_labels.append(cwe_label)
        
        # Collect metrics
        precision_values.append(precision)
        recall_values.append(recall)
        accuracy_values.append(accuracy)
        f1_values.append(f1)
        fpr_values.append(fpr)
    
    # Calculate dynamic figure size based on number of bars
    n_bars = len(cwe_labels)
    # Base width per bar (in inches) - adjust this for desired spacing
    width_per_bar = 1.2
    # Minimum width to ensure readability
    min_width = 12
    # Calculate total width needed
    total_width = max(min_width, n_bars * width_per_bar)
    # Height per chart (5 charts total)
    chart_height = 6
    total_height = chart_height * 5  # 5 charts stacked vertically
    
    # Create figure with 5 subplots arranged vertically
    fig, axes = plt.subplots(5, 1, figsize=(total_width, total_height))
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    # Define colors for bars
    colors = plt.cm.Set3(np.linspace(0, 1, len(cwe_labels)))
    
    # Calculate dynamic font size based on number of bars
    font_size = max(8, min(14, 30 // n_bars))  # Better font size scaling
    
    # Create charts for each metric
    metrics_data = [
        ('Precision', precision_values, axes[0]),
        ('Recall', recall_values, axes[1]),
        ('Accuracy', accuracy_values, axes[2]),
        ('F1-Score', f1_values, axes[3]),
        ('False Positive Rate', fpr_values, axes[4])
    ]
    
    for metric_name, values, ax in metrics_data:
        # Create bar chart
        bars = ax.bar(range(len(cwe_labels)), values, color=colors, alpha=0.7)
        ax.set_title(f'{metric_name} by CWE', fontsize=14, fontweight='bold')
        ax.set_ylabel(metric_name, fontsize=12)
        ax.set_ylim(0, 1)
        ax.set_xticks(range(len(cwe_labels)))
        ax.set_xticklabels(cwe_labels, rotation=45, ha='right', fontsize=font_size)
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{value:.3f}', ha='center', va='bottom', fontsize=8)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the plot
    plot_path = os.path.join(reports_dir, 'cwe_metrics_bar_charts.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    print(f"✅ CWE metrics bar charts saved: {plot_path}")
    
    # Close the figure to free memory
    plt.close()

def print_beautiful_summary(results_data):
    """Print beautiful formatted summary grouped by CWE and Model"""
    
    # Group by CWE and Model
    grouped_data = defaultdict(lambda: defaultdict(list))
    
    for run_info, stats in results_data:
        run_id, cwe, model = run_info
        grouped_data[cwe][model].append((run_id, stats))
    
    print("\n" + "="*100)
    print("🎯 COMPREHENSIVE LLM FALSE POSITIVE ANALYSIS REPORT")
    print("="*100)
    
    for cwe in sorted(grouped_data.keys()):
        print(f"\n{'#'*80}")
        print(f"📊 CWE: {cwe}")
        print(f"{'#'*80}")
        
        for model in sorted(grouped_data[cwe].keys()):
            print(f"\n🤖 MODEL: {model.upper()}")
            print(f"{'─'*60}")
            
            for run_id, stats in grouped_data[cwe][model]:
                print(f"\n📈 Run {run_id}:")
                
                # Calculate metrics for this run
                metrics = calculate_metrics(stats)
                
                # Real vulnerabilities section
                if stats['n_real_vuln'] > 0:
                    print(f"  🔴 Real Vulnerabilities ({stats['n_real_vuln']} total):")
                    print(f"    ✅ Correctly detected as vulnerability: {stats['real_vuln_as_vuln']} ({stats['real_vuln_as_vuln_pct']:.1f}%)")
                    print(f"    ❌ Mistakenly flagged as false positive: {stats['real_vuln_as_fp']} ({stats['real_vuln_as_fp_pct']:.1f}%)")
                else:
                    print(f"  🔴 Real Vulnerabilities: None in this run")
                
                # Not vulnerabilities section
                if stats['n_not_vuln'] > 0:
                    print(f"  🟢 Not Vulnerabilities ({stats['n_not_vuln']} total):")
                    print(f"    ✅ Correctly detected as false positive: {stats['not_vuln_as_fp']} ({stats['not_vuln_as_fp_pct']:.1f}%)")
                    print(f"    ❌ Mistakenly flagged as vulnerability: {stats['not_vuln_as_vuln']} ({stats['not_vuln_as_vuln_pct']:.1f}%)")
                else:
                    print(f"  🟢 Not Vulnerabilities: None in this run")
                
                # Print metrics
                print(f"  📊 Metrics:")
                print(f"    TP: {metrics['TP']}, FP: {metrics['FP']}, TN: {metrics['TN']}, FN: {metrics['FN']}")
                print(f"    Precision: {metrics['precision']:.4f}")
                print(f"    Recall: {metrics['recall']:.4f}")
                print(f"    F1-Score: {metrics['f1_score']:.4f}")
                print(f"    Accuracy: {metrics['accuracy']:.4f}")
                print(f"    FPR: {metrics['fpr']:.4f}")
    
    print(f"\n{'='*100}")
    print("📋 SUMMARY STATISTICS")
    print(f"{'='*100}")
    
    # Calculate overall statistics
    total_runs = len(results_data)
    models = set(run_info[2] for run_info, _ in results_data)
    cwes = set(run_info[1] for run_info, _ in results_data)
    
    print(f"📊 Total Runs Analyzed: {total_runs}")
    print(f"🤖 Models Tested: {', '.join(sorted(models))}")
    print(f"🎯 CWEs Covered: {', '.join(sorted(cwes))}")
    
    # Model performance summary
    print(f"\n🏆 MODEL PERFORMANCE SUMMARY:")
    model_stats = defaultdict(lambda: {'runs': 0, 'total_real_vuln': 0, 'total_not_vuln': 0})
    
    for run_info, stats in results_data:
        model = run_info[2]
        model_stats[model]['runs'] += 1
        model_stats[model]['total_real_vuln'] += stats['n_real_vuln']
        model_stats[model]['total_not_vuln'] += stats['n_not_vuln']
    
    for model in sorted(model_stats.keys()):
        stats = model_stats[model]
        print(f"  {model.upper()}: {stats['runs']} runs, {stats['total_real_vuln']} real vulns, {stats['total_not_vuln']} not vulns")

def main():
    results_dir = "results"
    if not os.path.exists(results_dir):
        print(f"❌ Results directory not found: {results_dir}")
        return
    
    print("🔍 Analyzing LLM detection results...")
    
    # Collect all results
    results_data = []
    run_folders = [os.path.join(results_dir, d) for d in os.listdir(results_dir) 
                   if os.path.isdir(os.path.join(results_dir, d))]
    
    for run_folder in sorted(run_folders):
        try:
            prompt_version, dataset, cwe, model = extract_run_info_from_folder(run_folder)
            csv_path = find_evaluation_csv(run_folder)
            
            if not csv_path:
                continue
                
            df = pd.read_csv(csv_path)
            if 'ground_truth_is_vulnerable' not in df.columns or 'llm_False Positive' not in df.columns:
                continue
                
            stats = count_detection_types(df)
            results_data.append(((run_id, cwe, model), stats))
            
        except Exception as e:
            print(f"⚠️  Error processing {run_folder}: {e}")
            continue
    
    if not results_data:
        print("❌ No valid results found!")
        return
    
    # Generate CSV report with metrics
    csv_df = generate_csv_report(results_data)
    
    # Save metrics data for plotting
    plotting_data = save_metrics_for_plotting(results_data)
    
    # Create confusion matrix plots
    create_confusion_matrix_plots(results_data)
    
    # Create model confusion matrix plots
    create_model_confusion_matrix_plots(results_data)

    # Create CWE confusion matrix plots
    create_cwe_confusion_matrix_plots(results_data)
    
    # Create metrics bar charts
    create_metrics_bar_charts(results_data)

    # Create model metrics bar charts
    create_model_metrics_bar_charts(results_data)

    # Create CWE metrics bar charts
    create_cwe_metrics_bar_charts(results_data)
    
    # Print beautiful summary
    print_beautiful_summary(results_data)
    
    print(f"\n✅ Analysis complete!")
    print(f"📊 Check 'evaluation_reports/comprehensive_llm_analysis_report.csv' for detailed data with metrics")
    print(f"📈 Check 'evaluation_reports/metrics_for_plotting.json' for plotting data")
    print(f"📊 Check 'evaluation_reports/confusion_matrices_all_runs.png' for confusion matrix visualization")
    print(f"📊 Check 'evaluation_reports/confusion_matrices_by_model.png' for model-wise confusion matrix visualization")
    print(f"📊 Check 'evaluation_reports/confusion_matrices_by_cwe.png' for CWE-wise confusion matrix visualization")
    print(f"📊 Check 'evaluation_reports/metrics_bar_charts.png' for metrics bar charts")
    print(f"📊 Check 'evaluation_reports/model_metrics_bar_charts.png' for model-wise metrics bar charts")
    print(f"📊 Check 'evaluation_reports/cwe_metrics_bar_charts.png' for CWE-wise metrics bar charts")

if __name__ == "__main__":
    main() 