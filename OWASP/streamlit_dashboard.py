#!/usr/bin/env python3
"""
OWASP Experiment Analysis Dashboard
Interactive web-based visualization for experiment results
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import plotly.figure_factory as ff
import json
import os
import glob
from pathlib import Path
import seaborn as sns
import matplotlib.pyplot as plt

# Page configuration
st.set_page_config(
    page_title="OWASP Experiment Analysis",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded"
)

@st.cache_data
def load_experiment_data():
    """Load all experiment data from CSV files in results folder"""
    results_dir = Path("results")
    all_data = []
    
    if not results_dir.exists():
        st.error("Results directory not found!")
        return pd.DataFrame()
    
    # Find only evaluation CSV files in results subdirectories and exclude unfiltered ones
    csv_files = glob.glob(str(results_dir / "**/evaluation_*.csv"), recursive=True)
    csv_files = [p for p in csv_files if not p.endswith("_unfiltered.csv")]
    
    for csv_file in csv_files:
        try:
            # Extract run information from file path
            file_path = Path(csv_file)
            run_info = file_path.parent.name  # Directory name contains run info
            
            # Parse prompt_version, dataset, cwe, model from directory name
            # Expected format: {promptversion}_{dataset}_{CWE}_{model}
            parts = run_info.split('_')
            
            if len(parts) >= 4 and 'CWE-' in run_info:
                # New format: {promptversion}_{dataset}_{CWE}_{model}
                prompt_version = parts[0]
                dataset = parts[1]
                
                # Find CWE part
                cwe_part = None
                model_parts = []
                
                for i, part in enumerate(parts[2:], 2):
                    if part.startswith("CWE-"):
                        cwe_part = part
                        # Everything after CWE is model parts
                        model_parts = parts[i+1:]
                        break
                
                if cwe_part:
                    cwe = cwe_part
                    model = '_'.join(model_parts) if model_parts else "unknown"
                    run_id = "default"  # Default run_id since it's not in directory name
                else:
                    prompt_version = "unknown"
                    dataset = "unknown"
                    cwe = "unknown"
                    model = "unknown"
                    run_id = "unknown"
            else:
                # Fallback to old format parsing
                cwe_part = None
                model_parts = []
                run_id_parts = []
                
                for part in parts:
                    if part.startswith("CWE-"):
                        cwe_part = part
                    elif cwe_part is None:
                        run_id_parts.append(part)
                    else:
                        model_parts.append(part)
                
                if cwe_part:
                    prompt_version = "baseline"  # Default for old format
                    dataset = "owasp"  # Default for old format
                    run_id = '_'.join(run_id_parts)
                    cwe = cwe_part
                    model = '_'.join(model_parts) if model_parts else "unknown"
                else:
                    # Fallback to simple parsing if no CWE pattern found
                    if len(parts) >= 3:
                        prompt_version = "baseline"
                        dataset = "owasp"
                        run_id = parts[0]
                        cwe = parts[1]
                        model = '_'.join(parts[2:])
                    else:
                        prompt_version = "unknown"
                        dataset = "unknown"
                        run_id = "unknown"
                        cwe = "unknown"
                        model = "unknown"
            
            # Load CSV data
            df = pd.read_csv(csv_file)
            
            # Add metadata
            df['prompt_version'] = prompt_version
            df['dataset'] = dataset
            df['run_id'] = run_id
            df['cwe'] = cwe
            df['model'] = model
            df['file_path'] = str(file_path)
            
            all_data.append(df)
            
        except Exception as e:
            st.warning(f"Error loading {csv_file}: {e}")
    
    if not all_data:
        st.error("No CSV files found in results directory!")
        return pd.DataFrame()
    
    # Combine all data
    combined_df = pd.concat(all_data, ignore_index=True)
    
    # Calculate confusion matrix from individual test results
    aggregated_data = []
    
    for (prompt_version, dataset, run_id, cwe, model), group in combined_df.groupby(['prompt_version', 'dataset', 'run_id', 'cwe', 'model']):
        # Calculate confusion matrix from individual test results
        tp = 0  # True Positives: LLM says vulnerable, actually vulnerable
        fp = 0  # False Positives: LLM says vulnerable, actually safe
        tn = 0  # True Negatives: LLM says safe, actually safe
        fn = 0  # False Negatives: LLM says safe, actually vulnerable
        
        # Count confusion matrix elements
        for _, row in group.iterrows():
            is_vulnerable = row.get('ground_truth_is_vulnerable', False)
            
            # Determine LLM prediction based on available columns
            llm_prediction = None
            
            if 'llm_Attack Feasible?' in row and pd.notna(row['llm_Attack Feasible?']):
                llm_prediction = row['llm_Attack Feasible?'] == 'Yes'
            elif 'llm_False Positive' in row and pd.notna(row['llm_False Positive']):
                llm_prediction = row['llm_False Positive'] == 'No'  # Not a false positive = vulnerable
            else:
                continue  # Skip if we can't determine prediction
            
            if llm_prediction and is_vulnerable:
                tn += 1
            elif llm_prediction and not is_vulnerable:
                fn += 1
            elif not llm_prediction and not is_vulnerable:
                tp += 1
            elif not llm_prediction and is_vulnerable:
                fp += 1
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        aggregated_data.append({
            'prompt_version': prompt_version,
            'dataset': dataset,
            'run_id': run_id,
            'cwe': cwe,
            'model': model,
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'precision': precision,
            'recall': recall,
            'accuracy': accuracy,
            'f1_score': f1_score,
            'fpr': fpr,
            'total_tests': len(group)
        })
    
    # Create aggregated dataframe
    if aggregated_data:
        result_df = pd.DataFrame(aggregated_data)
        result_df.attrs['tp_col'] = 'true_positives'
        result_df.attrs['fp_col'] = 'false_positives'
        result_df.attrs['tn_col'] = 'true_negatives'
        result_df.attrs['fn_col'] = 'false_negatives'
        
        # Debug: Show aggregation results
        st.write(f"✅ Aggregated {len(aggregated_data)} experiments")
        st.write("Sample aggregated data:")
        st.write(result_df.head())
        
        return result_df
    else:
        st.error("No valid data could be aggregated from the CSV files.")
        st.write("This might be due to missing or invalid columns in the CSV files.")
        return pd.DataFrame()

def calculate_custom_metrics(df):
    """Calculate custom metrics based on user-defined variables"""
    # Get the actual column names from the dataframe attributes
    tp_col = df.attrs.get('tp_col', 'true_positives')
    fp_col = df.attrs.get('fp_col', 'false_positives')
    tn_col = df.attrs.get('tn_col', 'true_negatives')
    fn_col = df.attrs.get('fn_col', 'false_negatives')
    
    # Define basic variables using the correct column names
    df['TP'] = df[tp_col]
    df['FP'] = df[fp_col]
    df['TN'] = df[tn_col]
    df['FN'] = df[fn_col]
    
    # Calculate standard metrics
    df['precision_custom'] = df['TP'] / (df['TP'] + df['FP'])
    df['recall_custom'] = df['TP'] / (df['TP'] + df['FN'])
    df['f1_custom'] = 2 * (df['precision_custom'] * df['recall_custom']) / (df['precision_custom'] + df['recall_custom'])
    
    return df



def main():
    st.title("🔬 OWASP Experiment Analysis Dashboard")
    st.markdown("Interactive analysis of security vulnerability detection experiments")
    
    # Load data
    with st.spinner("Loading experiment data..."):
        df = load_experiment_data()
    
    if df.empty:
        st.error("No data loaded. Please check your results directory.")
        st.info("Make sure you have CSV files in the 'results' folder with the required columns.")
        return
    
    # Debug: Show what we loaded
    st.write("📊 Data loaded successfully!")
    st.write(f"Shape: {df.shape}")
    st.write(f"Columns: {list(df.columns)}")
    
    # Check if we have the required columns
    required_cols = ['true_positives', 'false_positives', 'true_negatives', 'false_negatives']
    if not all(col in df.columns for col in required_cols):
        st.error("Required columns (true_positives, false_positives, true_negatives, false_negatives) not found in the data.")
        st.write("Available columns:", list(df.columns))
        st.info("Please ensure your CSV files contain the required confusion matrix data.")
        return
    
    # Calculate custom metrics
    df = calculate_custom_metrics(df)
    
    # Sidebar for filters and custom variables
    st.sidebar.header("🎛️ Controls")
    
    # Data filters
    st.sidebar.subheader("📊 Data Filters")
    
    # Dataset filter
    available_datasets = ['All'] + sorted(df['dataset'].unique().tolist())
    selected_datasets = st.sidebar.multiselect("Select Datasets", available_datasets, default=['All'])
    
    available_runs = ['All'] + sorted(df['run_id'].unique().tolist())
    selected_runs = st.sidebar.multiselect("Select Runs", available_runs, default=['All'])
    
    available_cwes = ['All'] + sorted(df['cwe'].unique().tolist())
    selected_cwes = st.sidebar.multiselect("Select CWEs", available_cwes, default=['All'])
    
    available_models = ['All'] + sorted(df['model'].unique().tolist())
    selected_models = st.sidebar.multiselect("Select Models", available_models, default=['All'])
    
    # Prompt version filter
    available_prompt_versions = ['All'] + sorted(df['prompt_version'].unique().tolist())
    selected_prompt_versions = st.sidebar.multiselect("Select Prompt Versions", available_prompt_versions, default=['All'])
    
    # Apply filters
    filtered_df = df.copy()
    if 'All' not in selected_datasets:
        filtered_df = filtered_df[filtered_df['dataset'].isin(selected_datasets)]
    if 'All' not in selected_runs:
        filtered_df = filtered_df[filtered_df['run_id'].isin(selected_runs)]
    if 'All' not in selected_cwes:
        filtered_df = filtered_df[filtered_df['cwe'].isin(selected_cwes)]
    if 'All' not in selected_models:
        filtered_df = filtered_df[filtered_df['model'].isin(selected_models)]
    if 'All' not in selected_prompt_versions:
        filtered_df = filtered_df[filtered_df['prompt_version'].isin(selected_prompt_versions)]
    
    # Custom variable definitions
    st.sidebar.subheader("🔧 Custom Variables")
    
    # User-defined weights
    tp_weight = st.sidebar.slider("TP Weight", 0.0, 5.0, 2.0, 0.1, help="Weight for True Positives")
    fp_penalty = st.sidebar.slider("FP Penalty", 0.0, 2.0, 0.5, 0.1, help="Penalty for False Positives")
    tn_bonus = st.sidebar.slider("TN Bonus", 0.0, 3.0, 1.5, 0.1, help="Bonus for True Negatives")
    fn_penalty = st.sidebar.slider("FN Penalty", 0.0, 2.0, 1.0, 0.1, help="Penalty for False Negatives")
    
    # Calculate custom score
    filtered_df['custom_score'] = (
        filtered_df['TP'] * tp_weight - 
        filtered_df['FP'] * fp_penalty + 
        filtered_df['TN'] * tn_bonus - 
        filtered_df['FN'] * fn_penalty
    )
    
    # Display current formula
    st.sidebar.markdown("**Current Formula:**")
    st.sidebar.latex(f'''
    \\text{{Custom Score}} = (TP \\times {tp_weight}) - (FP \\times {fp_penalty}) + (TN \\times {tn_bonus}) - (FN \\times {fn_penalty})
    ''')
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📈 Data Overview")
        st.write(f"**Total Experiments:** {len(filtered_df)}")
        st.write(f"**Unique Datasets:** {filtered_df['dataset'].nunique()}")
        st.write(f"**Unique Runs:** {filtered_df['run_id'].nunique()}")
        st.write(f"**Unique CWEs:** {filtered_df['cwe'].nunique()}")
        st.write(f"**Unique Models:** {filtered_df['model'].nunique()}")
        st.write(f"**Unique Prompt Versions:** {filtered_df['prompt_version'].nunique()}")
        
        # Show dataset breakdown
        if not filtered_df.empty:
            dataset_counts = filtered_df['dataset'].value_counts()
            st.write("**Dataset Breakdown:**")
            for dataset, count in dataset_counts.items():
                st.write(f"  - {dataset}: {count} experiments")
            
            # Show prompt version breakdown
            prompt_version_counts = filtered_df['prompt_version'].value_counts()
            st.write("**Prompt Version Breakdown:**")
            for prompt_version, count in prompt_version_counts.items():
                st.write(f"  - {prompt_version}: {count} experiments")
        
        # Show available columns for debugging
        with st.expander("🔍 Data Columns (for debugging)"):
            st.write("Available columns:", list(filtered_df.columns))
            if not filtered_df.empty:
                st.write("Sample data:")
                st.dataframe(filtered_df.head(3))
    
    with col2:
        st.subheader("📊 Summary Statistics")
        if not filtered_df.empty:
            # Calculate overall aggregated metrics from all experiments
            total_tp = filtered_df['TP'].sum()
            total_fp = filtered_df['FP'].sum()
            total_tn = filtered_df['TN'].sum()
            total_fn = filtered_df['FN'].sum()
            
            # Calculate overall metrics from aggregated totals
            overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
            overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
            overall_accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
            overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0
            
            # Calculate overall custom score
            overall_custom_score = (
                total_tp * tp_weight - 
                total_fp * fp_penalty + 
                total_tn * tn_bonus - 
                total_fn * fn_penalty
            )
            
            st.write(f"**Overall Precision:** {overall_precision:.3f}")
            st.write(f"**Overall Recall:** {overall_recall:.3f}")
            st.write(f"**Overall Accuracy:** {overall_accuracy:.3f}")
            st.write(f"**Overall F1-Score:** {overall_f1:.3f}")
            st.write(f"**Overall Custom Score:** {overall_custom_score:.3f}")
            st.write(f"**Total Experiments:** {len(filtered_df)}")
    
    # Visualizations
    st.header("📊 Interactive Visualizations")
    
    # Tab layout for different visualizations
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "🎯 Performance Metrics", 
        "📊 Custom Score Analysis", 
        "🔍 Confusion Matrix", 
        "📈 Time Series", 
        "📋 Data Table",
        "🗂️ Dataset Analysis",
        "🔥 Interactive Heatmaps",
        "📊 Comprehensive Tables"
    ])
    
    with tab1:
        st.subheader("Performance Metrics Comparison")
        
        # Metric selection
        metric_options = ['precision', 'recall', 'accuracy', 'f1_score', 'fpr', 'custom_score']
        selected_metric = st.selectbox("Select Metric", metric_options, format_func=lambda x: x.replace('_', ' ').title())
        
        # Create bar chart
        if selected_metric in filtered_df.columns:
            # Group by model and calculate aggregated metrics (not simple averaging)
            model_metrics_data = []
            
            for model_name, model_group in filtered_df.groupby('model'):
                # Aggregate confusion matrix for this model
                total_tp = model_group['TP'].sum()
                total_fp = model_group['FP'].sum()
                total_tn = model_group['TN'].sum()
                total_fn = model_group['FN'].sum()
                
                # Calculate aggregated metrics for this model
                if selected_metric == 'precision':
                    metric_value = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                elif selected_metric == 'recall':
                    metric_value = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                elif selected_metric == 'accuracy':
                    metric_value = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
                elif selected_metric == 'f1_score':
                    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                    metric_value = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                elif selected_metric == 'fpr':
                    metric_value = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
                elif selected_metric == 'custom_score':
                    metric_value = (
                        total_tp * tp_weight - 
                        total_fp * fp_penalty + 
                        total_tn * tn_bonus - 
                        total_fn * fn_penalty
                    )
                else:
                    metric_value = 0
                
                model_metrics_data.append({
                    'model': model_name,
                    selected_metric: metric_value
                })
            
            model_metrics = pd.DataFrame(model_metrics_data)
            model_metrics = model_metrics.sort_values(selected_metric, ascending=False)
            
            # Create bar chart
            fig = px.bar(
                model_metrics,
                x='model',
                y=selected_metric,
                title=f"Aggregated {selected_metric.replace('_', ' ').title()} by Model",
                color=selected_metric,
                color_continuous_scale='RdYlGn',
                text=model_metrics[selected_metric].round(3)
            )
            fig.update_traces(textposition='outside')
            fig.update_layout(
                height=500,
                xaxis_title="Model",
                yaxis_title=selected_metric.replace('_', ' ').title(),
                showlegend=False
            )
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True, key="model_metrics")
            
            # Also show detailed breakdown by CWE
            st.subheader(f"Detailed {selected_metric.replace('_', ' ').title()} by Model and CWE")
            
            # Create grouped bar chart for CWE breakdown with proper aggregation
            cwe_model_metrics_data = []
            
            for (model_name, cwe_name), group in filtered_df.groupby(['model', 'cwe']):
                # Aggregate confusion matrix for this model+CWE combination
                total_tp = group['TP'].sum()
                total_fp = group['FP'].sum()
                total_tn = group['TN'].sum()
                total_fn = group['FN'].sum()
                
                # Calculate aggregated metrics for this model+CWE combination
                if selected_metric == 'precision':
                    metric_value = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                elif selected_metric == 'recall':
                    metric_value = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                elif selected_metric == 'accuracy':
                    metric_value = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
                elif selected_metric == 'f1_score':
                    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                    metric_value = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                elif selected_metric == 'fpr':
                    metric_value = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
                elif selected_metric == 'custom_score':
                    metric_value = (
                        total_tp * tp_weight - 
                        total_fp * fp_penalty + 
                        total_tn * tn_bonus - 
                        total_fn * fn_penalty
                    )
                else:
                    metric_value = 0
                
                cwe_model_metrics_data.append({
                    'model': model_name,
                    'cwe': cwe_name,
                    selected_metric: metric_value
                })
            
            cwe_model_metrics = pd.DataFrame(cwe_model_metrics_data)
            
            fig2 = px.bar(
                cwe_model_metrics,
                x='model',
                y=selected_metric,
                color='cwe',
                title=f"Aggregated {selected_metric.replace('_', ' ').title()} by Model and CWE",
                barmode='group'
            )
            fig2.update_layout(
                height=500,
                xaxis_title="Model",
                yaxis_title=selected_metric.replace('_', ' ').title(),
                xaxis={'tickangle': 45}
            )
            st.plotly_chart(fig2, use_container_width=True, key="cwe_model_metrics")
            
            # Show prompt version breakdown
            st.subheader(f"{selected_metric.replace('_', ' ').title()} by Prompt Version")
            
            # Create prompt version comparison chart with proper aggregation
            prompt_version_metrics_data = []
            
            for prompt_version, group in filtered_df.groupby('prompt_version'):
                # Aggregate confusion matrix for this prompt version
                total_tp = group['TP'].sum()
                total_fp = group['FP'].sum()
                total_tn = group['TN'].sum()
                total_fn = group['FN'].sum()
                
                # Calculate aggregated metrics for this prompt version
                if selected_metric == 'precision':
                    metric_value = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                elif selected_metric == 'recall':
                    metric_value = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                elif selected_metric == 'accuracy':
                    metric_value = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
                elif selected_metric == 'f1_score':
                    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                    metric_value = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                elif selected_metric == 'fpr':
                    metric_value = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
                elif selected_metric == 'custom_score':
                    metric_value = (
                        total_tp * tp_weight - 
                        total_fp * fp_penalty + 
                        total_tn * tn_bonus - 
                        total_fn * fn_penalty
                    )
                else:
                    metric_value = 0
                
                prompt_version_metrics_data.append({
                    'prompt_version': prompt_version,
                    selected_metric: metric_value
                })
            
            prompt_version_metrics = pd.DataFrame(prompt_version_metrics_data)
            prompt_version_metrics = prompt_version_metrics.sort_values(selected_metric, ascending=False)
            
            fig3 = px.bar(
                prompt_version_metrics,
                x='prompt_version',
                y=selected_metric,
                title=f"Aggregated {selected_metric.replace('_', ' ').title()} by Prompt Version",
                color=selected_metric,
                color_continuous_scale='RdYlGn',
                text=prompt_version_metrics[selected_metric].round(3)
            )
            fig3.update_traces(textposition='outside')
            fig3.update_layout(
                height=400,
                xaxis_title="Prompt Version",
                yaxis_title=selected_metric.replace('_', ' ').title(),
                showlegend=False
            )
            st.plotly_chart(fig3, use_container_width=True, key="prompt_version_metrics")
            
            # Show dataset breakdown
            st.subheader(f"{selected_metric.replace('_', ' ').title()} by Dataset")
            
            # Create dataset comparison chart with proper aggregation
            dataset_metrics_data = []
            
            for dataset, group in filtered_df.groupby('dataset'):
                # Aggregate confusion matrix for this dataset
                total_tp = group['TP'].sum()
                total_fp = group['FP'].sum()
                total_tn = group['TN'].sum()
                total_fn = group['FN'].sum()
                
                # Calculate aggregated metrics for this dataset
                if selected_metric == 'precision':
                    metric_value = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                elif selected_metric == 'recall':
                    metric_value = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                elif selected_metric == 'accuracy':
                    metric_value = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
                elif selected_metric == 'f1_score':
                    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                    metric_value = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                elif selected_metric == 'fpr':
                    metric_value = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
                elif selected_metric == 'custom_score':
                    metric_value = (
                        total_tp * tp_weight - 
                        total_fp * fp_penalty + 
                        total_tn * tn_bonus - 
                        total_fn * fn_penalty
                    )
                else:
                    metric_value = 0
                
                dataset_metrics_data.append({
                    'dataset': dataset,
                    selected_metric: metric_value
                })
            
            dataset_metrics = pd.DataFrame(dataset_metrics_data)
            dataset_metrics = dataset_metrics.sort_values(selected_metric, ascending=False)
            
            fig4 = px.bar(
                dataset_metrics,
                x='dataset',
                y=selected_metric,
                title=f"Aggregated {selected_metric.replace('_', ' ').title()} by Dataset",
                color=selected_metric,
                color_continuous_scale='RdYlGn',
                text=dataset_metrics[selected_metric].round(3)
            )
            fig4.update_traces(textposition='outside')
            fig4.update_layout(
                height=400,
                xaxis_title="Dataset",
                yaxis_title=selected_metric.replace('_', ' ').title(),
                showlegend=False
            )
            st.plotly_chart(fig4, use_container_width=True, key="dataset_metrics")
            
            # Show individual experiment results (runs) for the selected metric
            st.subheader(f"Individual Experiment Results: {selected_metric.replace('_', ' ').title()}")
            
            # Create a bar chart showing individual experiment results
            # Sort by the selected metric in descending order
            individual_results = filtered_df.sort_values(selected_metric, ascending=False)
            
            # Create experiment labels for x-axis
            individual_results['experiment_label'] = individual_results.apply(
                lambda row: f"{row['dataset']}_{row['cwe']}_{row['model']}_{row['prompt_version']}", axis=1
            )
            
            fig5 = px.bar(
                individual_results,
                x='experiment_label',
                y=selected_metric,
                color='dataset',
                title=f"Individual {selected_metric.replace('_', ' ').title()} by Experiment",
                text=individual_results[selected_metric].round(3),
                hover_data=['run_id', 'cwe', 'model', 'dataset', 'prompt_version', 'total_tests', 'TP', 'FP', 'TN', 'FN']
            )
            fig5.update_traces(textposition='outside')
            fig5.update_layout(
                height=600,
                xaxis_title="Experiment (Dataset_CWE_Model_PromptVersion)",
                yaxis_title=selected_metric.replace('_', ' ').title(),
                xaxis={'tickangle': 45, 'tickmode': 'array', 'ticktext': individual_results['experiment_label'], 'tickvals': list(range(len(individual_results)))},
                showlegend=True
            )
            st.plotly_chart(fig5, use_container_width=True, key="individual_experiments")
    
    with tab2:
        st.subheader("Custom Score Analysis")
        
        # Scatter plot of custom score vs other metrics
        x_metric = st.selectbox("X-axis metric", ['precision', 'recall', 'accuracy', 'f1_score'], key='x_metric')
        y_metric = st.selectbox("Y-axis metric", ['custom_score'], key='y_metric')
        
        fig = px.scatter(
            filtered_df,
            x=x_metric,
            y=y_metric,
            color='model',
            size='TP',
            hover_data=['run_id', 'cwe', 'dataset', 'prompt_version', 'TP', 'FP', 'TN', 'FN'],
            title=f"{x_metric.replace('_', ' ').title()} vs Custom Score"
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True, key="scatter_plot")
        
        # Custom score distribution by model
        fig = px.histogram(
            filtered_df,
            x='custom_score',
            color='model',
            title="Custom Score Distribution by Model"
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True, key="custom_score_model")
        
        # Custom score distribution by dataset
        fig2 = px.histogram(
            filtered_df,
            x='custom_score',
            color='dataset',
            title="Custom Score Distribution by Dataset"
        )
        fig2.update_layout(height=400)
        st.plotly_chart(fig2, use_container_width=True, key="custom_score_dataset")
        
        # Custom score distribution by prompt version
        fig3 = px.histogram(
            filtered_df,
            x='custom_score',
            color='prompt_version',
            title="Custom Score Distribution by Prompt Version"
        )
        fig3.update_layout(height=400)
        st.plotly_chart(fig3, use_container_width=True, key="custom_score_prompt_version")
    
    with tab3:
        st.subheader("Confusion Matrix Analysis")
        
        # Select specific experiment for confusion matrix
        if not filtered_df.empty:
            experiment_selector = st.selectbox(
                "Select Experiment for Confusion Matrix",
                filtered_df.index,
                format_func=lambda x: f"{filtered_df.loc[x, 'run_id']} - {filtered_df.loc[x, 'cwe']} - {filtered_df.loc[x, 'model']} - {filtered_df.loc[x, 'prompt_version']}"
            )
            
            selected_exp = filtered_df.loc[experiment_selector]
            
            # Create confusion matrix
            cm_data = np.array([
                [selected_exp['TN'], selected_exp['FP']],
                [selected_exp['FN'], selected_exp['TP']]
            ])
            
            fig = go.Figure(data=go.Heatmap(
                z=cm_data,
                x=['Predicted Negative', 'Predicted Positive'],
                y=['Actual Negative', 'Actual Positive'],
                text=cm_data,
                texttemplate="%{text}",
                textfont={"size": 16},
                colorscale='Blues'
            ))
            
            fig.update_layout(
                title=f"Confusion Matrix: {selected_exp['run_id']} - {selected_exp['cwe']} - {selected_exp['model']} - {selected_exp['prompt_version']}",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True, key="confusion_matrix")
    
    with tab4:
        st.subheader("Time Series Analysis")
        
        # If you have timestamp data, you can add time series analysis here
        st.info("Time series analysis would be available if timestamp data is present in your CSV files.")
        
        # For now, show metric trends by run with proper aggregation
        if 'run_id' in filtered_df.columns:
            # Calculate aggregated metrics for each run_id
            run_metrics_data = []
            
            for run_id, group in filtered_df.groupby('run_id'):
                # Aggregate confusion matrix for this run
                total_tp = group['TP'].sum()
                total_fp = group['FP'].sum()
                total_tn = group['TN'].sum()
                total_fn = group['FN'].sum()
                
                # Calculate aggregated metrics for this run
                precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
                f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                custom_score = (
                    total_tp * tp_weight - 
                    total_fp * fp_penalty + 
                    total_tn * tn_bonus - 
                    total_fn * fn_penalty
                )
                
                run_metrics_data.append({
                    'run_id': run_id,
                    'precision': precision,
                    'recall': recall,
                    'accuracy': accuracy,
                    'f1_score': f1_score,
                    'custom_score': custom_score
                })
            
            run_metrics_df = pd.DataFrame(run_metrics_data)
            
            fig = px.line(
                run_metrics_df,
                x='run_id',
                y=['precision', 'recall', 'accuracy', 'f1_score', 'custom_score'],
                title="Aggregated Metric Trends by Run"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab5:
        st.subheader("Data Table")
        
        # Create three columns for the tables
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**📊 All Experiments Data**")
            # Display filtered data
            display_columns = ['dataset', 'run_id', 'cwe', 'model', 'prompt_version', 'TP', 'FP', 'TN', 'FN', 
                              'precision', 'recall', 'accuracy', 'f1_score', 'custom_score']
            
            available_columns = [col for col in display_columns if col in filtered_df.columns]
            
            st.dataframe(
                filtered_df[available_columns].round(3),
                use_container_width=True
            )
            
            # Download button for all data
            csv = filtered_df.to_csv(index=False)
            st.download_button(
                label="Download all data as CSV",
                data=csv,
                file_name="filtered_experiment_data.csv",
                mime="text/csv"
            )
        
        with col2:
            st.markdown("**🤖 Experiments Grouped by Model**")
            
            # Group data by model and calculate aggregated metrics
            model_grouped_data = []
            
            for model_name, model_group in filtered_df.groupby('model'):
                # Calculate aggregated metrics for this model
                total_tp = model_group['TP'].sum()
                total_fp = model_group['FP'].sum()
                total_tn = model_group['TN'].sum()
                total_fn = model_group['FN'].sum()
                
                # Calculate overall metrics for the model
                overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                overall_accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
                overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0
                
                # Calculate custom score for the model
                overall_custom_score = (
                    total_tp * tp_weight - 
                    total_fp * fp_penalty + 
                    total_tn * tn_bonus - 
                    total_fn * fn_penalty
                )
                
                # Count experiments and unique CWEs for this model
                num_experiments = len(model_group)
                unique_cwes = model_group['cwe'].nunique()
                unique_datasets = model_group['dataset'].nunique()
                unique_prompt_versions = model_group['prompt_version'].nunique()
                
                model_grouped_data.append({
                    'Model': model_name,
                    'Experiments': num_experiments,
                    'Unique CWEs': unique_cwes,
                    'Unique Datasets': unique_datasets,
                    'Unique Prompt Versions': unique_prompt_versions,
                    'Total TP': total_tp,
                    'Total FP': total_fp,
                    'Total TN': total_tn,
                    'Total FN': total_fn,
                    'Overall Precision': overall_precision,
                    'Overall Recall': overall_recall,
                    'Overall Accuracy': overall_accuracy,
                    'Overall F1-Score': overall_f1,
                    'Overall Custom Score': overall_custom_score
                })
            
            # Convert to DataFrame and sort by custom score
            model_grouped_df = pd.DataFrame(model_grouped_data)
            if not model_grouped_df.empty:
                model_grouped_df = model_grouped_df.sort_values('Overall Custom Score', ascending=False)
                
                # Display the model-grouped table
                st.dataframe(
                    model_grouped_df.round(3),
                    use_container_width=True
                )
                
                # Download button for model-grouped data
                csv_model = model_grouped_df.to_csv(index=False)
                st.download_button(
                    label="Download model-grouped data as CSV",
                    data=csv_model,
                    file_name="model_grouped_experiment_data.csv",
                    mime="text/csv"
                )
            else:
                st.warning("No data available for model grouping.")
        
        with col3:
            st.markdown("**🔒 Experiments Grouped by CWE**")
            
            # Group data by CWE and calculate aggregated metrics
            cwe_grouped_data = []
            
            for cwe_name, cwe_group in filtered_df.groupby('cwe'):
                # Calculate aggregated metrics for this CWE
                total_tp = cwe_group['TP'].sum()
                total_fp = cwe_group['FP'].sum()
                total_tn = cwe_group['TN'].sum()
                total_fn = cwe_group['FN'].sum()
                
                # Calculate overall metrics for the CWE
                overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
                overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
                overall_accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
                overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0
                
                # Calculate custom score for the CWE
                overall_custom_score = (
                    total_tp * tp_weight - 
                    total_fp * fp_penalty + 
                    total_tn * tn_bonus - 
                    total_fn * fn_penalty
                )
                
                # Count experiments and unique models for this CWE
                num_experiments = len(cwe_group)
                unique_models = cwe_group['model'].nunique()
                unique_datasets = cwe_group['dataset'].nunique()
                unique_prompt_versions = cwe_group['prompt_version'].nunique()
                
                cwe_grouped_data.append({
                    'CWE': cwe_name,
                    'Experiments': num_experiments,
                    'Unique Models': unique_models,
                    'Unique Datasets': unique_datasets,
                    'Unique Prompt Versions': unique_prompt_versions,
                    'Total TP': total_tp,
                    'Total FP': total_fp,
                    'Total TN': total_tn,
                    'Total FN': total_fn,
                    'Overall Precision': overall_precision,
                    'Overall Recall': overall_recall,
                    'Overall Accuracy': overall_accuracy,
                    'Overall F1-Score': overall_f1,
                    'Overall Custom Score': overall_custom_score
                })
            
            # Convert to DataFrame and sort by custom score
            cwe_grouped_df = pd.DataFrame(cwe_grouped_data)
            if not cwe_grouped_df.empty:
                cwe_grouped_df = cwe_grouped_df.sort_values('Overall Custom Score', ascending=False)
                
                # Display the CWE-grouped table
                st.dataframe(
                    cwe_grouped_df.round(3),
                    use_container_width=True
                )
                
                # Download button for CWE-grouped data
                csv_cwe = cwe_grouped_df.to_csv(index=False)
                st.download_button(
                    label="Download CWE-grouped data as CSV",
                    data=csv_cwe,
                    file_name="cwe_grouped_experiment_data.csv",
                    mime="text/csv"
                )
            else:
                st.warning("No data available for CWE grouping.")
        
        # Add a summary section below all three tables
        st.markdown("---")
        st.subheader("📈 Summary Comparison")
        
        if not filtered_df.empty:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                # Best performing model
                if not model_grouped_df.empty:
                    best_model = model_grouped_df.loc[model_grouped_df['Overall Custom Score'].idxmax()]
                    st.metric(
                        "🏆 Best Model",
                        best_model['Model'],
                        f"Score: {best_model['Overall Custom Score']:.3f}"
                    )
                else:
                    st.metric("🏆 Best Model", "N/A", "No data")
            
            with col2:
                # Best performing CWE
                if not cwe_grouped_df.empty:
                    best_cwe = cwe_grouped_df.loc[cwe_grouped_df['Overall Custom Score'].idxmax()]
                    st.metric(
                        "🔒 Best CWE",
                        best_cwe['CWE'],
                        f"Score: {best_cwe['Overall Custom Score']:.3f}"
                    )
                else:
                    st.metric("🔒 Best CWE", "N/A", "No data")
            
            with col3:
                # Model with most experiments
                if not model_grouped_df.empty:
                    most_experiments_model = model_grouped_df.loc[model_grouped_df['Experiments'].idxmax()]
                    st.metric(
                        "🔬 Most Experiments (Model)",
                        most_experiments_model['Model'],
                        f"Count: {most_experiments_model['Experiments']}"
                    )
                else:
                    st.metric("🔬 Most Experiments (Model)", "N/A", "No data")
            
            with col4:
                # CWE with most experiments
                if not cwe_grouped_df.empty:
                    most_experiments_cwe = cwe_grouped_df.loc[cwe_grouped_df['Experiments'].idxmax()]
                    st.metric(
                        "🔬 Most Experiments (CWE)",
                        most_experiments_cwe['CWE'],
                        f"Count: {most_experiments_cwe['Experiments']}"
                    )
                else:
                    st.metric("🔬 Most Experiments (CWE)", "N/A", "No data")
    
    with tab6:
        st.subheader("Dataset Analysis")
        
        if not filtered_df.empty:
            # Selection controls
            col1, col2, col3 = st.columns(3)
            
            with col1:
                selected_dataset = st.selectbox(
                    "Select Dataset",
                    options=sorted(filtered_df['dataset'].unique()),
                    key='dataset_selector'
                )
            
            with col2:
                selected_prompt_version = st.selectbox(
                    "Select Prompt Version",
                    options=sorted(filtered_df['prompt_version'].unique()),
                    key='prompt_version_selector'
                )
            
            with col3:
                selected_model = st.selectbox(
                    "Select Model",
                    options=sorted(filtered_df['model'].unique()),
                    key='model_selector'
                )
            
            # Filter data based on selection
            filtered_data = filtered_df[
                (filtered_df['dataset'] == selected_dataset) &
                (filtered_df['prompt_version'] == selected_prompt_version) &
                (filtered_df['model'] == selected_model)
            ]
            
            if not filtered_data.empty:
                # Create CWE summary table
                cwe_summary = filtered_data.groupby('cwe').agg({
                    'TP': 'sum',
                    'TN': 'sum',
                    'FP': 'sum',
                    'FN': 'sum'
                }).reset_index()
                
                # Add calculated columns
                cwe_summary['Safe'] = cwe_summary['TN'] + cwe_summary['FP']
                cwe_summary['Vulnerable'] = cwe_summary['TP'] + cwe_summary['FN']
                cwe_summary['Total Test Cases'] = cwe_summary['TP'] + cwe_summary['TN'] + cwe_summary['FP'] + cwe_summary['FN']
                
                # Reorder columns
                cwe_summary = cwe_summary[['cwe', 'Total Test Cases', 'Safe', 'Vulnerable']]
                
                # Sort by total test cases (descending)
                cwe_summary = cwe_summary.sort_values('Total Test Cases', ascending=False)
                
                st.subheader(f"📊 CWE Analysis: {selected_dataset} - {selected_prompt_version} - {selected_model}")
                
                # Display the table
                st.dataframe(
                    cwe_summary,
                    use_container_width=True,
                    column_config={
                        'cwe': st.column_config.TextColumn("CWE", width="medium"),
                        'Total Test Cases': st.column_config.NumberColumn("Total Test Cases", format="%d"),
                        'Safe': st.column_config.NumberColumn("Safe", format="%d"),
                        'Vulnerable': st.column_config.NumberColumn("Vulnerable", format="%d")
                    }
                )
                
                # Summary metrics
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    total_cases = cwe_summary['Total Test Cases'].sum()
                    st.metric("Total Test Cases", f"{total_cases:,}")
                
                with col2:
                    total_safe = cwe_summary['Safe'].sum()
                    st.metric("Total Safe", f"{total_safe:,}")
                
                with col3:
                    total_vulnerable = cwe_summary['Vulnerable'].sum()
                    st.metric("Total Vulnerable", f"{total_vulnerable:,}")
                
                # Export button
                csv_data = cwe_summary.to_csv(index=False)
                st.download_button(
                    "💾 Download CWE Summary",
                    csv_data,
                    f"cwe_summary_{selected_dataset}_{selected_prompt_version}_{selected_model}.csv",
                    "text/csv"
                )
                
            else:
                st.warning(f"No data found for the selected combination: {selected_dataset} - {selected_prompt_version} - {selected_model}")
                st.info("Try selecting different combinations of dataset, prompt version, and model.")
        else:
            st.warning("No data available for analysis.")
    
    with tab7:
        st.subheader("🔥 Interactive Heatmaps")
        st.markdown("Create customizable heatmaps to visualize performance metrics across different dimensions.")
        
        # Heatmap configuration
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Metric selection
            heatmap_metric = st.selectbox(
                "Select Metric",
                ['precision', 'recall', 'accuracy', 'f1_score', 'custom_score'],
                format_func=lambda x: x.replace('_', ' ').title(),
                key='heatmap_metric'
            )
        
        with col2:
            # X-axis selection
            x_axis = st.selectbox(
                "X-axis",
                ['dataset', 'model', 'prompt_version', 'cwe'],
                key='heatmap_x_axis'
            )
        
        with col3:
            # Y-axis selection
            y_axis = st.selectbox(
                "Y-axis",
                ['dataset', 'model', 'prompt_version', 'cwe'],
                key='heatmap_y_axis',
                index=1  # Default to 'model' to avoid same as x-axis
            )
        
        # Ensure x and y axes are different
        if x_axis == y_axis:
            st.warning("⚠️ Please select different dimensions for X and Y axes to create a meaningful heatmap.")
        else:
            # Create the heatmap
            try:
                # Group by selected dimensions and calculate mean of selected metric
                heatmap_data = filtered_df.groupby([x_axis, y_axis])[heatmap_metric].mean().reset_index()
                
                # Pivot the data for heatmap
                heatmap_pivot = heatmap_data.pivot(index=y_axis, columns=x_axis, values=heatmap_metric)
                
                # Fill NaN values with 0 or mean
                heatmap_pivot = heatmap_pivot.fillna(heatmap_pivot.mean().mean())
                
                # Create the heatmap
                fig = px.imshow(
                    heatmap_pivot,
                    title=f"{heatmap_metric.replace('_', ' ').title()} Heatmap: {y_axis.title()} vs {x_axis.title()}",
                    color_continuous_scale='RdYlGn',
                    aspect='equal',  # Make cells square
                    text_auto=True,
                    labels=dict(x=x_axis.title(), y=y_axis.title(), color=heatmap_metric.replace('_', ' ').title())
                )
                
                fig.update_layout(
                    height=600,
                    width=600,  # Set fixed width to maintain square aspect
                    xaxis_title=x_axis.title(),
                    yaxis_title=y_axis.title(),
                    coloraxis_colorbar_title=heatmap_metric.replace('_', ' ').title()
                )
                
                # Ensure square cells by setting equal scales
                fig.update_xaxes(scaleanchor="y", scaleratio=1)
                
                # Rotate x-axis labels for better readability
                fig.update_xaxes(tickangle=45)
                
                # Add grid lines for better cell visibility
                fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='rgba(128,128,128,0.2)')
                fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='rgba(128,128,128,0.2)')
                
                # Ensure the heatmap is centered and properly sized
                fig.update_layout(
                    margin=dict(l=50, r=50, t=80, b=50),
                    autosize=False
                )
                
                st.plotly_chart(fig, use_container_width=True, key=f"heatmap_{x_axis}_{y_axis}")
                
                # Show the data table below the heatmap
                st.subheader("📊 Heatmap Data Table")
                st.dataframe(heatmap_pivot.round(3), use_container_width=True)
                
                # Additional insights
                st.subheader("💡 Insights")
                col1, col2 = st.columns(2)
                
                with col1:
                    # Best performing combination
                    best_value = heatmap_pivot.max().max()
                    best_indices = heatmap_pivot.stack().idxmax()
                    st.metric(
                        "🏆 Best Performance",
                        f"{best_value:.3f}",
                        f"{best_indices[1]} + {best_indices[0]}"
                    )
                
                with col2:
                    # Worst performing combination
                    worst_value = heatmap_pivot.min().min()
                    worst_indices = heatmap_pivot.stack().idxmin()
                    st.metric(
                        "⚠️ Worst Performance",
                        f"{worst_value:.3f}",
                        f"{worst_indices[1]} + {worst_indices[0]}"
                    )
                
                # Performance distribution
                st.subheader("📈 Performance Distribution")
                fig_dist = px.histogram(
                    x=heatmap_pivot.values.flatten(),
                    title=f"Distribution of {heatmap_metric.replace('_', ' ').title()} Values",
                    nbins=20,
                    labels={'x': heatmap_metric.replace('_', ' ').title(), 'y': 'Frequency'}
                )
                fig_dist.update_layout(height=400)
                st.plotly_chart(fig_dist, use_container_width=True, key="heatmap_distribution")
                
                # Statistical summary
                st.subheader("📊 Statistical Summary")
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Mean", f"{heatmap_pivot.values.flatten().mean():.3f}")
                with col2:
                    st.metric("Median", f"{np.median(heatmap_pivot.values.flatten()):.3f}")
                with col3:
                    st.metric("Std Dev", f"{heatmap_pivot.values.flatten().std():.3f}")
                with col4:
                    st.metric("Range", f"{heatmap_pivot.values.flatten().max() - heatmap_pivot.values.flatten().min():.3f}")
                
                # Correlation analysis if applicable
                if len(heatmap_pivot.columns) > 1 and len(heatmap_pivot.index) > 1:
                    st.subheader("🔗 Correlation Analysis")
                    
                    # Calculate correlation matrix
                    correlation_matrix = heatmap_pivot.corr()
                    
                    fig_corr = px.imshow(
                        correlation_matrix,
                        title=f"Correlation Matrix for {x_axis.title()}",
                        color_continuous_scale='RdBu',
                        aspect='auto',
                        text_auto=True,
                        labels=dict(x=x_axis.title(), y=x_axis.title(), color="Correlation")
                    )
                    fig_corr.update_layout(height=400)
                    st.plotly_chart(fig_corr, use_container_width=True, key="correlation_matrix")
                
                # Export heatmap data
                st.subheader("📥 Export Options")
                col1, col2 = st.columns(2)
                
                with col1:
                    csv_data = heatmap_pivot.to_csv()
                    st.download_button(
                        "💾 Download CSV",
                        csv_data,
                        f"heatmap_{heatmap_metric}_{x_axis}_{y_axis}.csv",
                        "text/csv"
                    )
                
                with col2:
                    # Create a more detailed export with additional metadata
                    detailed_data = heatmap_data.copy()
                    detailed_data['metric'] = heatmap_metric
                    detailed_data['x_axis'] = x_axis
                    detailed_data['y_axis'] = y_axis
                    
                    detailed_csv = detailed_data.to_csv(index=False)
                    st.download_button(
                        "📊 Download Detailed Data",
                        detailed_csv,
                        f"detailed_heatmap_{heatmap_metric}_{x_axis}_{y_axis}.csv",
                        "text/csv"
                    )
                
            except Exception as e:
                st.error(f"❌ Error creating heatmap: {str(e)}")
                st.info("💡 Try selecting different dimensions or check if your data has sufficient values for the selected combination.")
                
                # Show debugging information
                with st.expander("🐛 Debug Information"):
                    st.write("**Error Details:**", str(e))
                    st.write("**Available Data:**")
                    st.write(f"- X-axis ({x_axis}): {filtered_df[x_axis].unique()}")
                    st.write(f"- Y-axis ({y_axis}): {filtered_df[y_axis].unique()}")
                    st.write(f"- Metric ({heatmap_metric}): Available in columns: {[col for col in filtered_df.columns if heatmap_metric in col]}")
    
    with tab8:
        st.subheader("📊 Comprehensive Tables")
        st.markdown("Detailed performance tables organized by different aspects of your experiments.")
        
        # Define metrics to display in tables
        metrics_to_display = ['precision', 'recall', 'accuracy', 'f1_score', 'custom_score']
        
        # Table configuration
        st.subheader("⚙️ Table Configuration")
        col1, col2 = st.columns(2)
        
        with col1:
            sort_by = st.selectbox(
                "Sort tables by metric",
                metrics_to_display,
                format_func=lambda x: x.replace('_', ' ').title(),
                key='table_sort_metric'
            )
        
        with col2:
            sort_order = st.selectbox(
                "Sort order",
                ['Descending (Best First)', 'Ascending (Worst First)'],
                key='table_sort_order'
            )
        
        ascending = sort_order == 'Ascending (Worst First)'
        
        # Create comprehensive tables for different aspects
        st.subheader("🔍 Performance by CWE")
        
        # Table 1: CWE-based performance with proper aggregation
        cwe_performance_data = []
        
        for cwe_name, cwe_group in filtered_df.groupby('cwe'):
            # Aggregate confusion matrix for this CWE
            total_tp = cwe_group['TP'].sum()
            total_fp = cwe_group['FP'].sum()
            total_tn = cwe_group['TN'].sum()
            total_fn = cwe_group['FN'].sum()
            
            # Calculate aggregated metrics for this CWE
            precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
            recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
            accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            custom_score = (
                total_tp * tp_weight - 
                total_fp * fp_penalty + 
                total_tn * tn_bonus - 
                total_fn * fn_penalty
            )
            
            cwe_performance_data.append({
                'cwe': cwe_name,
                'precision': precision,
                'recall': recall,
                'accuracy': accuracy,
                'f1_score': f1_score,
                'custom_score': custom_score
            })
        
        cwe_performance = pd.DataFrame(cwe_performance_data).set_index('cwe')
        
        # Sort the table
        cwe_performance = cwe_performance.sort_values(sort_by, ascending=ascending)
        
        # Display the table with styling
        st.dataframe(
            cwe_performance,
            use_container_width=True,
            column_config={
                col: st.column_config.NumberColumn(
                    col.replace('_', ' ').title(),
                    format="%.3f"
                ) for col in cwe_performance.columns
            }
        )
        
        # Export CWE table
        col1, col2 = st.columns(2)
        with col1:
            csv_data = cwe_performance.to_csv()
            st.download_button(
                "💾 Download CWE Table",
                csv_data,
                "cwe_performance_table.csv",
                "text/csv"
            )
        
        with col2:
            # Show CWE insights
            best_cwe = cwe_performance[metrics_to_display[0]].idxmax()
            worst_cwe = cwe_performance[metrics_to_display[0]].idxmin()
            st.info(f"🏆 Best CWE: {best_cwe} | ⚠️ Worst CWE: {worst_cwe}")
        
        st.markdown("---")
        
        # Table 2: Model-based performance with proper aggregation
        st.subheader("🤖 Performance by Model")
        
        model_performance_data = []
        
        for model_name, model_group in filtered_df.groupby('model'):
            # Aggregate confusion matrix for this model
            total_tp = model_group['TP'].sum()
            total_fp = model_group['FP'].sum()
            total_tn = model_group['TN'].sum()
            total_fn = model_group['FN'].sum()
            
            # Calculate aggregated metrics for this model
            precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
            recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
            accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            custom_score = (
                total_tp * tp_weight - 
                total_fp * fp_penalty + 
                total_tn * tn_bonus - 
                total_fn * fn_penalty
            )
            
            model_performance_data.append({
                'model': model_name,
                'precision': precision,
                'recall': recall,
                'accuracy': accuracy,
                'f1_score': f1_score,
                'custom_score': custom_score
            })
        
        model_performance = pd.DataFrame(model_performance_data).set_index('model')
        
        # Sort the table
        model_performance = model_performance.sort_values(sort_by, ascending=ascending)
        
        st.dataframe(
            model_performance,
            use_container_width=True,
            column_config={
                col: st.column_config.NumberColumn(
                    col.replace('_', ' ').title(),
                    format="%.3f"
                ) for col in model_performance.columns
            }
        )
        
        # Export Model table
        col1, col2 = st.columns(2)
        with col1:
            csv_data = model_performance.to_csv()
            st.download_button(
                "💾 Download Model Table",
                csv_data,
                "model_performance_table.csv",
                "text/csv"
            )
        
        with col2:
            # Show model insights
            best_model = model_performance[metrics_to_display[0]].idxmax()
            worst_model = model_performance[metrics_to_display[0]].idxmin()
            st.info(f"🏆 Best Model: {best_model} | ⚠️ Worst Model: {worst_model}")
        
        st.markdown("---")
        
        # Table 3: Dataset-based performance with proper aggregation
        st.subheader("📁 Performance by Dataset")
        
        dataset_performance_data = []
        
        for dataset, group in filtered_df.groupby('dataset'):
            # Aggregate confusion matrix for this dataset
            total_tp = group['TP'].sum()
            total_fp = group['FP'].sum()
            total_tn = group['TN'].sum()
            total_fn = group['FN'].sum()
            
            # Calculate aggregated metrics for this dataset
            precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
            recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
            accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            custom_score = (
                total_tp * tp_weight - 
                total_fp * fp_penalty + 
                total_tn * tn_bonus - 
                total_fn * fn_penalty
            )
            
            dataset_performance_data.append({
                'dataset': dataset,
                'precision': precision,
                'recall': recall,
                'accuracy': accuracy,
                'f1_score': f1_score,
                'custom_score': custom_score
            })
        
        dataset_performance = pd.DataFrame(dataset_performance_data).set_index('dataset')
        
        # Sort the table
        dataset_performance = dataset_performance.sort_values(sort_by, ascending=ascending)
        
        st.dataframe(
            dataset_performance,
            use_container_width=True,
            column_config={
                col: st.column_config.NumberColumn(
                    col.replace('_', ' ').title(),
                    format="%.3f"
                ) for col in dataset_performance.columns
            }
        )
        
        # Export Dataset table
        col1, col2 = st.columns(2)
        with col1:
            csv_data = dataset_performance.to_csv()
            st.download_button(
                "💾 Download Dataset Table",
                csv_data,
                "dataset_performance_table.csv",
                "text/csv"
            )
        
        with col2:
            # Show dataset insights
            best_dataset = dataset_performance[metrics_to_display[0]].idxmax()
            worst_dataset = dataset_performance[metrics_to_display[0]].idxmin()
            st.info(f"🏆 Best Dataset: {best_dataset} | ⚠️ Worst Dataset: {worst_dataset}")
        
        st.markdown("---")
        
        # Table 4: Prompt Version-based performance with proper aggregation
        st.subheader("📝 Performance by Prompt Version")
        
        prompt_performance_data = []
        
        for prompt_version, group in filtered_df.groupby('prompt_version'):
            # Aggregate confusion matrix for this prompt version
            total_tp = group['TP'].sum()
            total_fp = group['FP'].sum()
            total_tn = group['TN'].sum()
            total_fn = group['FN'].sum()
            
            # Calculate aggregated metrics for this prompt version
            precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
            recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
            accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            custom_score = (
                total_tp * tp_weight - 
                total_fp * fp_penalty + 
                total_tn * tn_bonus - 
                total_fn * fn_penalty
            )
            
            prompt_performance_data.append({
                'prompt_version': prompt_version,
                'precision': precision,
                'recall': recall,
                'accuracy': accuracy,
                'f1_score': f1_score,
                'custom_score': custom_score
            })
        
        prompt_performance = pd.DataFrame(prompt_performance_data).set_index('prompt_version')
        
        # Sort the table
        prompt_performance = prompt_performance.sort_values(sort_by, ascending=ascending)
        
        st.dataframe(
            prompt_performance,
            use_container_width=True,
            column_config={
                col: st.column_config.NumberColumn(
                    col.replace('_', ' ').title(),
                    format="%.3f"
                ) for col in prompt_performance.columns
            }
        )
        
        # Export Prompt Version table
        col1, col2 = st.columns(2)
        with col1:
            csv_data = prompt_performance.to_csv()
            st.download_button(
                "💾 Download Prompt Version Table",
                csv_data,
                "prompt_version_performance_table.csv",
                "text/csv"
            )
        
        with col2:
            # Show prompt version insights
            best_prompt = prompt_performance[metrics_to_display[0]].idxmax()
            worst_prompt = prompt_performance[metrics_to_display[0]].idxmin()
            st.info(f"🏆 Best Prompt Version: {best_prompt} | ⚠️ Worst Prompt Version: {worst_prompt}")
        
        # Summary statistics
        st.markdown("---")
        st.subheader("📈 Overall Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Experiments", len(filtered_df))
        with col2:
            st.metric("Unique CWEs", filtered_df['cwe'].nunique())
        with col3:
            st.metric("Models Tested", filtered_df['model'].nunique())
        with col4:
            st.metric("Prompt Versions", filtered_df['prompt_version'].nunique())
        
        # Export all tables combined
        st.subheader("📥 Export All Tables")
        
        # Create a comprehensive summary
        summary_data = []
        for aspect in ['cwe', 'model', 'dataset', 'prompt_version']:
            aspect_performance = filtered_df.groupby(aspect)[metrics_to_display].mean().round(3)
            aspect_performance['aspect_type'] = aspect
            aspect_performance['aspect_name'] = aspect_performance.index
            aspect_performance = aspect_performance.reset_index(drop=True)
            summary_data.append(aspect_performance)
        
        combined_summary = pd.concat(summary_data, ignore_index=True)
        
        col1, col2 = st.columns(2)
        with col1:
            csv_data = combined_summary.to_csv(index=False)
            st.download_button(
                "💾 Download Combined Summary",
                csv_data,
                "all_performance_tables.csv",
                "text/csv"
            )
        
        with col2:
            # Create a pivot table for easy comparison
            pivot_data = filtered_df.groupby(['cwe', 'model'])[metrics_to_display[0]].mean().reset_index()
            pivot_table = pivot_data.pivot(index='cwe', columns='model', values=metrics_to_display[0]).round(3)
            
            csv_data = pivot_table.to_csv()
            st.download_button(
                "📊 Download CWE vs Model Pivot",
                csv_data,
                "cwe_model_pivot_table.csv",
                "text/csv"
            )
    
    # Footer
    st.markdown("---")
    st.markdown("**Dashboard created for OWASP False Positive Reduction Analysis**")

if __name__ == "__main__":
    main() 