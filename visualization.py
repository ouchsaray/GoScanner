import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
from utils import sanitize_path_for_display, get_file_snippet

def plot_crypto_findings_distribution(scan_results):
    """
    Create a pie chart showing the distribution of crypto findings by type.
    
    Args:
        scan_results (dict): Results from the scan
    
    Returns:
        plotly.graph_objects.Figure: Plotly figure object
    """
    findings = scan_results['findings']
    
    # Count findings by type
    type_counts = Counter([finding['type'] for finding in findings])
    
    # Create dataframe for plotting
    df = pd.DataFrame({
        'Type': list(type_counts.keys()),
        'Count': list(type_counts.values())
    })
    
    # Create pie chart
    fig = px.pie(
        df, 
        values='Count', 
        names='Type',
        title='Distribution of Crypto Findings by Type',
        color_discrete_sequence=px.colors.qualitative.Safe,
        hole=0.4
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(legend_title="Finding Types")
    
    return fig

def create_findings_table(scan_results):
    """
    Create a pandas DataFrame for displaying findings in a table.
    
    Args:
        scan_results (dict): Results from the scan
    
    Returns:
        pandas.DataFrame: DataFrame with findings
    """
    findings = scan_results['findings']
    
    # Create a DataFrame from the findings
    df = pd.DataFrame(findings)
    
    # Sanitize file paths for display
    df['display_path'] = df['file_path'].apply(sanitize_path_for_display)
    
    # Reorder and select columns for display
    display_columns = ['display_path', 'type', 'name', 'category', 'line_number', 'description']
    
    # Ensure all required columns exist
    for col in display_columns:
        if col not in df.columns and col != 'display_path':
            df[col] = ''
    
    display_df = df[display_columns].copy()
    
    # Rename columns for better display
    display_df.columns = ['File Path', 'Type', 'Name', 'Category', 'Line Number', 'Description']
    
    return display_df

def display_findings_details(scan_results):
    """
    Display detailed information about each finding with code snippets.
    
    Args:
        scan_results (dict): Results from the scan
    """
    findings = scan_results['findings']
    
    # Group findings by file path
    file_paths = sorted(set([finding['file_path'] for finding in findings]))
    
    for file_path in file_paths:
        with st.expander(f"File: {sanitize_path_for_display(file_path)}"):
            # Get findings for this file
            file_findings = [f for f in findings if f['file_path'] == file_path]
            
            # Display each finding with code snippet
            for i, finding in enumerate(file_findings):
                st.markdown(f"**Finding {i+1}:** {finding['description']}")
                st.markdown(f"**Type:** {finding['type']} | **Category:** {finding['category']} | **Line:** {finding['line_number']}")
                
                # Get code snippet
                if 'line_number' in finding and finding['line_number'] > 0:
                    snippet = get_file_snippet(file_path, finding['line_number'])
                    st.code(snippet, language='go')
                
                st.divider()

def create_crypto_libraries_chart(scan_results):
    """
    Create a bar chart showing the distribution of crypto libraries found.
    
    Args:
        scan_results (dict): Results from the scan
    
    Returns:
        plotly.graph_objects.Figure: Plotly figure object or None if no libraries found
    """
    findings = scan_results['findings']
    
    # Filter library findings
    library_findings = [f for f in findings if f['type'] in ['package', 'library']]
    
    if not library_findings:
        return None
    
    # Count libraries by name
    lib_counts = Counter([finding['name'] for finding in library_findings])
    
    # Create dataframe for plotting
    df = pd.DataFrame({
        'Library': list(lib_counts.keys()),
        'Count': list(lib_counts.values())
    })
    
    # Sort by count
    df = df.sort_values('Count', ascending=False)
    
    # Create bar chart
    fig = px.bar(
        df, 
        x='Library', 
        y='Count',
        title='Crypto Libraries Found',
        color='Count',
        color_continuous_scale=px.colors.sequential.Viridis
    )
    
    fig.update_layout(xaxis_title="Library", yaxis_title="Occurrences")
    
    return fig
