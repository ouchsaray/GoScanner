import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
from utils import sanitize_path_for_display, get_file_snippet

# Color mapping for severity levels
SEVERITY_COLORS = {
    'HIGH': '#FF4B4B',    # Red
    'MEDIUM': '#FFA500',  # Orange
    'LOW': '#FFEB3B',     # Yellow
    'INFO': '#4CAF50'     # Green
}

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

def plot_severity_distribution(scan_results):
    """
    Create a pie chart showing the distribution of findings by severity.
    
    Args:
        scan_results (dict): Results from the scan
    
    Returns:
        plotly.graph_objects.Figure: Plotly figure object
    """
    # Use severity counts if available in the results
    if 'severity_counts' in scan_results:
        # Create dataframe from severity counts
        df = pd.DataFrame({
            'Severity': [s.upper() for s in scan_results['severity_counts'].keys()],
            'Count': list(scan_results['severity_counts'].values())
        })
    else:
        # Count findings by severity
        findings = scan_results['findings']
        severity_counts = Counter([
            finding.get('severity', 'INFO').upper() 
            for finding in findings
        ])
        
        # Create dataframe for plotting
        df = pd.DataFrame({
            'Severity': list(severity_counts.keys()),
            'Count': list(severity_counts.values())
        })
    
    # Only show severities with counts > 0
    df = df[df['Count'] > 0]
    
    # Define custom color map
    colors = [SEVERITY_COLORS.get(severity, '#808080') for severity in df['Severity']]
    
    # Create pie chart
    fig = px.pie(
        df, 
        values='Count', 
        names='Severity',
        title='Distribution of Findings by Severity',
        color='Severity',
        color_discrete_map={s: SEVERITY_COLORS.get(s, '#808080') for s in df['Severity']},
        hole=0.4
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(legend_title="Severity Levels")
    
    return fig

def create_findings_table(scan_results):
    """
    Create a pandas DataFrame for displaying findings in a table with severity information.
    
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
    
    # Ensure severity column exists
    if 'severity' not in df.columns:
        df['severity'] = 'INFO'
    
    # Reorder and select columns for display
    display_columns = ['display_path', 'severity', 'type', 'name', 'category', 'line_number', 'description']
    
    # Ensure all required columns exist
    for col in display_columns:
        if col not in df.columns and col != 'display_path':
            df[col] = ''
    
    display_df = df[display_columns].copy()
    
    # Rename columns for better display
    display_df.columns = ['File Path', 'Severity', 'Type', 'Name', 'Category', 'Line Number', 'Description']
    
    return display_df

def display_findings_details(scan_results):
    """
    Display detailed information about each finding with code snippets, severity ratings,
    and recommendations.
    
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
            
            # Sort findings by severity (HIGH first)
            severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
            file_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'INFO').upper(), 4))
            
            # Display each finding with code snippet
            for i, finding in enumerate(file_findings):
                # Get severity and appropriate styling
                severity = finding.get('severity', 'INFO').upper()
                severity_color = SEVERITY_COLORS.get(severity, '#808080')
                
                # Create a container for this finding
                with st.container():
                    # Display finding header with severity badge
                    st.markdown(
                        f"<div style='display: flex; align-items: center;'>"
                        f"<span style='background-color: {severity_color}; color: white; padding: 2px 8px; "
                        f"border-radius: 4px; margin-right: 10px;'>{severity}</span>"
                        f"<span style='font-weight: bold;'>Finding {i+1}:</span> {finding['description']}"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                    
                    # Display metadata
                    st.markdown(f"**Type:** {finding['type']} | **Category:** {finding['category']} | **Line:** {finding['line_number']}")
                    
                    # Display recommendation if available
                    if 'recommendation' in finding and finding['recommendation']:
                        st.markdown(f"**Recommendation:** {finding['recommendation']}")
                    
                    # Display matched text if available
                    if 'matched_text' in finding and finding['matched_text']:
                        st.markdown(f"**Matched Text:** `{finding['matched_text']}`")
                    
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

def create_antipatterns_chart(scan_results):
    """
    Create a bar chart showing the security issues and antipatterns found.
    
    Args:
        scan_results (dict): Results from the scan
    
    Returns:
        plotly.graph_objects.Figure: Plotly figure object or None if no antipatterns found
    """
    findings = scan_results['findings']
    
    # Filter antipattern findings
    antipattern_findings = [f for f in findings if f['type'] == 'antipattern' or f.get('severity', 'INFO').upper() == 'HIGH']
    
    if not antipattern_findings:
        return None
    
    # Count antipatterns by name
    antipattern_counts = Counter([finding['name'] for finding in antipattern_findings])
    
    # Create dataframe for plotting
    df = pd.DataFrame({
        'Issue': list(antipattern_counts.keys()),
        'Count': list(antipattern_counts.values())
    })
    
    # Sort by count
    df = df.sort_values('Count', ascending=False)
    
    # Create bar chart
    fig = px.bar(
        df, 
        x='Issue', 
        y='Count',
        title='Security Issues and Antipatterns',
        color='Count',
        color_continuous_scale=px.colors.sequential.Reds
    )
    
    fig.update_layout(xaxis_title="Security Issue", yaxis_title="Occurrences")
    
    return fig

def display_security_summary(scan_results):
    """
    Display a summary of security findings with severity distribution.
    
    Args:
        scan_results (dict): Results from the scan
    """
    findings = scan_results['findings']
    
    # Count findings by severity
    severity_counts = {
        'HIGH': sum(1 for f in findings if f.get('severity', 'INFO').upper() == 'HIGH'),
        'MEDIUM': sum(1 for f in findings if f.get('severity', 'INFO').upper() == 'MEDIUM'),
        'LOW': sum(1 for f in findings if f.get('severity', 'INFO').upper() == 'LOW'),
        'INFO': sum(1 for f in findings if f.get('severity', 'INFO').upper() == 'INFO')
    }
    
    # Create columns for the summary
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"<div style='background-color: {SEVERITY_COLORS['HIGH']}; color: white; padding: 10px; "
                   f"border-radius: 5px; text-align: center;'>"
                   f"<h1>{severity_counts['HIGH']}</h1>"
                   f"<p>High Severity</p></div>", unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"<div style='background-color: {SEVERITY_COLORS['MEDIUM']}; color: white; padding: 10px; "
                   f"border-radius: 5px; text-align: center;'>"
                   f"<h1>{severity_counts['MEDIUM']}</h1>"
                   f"<p>Medium Severity</p></div>", unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"<div style='background-color: {SEVERITY_COLORS['LOW']}; color: white; padding: 10px; "
                   f"border-radius: 5px; text-align: center;'>"
                   f"<h1>{severity_counts['LOW']}</h1>"
                   f"<p>Low Severity</p></div>", unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"<div style='background-color: {SEVERITY_COLORS['INFO']}; color: white; padding: 10px; "
                   f"border-radius: 5px; text-align: center;'>"
                   f"<h1>{severity_counts['INFO']}</h1>"
                   f"<p>Informational</p></div>", unsafe_allow_html=True)
    
    # Display security score
    total_weighted = (severity_counts['HIGH'] * 10 + 
                     severity_counts['MEDIUM'] * 5 + 
                     severity_counts['LOW'] * 2)
    
    total_findings = sum(severity_counts.values())
    
    if total_findings > 0:
        # Higher score means more issues (worse)
        security_score = min(100, int(total_weighted / max(1, total_findings) * 10))
        
        # Invert for display (higher is better)
        display_score = max(0, 100 - security_score)
        
        # Determine color based on score
        if display_score >= 80:
            score_color = '#4CAF50'  # Green
        elif display_score >= 60:
            score_color = '#FFC107'  # Amber
        elif display_score >= 40:
            score_color = '#FF9800'  # Orange
        else:
            score_color = '#F44336'  # Red
        
        st.markdown("<h3 style='text-align: center; margin-top: 20px;'>Security Score</h3>", 
                   unsafe_allow_html=True)
        
        st.markdown(f"<div style='text-align: center; margin: 20px 0;'>"
                   f"<div style='display: inline-block; width: 150px; height: 150px; border-radius: 50%; "
                   f"background: conic-gradient({score_color} {display_score}%, #e0e0e0 0); "
                   f"display: flex; align-items: center; justify-content: center;'>"
                   f"<div style='background: white; width: 120px; height: 120px; border-radius: 50%; "
                   f"display: flex; align-items: center; justify-content: center;'>"
                   f"<span style='font-size: 32px; font-weight: bold;'>{display_score}</span>"
                   f"</div></div></div>", unsafe_allow_html=True)
        
        # Add explanation
        st.markdown("<p style='text-align: center; font-size: 14px; color: #666;'>"
                   "Security score is based on the weighted number and severity of findings.<br>"
                   "Higher score indicates better security posture.</p>", 
                   unsafe_allow_html=True)
