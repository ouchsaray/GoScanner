import streamlit as st
import os
import tempfile
import shutil
import pandas as pd
from pathlib import Path

from go_crypto_scanner import scan_golang_files
from utils import upload_and_save_files, extract_git_repo, get_file_snippet
from visualization import (
    plot_crypto_findings_distribution,
    plot_severity_distribution,
    create_findings_table,
    display_findings_details,
    create_crypto_libraries_chart,
    create_antipatterns_chart,
    display_security_summary
)

# Set page config
st.set_page_config(
    page_title="Golang Crypto Scanner",
    page_icon="🔒",
    layout="wide"
)

def main():
    st.title("Golang Crypto Asset & Security Scanner")
    st.markdown("""
    This enhanced tool scans Golang projects to identify cryptographic libraries, assets, and security issues.
    Upload your Go files or provide a Git repository URL to analyze cryptographic components and potential vulnerabilities.
    """)
    
    # Create tabs for different input methods
    tab1, tab2 = st.tabs(["Upload Files", "Git Repository"])
    
    with tab1:
        st.header("Upload Go Files")
        uploaded_files = st.file_uploader("Upload your Go files", 
                                         type=["go"], 
                                         accept_multiple_files=True)
        
        if uploaded_files:
            with st.spinner("Processing uploaded files..."):
                # Create temporary directory for uploaded files
                temp_dir = tempfile.mkdtemp()
                try:
                    # Save uploaded files to temp directory
                    file_paths = upload_and_save_files(uploaded_files, temp_dir)
                    
                    if file_paths:
                        # Scan the Go files
                        scan_results = scan_golang_files(file_paths)
                        display_results(scan_results)
                finally:
                    # Clean up temporary directory
                    shutil.rmtree(temp_dir)
    
    with tab2:
        st.header("Scan Git Repository")
        repo_url = st.text_input("Enter Git repository URL")
        branch = st.text_input("Branch (optional, defaults to main/master)", "")
        
        if st.button("Scan Repository") and repo_url:
            with st.spinner("Cloning and scanning repository..."):
                # Create temporary directory for git repo
                temp_dir = tempfile.mkdtemp()
                try:
                    # Clone the repository
                    success, message = extract_git_repo(repo_url, temp_dir, branch)
                    
                    if success:
                        st.success(message)
                        # Get all Go files in the repository
                        go_files = list(Path(temp_dir).rglob("*.go"))
                        
                        if go_files:
                            # Scan the Go files
                            scan_results = scan_golang_files([str(f) for f in go_files])
                            display_results(scan_results)
                        else:
                            st.warning("No Go files found in the repository.")
                    else:
                        st.error(message)
                finally:
                    # Clean up temporary directory
                    shutil.rmtree(temp_dir)

def display_results(scan_results):
    """Display the scanning results with visualizations, security ratings, and tables"""
    if not scan_results or not scan_results['findings']:
        st.warning("No cryptographic assets or libraries found in the scanned files.")
        return
    
    st.success(f"Scan completed! Found {len(scan_results['findings'])} crypto-related elements.")
    
    # Display security summary cards
    st.subheader("Security Overview")
    display_security_summary(scan_results)
    
    # Create tabs for different result views
    overview_tab, details_tab, security_tab = st.tabs(["Overview", "Detailed Findings", "Security Analysis"])
    
    with overview_tab:
        # Distribution charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Findings by Category")
            fig1 = plot_crypto_findings_distribution(scan_results)
            st.plotly_chart(fig1, use_container_width=True)
        
        with col2:
            st.subheader("Findings by Severity")
            fig2 = plot_severity_distribution(scan_results)
            st.plotly_chart(fig2, use_container_width=True)
        
        # Summary metrics
        st.subheader("Summary Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Files Scanned", scan_results['total_files'])
        with col2:
            st.metric("Files with Crypto", len(scan_results['files_with_crypto']))
        with col3:
            st.metric("Total Findings", len(scan_results['findings']))
        
        # Get count of high severity issues
        high_count = sum(1 for f in scan_results['findings'] 
                         if f.get('severity', '').upper() == 'HIGH')
        with col4:
            st.metric("High Severity Issues", high_count, 
                     delta=-high_count, delta_color="inverse")
        
        # Display crypto libraries chart
        st.subheader("Crypto Libraries Found")
        lib_chart = create_crypto_libraries_chart(scan_results)
        if lib_chart:
            st.plotly_chart(lib_chart, use_container_width=True)
        else:
            st.info("No specific crypto libraries found.")
    
    with details_tab:
        # Display findings table
        st.subheader("Crypto Components Found")
        findings_df = create_findings_table(scan_results)
        
        # Add filters for the table
        col1, col2, col3 = st.columns(3)
        with col1:
            severity_filter = st.multiselect("Filter by Severity", 
                                            options=sorted(findings_df['Severity'].unique()),
                                            default=sorted(findings_df['Severity'].unique()))
        with col2:
            type_filter = st.multiselect("Filter by Type", 
                                       options=sorted(findings_df['Type'].unique()),
                                       default=sorted(findings_df['Type'].unique()))
        with col3:
            search_term = st.text_input("Search in Name or Description", "")
        
        # Apply filters
        filtered_df = findings_df
        if severity_filter:
            filtered_df = filtered_df[filtered_df['Severity'].isin(severity_filter)]
        if type_filter:
            filtered_df = filtered_df[filtered_df['Type'].isin(type_filter)]
        if search_term:
            mask = (filtered_df['Name'].str.contains(search_term, case=False)) | \
                   (filtered_df['Description'].str.contains(search_term, case=False))
            filtered_df = filtered_df[mask]
        
        # Show the filtered table
        st.dataframe(filtered_df, use_container_width=True)
        
        # Display detailed findings
        st.subheader("Detailed Findings")
        display_findings_details(scan_results)
    
    with security_tab:
        # Display security issues chart
        st.subheader("Security Issues and Antipatterns")
        antipatterns_chart = create_antipatterns_chart(scan_results)
        if antipatterns_chart:
            st.plotly_chart(antipatterns_chart, use_container_width=True)
        else:
            st.info("No specific security issues or antipatterns found.")
        
        # Filter findings to show only HIGH and MEDIUM severity issues
        high_med_findings = [f for f in scan_results['findings'] 
                           if f.get('severity', '').upper() in ['HIGH', 'MEDIUM']]
        
        if high_med_findings:
            st.subheader("Critical Security Issues")
            st.markdown("""
            The following issues should be addressed as they may pose security risks:
            """)
            
            for i, finding in enumerate(high_med_findings):
                with st.expander(f"{i+1}. {finding['description']} ({finding.get('severity', 'MEDIUM')})"):
                    st.markdown(f"**Location:** {finding['file_path']}, Line {finding['line_number']}")
                    
                    if 'recommendation' in finding and finding['recommendation']:
                        st.markdown(f"**Recommendation:** {finding['recommendation']}")
                    
                    if 'line_number' in finding and finding['line_number'] > 0:
                        snippet = get_file_snippet(finding['file_path'], finding['line_number'])
                        st.code(snippet, language='go')
        else:
            st.success("No critical security issues found.")

if __name__ == "__main__":
    main()
