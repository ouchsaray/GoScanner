import streamlit as st
import os
import tempfile
import shutil
import pandas as pd
from pathlib import Path

from go_crypto_scanner import scan_golang_files
from utils import upload_and_save_files, extract_git_repo
from visualization import (
    plot_crypto_findings_distribution,
    create_findings_table,
    display_findings_details
)

# Set page config
st.set_page_config(
    page_title="Golang Crypto Scanner",
    page_icon="🔒",
    layout="wide"
)

def main():
    st.title("Golang Crypto Asset Scanner")
    st.markdown("""
    This tool scans Golang projects to identify cryptographic libraries, assets, and functions.
    Upload your Go files or provide a Git repository URL to analyze the cryptographic components.
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
    """Display the scanning results with visualizations and tables"""
    if not scan_results or not scan_results['findings']:
        st.warning("No cryptographic assets or libraries found in the scanned files.")
        return
    
    st.success(f"Scan completed! Found {len(scan_results['findings'])} crypto-related elements.")
    
    # Display summary statistics
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Findings by Category")
        fig = plot_crypto_findings_distribution(scan_results)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Summary")
        st.metric("Total Files Scanned", scan_results['total_files'])
        st.metric("Files with Crypto Components", len(scan_results['files_with_crypto']))
        st.metric("Total Crypto Components Found", len(scan_results['findings']))
    
    # Display findings table
    st.subheader("Crypto Components Found")
    findings_df = create_findings_table(scan_results)
    st.dataframe(findings_df, use_container_width=True)
    
    # Display detailed findings
    st.subheader("Detailed Findings")
    display_findings_details(scan_results)

if __name__ == "__main__":
    main()
