#!/usr/bin/env python3
"""
Command-line interface for Golang Crypto Asset Scanner.
This script allows scanning Go files or Git repositories for crypto assets without using the Streamlit UI.
"""

import os
import sys
import json
import argparse
import tempfile
import shutil
from pathlib import Path

from go_crypto_scanner import scan_golang_files
from git_handler import clone_git_repo, get_go_files_in_repo

def setup_argparse():
    """Setup command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="Golang Crypto Asset Scanner - Identify cryptographic libraries and functions in Go code",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Create a group for input methods (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    
    # File or directory input
    input_group.add_argument(
        '-f', '--files',
        nargs='+',
        help='Path to Go file(s) or directory containing Go files to scan'
    )
    
    # Git repository input
    input_group.add_argument(
        '-g', '--git',
        help='URL of Git repository to clone and scan'
    )
    
    # Git branch (optional)
    parser.add_argument(
        '-b', '--branch',
        help='Branch to checkout (for Git repository scanning)',
        default=None
    )
    
    # Output file (optional)
    parser.add_argument(
        '-o', '--output',
        help='Path to output file (JSON format)',
        default=None
    )
    
    # Verbose output
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser

def scan_files(file_paths, verbose=False):
    """Scan the specified Go files"""
    if verbose:
        print(f"Scanning {len(file_paths)} Go files...")
    
    # Validate file paths
    valid_paths = []
    for path in file_paths:
        if os.path.isfile(path) and path.endswith('.go'):
            valid_paths.append(path)
        elif os.path.isdir(path):
            # If directory, add all Go files in it
            for go_file in Path(path).rglob('*.go'):
                valid_paths.append(str(go_file))
    
    if not valid_paths:
        print("Error: No valid Go files found to scan.")
        return None
    
    if verbose:
        print(f"Found {len(valid_paths)} Go files to scan.")
    
    # Perform the scan
    return scan_golang_files(valid_paths)

def scan_git_repo(repo_url, branch=None, verbose=False):
    """Clone and scan a Git repository"""
    if verbose:
        print(f"Cloning repository: {repo_url}")
        if branch:
            print(f"Using branch: {branch}")
    
    # Create a temporary directory for the repository
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clone the repository
        clone_success = clone_git_repo(repo_url, temp_dir, branch)
        
        if not clone_success:
            print("Error: Failed to clone repository.")
            return None
        
        # Get all Go files in the repository
        go_files = get_go_files_in_repo(temp_dir)
        
        if not go_files:
            print("No Go files found in the repository.")
            return None
        
        if verbose:
            print(f"Found {len(go_files)} Go files in repository.")
        
        # Scan the Go files
        return scan_golang_files(go_files)
    
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)

def print_results_summary(results):
    """Print a summary of the scan results to the console"""
    if not results or not results['findings']:
        print("No cryptographic assets or libraries found.")
        return
    
    print("\n=== Scan Results Summary ===")
    print(f"Total files scanned: {results['total_files']}")
    print(f"Files with crypto components: {len(results['files_with_crypto'])}")
    print(f"Total crypto components found: {len(results['findings'])}")
    
    # Count findings by type
    type_counts = {}
    for finding in results['findings']:
        finding_type = finding['type']
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
    
    print("\nFindings by type:")
    for finding_type, count in type_counts.items():
        print(f"  {finding_type}: {count}")
    
    # Print detailed findings
    print("\n=== Detailed Findings ===")
    for i, finding in enumerate(results['findings'], 1):
        print(f"{i}. {finding['description']}")
        print(f"   File: {finding['file_path']}")
        print(f"   Type: {finding['type']}")
        print(f"   Category: {finding['category']}")
        print(f"   Line: {finding['line_number']}")
        print()

def save_results_to_file(results, output_file):
    """Save the scan results to a JSON file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving results to file: {str(e)}")
        return False

def main():
    """Main entry point for the CLI application"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Scan files or git repository based on input
    if args.files:
        results = scan_files(args.files, args.verbose)
    elif args.git:
        results = scan_git_repo(args.git, args.branch, args.verbose)
    else:
        parser.print_help()
        return 1
    
    # Check if scan was successful
    if not results:
        return 1
    
    # Print results summary
    print_results_summary(results)
    
    # Save results to file if specified
    if args.output:
        save_results_to_file(results, args.output)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())