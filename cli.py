#!/usr/bin/env python3
"""
Command-line interface for Golang Crypto Asset Scanner.
This script allows scanning Go files or Git repositories for crypto assets without using the Streamlit UI.
Features enhanced UX with progress bars, timeout handling, and colorful output.
"""

import os
import sys
import json
import time
import signal
import argparse
import tempfile
import threading
import traceback
import shutil
from pathlib import Path
from datetime import datetime

from tqdm import tqdm
from colorama import Fore, Style, init

from go_crypto_scanner import scan_golang_files
from git_handler import clone_git_repo, get_go_files_in_repo

# Initialize colorama
init(autoreset=True)

# Constants
TIMEOUT_SECONDS = 60
VERSION = "1.0.0"

class TimeoutError(Exception):
    """Exception raised when a file scan times out."""
    pass

class FileScanResult:
    """Class to store the result of scanning a single file."""
    def __init__(self, file_path):
        self.file_path = file_path
        self.success = False
        self.error = None  # type: str or None
        self.findings = []
        self.elapsed_time = 0.0  # type: float
        self.timed_out = False

def setup_argparse():
    """Setup command-line argument parser"""
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}Golang Crypto Asset Scanner v{VERSION}{Style.RESET_ALL} - Identify cryptographic libraries and functions in Go code",
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
    
    # Timeout (optional)
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        help=f'Timeout in seconds for scanning each file (default: {TIMEOUT_SECONDS})',
        default=TIMEOUT_SECONDS
    )
    
    # Verbose output
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Quiet mode
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress all output except errors and final summary'
    )
    
    return parser

def print_banner():
    """Print a banner for the application"""
    banner = f"""
{Fore.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ {Fore.WHITE}Golang Crypto Asset Scanner v{VERSION}{Fore.CYAN}                      ┃
┃ {Fore.WHITE}Scan Go files for cryptographic libraries and assets{Fore.CYAN}        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Style.RESET_ALL}
    """
    print(banner)

def timeout_handler(signum, frame):
    """Handler for timeout signal"""
    raise TimeoutError("Scan operation timed out")

def scan_single_file(file_path, timeout_seconds):
    """
    Scan a single Go file with timeout handling
    
    Args:
        file_path (str): Path to the Go file
        timeout_seconds (int): Timeout in seconds
        
    Returns:
        FileScanResult: Result of the file scan
    """
    result = FileScanResult(file_path)
    
    # Set up the timeout handler
    original_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_seconds)
    
    start_time = time.time()
    
    try:
        # Read file content
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            content = file.read()
        
        from go_crypto_scanner import analyze_go_file
        file_findings = analyze_go_file(file_path, content)
        
        # Record results
        result.success = True
        result.findings = file_findings
    
    except TimeoutError:
        result.timed_out = True
        result.error = f"Timeout after {timeout_seconds} seconds"
    
    except Exception as e:
        result.error = str(e)
    
    finally:
        # Cancel the alarm and restore the original handler
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_handler)
        
        # Record elapsed time
        result.elapsed_time = time.time() - start_time
    
    return result

def scan_files(file_paths, timeout_seconds=TIMEOUT_SECONDS, verbose=False, quiet=False):
    """
    Scan the specified Go files with progress reporting and timeout handling
    
    Args:
        file_paths (list): List of file paths to scan
        timeout_seconds (int): Timeout in seconds for each file
        verbose (bool): Whether to enable verbose output
        quiet (bool): Whether to suppress non-essential output
        
    Returns:
        dict: Results of the scan
    """
    if not quiet:
        print(f"\n{Fore.YELLOW}Validating input files...{Style.RESET_ALL}")
    
    # Validate file paths and collect Go files
    valid_paths = []
    skipped_paths = []
    
    for path in file_paths:
        if os.path.isfile(path):
            if path.endswith('.go'):
                valid_paths.append(path)
            else:
                skipped_paths.append((path, "Not a Go file"))
        elif os.path.isdir(path):
            # If directory, find all Go files in it
            found_files = list(Path(path).rglob("*.go"))
            valid_paths.extend([str(f) for f in found_files])
            
            if verbose and not quiet:
                print(f"{Fore.BLUE}Found {len(found_files)} Go files in directory: {path}{Style.RESET_ALL}")
        else:
            skipped_paths.append((path, "File or directory not found"))
    
    if not valid_paths:
        print(f"{Fore.RED}Error: No valid Go files found to scan.{Style.RESET_ALL}")
        return None
    
    if not quiet:
        print(f"{Fore.GREEN}Found {len(valid_paths)} Go files to scan.{Style.RESET_ALL}")
        if skipped_paths and verbose:
            print(f"\n{Fore.YELLOW}Skipped {len(skipped_paths)} invalid paths:{Style.RESET_ALL}")
            for path, reason in skipped_paths:
                print(f"  {Fore.RED}✗ {path} - {reason}{Style.RESET_ALL}")
    
    # Initialize scan results
    results = {
        'total_files': len(valid_paths),
        'files_with_crypto': set(),
        'findings': [],
        'skipped_files': [],
        'timed_out_files': [],
        'scan_timestamp': datetime.now().isoformat(),
        'scan_duration': 0
    }
    
    # Start scanning with progress bar
    scan_start_time = time.time()
    
    if not quiet:
        print(f"\n{Fore.YELLOW}Scanning files for crypto assets...{Style.RESET_ALL}")
    
    # Create progress bar
    progress_bar = tqdm(
        valid_paths, 
        desc="Scanning", 
        unit="file", 
        disable=quiet,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
    )
    
    for file_path in progress_bar:
        if not quiet and verbose:
            tqdm.write(f"Scanning: {file_path}")
        
        # Update progress bar description to show current file (shortened)
        filename = os.path.basename(file_path)
        progress_bar.set_description(f"Scanning {filename}")
        
        # Scan the file with timeout
        scan_result = scan_single_file(file_path, timeout_seconds)
        
        if scan_result.success:
            if scan_result.findings:
                results['files_with_crypto'].add(file_path)
                results['findings'].extend(scan_result.findings)
                
                if not quiet and verbose:
                    tqdm.write(f"{Fore.GREEN}✓ Found {len(scan_result.findings)} crypto elements in {filename}{Style.RESET_ALL}")
        else:
            if scan_result.timed_out:
                results['timed_out_files'].append({
                    'file_path': file_path,
                    'error': scan_result.error,
                    'elapsed_time': scan_result.elapsed_time
                })
                
                if not quiet:
                    tqdm.write(f"{Fore.RED}⚠ Timeout scanning {filename} after {timeout_seconds}s{Style.RESET_ALL}")
            else:
                results['skipped_files'].append({
                    'file_path': file_path,
                    'error': scan_result.error
                })
                
                if not quiet and verbose:
                    tqdm.write(f"{Fore.YELLOW}⚠ Error scanning {filename}: {scan_result.error}{Style.RESET_ALL}")
    
    # Record scan duration
    results['scan_duration'] = time.time() - scan_start_time
    
    # Convert set to list for serialization
    results['files_with_crypto'] = list(results['files_with_crypto'])
    
    return results

def scan_git_repo(repo_url, branch=None, timeout_seconds=TIMEOUT_SECONDS, verbose=False, quiet=False):
    """
    Clone and scan a Git repository with progress reporting
    
    Args:
        repo_url (str): URL of the Git repository to clone
        branch (str): Optional branch to checkout
        timeout_seconds (int): Timeout in seconds for each file
        verbose (bool): Whether to enable verbose output
        quiet (bool): Whether to suppress non-essential output
        
    Returns:
        dict: Results of the scan
    """
    if not quiet:
        print(f"\n{Fore.YELLOW}Cloning repository: {repo_url}{Style.RESET_ALL}")
        if branch:
            print(f"{Fore.BLUE}Using branch: {branch}{Style.RESET_ALL}")
    
    # Create a temporary directory for the repository
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clone the repository with progress indication
        if not quiet:
            print(f"{Fore.YELLOW}Cloning...{Style.RESET_ALL}")
            
        clone_start_time = time.time()
        clone_success = clone_git_repo(repo_url, temp_dir, branch)
        clone_duration = time.time() - clone_start_time
        
        if not clone_success:
            print(f"{Fore.RED}Error: Failed to clone repository.{Style.RESET_ALL}")
            return None
        
        if not quiet:
            print(f"{Fore.GREEN}Repository cloned successfully in {clone_duration:.2f} seconds.{Style.RESET_ALL}")
        
        # Get all Go files in the repository
        if not quiet:
            print(f"{Fore.YELLOW}Finding Go files in repository...{Style.RESET_ALL}")
            
        go_files = get_go_files_in_repo(temp_dir)
        
        if not go_files:
            print(f"{Fore.RED}No Go files found in the repository.{Style.RESET_ALL}")
            return None
        
        if not quiet:
            print(f"{Fore.GREEN}Found {len(go_files)} Go files in repository.{Style.RESET_ALL}")
        
        # Scan the Go files
        return scan_files(go_files, timeout_seconds, verbose, quiet)
    
    finally:
        # Clean up the temporary directory
        if not quiet and verbose:
            print(f"{Fore.BLUE}Cleaning up temporary directory...{Style.RESET_ALL}")
            
        shutil.rmtree(temp_dir)

def print_results_summary(results, verbose=False, quiet=False):
    """
    Print a summary of the scan results to the console
    
    Args:
        results (dict): Scan results
        verbose (bool): Whether to enable verbose output
        quiet (bool): Whether to suppress non-essential output
    """
    if quiet:
        return
        
    if not results['findings']:
        print(f"\n{Fore.YELLOW}No cryptographic assets or libraries found.{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}═════════════════════════════════════════{Style.RESET_ALL}")
    print(f"{Fore.CYAN}           SCAN RESULTS SUMMARY           {Style.RESET_ALL}")
    print(f"{Fore.CYAN}═════════════════════════════════════════{Style.RESET_ALL}")
    
    print(f"\n{Fore.WHITE}Total files scanned:{Style.RESET_ALL} {results['total_files']}")
    print(f"{Fore.WHITE}Files with crypto components:{Style.RESET_ALL} {len(results['files_with_crypto'])}")
    print(f"{Fore.WHITE}Total crypto components found:{Style.RESET_ALL} {len(results['findings'])}")
    print(f"{Fore.WHITE}Scan duration:{Style.RESET_ALL} {results['scan_duration']:.2f} seconds")
    
    if results['skipped_files']:
        print(f"{Fore.WHITE}Files skipped due to errors:{Style.RESET_ALL} {len(results['skipped_files'])}")
    
    if results['timed_out_files']:
        print(f"{Fore.RED}Files timed out:{Style.RESET_ALL} {len(results['timed_out_files'])}")
    
    # Count findings by type
    type_counts = {}
    for finding in results['findings']:
        finding_type = finding['type']
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
    
    print(f"\n{Fore.CYAN}Findings by type:{Style.RESET_ALL}")
    for finding_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {Fore.GREEN}● {finding_type}:{Style.RESET_ALL} {count}")
    
    # Print files that timed out
    if results['timed_out_files'] and verbose:
        print(f"\n{Fore.RED}Timed out files:{Style.RESET_ALL}")
        for timeout_info in results['timed_out_files']:
            print(f"  {Fore.RED}⚠ {timeout_info['file_path']}{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}Reason: {timeout_info['error']}{Style.RESET_ALL}")
    
    # Print detailed findings if verbose
    if verbose:
        print(f"\n{Fore.CYAN}═════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.CYAN}           DETAILED FINDINGS              {Style.RESET_ALL}")
        print(f"{Fore.CYAN}═════════════════════════════════════════{Style.RESET_ALL}")
        
        # Group findings by file
        findings_by_file = {}
        for finding in results['findings']:
            file_path = finding['file_path']
            if file_path not in findings_by_file:
                findings_by_file[file_path] = []
            findings_by_file[file_path].append(finding)
        
        for file_path, findings in findings_by_file.items():
            print(f"\n{Fore.WHITE}File: {file_path}{Style.RESET_ALL}")
            for finding in findings:
                print(f"  {Fore.GREEN}● {finding['description']}{Style.RESET_ALL}")
                print(f"    Type: {finding['type']}, Category: {finding['category']}, Line: {finding['line_number']}")

def save_results_to_file(results, output_file, quiet=False):
    """
    Save the scan results to a JSON file
    
    Args:
        results (dict): Scan results
        output_file (str): Path to output file
        quiet (bool): Whether to suppress non-essential output
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        if not quiet:
            print(f"\n{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"\n{Fore.RED}Error saving results to file: {str(e)}{Style.RESET_ALL}")
        return False

def main():
    """Main entry point for the CLI application"""
    try:
        parser = setup_argparse()
        args = parser.parse_args()
        
        # Print banner unless in quiet mode
        if not args.quiet:
            print_banner()
        
        # Scan files or git repository based on input
        if args.files:
            results = scan_files(args.files, args.timeout, args.verbose, args.quiet)
        elif args.git:
            results = scan_git_repo(args.git, args.branch, args.timeout, args.verbose, args.quiet)
        else:
            parser.print_help()
            return 1
        
        # Check if scan was successful
        if not results:
            return 1
        
        # Print results summary
        print_results_summary(results, args.verbose, args.quiet)
        
        # Save results to file if specified
        if args.output:
            save_results_to_file(results, args.output, args.quiet)
        
        return 0
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        return 130
    
    except Exception as e:
        print(f"\n{Fore.RED}An unexpected error occurred:{Style.RESET_ALL}")
        print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
        # Safely access the quiet attribute, defaulting to False if args is not defined
        quiet_mode = getattr(args, 'quiet', False) if 'args' in locals() else False
        if not quiet_mode:
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())