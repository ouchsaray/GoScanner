import os
import re
import ast
import subprocess
import tempfile
from pathlib import Path
from crypto_definitions import (
    CRYPTO_PACKAGES,
    CRYPTO_FUNCTIONS,
    CRYPTO_CONSTANTS,
    CRYPTO_LIBRARIES
)

def scan_golang_files(file_paths):
    """
    Scan Go files to identify cryptographic libraries, assets, and functions.
    
    Args:
        file_paths (list): List of file paths to Go files
    
    Returns:
        dict: Results of the scan containing findings
    """
    results = {
        'total_files': len(file_paths),
        'files_with_crypto': set(),
        'findings': []
    }
    
    for file_path in file_paths:
        # Check if file exists and is readable
        if not os.path.isfile(file_path):
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                
                # Process the file content
                findings = analyze_go_file(file_path, content)
                
                if findings:
                    results['files_with_crypto'].add(file_path)
                    results['findings'].extend(findings)
        
        except Exception as e:
            print(f"Error processing file {file_path}: {str(e)}")
    
    # Convert set to list for serialization
    results['files_with_crypto'] = list(results['files_with_crypto'])
    
    return results

def analyze_go_file(file_path, content):
    """
    Analyze a Go file to identify crypto-related elements.
    
    Args:
        file_path (str): Path to the Go file
        content (str): Content of the Go file
    
    Returns:
        list: List of findings with details
    """
    findings = []
    
    # Extract package imports
    imports = extract_imports(content)
    
    # Check for crypto-related imports
    for imp in imports:
        for crypto_pkg in CRYPTO_PACKAGES:
            if crypto_pkg in imp:
                findings.append({
                    'file_path': file_path,
                    'type': 'package',
                    'name': imp,
                    'category': 'crypto_import',
                    'line_number': find_line_number(content, f'import "{imp}"') or 
                                  find_line_number(content, f'import ({imp}') or 0,
                    'description': f"Imported crypto package: {imp}"
                })
    
    # Check for third-party crypto libraries
    for lib, pattern in CRYPTO_LIBRARIES.items():
        if re.search(pattern, content):
            findings.append({
                'file_path': file_path,
                'type': 'library',
                'name': lib,
                'category': 'third_party_library',
                'line_number': find_line_number(content, pattern) or 0,
                'description': f"Using third-party crypto library: {lib}"
            })
    
    # Check for crypto function calls
    for func in CRYPTO_FUNCTIONS:
        pattern = r'\b' + re.escape(func) + r'\s*\('
        matches = re.finditer(pattern, content)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'file_path': file_path,
                'type': 'function',
                'name': func,
                'category': 'crypto_function',
                'line_number': line_num,
                'description': f"Crypto function call: {func}"
            })
    
    # Check for crypto constants
    for const, pattern in CRYPTO_CONSTANTS.items():
        if re.search(pattern, content):
            findings.append({
                'file_path': file_path,
                'type': 'constant',
                'name': const,
                'category': 'crypto_constant',
                'line_number': find_line_number(content, pattern) or 0,
                'description': f"Crypto constant: {const}"
            })
    
    # Check for custom crypto function definitions
    custom_funcs = extract_custom_crypto_functions(content)
    for func in custom_funcs:
        findings.append({
            'file_path': file_path,
            'type': 'function_definition',
            'name': func['name'],
            'category': 'custom_crypto_function',
            'line_number': func['line_number'],
            'description': f"Custom crypto function definition: {func['name']}"
        })
    
    return findings

def extract_imports(content):
    """Extract package imports from Go file content"""
    imports = []
    
    # Single line imports
    single_imports = re.findall(r'import\s+"([^"]+)"', content)
    imports.extend(single_imports)
    
    # Multi-line imports
    multi_import_blocks = re.findall(r'import\s+\(\s*(.*?)\s*\)', content, re.DOTALL)
    for block in multi_import_blocks:
        block_imports = re.findall(r'"([^"]+)"', block)
        imports.extend(block_imports)
    
    return imports

def find_line_number(content, pattern):
    """Find the line number for a pattern in the content"""
    try:
        match = re.search(pattern, content)
        if not match:
            return None
        
        return content[:match.start()].count('\n') + 1
    except re.error:
        # Handle regex pattern errors
        return None

def extract_custom_crypto_functions(content):
    """Extract potential custom crypto functions based on naming patterns"""
    crypto_keywords = ['crypt', 'encrypt', 'decrypt', 'hash', 'md5', 'sha', 
                      'aes', 'rsa', 'dsa', 'cipher', 'signature']
    
    custom_funcs = []
    
    # Match function definitions with crypto-related names
    func_pattern = r'func\s+(\w+)\s*\('
    matches = re.finditer(func_pattern, content)
    
    for match in matches:
        func_name = match.group(1)
        if any(keyword in func_name.lower() for keyword in crypto_keywords):
            line_num = content[:match.start()].count('\n') + 1
            custom_funcs.append({
                'name': func_name,
                'line_number': line_num
            })
    
    return custom_funcs
