import os
import re
import ast
import subprocess
import tempfile
from pathlib import Path
from crypto_definitions import (
    SEVERITY,
    CRYPTO_PACKAGES,
    CRYPTO_FUNCTIONS,
    CRYPTO_CONSTANTS,
    CRYPTO_LIBRARIES,
    CRYPTO_ANTIPATTERNS
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
        'findings': [],
        'severity_counts': {
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
    }
    
    for file_path in file_paths:
        # Check if file exists and is readable
        if not os.path.isfile(file_path):
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                content = file.read()
                
                # Process the file content
                findings = analyze_go_file(file_path, content)
                
                if findings:
                    results['files_with_crypto'].add(file_path)
                    results['findings'].extend(findings)
                    
                    # Count findings by severity
                    for finding in findings:
                        severity = finding.get('severity', SEVERITY["INFO"]).lower()
                        results['severity_counts'][severity] = results['severity_counts'].get(severity, 0) + 1
        
        except Exception as e:
            print(f"Error processing file {file_path}: {str(e)}")
    
    # Convert set to list for serialization
    results['files_with_crypto'] = list(results['files_with_crypto'])
    
    return results

def analyze_go_file(file_path, content):
    """
    Analyze a Go file to identify crypto-related elements with detailed security information.
    
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
        for pkg in CRYPTO_PACKAGES:
            if isinstance(pkg, dict) and 'name' in pkg:
                pkg_name = pkg['name']
                
                if pkg_name in imp:
                    severity = pkg.get('severity', SEVERITY["INFO"])
                    description = pkg.get('description', f"Imported crypto package: {imp}")
                    recommendation = pkg.get('recommendation', "")
                    
                    finding = {
                        'file_path': file_path,
                        'type': 'package',
                        'name': imp,
                        'category': 'crypto_import',
                        'line_number': find_line_number(content, f'import "{imp}"') or 
                                      find_line_number(content, f'import ({imp}') or 0,
                        'description': description,
                        'severity': severity
                    }
                    
                    if recommendation:
                        finding['recommendation'] = recommendation
                    
                    findings.append(finding)
            elif isinstance(pkg, str):  # For backward compatibility
                if pkg in imp:
                    finding = {
                        'file_path': file_path,
                        'type': 'package',
                        'name': imp,
                        'category': 'crypto_import',
                        'line_number': find_line_number(content, f'import "{imp}"') or 
                                      find_line_number(content, f'import ({imp}') or 0,
                        'description': f"Imported crypto package: {imp}",
                        'severity': SEVERITY["INFO"]
                    }
                    
                    findings.append(finding)
    
    # Check for third-party crypto libraries
    for lib, lib_info in CRYPTO_LIBRARIES.items():
        if isinstance(lib_info, dict) and 'pattern' in lib_info:
            pattern = lib_info['pattern']
            if re.search(pattern, content):
                severity = lib_info.get('severity', SEVERITY["INFO"])
                description = lib_info.get('description', f"Using third-party crypto library: {lib}")
                recommendation = lib_info.get('recommendation', "")
                
                finding = {
                    'file_path': file_path,
                    'type': 'library',
                    'name': lib,
                    'category': 'third_party_library',
                    'line_number': find_line_number(content, pattern) or 0,
                    'description': description,
                    'severity': severity
                }
                
                if recommendation:
                    finding['recommendation'] = recommendation
                
                findings.append(finding)
        elif isinstance(lib_info, str):  # For backward compatibility
            pattern = lib_info
            if re.search(pattern, content):
                findings.append({
                    'file_path': file_path,
                    'type': 'library',
                    'name': lib,
                    'category': 'third_party_library',
                    'line_number': find_line_number(content, pattern) or 0,
                    'description': f"Using third-party crypto library: {lib}",
                    'severity': SEVERITY["INFO"]
                })
    
    # Check for crypto function calls
    for func_info in CRYPTO_FUNCTIONS:
        if isinstance(func_info, dict) and 'name' in func_info:
            func = func_info['name']
            pattern = r'\b' + re.escape(func) + r'\s*\('
            matches = re.finditer(pattern, content)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                severity = func_info.get('severity', SEVERITY["INFO"])
                description = func_info.get('description', f"Crypto function call: {func}")
                recommendation = func_info.get('recommendation', "")
                
                finding = {
                    'file_path': file_path,
                    'type': 'function',
                    'name': func,
                    'category': 'crypto_function',
                    'line_number': line_num,
                    'description': description,
                    'severity': severity
                }
                
                if recommendation:
                    finding['recommendation'] = recommendation
                
                findings.append(finding)
        elif isinstance(func_info, str):  # For backward compatibility
            func = func_info
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
                    'description': f"Crypto function call: {func}",
                    'severity': SEVERITY["INFO"]
                })
    
    # Check for crypto constants and patterns
    for const, const_info in CRYPTO_CONSTANTS.items():
        if isinstance(const_info, dict) and 'pattern' in const_info:
            pattern = const_info['pattern']
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                matched_text = match.group(0)
                severity = const_info.get('severity', SEVERITY["INFO"])
                description = const_info.get('description', f"Crypto constant: {const}")
                recommendation = const_info.get('recommendation', "")
                
                finding = {
                    'file_path': file_path,
                    'type': 'constant',
                    'name': const,
                    'matched_text': matched_text,
                    'category': 'crypto_constant',
                    'line_number': line_num,
                    'description': description,
                    'severity': severity
                }
                
                if recommendation:
                    finding['recommendation'] = recommendation
                
                findings.append(finding)
        elif isinstance(const_info, str):  # For backward compatibility
            pattern = const_info
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'file_path': file_path,
                    'type': 'constant',
                    'name': const,
                    'category': 'crypto_constant',
                    'line_number': find_line_number(content, pattern) or 0,
                    'description': f"Crypto constant: {const}",
                    'severity': SEVERITY["INFO"]
                })
    
    # Check for custom crypto function definitions
    custom_funcs = extract_custom_crypto_functions(content)
    for func in custom_funcs:
        # Custom crypto functions are often considered medium risk due to potential issues
        findings.append({
            'file_path': file_path,
            'type': 'function_definition',
            'name': func['name'],
            'category': 'custom_crypto_function',
            'line_number': func['line_number'],
            'description': f"Custom crypto function definition: {func['name']}",
            'severity': SEVERITY["MEDIUM"],
            'recommendation': "Consider using standard, well-vetted crypto libraries instead of custom implementations"
        })
    
    # Check for crypto antipatterns (insecure practices)
    for pattern_name, pattern_info in CRYPTO_ANTIPATTERNS.items():
        pattern = pattern_info['pattern']
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            matched_text = match.group(0)
            severity = pattern_info.get('severity', SEVERITY["HIGH"])
            description = pattern_info.get('description', f"Potential security issue: {pattern_name}")
            recommendation = pattern_info.get('recommendation', "")
            
            finding = {
                'file_path': file_path,
                'type': 'antipattern',
                'name': pattern_name,
                'matched_text': matched_text,
                'category': 'security_issue',
                'line_number': line_num,
                'description': description,
                'severity': severity
            }
            
            if recommendation:
                finding['recommendation'] = recommendation
            
            findings.append(finding)
    
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
                       'aes', 'rsa', 'dsa', 'cipher', 'signature', 'random', 
                       'secure', 'sign', 'verify', 'salt', 'nonce', 'iv']
    
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

def extract_code_snippet(content, line_number, context=3):
    """
    Extract code snippet around a specific line number with context
    
    Args:
        content (str): File content
        line_number (int): Line number to extract snippet around
        context (int): Number of lines of context before and after
    
    Returns:
        str: Code snippet
    """
    lines = content.splitlines()
    start_line = max(0, line_number - context - 1)
    end_line = min(len(lines), line_number + context)
    
    snippet_lines = []
    for i in range(start_line, end_line):
        line_prefix = "→ " if i == line_number - 1 else "  "
        snippet_lines.append(f"{line_prefix}{i+1}: {lines[i]}")
    
    return "\n".join(snippet_lines)
