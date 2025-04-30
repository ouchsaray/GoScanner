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
    
    # Check for PRNG weaknesses (use of math/rand instead of crypto/rand)
    findings.extend(check_prng_weaknesses(file_path, content))
    
    # Check for certificate validation bypasses
    findings.extend(check_certificate_validation(file_path, content))
    
    # Check for nonce reuse issues
    findings.extend(check_nonce_reuse(file_path, content))
    
    # Check for side-channel protection
    findings.extend(check_side_channel_protection(file_path, content))
    
    # Check for key length issues
    findings.extend(check_key_length_issues(file_path, content))
    
    # Check for hardcoded credentials
    findings.extend(check_hardcoded_credentials(file_path, content))
    
    return findings

def check_prng_weaknesses(file_path, content):
    """
    Check for pseudorandom number generator weaknesses, particularly use of 
    non-cryptographic random number generators for security purposes.
    
    Args:
        file_path (str): Path to the Go file
        content (str): Content of the Go file
        
    Returns:
        list: List of findings related to PRNG weaknesses
    """
    findings = []
    
    # Look for imports of math/rand
    if re.search(r'import\s+[("]*math/rand[)"]*', content):
        # Now look for contexts that suggest security usage
        rand_patterns = [
            (r'rand\.(Intn|Int|Float\d+)\s*\([^)]*\).*\b(password|key|token|secret|iv|nonce)\b', 
             "Using non-cryptographic PRNG for security-sensitive value"),
            (r'\b(password|key|token|secret|iv|nonce)\b.*rand\.(Intn|Int|Float\d+)\s*\([^)]*\)', 
             "Using non-cryptographic PRNG for security-sensitive value"),
            (r'rand\.Seed\s*\(\s*time\.Now\(\)\.UnixNano\(\)\s*\)', 
             "Using predictable seed for random number generator")
        ]
        
        for pattern, description in rand_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                matched_text = match.group(0)
                
                finding = {
                    'file_path': file_path,
                    'type': 'antipattern',
                    'name': 'Insecure Random Number Generation',
                    'matched_text': matched_text,
                    'category': 'security_issue',
                    'line_number': line_num,
                    'description': description,
                    'severity': SEVERITY["HIGH"],
                    'recommendation': "Use crypto/rand for security-sensitive operations requiring randomness"
                }
                
                findings.append(finding)
    
    return findings

def check_certificate_validation(file_path, content):
    """
    Check for certificate validation bypass issues in TLS configurations.
    
    Args:
        file_path (str): Path to the Go file
        content (str): Content of the Go file
        
    Returns:
        list: List of findings related to certificate validation issues
    """
    findings = []
    
    # Already checked basic InsecureSkipVerify in CRYPTO_ANTIPATTERNS, but let's add more cases
    
    # Check for custom certificate verification bypasses or dangerous verification settings
    cert_bypass_patterns = [
        (r'VerifyPeerCertificate\s*:.*nil', 
         "Setting VerifyPeerCertificate to nil while InsecureSkipVerify is true"),
        (r'CertificateVerify.*func\s*\([^)]*\)\s*{\s*return\s*nil\s*}', 
         "Custom certificate verification function that returns nil/ignores errors"),
        (r'tls\.Config\s*{\s*[^}]*RootCAs\s*:\s*nil', 
         "Using nil for RootCAs in custom TLS configuration"),
        (r'x509\.VerifyOptions\s*{\s*[^}]*DNSName\s*:\s*""\s*[^}]*}', 
         "Empty DNS name in certificate verification options")
    ]
    
    for pattern, description in cert_bypass_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            matched_text = match.group(0)
            
            finding = {
                'file_path': file_path,
                'type': 'antipattern',
                'name': 'Certificate Validation Bypass',
                'matched_text': matched_text,
                'category': 'security_issue',
                'line_number': line_num,
                'description': description,
                'severity': SEVERITY["HIGH"],
                'recommendation': "Always properly verify TLS certificates in production code. Set InsecureSkipVerify to false and use proper certificate chains."
            }
            
            findings.append(finding)
    
    return findings

def check_nonce_reuse(file_path, content):
    """
    Check for potential nonce reuse issues, particularly with stream ciphers or AEAD.
    
    Args:
        file_path (str): Path to the Go file
        content (str): Content of the Go file
        
    Returns:
        list: List of findings related to potential nonce reuse
    """
    findings = []
    
    # Look for patterns suggesting static or reused nonces
    nonce_reuse_patterns = [
        (r'var\s+\w+Nonce\s*=\s*\[\]byte{[^}]+}', 
         "Static nonce definition might lead to nonce reuse"),
        (r'nonce\s*:=\s*\[\]byte{[^}]+}', 
         "Hardcoded nonce value"),
        (r'(?:nonce|iv)\s*:=\s*make\(\[\]byte,\s*\d+\s*\)(\s*//[^\n]*)*\s*[^/\n]*$', 
         "Nonce created but potentially not filled with random data"),
        (r'for\s+[^{]*{[^}]*\s+\w*[Nn]once\w*\s*:=[^=]*[^}]*cipher', 
         "Potential nonce reuse in loop with cipher operations")
    ]
    
    for pattern, description in nonce_reuse_patterns:
        matches = re.finditer(pattern, content, re.MULTILINE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            matched_text = match.group(0)
            
            # Check for explicit randomness
            context = extract_code_snippet(content, line_num, context=5)
            if 'crypto/rand' not in context and 'Read(' not in context:
                finding = {
                    'file_path': file_path,
                    'type': 'antipattern',
                    'name': 'Potential Nonce Reuse',
                    'matched_text': matched_text,
                    'category': 'security_issue',
                    'line_number': line_num,
                    'description': description,
                    'severity': SEVERITY["HIGH"],
                    'recommendation': "Generate a unique nonce/IV for each encryption operation using crypto/rand and never reuse them, especially with stream ciphers or GCM mode"
                }
                
                findings.append(finding)
    
    return findings

def check_side_channel_protection(file_path, content):
    """
    Check for proper side-channel protection, particularly constant-time operations
    for sensitive data comparisons.
    
    Args:
        file_path (str): Path to the Go file
        content (str): Content of the Go file
        
    Returns:
        list: List of findings related to side-channel vulnerabilities
    """
    findings = []
    
    # Check for standard comparison of sensitive values
    sensitive_compares = [
        (r'(password|secret|token|signature|hmac|mac|hash)\s*==\s*[^=]', 
         "Direct comparison of sensitive values may be vulnerable to timing attacks"),
        (r'bytes.Equal\s*\(\s*(password|secret|token|signature|hmac|mac|hash)', 
         "Using bytes.Equal instead of subtle.ConstantTimeCompare for sensitive comparison"),
        (r'reflect.DeepEqual\s*\(\s*(password|secret|token|signature|hmac|mac|hash)', 
         "Using reflect.DeepEqual instead of subtle.ConstantTimeCompare for sensitive comparison")
    ]
    
    for pattern, description in sensitive_compares:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            matched_text = match.group(0)
            
            # Check if we're not using subtle.ConstantTimeCompare in the same context
            context = extract_code_snippet(content, line_num, context=3)
            if 'subtle.ConstantTimeCompare' not in context and 'crypto/subtle' not in context:
                finding = {
                    'file_path': file_path,
                    'type': 'antipattern',
                    'name': 'Non-Constant Time Comparison',
                    'matched_text': matched_text,
                    'category': 'security_issue',
                    'line_number': line_num,
                    'description': description,
                    'severity': SEVERITY["MEDIUM"],
                    'recommendation': "Use crypto/subtle.ConstantTimeCompare for comparing sensitive values to prevent timing attacks"
                }
                
                findings.append(finding)
    
    return findings

def check_key_length_issues(file_path, content):
    """
    Check for insecure key lengths in cryptographic operations.
    
    Args:
        file_path (str): Path to the Go file
        content (str): Content of the Go file
        
    Returns:
        list: List of findings related to key length issues
    """
    findings = []
    
    # Patterns already in CRYPTO_CONSTANTS for small key sizes, but let's add more specific cases
    key_length_patterns = [
        (r'rsa\.GenerateKey\s*\([^,]+,\s*(\d+)\s*\)', 
         lambda match: int(match.group(1)) < 2048,
         f"RSA key size below 2048 bits: {{match_val}}",
         "Use at least 2048 bits for RSA keys, preferably 3072 or 4096 for longer-term security"),
        
        (r'dsa\.GenerateParameters\s*\([^,]+,\s*(\d+)\s*,', 
         lambda match: int(match.group(1)) < 2048,
         f"DSA key parameters below 2048 bits: {{match_val}}",
         "Use at least 2048 bits for DSA keys or consider using ECDSA instead"),
        
        (r'ecdsa\.GenerateKey\s*\([^,]*P(224|192)\b[^,]*,', 
         lambda match: True,  # Always match these curves
         f"Using weaker elliptic curve: {{match_val}}",
         "Use P-256, P-384, or P-521 curves instead of P-224 or P-192"),
        
        (r'aes\.NewCipher\s*\(\s*\w+\s*\[\s*:\s*(\d+)\s*\]\s*\)', 
         lambda match: int(match.group(1)) < 16,
         f"AES key length below 128 bits: {{match_val}} bytes",
         "Use at least 16 bytes (128 bits) for AES keys, preferably 24 (192) or 32 (256) bytes")
    ]
    
    for pattern, condition_check, description_template, recommendation in key_length_patterns:
        matches = re.finditer(pattern, content, re.MULTILINE)
        for match in matches:
            if condition_check(match):
                line_num = content[:match.start()].count('\n') + 1
                matched_text = match.group(0)
                match_val = match.group(1)
                
                description = description_template.replace("{match_val}", match_val)
                
                finding = {
                    'file_path': file_path,
                    'type': 'antipattern',
                    'name': 'Insecure Key Length',
                    'matched_text': matched_text,
                    'category': 'security_issue',
                    'line_number': line_num,
                    'description': description,
                    'severity': SEVERITY["HIGH"],
                    'recommendation': recommendation
                }
                
                findings.append(finding)
    
    return findings

def check_hardcoded_credentials(file_path, content):
    """
    Enhanced check for hardcoded credentials beyond the basic patterns in CRYPTO_CONSTANTS.
    
    Args:
        file_path (str): Path to the Go file
        content (str): Content of the Go file
        
    Returns:
        list: List of findings related to hardcoded credentials
    """
    findings = []
    
    # Additional patterns to check for hardcoded credentials
    credential_patterns = [
        (r'(?:const|var)\s+(\w+(?:Key|Secret|Password|Token|Auth))\s*=\s*["`\']([^"`\']{8,})["`\']', 
         "Hardcoded credential - potentially sensitive: {name} = {value_preview}"),
        (r'authentication\s*:\s*["`\']([^"`\']{8,})["`\']', 
         "Hardcoded authentication string detected"),
        (r'(?:username|user|login)[:=]\s*["`\']([^"`\']+)["`\']\s*(?:,|\n|\r|\})\s*(?:password|pass|pwd)[:=]\s*["`\']([^"`\']+)["`\']', 
         "Hardcoded username and password combination detected"),
        (r'[Bb]earer\s+["`\']([A-Za-z0-9\-_=]{8,})["`\']', 
         "Hardcoded Bearer token detected"),
        (r'[Aa]uthorization\s*[:=]\s*["`\'].{8,}["`\']', 
         "Hardcoded Authorization header value detected"),
        (r'(?:jwt|token)\s*[:=]\s*["`\'][A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}["`\']', 
         "Hardcoded JWT token detected")
    ]
    
    for pattern, description_template in credential_patterns:
        matches = re.finditer(pattern, content, re.MULTILINE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            matched_text = match.group(0)
            
            # Create description
            description = description_template
            if '{name}' in description_template and match.groups():
                name = match.group(1)
                description = description_template.replace('{name}', name)
            
            if '{value_preview}' in description_template and len(match.groups()) > 1:
                value = match.group(2)
                preview = value[:3] + '...' + value[-3:] if len(value) > 10 else value
                description = description.replace('{value_preview}', preview)
            
            finding = {
                'file_path': file_path,
                'type': 'antipattern',
                'name': 'Hardcoded Credentials',
                'matched_text': matched_text,
                'category': 'security_issue',
                'line_number': line_num,
                'description': description,
                'severity': SEVERITY["HIGH"],
                'recommendation': "Never hardcode credentials in source code. Use environment variables, secure vaults, or configuration systems designed for secrets management."
            }
            
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
