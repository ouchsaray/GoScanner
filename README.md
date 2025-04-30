# Golang Crypto Asset Scanner

A tool for analyzing Golang projects to identify and visualize cryptographic libraries, assets, and functions, as well as detect cryptographic vulnerabilities and security issues. Available as both a Streamlit web application and a command-line interface.

## Overview

The Golang Crypto Asset Scanner is a specialized tool designed for security researchers, developers, and code auditors who need to quickly identify cryptographic implementations in Go projects. The scanner detects standard and third-party crypto libraries, crypto functions, constants, and even attempts to identify custom cryptographic implementations based on naming conventions. It also provides security ratings and recommendations for identified crypto components.

## Features

- **Dual Input Methods**: Upload Go files directly or scan an entire Git repository
- **Comprehensive Detection**: Identifies a wide range of crypto-related components:
  - Standard Go crypto packages
  - Third-party crypto libraries
  - Crypto function calls and definitions
  - Crypto constants and parameters
  - Custom crypto functions (based on naming patterns)
- **Security Analysis**: Assigns severity ratings and provides recommendations
- **Visual Analysis**: Interactive charts and tables to visualize findings
- **Code Snippets**: View the actual code context for each finding
- **Repository Structure**: View the structure of analyzed git repositories
- **Command-Line Interface**: Run scans directly from the terminal without UI

## Insecure Crypto Algorithm Detection

The scanner identifies the following insecure cryptographic algorithms and practices:

### Hashing Algorithms
- **MD5**: Cryptographically broken due to collision vulnerabilities
- **SHA-1**: No longer secure for signatures, vulnerable to collision attacks

### Encryption Algorithms
- **DES/3DES**: Uses inadequate key sizes vulnerable to brute force attacks
- **RC4**: Known to be insecure, contains serious weaknesses

### Insecure Modes
- **ECB Mode**: Does not provide semantic security, patterns in the plaintext remain visible
- **CBC Mode without proper authentication**: Vulnerable to padding oracle attacks

### Insecure Practices
- **Hardcoded Cryptographic Values**: Detection of hardcoded keys, IVs, salts, or passwords
- **Static Initialization Vectors**: IVs should be unique for each encryption operation
- **Non-cryptographic Random Numbers**: Using `math/rand` instead of `crypto/rand`
- **Insecure TLS Configuration**: TLS certificate verification disabled via `InsecureSkipVerify: true`
- **Custom Crypto Implementations**: Potentially insecure custom implementations
- **Short Key Sizes**: Detection of RSA keys under 2048 bits, symmetric keys under 128 bits

## How to Use

### Web Interface

#### Option 1: Upload Go Files

1. Navigate to the "Upload Files" tab
2. Click the upload area to select one or more `.go` files
3. The application will automatically process the files and display results

#### Option 2: Scan Git Repository

1. Navigate to the "Git Repository" tab
2. Enter the URL of a Git repository containing Go code
3. Optionally specify a branch (defaults to main/master)
4. Click "Scan Repository" to initiate scanning
5. View results in the visualization panels

### Command-Line Interface

Run the scanner directly from the terminal using `cli.py`:

```bash
# Scan local Go files or directories
python cli.py -f path/to/file.go path/to/directory

# Scan a Git repository
python cli.py -g https://github.com/username/repo.git

# Scan a specific branch of a Git repository
python cli.py -g https://github.com/username/repo.git -b develop

# Save results to a JSON file
python cli.py -f path/to/files -o results.json

# Enable verbose output
python cli.py -f path/to/files -v
```

For help and available options:
```bash
python cli.py --help
```

## Visualization and Results

The scanner provides several visualization methods for analyzing results:

### Overview Dashboard
- **Security Score**: A calculated score based on the number and severity of findings
- **Severity Distribution**: Pie chart showing the distribution of findings by severity level
- **Summary Metrics**: Total files scanned, files with crypto components, high severity issues
- **Type Distribution**: Pie chart showing the distribution of different finding types
- **Crypto Libraries Chart**: Bar chart showing the distribution of identified crypto libraries

### Detailed Analysis
- **Findings Table**: Interactive table with all identified crypto components
  - Filter by severity (HIGH, MEDIUM, LOW, INFO)
  - Filter by type (package, library, function, etc.)
  - Search by name or description
- **Detailed Findings**: Expandable sections with:
  - Code snippets for each finding
  - Severity badges for quick identification
  - Detailed recommendations for addressing issues
  - Contextual information about each crypto component

### Security Analysis
- **Security Issues Chart**: Visual representation of identified security issues
- **Critical Issues View**: Focused view of HIGH and MEDIUM severity issues
- **Detailed Recommendations**: Specific guidance for addressing each security concern

## Technology Stack

- **Streamlit**: Web application framework
- **GitPython**: Git repository handling
- **Pandas**: Data manipulation and analysis
- **Plotly**: Interactive visualizations

## Use Cases

- Security audits of Go projects
- Compliance checks for cryptographic implementations
- Educational tool for understanding cryptography usage in Go
- Quick assessment of cryptographic attack surface

## Known Limitations

- The scanner relies on pattern matching and may produce some false positives
- Custom crypto implementations may not be detected if they don't follow common naming conventions
- Complex or obfuscated code might not be properly analyzed

## Future Improvements

### Planned Enhancements
- **Additional Security Checks**:
  - Nonce reuse detection for stream and AEAD ciphers
  - Certificate validation bypass detection (deeper analysis)
  - Side-channel vulnerability prevention assessment
  - Cross-package crypto primitive composition analysis
  - Additional hardcoded credential detection patterns

- **Technical Improvements**:
  - Deeper static analysis with call graph tracking
  - Inter-procedural data flow analysis
  - Support for more Go frameworks and libraries
  - Known CVE detection for identified crypto libraries
  - Dependency chain analysis for transitive crypto usage

- **Language Support**:
  - Expand support to other languages like Rust, Java, and C/C++
  - Multi-language project analysis capabilities
  - Language-specific crypto vulnerability detection

- **Workflow Integration**:
  - CI/CD pipeline integration for automated scanning
  - Pull request integration for continuous security assessment
  - Historical trend analysis of crypto usage in a project