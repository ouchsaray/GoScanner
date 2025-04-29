# Golang Crypto Asset Scanner

A Streamlit-based tool for analyzing Golang projects to identify and visualize cryptographic libraries, assets, and functions.

## Overview

The Golang Crypto Asset Scanner is a specialized tool designed for security researchers, developers, and code auditors who need to quickly identify cryptographic implementations in Go projects. The scanner detects standard and third-party crypto libraries, crypto functions, constants, and even attempts to identify custom cryptographic implementations based on naming conventions.

## Features

- **Dual Input Methods**: Upload Go files directly or scan an entire Git repository
- **Comprehensive Detection**: Identifies a wide range of crypto-related components:
  - Standard Go crypto packages
  - Third-party crypto libraries
  - Crypto function calls and definitions
  - Crypto constants and parameters
  - Custom crypto functions (based on naming patterns)
- **Visual Analysis**: Interactive charts and tables to visualize findings
- **Code Snippets**: View the actual code context for each finding
- **Repository Structure**: View the structure of analyzed git repositories

## How to Use

### Option 1: Upload Go Files

1. Navigate to the "Upload Files" tab
2. Click the upload area to select one or more `.go` files
3. The application will automatically process the files and display results

### Option 2: Scan Git Repository

1. Navigate to the "Git Repository" tab
2. Enter the URL of a Git repository containing Go code
3. Optionally specify a branch (defaults to main/master)
4. Click "Scan Repository" to initiate scanning
5. View results in the visualization panels

## Visualization and Results

The scanner provides several visualization methods for analyzing results:

- **Summary Metrics**: Total files scanned, files with crypto components, total findings
- **Distribution Chart**: Pie chart showing the distribution of different finding types
- **Findings Table**: Detailed table with all identified crypto components
- **Detailed Findings**: Expandable sections with code snippets for each finding

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

- Add support for more programming languages
- Implement deeper static analysis techniques
- Provide security recommendations based on findings
- Add support for vulnerable crypto pattern detection