# Golang Crypto Asset Scanner - Usage Examples

This document provides practical examples for using both the web interface and command-line tools of the Golang Crypto Asset Scanner.

## Web Interface Usage

Start the Streamlit web interface:

```bash
streamlit run app.py --server.port 5000
```

Then open your browser to http://localhost:5000 (or the provided URL).

### Example 1: Scanning a Public Go Repository

1. Click on the "Git Repository" tab
2. Enter a repository URL, e.g., `https://github.com/golang/crypto`
3. (Optional) Specify a branch, e.g., `master`
4. Click "Scan Repository"
5. Review the findings in the generated charts and tables

### Example 2: Uploading Local Go Files

1. Click on the "Upload Files" tab
2. Click on the upload area to select Go files from your computer
3. Select one or more `.go` files
4. Review the findings in the generated charts and tables

## Enhanced Command-Line Interface Usage

The CLI tool is ideal for automation, CI/CD pipelines, or scripting scenarios. It features:

- Colorful, user-friendly output
- Live progress bars showing scan status
- Per-file timeout handling (default: 60 seconds)
- Detailed error reporting
- Ability to save results to JSON

### Basic Command Examples

#### Example 1: Scanning a Local Go File

```bash
./cli.py -f path/to/your/file.go
```

#### Example 2: Scanning Multiple Files and Saving Results

```bash
./cli.py -f file1.go file2.go -o scan_results.json
```

#### Example 3: Scanning a Directory Containing Go Files

```bash
./cli.py -f ./project_directory
```

#### Example 4: Scanning a Git Repository

```bash
./cli.py -g https://github.com/golang/crypto
```

#### Example 5: Scanning a Specific Branch of a Repository

```bash
./cli.py -g https://github.com/ethereum/go-ethereum -b develop -o ethereum_results.json
```

### Advanced CLI Options

#### Verbose Mode

For detailed output including all findings and errors:

```bash
./cli.py -f ./project_directory -v
```

#### Quiet Mode

For minimal output (only errors and final summary):

```bash
./cli.py -f ./project_directory -q
```

#### Custom Timeout

Set a custom timeout for scanning each file (in seconds):

```bash
./cli.py -f large_project_directory -t 120
```

#### Full Example with Multiple Options

```bash
./cli.py -g https://github.com/ethereum/go-ethereum -b develop -o results.json -v -t 90
```

This will:
- Clone the Ethereum Go repo
- Check out the "develop" branch
- Use verbose output mode
- Set file scan timeout to 90 seconds
- Save results to results.json

## UX Features of the CLI

The enhanced CLI provides several user experience improvements:

- **Colorful Output**: Different colors indicate different types of information
- **Progress Bar**: Shows scan progress, estimated time remaining, and scan rate
- **File-by-File Updates**: Shows the current file being scanned
- **Timeout Handling**: Automatically detects when a file scan is taking too long
- **Error Reporting**: Highlights files that couldn't be processed
- **Summary Statistics**: Provides a detailed breakdown of findings

### Example Output

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Golang Crypto Asset Scanner v1.0.0                      ┃
┃ Scan Go files for cryptographic libraries and assets    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Validating input files...
Found 42 Go files to scan.

Scanning files for crypto assets...
Scanning main.go: 100%|████████████████| 42/42 [00:05<00:00, 7.52file/s]

═════════════════════════════════════════
           SCAN RESULTS SUMMARY           
═════════════════════════════════════════

Total files scanned: 42
Files with crypto components: 15
Total crypto components found: 37
Scan duration: 5.32 seconds

Findings by type:
  ● package: 12
  ● function: 18
  ● library: 5
  ● constant: 2

Results saved to scan_results.json
```

## Combining Web and CLI Approaches

You can use both interfaces together in a workflow:

1. Use the CLI for batch processing or initial scans:
   ```bash
   ./cli.py -g https://github.com/project/repo -o results.json
   ```

2. Start the web interface to visualize and explore the saved results:
   ```bash
   streamlit run app.py --server.port 5000
   ```

3. Upload the `results.json` file to the web interface for visualization if you want to add this feature in the future.

## Notes on Performance and Troubleshooting

- The CLI version is more efficient for large repositories as it doesn't have the overhead of the web interface
- For very large codebases, consider scanning specific directories rather than the entire repository
- If a file scan times out (default: 60 seconds), the tool will skip that file and continue with the rest
- Use the `-t` option to adjust timeout duration for complex files
- The scanner's performance depends on the size and complexity of the codebase being analyzed