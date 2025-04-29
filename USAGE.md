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

## Command-Line Interface Usage

The CLI tool is ideal for automation, CI/CD pipelines, or scripting scenarios.

### Example 1: Scanning a Local Go File

```bash
./cli.py -f path/to/your/file.go -v
```

### Example 2: Scanning Multiple Files and Saving Results

```bash
./cli.py -f file1.go file2.go -o scan_results.json
```

### Example 3: Scanning a Directory Containing Go Files

```bash
./cli.py -f ./project_directory -v
```

### Example 4: Scanning a Git Repository

```bash
./cli.py -g https://github.com/golang/crypto -v
```

### Example 5: Scanning a Specific Branch of a Repository

```bash
./cli.py -g https://github.com/ethereum/go-ethereum -b develop -o ethereum_results.json
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

## Notes on Performance

- The CLI version is more efficient for large repositories as it doesn't have the overhead of the web interface
- For very large codebases, consider scanning specific directories rather than the entire repository
- The scanner's performance depends on the size and complexity of the codebase being analyzed