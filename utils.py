import os
import tempfile
import git
import shutil
from pathlib import Path
import streamlit as st

def upload_and_save_files(uploaded_files, temp_dir):
    """
    Save uploaded files to a temporary directory.
    
    Args:
        uploaded_files (list): List of uploaded files
        temp_dir (str): Path to temporary directory
    
    Returns:
        list: List of paths to saved files
    """
    file_paths = []
    
    for uploaded_file in uploaded_files:
        # Create a unique file path in the temp directory
        file_path = os.path.join(temp_dir, uploaded_file.name)
        
        # Write the file content to the temp directory
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        file_paths.append(file_path)
    
    return file_paths

def extract_git_repo(repo_url, target_dir, branch=None):
    """
    Clone a git repository to the target directory.
    
    Args:
        repo_url (str): URL of the git repository
        target_dir (str): Path to the target directory
        branch (str): Branch to checkout (optional)
    
    Returns:
        tuple: (success, message) indicating success status and message
    """
    try:
        # Clone the repository
        if not branch:
            git.Repo.clone_from(repo_url, target_dir)
        else:
            git.Repo.clone_from(repo_url, target_dir, branch=branch)
        
        # Count Go files in the repository
        go_files = list(Path(target_dir).rglob("*.go"))
        
        return True, f"Repository cloned successfully! Found {len(go_files)} Go files."
    
    except git.GitCommandError as e:
        return False, f"Git error: {str(e)}"
    
    except Exception as e:
        return False, f"Error: {str(e)}"

def get_file_snippet(file_path, line_number, context=3):
    """
    Get a snippet of code from a file around a specific line number.
    
    Args:
        file_path (str): Path to the file
        line_number (int): Line number to focus on
        context (int): Number of lines of context to include before and after
    
    Returns:
        str: Snippet of code
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            
            start_line = max(0, line_number - context - 1)
            end_line = min(len(lines), line_number + context)
            
            snippet_lines = lines[start_line:end_line]
            snippet = ''.join(snippet_lines)
            
            return snippet
    except Exception as e:
        return f"Error reading file: {str(e)}"

def sanitize_path_for_display(path, max_length=70):
    """
    Sanitize a file path for display, shortening if necessary.
    
    Args:
        path (str): File path to sanitize
        max_length (int): Maximum length for display
    
    Returns:
        str: Sanitized path
    """
    if len(path) <= max_length:
        return path
    
    parts = Path(path).parts
    
    if len(parts) <= 2:
        return path
    
    # Keep first and last part, replace middle with ellipsis
    return os.path.join(parts[0], '...', parts[-1])
