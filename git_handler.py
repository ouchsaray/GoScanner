import os
import tempfile
import git
import shutil
from pathlib import Path
import streamlit as st

def clone_git_repo(repo_url, target_dir, branch=None):
    """
    Clone a git repository to a target directory.
    
    Args:
        repo_url (str): URL of the git repository
        target_dir (str): Path to the target directory
        branch (str): Optional branch to checkout
    
    Returns:
        bool: True if cloning was successful, False otherwise
    """
    try:
        # Clone the repository
        if not branch or branch.strip() == "":
            # Try to clone default branch
            git.Repo.clone_from(repo_url, target_dir)
        else:
            # Clone specific branch
            git.Repo.clone_from(repo_url, target_dir, branch=branch)
        
        return True
    except git.GitCommandError as e:
        st.error(f"Git command error: {str(e)}")
        return False
    except Exception as e:
        st.error(f"Error cloning repository: {str(e)}")
        return False

def get_go_files_in_repo(repo_dir):
    """
    Get all Go files in a repository directory.
    
    Args:
        repo_dir (str): Path to the repository directory
    
    Returns:
        list: List of paths to Go files
    """
    go_files = []
    
    try:
        # Walk through the repository directory
        for root, dirs, files in os.walk(repo_dir):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            
            # Add Go files to the list
            for file in files:
                if file.endswith('.go'):
                    go_files.append(os.path.join(root, file))
    
    except Exception as e:
        st.error(f"Error scanning repository: {str(e)}")
    
    return go_files

def get_repo_structure(repo_dir):
    """
    Get the structure of a repository.
    
    Args:
        repo_dir (str): Path to the repository directory
    
    Returns:
        dict: Dictionary representing the repository structure
    """
    structure = {}
    
    try:
        for root, dirs, files in os.walk(repo_dir):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            
            # Relativize path
            rel_path = os.path.relpath(root, repo_dir)
            if rel_path == '.':
                rel_path = ''
            
            # Add files to structure
            structure[rel_path] = []
            for file in files:
                if file.endswith('.go'):
                    structure[rel_path].append(file)
    
    except Exception as e:
        st.error(f"Error getting repository structure: {str(e)}")
    
    return structure
