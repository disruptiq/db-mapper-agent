#!/usr/bin/env python3
"""File discovery module for scanning repositories."""

import fnmatch
import os
import subprocess
from pathlib import Path
from typing import List, Optional


# Language detection by file extensions
LANGUAGE_EXTENSIONS = {
    "python": [".py", ".pyx", ".pyw"],
    "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
    "java": [".java"],
    "csharp": [".cs", ".vb"],
    "php": [".php"],
    "ruby": [".rb"],
    "go": [".go"],
    "sql": [".sql"],
    "yaml": [".yml", ".yaml"],
    "json": [".json"],
    "xml": [".xml"],
    "ini": [".ini", ".cfg", ".conf"],
    "env": [".env"],
    "docker": ["Dockerfile", ".dockerfile"],
    "terraform": [".tf", ".tfvars"],
}

# Default exclude patterns for common non-scannable files
DEFAULT_EXCLUDE_PATTERNS = [
    "**/*.jpg", "**/*.jpeg", "**/*.png", "**/*.gif", "**/*.bmp", "**/*.tiff",
    "**/*.exe", "**/*.dll", "**/*.so", "**/*.dylib", "**/*.bin",
    "**/*.zip", "**/*.tar", "**/*.gz", "**/*.rar", "**/*.7z",
    "**/*.pdf", "**/*.doc", "**/*.docx", "**/*.xls", "**/*.xlsx",
    "**/*.mp4", "**/*.avi", "**/*.mov", "**/*.mp3", "**/*.wav",
    "**/*.pyc", "**/__pycache__/**", "**/.git/**", "**/node_modules/**",
    "**/venv/**", "**/.venv/**", "**/env/**", "**/.env/**",
    "**/*.md", "**/*.yaml", "**/*.yml",
    # Test files and directories
    "**/test/**", "**/tests/**", "**/__tests__/**", "**/spec/**", "**/specs/**",
    "**/*.test.*", "**/*.spec.*", "**/*Test.*", "**/*Spec.*",
    "**/test_*", "**/*_test.*", "**/*_spec.*",
    "test_*", "*_test.*", "*_spec.*",
    "**/fixtures/**", "**/mocks/**"
]



def _get_git_files(repo_path: Path) -> List[Path]:
    """Get all files tracked by git in the repository."""
    try:
        # Use git ls-files --cached for tracked files only (faster for scanning)
        result = subprocess.run(
            ['git', 'ls-files', '--cached'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60  # Increased timeout for massive repos
        )
        if result.returncode == 0:
            files = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    files.append(repo_path / line.strip())
            return files
    except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def discover_files(
    repo_path: Path,
    include_patterns: List[str],
    exclude_patterns: List[str],
    languages: Optional[List[str]] = None,
) -> List[Path]:
    """Discover files in the repository matching the criteria.

    Uses git ls-files for faster discovery and automatic .gitignore respect.

    Args:
        repo_path: Root path of the repository
        include_patterns: Glob patterns to include
        exclude_patterns: Glob patterns to exclude
        languages: List of languages to filter by (None for all)

    Returns:
        List of matching file paths
    """
    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError(f"Repository path {repo_path} does not exist or is not a directory")

    # If no languages specified, include all
    allowed_extensions = set()
    if languages:
        for lang in languages:
            if lang in LANGUAGE_EXTENSIONS:
                allowed_extensions.update(LANGUAGE_EXTENSIONS[lang])
    else:
        # Include all known extensions
        for exts in LANGUAGE_EXTENSIONS.values():
            allowed_extensions.update(exts)

    # Also include common config files
    allowed_extensions.update(LANGUAGE_EXTENSIONS["yaml"])
    allowed_extensions.update(LANGUAGE_EXTENSIONS["json"])
    allowed_extensions.update(LANGUAGE_EXTENSIONS["ini"])
    allowed_extensions.update(LANGUAGE_EXTENSIONS["env"])
    allowed_extensions.update(LANGUAGE_EXTENSIONS["docker"])
    allowed_extensions.update(LANGUAGE_EXTENSIONS["terraform"])

    # Use git ls-files --cached for fastest discovery in git repos (respects .gitignore)
    all_files = []
    git_files = _get_git_files(repo_path)
    if git_files:
        all_files = git_files
    else:
        # Fallback to filesystem traversal if git ls-files fails (non-git repos)
        for pattern in include_patterns:
            for path in repo_path.rglob(pattern):
                if path.is_file():
                    all_files.append(path)

    # Pre-compute exclude extensions and patterns for faster filtering
    exclude_extensions = set()
    exclude_path_patterns = []
    exclude_dir_patterns = []

    for pattern in exclude_patterns:
        if pattern.startswith("**/*.") and pattern.count("*") == 1:
            # Simple extension pattern like "**/*.jpg"
            exclude_extensions.add("." + pattern.split(".")[-1])
        elif pattern.endswith("/**"):
            # Directory pattern like "**/node_modules/**"
            exclude_dir_patterns.append(pattern[:-3])  # Remove "/**"
        else:
            exclude_path_patterns.append(pattern)

    # Filter files with optimized checks
    files = []
    repo_path_str = str(repo_path)

    for path in all_files:
        path_str = str(path)

        # Quick extension check first (fastest)
        if path.suffix in exclude_extensions:
            continue

        # Fast directory exclusion check
        if exclude_dir_patterns:
            for dir_pattern in exclude_dir_patterns:
                if dir_pattern in path_str:
                    continue

        # Check if file actually exists (git ls-files might include deleted files)
        if not path.exists():
            continue

        # Check exclude path patterns (only for complex patterns)
        if exclude_path_patterns:
            # Use string relative path calculation (faster than pathlib.relative_to)
            if path_str.startswith(repo_path_str):
                relative_str = path_str[len(repo_path_str):].lstrip(os.sep)
            else:
                relative_str = str(path.relative_to(repo_path))

            if any(fnmatch.fnmatch(relative_str, excl) for excl in exclude_path_patterns):
                continue

        # Check include patterns
        if include_patterns != ["**/*"]:  # Only filter if not including everything
            if not relative_str:
                if path_str.startswith(repo_path_str):
                    relative_str = path_str[len(repo_path_str):].lstrip(os.sep)
                else:
                    relative_str = str(path.relative_to(repo_path))

            if not any(fnmatch.fnmatch(relative_str, incl) for incl in include_patterns):
                continue

        # Check allowed extensions
        if allowed_extensions and path.suffix not in allowed_extensions:
            # Check for exact filename matches (like Dockerfile)
            if path.name not in allowed_extensions:
                continue

        # Skip very large files to avoid memory issues
        try:
            file_size = path.stat().st_size
            max_file_size = 50 * 1024 * 1024  # 50MB limit
            if file_size > max_file_size:
                continue
        except OSError:
            # Skip files we can't stat
            continue

        files.append(path)

    return files
