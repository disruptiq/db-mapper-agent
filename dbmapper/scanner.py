#!/usr/bin/env python3
"""File discovery module for scanning repositories."""

import fnmatch
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
    "**/*.md", "**/*.yaml", "**/*.yml"
]



def _get_git_files(repo_path: Path) -> List[Path]:
    """Get all files tracked by git in the repository."""
    try:
        result = subprocess.run(
            ['git', 'ls-files'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            files = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    files.append(repo_path / line.strip())
            return files
    except (subprocess.SubprocessError, FileNotFoundError):
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

    # Use git ls-files for faster discovery (respects .gitignore and is efficient)
    all_files = []
    git_files = _get_git_files(repo_path)
    if git_files:
        all_files = git_files
    else:
        # Fallback to filesystem traversal if git ls-files fails
        for pattern in include_patterns:
            for path in repo_path.rglob(pattern):
                if path.is_file():
                    all_files.append(path)

    # Filter files
    files = []
    for path in all_files:
        # Check if file actually exists (git ls-files might include deleted files)
        if not path.exists():
            continue

        # Check exclude patterns
        relative_path = str(path.relative_to(repo_path))
        if any(fnmatch.fnmatch(relative_path, excl) for excl in exclude_patterns):
            continue

        # Check include patterns
        if include_patterns != ["**/*"]:  # Only filter if not including everything
            if not any(fnmatch.fnmatch(relative_path, incl) for incl in include_patterns):
                continue

        # Check extension
        if allowed_extensions and path.suffix not in allowed_extensions:
            # Check for exact filename matches (like Dockerfile)
            if path.name not in allowed_extensions:
                continue

        files.append(path)

    return files
