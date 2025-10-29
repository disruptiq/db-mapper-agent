#!/usr/bin/env python3
"""Detector modules for identifying database-related artifacts."""

import re
from pathlib import Path
from typing import List, Dict, Any
import signal
import sys

from .secret_detector import detect_secrets
from .migration_detector import detect_migrations, detect_schema_changes
from .ast_parser import detect_with_ast
from .csharp_detector import detect_csharp_db_patterns
from .php_detector import detect_php_db_patterns
from .description_generator import generate_finding_description
import concurrent.futures


# Pre-compiled regex patterns for performance
DSN_PATTERN = re.compile(r'(?i)(postgres(?:ql)?|mysql|mariadb|mongodb|sqlite|mssql)://[\w:@\-\.\/\%\?\=~\&]+')
ENV_VAR_PATTERN = re.compile(r'(?m)^(DB_URL|DATABASE_URL|[A-Z_]*DB[A-Z_]*)[\s]*=[\s]*(.+)')
ORM_MODEL_PATTERN = re.compile(r'class\s+(\w+)\s*\([^)]*models\.Model[^)]*\)')
SQL_PATTERN = re.compile(r'(?is)(SELECT|INSERT|UPDATE|DELETE|CREATE\s+TABLE|ALTER\s+TABLE)\s+.+')


def process_single_file(file_path: Path) -> List[Dict[str, Any]]:
    """Process a single file for database artifacts."""
    findings = []

    try:
        # Check file size to avoid loading very large files into memory
        file_size = file_path.stat().st_size
        max_file_size = 50 * 1024 * 1024  # 50MB limit

        if file_size > max_file_size:
            # For very large files, skip processing to avoid memory issues
            return findings

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
    except Exception:
        return findings  # Return empty list for unreadable files

    # AST-based detection for supported languages
    ast_findings = detect_with_ast(content, file_path)
    findings.extend(ast_findings)

    # Connection detector
    for match in DSN_PATTERN.finditer(content):
        provider = match.group(1).lower()
        if provider == 'postgres':
            provider = 'postgresql'
        findings.append({
            "type": "connection",
            "provider": provider,
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [match.group(0)],
            "confidence": 0.95,
        })

    # Env var detector
    for match in ENV_VAR_PATTERN.finditer(content):
        var_name = match.group(1)
        value = match.group(2).strip()
        if DSN_PATTERN.search(value):
            provider_match = DSN_PATTERN.search(value)
            provider = provider_match.group(1).lower()
            if provider == 'postgres':
                provider = 'postgresql'
            findings.append({
                "type": "connection",
                "provider": provider,
                "file": str(file_path),
                "line": content[:match.start()].count('\n') + 1,
                "evidence": [f"{var_name}={value}"],
                "confidence": 0.9,
            })

    # ORM model detector (basic Django)
    if file_path.suffix == '.py':
        for match in ORM_MODEL_PATTERN.finditer(content):
            model_name = match.group(1)
            findings.append({
                "type": "orm_model",
                "framework": "django",
                "file": str(file_path),
                "line": content[:match.start()].count('\n') + 1,
                "evidence": [f"class {model_name}(models.Model):"],
                "confidence": 0.95,
            })

    # Raw SQL detector - skip config files and migration files that might contain SQL as data
    config_extensions = {'.yaml', '.yml', '.json', '.xml', '.ini', '.cfg', '.conf', '.env', '.toml', '.properties'}
    migration_indicators = ['migration', 'migrations', 'flyway', 'alembic', 'prisma']
    is_migration_file = any(indicator in str(file_path).lower() for indicator in migration_indicators)

    if file_path.suffix.lower() not in config_extensions and not is_migration_file:
        for match in SQL_PATTERN.finditer(content):
            sql_type = match.group(1).upper()
            findings.append({
                "type": "raw_sql",
                "sql_type": sql_type,
                "file": str(file_path),
                "line": content[:match.start()].count('\n') + 1,
                "evidence": [match.group(0)],
                "confidence": 0.8,
            })

    # Migration detection
    migration_findings = detect_migrations(content, file_path)
    findings.extend(migration_findings)

    # Schema change detection
    schema_findings = detect_schema_changes(content, file_path)
    findings.extend(schema_findings)

    # C# detection
    if file_path.suffix.lower() in ['.cs', '.vb']:
        csharp_findings = detect_csharp_db_patterns(content, file_path)
        findings.extend(csharp_findings)

    # PHP detection
    if file_path.suffix.lower() in ['.php']:
        php_findings = detect_php_db_patterns(content, file_path)
        findings.extend(php_findings)

    # Secret detection (run on all files)
    secret_findings = detect_secrets(content, file_path)
    findings.extend(secret_findings)

    # Generate natural language descriptions for all findings
    for finding in findings:
        finding["description"] = generate_finding_description(finding)

    return findings


def run_detectors(files: List[Path], threads: int = 4) -> List[Dict[str, Any]]:
    """Run all enabled detectors on the discovered files.

    Args:
        files: List of file paths to scan
        threads: Number of threads to use

    Returns:
        List of findings
    """
    findings = []
    future_to_file = {}

    try:
        if threads > 1:
            # Use parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                # Submit all file processing tasks
                future_to_file = {executor.submit(process_single_file, file_path): file_path for file_path in files}

                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_file):
                    file_findings = future.result()
                    findings.extend(file_findings)
        else:
            # Sequential processing
            for file_path in files:
                file_findings = process_single_file(file_path)
                findings.extend(file_findings)

        # Assign IDs to all findings
        for i, finding in enumerate(findings, 1):
            finding["id"] = f"f-{i:04d}"

        return findings
    except KeyboardInterrupt:
        print("Scan interrupted during detector processing. Cancelling remaining tasks...", file=sys.stderr)
        # Cancel any pending futures
        for future in future_to_file.values():
            if not future.done():
                future.cancel()
        raise
