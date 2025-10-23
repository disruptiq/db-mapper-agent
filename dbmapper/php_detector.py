#!/usr/bin/env python3
"""PHP detection module for Laravel, Doctrine, and other PHP frameworks."""

import re
from pathlib import Path
from typing import List, Dict, Any


# Laravel Eloquent patterns
LARAVEL_MODEL_PATTERN = r'class\s+(\w+)\s+extends\s+(?:Model|Illuminate\\Database\\Eloquent\\Model)'
LARAVEL_MIGRATION_PATTERN = r'class\s+(\w+)\s+extends\s+(?:Migration|Illuminate\\Database\\Migrations\\Migration)'
LARAVEL_CONNECTION_PATTERN = r'(?i)(?:DB_CONNECTION|DATABASE_URL)\s*[=:]\s*["\']([^"\']*(?:mysql|pgsql|sqlite|mongodb)[^"\']*)["\']'

# Doctrine patterns
DOCTRINE_ENTITY_PATTERN = r'@\w*Entity\s+class\s+(\w+)'
DOCTRINE_REPOSITORY_PATTERN = r'class\s+(\w+)Repository\s+extends\s+EntityRepository'

# Raw SQL and Query Builder patterns
PHP_SQL_PATTERNS = [
    (r'\$this->db->query\s*\(', "codeigniter_query"),
    (r'DB::select\s*\(', "laravel_query_builder"),
    (r'DB::insert\s*\(', "laravel_query_builder"),
    (r'DB::update\s*\(', "laravel_query_builder"),
    (r'DB::delete\s*\(', "laravel_query_builder"),
    (r'\$pdo->query\s*\(', "pdo_query"),
    (r'\$pdo->prepare\s*\(', "pdo_prepare"),
    (r'mysqli_query\s*\(', "mysqli_query"),
]


def detect_php_db_patterns(content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Detect PHP database patterns across different frameworks."""
    findings = []

    # Laravel Eloquent models
    for match in re.finditer(LARAVEL_MODEL_PATTERN, content):
        model_name = match.group(1)
        findings.append({
            "type": "orm_model",
            "framework": "laravel",
            "model_name": model_name,
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [f"class {model_name} extends Model"],
            "confidence": 0.95,
        })

    # Laravel migrations
    for match in re.finditer(LARAVEL_MIGRATION_PATTERN, content):
        migration_name = match.group(1)
        findings.append({
            "type": "migration",
            "framework": "laravel",
            "migration_type": "migration_class",
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [f"class {migration_name} extends Migration"],
            "confidence": 0.9,
        })

    # Doctrine entities
    for match in re.finditer(DOCTRINE_ENTITY_PATTERN, content):
        entity_name = match.group(1)
        findings.append({
            "type": "orm_model",
            "framework": "doctrine",
            "model_name": entity_name,
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [f"@Entity class {entity_name}"],
            "confidence": 0.9,
        })

    # Database connections
    for match in re.finditer(LARAVEL_CONNECTION_PATTERN, content):
        connection_string = match.group(1)
        provider = "unknown"
        if "mysql" in connection_string:
            provider = "mysql"
        elif "pgsql" in connection_string:
            provider = "postgresql"
        elif "sqlite" in connection_string:
            provider = "sqlite"
        elif "mongodb" in connection_string:
            provider = "mongodb"

        findings.append({
            "type": "connection",
            "provider": provider,
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [connection_string],
            "confidence": 0.85,
        })

    # Raw SQL and query builder patterns
    for pattern, framework in PHP_SQL_PATTERNS:
        for match in re.finditer(pattern, content):
            findings.append({
                "type": "raw_sql",
                "sql_type": "PHP_QUERY",
                "framework": framework,
                "file": str(file_path),
                "line": content[:match.start()].count('\n') + 1,
                "evidence": [content[match.start():match.start()+50] + "..."],
                "confidence": 0.8,
            })

    return findings
