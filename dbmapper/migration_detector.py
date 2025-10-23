#!/usr/bin/env python3
"""Migration detection module for identifying database migration files and patterns."""

import re
from pathlib import Path
from typing import List, Dict, Any


# Migration file patterns by framework
MIGRATION_PATTERNS = {
    "django": {
        "file_patterns": [r"migrations/.*\.py$", r".*migrate.*\.py$"],
        "content_patterns": [
            (r'def\s+migrate.*?\(', "migration_function", 0.9),
            (r'operations\s*=\s*\[', "django_operations", 0.95),
            (r'CreateModel\s*\(', "create_model", 0.9),
            (r'DeleteModel\s*\(', "delete_model", 0.9),
            (r'AddField\s*\(', "add_field", 0.9),
            (r'RemoveField\s*\(', "remove_field", 0.9),
            (r'RunSQL\s*\(', "run_sql", 0.8),
        ]
    },
    "alembic": {
        "file_patterns": [r"versions/.*\.py$", r".*alembic.*\.py$"],
        "content_patterns": [
            (r'def\s+upgrade\(\):', "alembic_upgrade", 0.95),
            (r'def\s+downgrade\(\):', "alembic_downgrade", 0.95),
            (r'op\.create_table', "create_table", 0.9),
            (r'op\.drop_table', "drop_table", 0.9),
            (r'op\.add_column', "add_column", 0.9),
            (r'op\.drop_column', "drop_column", 0.9),
        ]
    },
    "flyway": {
        "file_patterns": [r"db/migration/.*\.sql$", r"V.*__.*\.sql$"],
        "content_patterns": [
            (r'CREATE\s+TABLE', "create_table", 0.9),
            (r'ALTER\s+TABLE', "alter_table", 0.9),
            (r'DROP\s+TABLE', "drop_table", 0.9),
            (r'INSERT\s+INTO', "insert_data", 0.7),
            (r'UPDATE\s+.*SET', "update_data", 0.7),
        ]
    },
    "liquibase": {
        "file_patterns": [r".*\.xml$", r".*\.yaml$", r".*\.yml$", r".*\.json$"],
        "content_patterns": [
            (r'<createTable', "create_table", 0.9),
            (r'<dropTable', "drop_table", 0.9),
            (r'<addColumn', "add_column", 0.9),
            (r'<sql>', "raw_sql", 0.8),
        ]
    },
    "rails": {
        "file_patterns": [r"db/migrate/.*\.rb$", r".*migration.*\.rb$"],
        "content_patterns": [
            (r'def\s+change', "rails_change", 0.95),
            (r'def\s+up', "rails_up", 0.9),
            (r'def\s+down', "rails_down", 0.9),
            (r'create_table', "create_table", 0.9),
            (r'drop_table', "drop_table", 0.9),
            (r'add_column', "add_column", 0.9),
        ]
    }
}


def detect_migrations(content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Detect migration-related patterns in files."""
    findings = []
    framework = _identify_framework(file_path)

    if not framework:
        return findings

    patterns = MIGRATION_PATTERNS.get(framework, {}).get("content_patterns", [])
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        for pattern, migration_type, confidence in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "type": "migration",
                    "framework": framework,
                    "migration_type": migration_type,
                    "file": str(file_path),
                    "line": line_num,
                    "evidence": [line.strip()],
                    "confidence": confidence,
                })

    return findings


def _identify_framework(file_path: Path) -> str:
    """Identify the migration framework based on file path and structure."""
    path_str = str(file_path)

    # Django
    if 'migrations' in path_str and file_path.suffix == '.py':
        return "django"

    # Alembic
    if 'versions' in path_str and file_path.suffix == '.py':
        return "alembic"

    # Rails
    if 'db/migrate' in path_str and file_path.suffix == '.rb':
        return "rails"

    # Flyway
    if ('db/migration' in path_str or re.match(r'V.*__.*\.sql$', file_path.name)):
        return "flyway"

    # Liquibase (check content for XML/YAML structure)
    if file_path.suffix in ['.xml', '.yaml', '.yml', '.json']:
        return "liquibase"

    return None


def detect_schema_changes(content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Detect schema-related changes that might indicate migrations."""
    findings = []
    lines = content.splitlines()

    schema_patterns = [
        (r'CREATE\s+TABLE\s+(\w+)', "create_table", "table_creation"),
        (r'ALTER\s+TABLE\s+(\w+)', "alter_table", "table_modification"),
        (r'DROP\s+TABLE\s+(\w+)', "drop_table", "table_deletion"),
        (r'CREATE\s+INDEX\s+(\w+)', "create_index", "index_creation"),
        (r'ADD\s+CONSTRAINT\s+(\w+)', "add_constraint", "constraint_addition"),
    ]

    for line_num, line in enumerate(lines, 1):
        for pattern, change_type, description in schema_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                table_name = match.group(1) if match.groups() else "unknown"
                findings.append({
                    "type": "schema_change",
                    "change_type": change_type,
                    "table_name": table_name,
                    "description": description,
                    "file": str(file_path),
                    "line": line_num,
                    "evidence": [line.strip()],
                    "confidence": 0.8,
                })

    return findings
