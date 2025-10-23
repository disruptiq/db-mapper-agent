#!/usr/bin/env python3
"""C# and .NET detection module for Entity Framework and database patterns."""

import re
from pathlib import Path
from typing import List, Dict, Any


# Entity Framework patterns
EF_MODEL_PATTERN = r'public\s+class\s+(\w+)\s*:\s*(?:DbContext|IdentityDbContext|BaseEntity)'
EF_DBCONTEXT_PATTERN = r'public\s+class\s+(\w+)\s*:\s*DbContext'
EF_DBSET_PATTERN = r'public\s+(?:DbSet|IDbSet)<(\w+)>\s+(\w+)\s*{\s*get;\s*set;\s*}'
EF_CONNECTION_PATTERN = r'(?i)(?:connectionstring|connection_string)\s*[=:]\s*["\']([^"\']*(?:Data Source|Server|Database)[^"\']*)["\']'
EF_MIGRATION_PATTERN = r'(?:Add-Migration|Update-Database|migrationBuilder\.CreateTable)'
EF_RAW_SQL_PATTERN = r'(?:ExecuteSqlRaw|FromSqlRaw|ExecuteSqlCommand)\s*\('


def detect_csharp_db_patterns(content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Detect C# database patterns including Entity Framework."""
    findings = []

    # Entity Framework DbContext detection
    for match in re.finditer(EF_DBCONTEXT_PATTERN, content, re.IGNORECASE):
        class_name = match.group(1)
        findings.append({
            "type": "orm_model",
            "framework": "entity_framework",
            "model_name": class_name,
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [f"public class {class_name} : DbContext"],
            "confidence": 0.95,
        })

    # Entity Framework model classes
    for match in re.finditer(EF_MODEL_PATTERN, content, re.IGNORECASE):
        class_name = match.group(1)
        findings.append({
            "type": "orm_model",
            "framework": "entity_framework",
            "model_name": class_name,
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [f"public class {class_name} : BaseEntity"],
            "confidence": 0.9,
        })

    # DbSet properties
    for match in re.finditer(EF_DBSET_PATTERN, content, re.IGNORECASE):
        entity_type = match.group(1)
        property_name = match.group(2)
        findings.append({
            "type": "orm_model",
            "framework": "entity_framework",
            "model_name": entity_type,
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [f"public DbSet<{entity_type}> {property_name}"],
            "confidence": 0.9,
        })

    # Connection strings
    for match in re.finditer(EF_CONNECTION_PATTERN, content):
        connection_string = match.group(1)
        findings.append({
            "type": "connection",
            "provider": "sql_server",  # Most common for .NET
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [connection_string],
            "confidence": 0.85,
        })

    # Raw SQL usage
    for match in re.finditer(EF_RAW_SQL_PATTERN, content):
        findings.append({
            "type": "raw_sql",
            "sql_type": "RAW_SQL",
            "file": str(file_path),
            "line": content[:match.start()].count('\n') + 1,
            "evidence": [match.group(0)],
            "confidence": 0.8,
        })

    return findings
