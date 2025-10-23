#!/usr/bin/env python3
"""Cross-reference analysis module for finding relationships between database artifacts."""

import re
from pathlib import Path
from typing import List, Dict, Any, Set
from collections import defaultdict


def analyze_cross_references(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze relationships between findings and add cross-reference information."""
    enhanced_findings = []

    # Group findings by file and type
    file_findings = defaultdict(lambda: defaultdict(list))
    # Also group by type globally for efficient cross-file lookups
    global_findings_by_type = defaultdict(list)

    for finding in findings:
        file_path = finding["file"]
        finding_type = finding["type"]
        file_findings[file_path][finding_type].append(finding)
        global_findings_by_type[finding_type].append(finding)

    # Analyze relationships
    for finding in findings:
        enhanced_finding = finding.copy()

        # Add relationship information
        relationships = _find_relationships(finding, file_findings, global_findings_by_type)
        if relationships:
            enhanced_finding["relationships"] = relationships

        # Add usage context
        context = _analyze_usage_context(finding, file_findings)
        if context:
            enhanced_finding["usage_context"] = context

        enhanced_findings.append(enhanced_finding)

    return enhanced_findings


def _find_relationships(finding: Dict[str, Any], file_findings: Dict[str, Dict[str, List[Dict[str, Any]]]], global_findings_by_type: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Find relationships between this finding and others."""
    relationships = []
    finding_type = finding["type"]
    file_path = finding["file"]

    if finding_type == "orm_model":
        # Connect models to their SQL usage
        model_name = finding.get("model_name", "")
        if model_name:
            # Look for SQL queries that reference this model (across all files)
            for sql_finding in global_findings_by_type.get("raw_sql", []):
                sql_evidence = " ".join(sql_finding.get("evidence", [])).upper()
                if model_name.upper() in sql_evidence:
                    relationships.append({
                        "type": "used_by_query",
                        "target_id": sql_finding["id"],
                        "target_file": sql_finding["file"],
                        "description": f"Model '{model_name}' is used in SQL query"
                    })

            # Look for connections that might be used by this model (same file)
            for conn_finding in file_findings[file_path].get("connection", []):
                relationships.append({
                    "type": "uses_connection",
                    "target_id": conn_finding["id"],
                    "target_file": file_path,
                    "description": f"Model '{model_name}' likely uses database connection"
                })

    elif finding_type == "connection":
        # Connect connections to models and queries that might use them (same file)
        provider = finding.get("provider", "")
        for model_finding in file_findings[file_path].get("orm_model", []):
            relationships.append({
                "type": "provides_connection",
                "target_id": model_finding["id"],
                "target_file": file_path,
                "description": f"Provides {provider} connection for models"
            })

        for sql_finding in file_findings[file_path].get("raw_sql", []):
            relationships.append({
                "type": "provides_connection",
                "target_id": sql_finding["id"],
                "target_file": file_path,
                "description": f"Provides {provider} connection for SQL queries"
            })

    elif finding_type == "migration":
        # Connect migrations to models they might affect (same file)
        framework = finding.get("framework", "")
        migration_type = finding.get("migration_type", "")

        if migration_type in ["create_table", "add_column"]:
            # Look for models that might be created/modified by this migration
            table_name = finding.get("table_name", "").lower()
            for model_finding in file_findings[file_path].get("orm_model", []):
                model_name = model_finding.get("model_name", "").lower()
                if table_name == model_name or table_name == f"{model_name}s":
                    relationships.append({
                        "type": "creates_model",
                        "target_id": model_finding["id"],
                        "target_file": file_path,
                        "description": f"Migration creates/modifies model '{model_finding.get('model_name')}'"
                    })

    elif finding_type == "raw_sql":
        # Connect SQL queries to models they reference (same file)
        sql_evidence = " ".join(finding.get("evidence", [])).upper()

        # Extract potential table/model names from SQL
        potential_tables = _extract_table_names_from_sql(sql_evidence)

        for table in potential_tables:
            # Look for models with matching names
            for model_finding in file_findings[file_path].get("orm_model", []):
                model_name = model_finding.get("model_name", "").lower()
                if table.lower() == model_name or table.lower() == f"{model_name}s":
                    relationships.append({
                        "type": "references_model",
                        "target_id": model_finding["id"],
                        "target_file": file_path,
                        "description": f"SQL query references model '{model_finding.get('model_name')}'"
                    })

    return relationships


def _analyze_usage_context(finding: Dict[str, Any], file_findings: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
    """Analyze the usage context of a finding."""
    context = {}
    finding_type = finding["type"]
    file_path = finding["file"]

    if finding_type == "orm_model":
        # Count related queries and connections
        query_count = len(file_findings[file_path].get("raw_sql", []))
        connection_count = len(file_findings[file_path].get("connection", []))

        context["related_queries"] = query_count
        context["available_connections"] = connection_count
        context["risk_level"] = _calculate_risk_level(finding, query_count, connection_count)

    elif finding_type == "connection":
        # Count models and queries that might use this connection
        model_count = len(file_findings[file_path].get("orm_model", []))
        query_count = len(file_findings[file_path].get("raw_sql", []))

        context["potential_models"] = model_count
        context["potential_queries"] = query_count
        context["usage_estimate"] = model_count + query_count

    elif finding_type == "raw_sql":
        # Analyze SQL complexity and potential issues
        sql_content = " ".join(finding.get("evidence", []))
        context["sql_complexity"] = _analyze_sql_complexity(sql_content)
        context["has_parameters"] = "?" in sql_content or "%s" in sql_content
        context["is_dynamic"] = "SELECT" in sql_content.upper() and ("WHERE" in sql_content.upper() or "JOIN" in sql_content.upper())

    return context


# Pre-compiled regex patterns for table extraction
TABLE_PATTERNS = [
    re.compile(r'FROM\s+(\w+)', re.IGNORECASE),
    re.compile(r'JOIN\s+(\w+)', re.IGNORECASE),
    re.compile(r'UPDATE\s+(\w+)', re.IGNORECASE),
    re.compile(r'INSERT\s+INTO\s+(\w+)', re.IGNORECASE),
    re.compile(r'DELETE\s+FROM\s+(\w+)', re.IGNORECASE),
    re.compile(r'ALTER\s+TABLE\s+(\w+)', re.IGNORECASE),
    re.compile(r'CREATE\s+TABLE\s+(\w+)', re.IGNORECASE)
]

def _extract_table_names_from_sql(sql: str) -> Set[str]:
    """Extract potential table names from SQL queries."""
    tables = set()

    # Use pre-compiled patterns
    for pattern in TABLE_PATTERNS:
        matches = pattern.findall(sql)
        tables.update(matches)

    return tables


def _analyze_sql_complexity(sql: str) -> str:
    """Analyze the complexity of an SQL query."""
    sql = sql.upper()
    complexity_score = 0

    # Count complexity indicators
    if "JOIN" in sql: complexity_score += 2
    if "UNION" in sql: complexity_score += 2
    if "SUBQUERY" in sql or "SELECT" in sql and sql.count("SELECT") > 1: complexity_score += 3
    if "GROUP BY" in sql: complexity_score += 1
    if "ORDER BY" in sql: complexity_score += 1
    if "HAVING" in sql: complexity_score += 1
    if len(sql.split()) > 50: complexity_score += 2

    if complexity_score >= 5:
        return "high"
    elif complexity_score >= 2:
        return "medium"
    else:
        return "low"


def _calculate_risk_level(finding: Dict[str, Any], query_count: int, connection_count: int) -> str:
    """Calculate risk level based on usage context."""
    base_risk = 0

    # Risk factors
    if query_count > 5: base_risk += 2
    if connection_count == 0: base_risk += 3  # No connections found
    if finding.get("confidence", 0) < 0.8: base_risk += 1
    if finding.get("type") == "raw_sql": base_risk += 1  # Raw SQL is riskier

    if base_risk >= 4:
        return "high"
    elif base_risk >= 2:
        return "medium"
    else:
        return "low"


# Import moved to top
