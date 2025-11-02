#!/usr/bin/env python3
"""AST-based parsing module for improved accuracy in Python code analysis."""

import ast
from pathlib import Path
from typing import List, Dict, Any, Optional


class PythonASTParser:
    """AST-based parser for Python files to extract database-related patterns."""

    def __init__(self):
        self.findings = []

    def parse_content(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Parse Python content using AST for accurate extraction."""
        self.findings = []

        try:
            # Skip AST parsing for very large content to avoid performance issues
            if len(content) > 2 * 1024 * 1024:  # 2MB limit for AST parsing
                return self.findings

            tree = ast.parse(content, filename=str(file_path))
            self.visit(tree, file_path)

        except SyntaxError:
            # Fall back to regex-based parsing for files with syntax errors
            pass
        except Exception:
            # If AST parsing fails, continue with other methods
            pass

        return self.findings

    def visit(self, node: ast.AST, file_path: Path):
        """Visit AST nodes to extract database patterns."""
        if isinstance(node, ast.ClassDef):
            self._analyze_class(node, file_path)
        elif isinstance(node, ast.FunctionDef):
            self._analyze_function(node, file_path)
        elif isinstance(node, ast.Assign):
            self._analyze_assignment(node, file_path)
        elif isinstance(node, ast.Call):
            self._analyze_call(node, file_path)

        # Recursively visit child nodes
        for child in ast.iter_child_nodes(node):
            self.visit(child, file_path)

    def _analyze_class(self, node: ast.ClassDef, file_path: Path):
        """Analyze class definitions for ORM models."""
        # Check for Django models
        if self._is_django_model(node):
            self.findings.append({
                "type": "orm_model",
                "framework": "django",
                "model_name": node.name,
                "file": str(file_path),
                "line": node.lineno,
                "evidence": [f"class {node.name}(models.Model):"],
                "confidence": 0.95,
                "fields": self._extract_model_fields(node)
            })

    def _is_django_model(self, node: ast.ClassDef) -> bool:
        """Check if a class is a Django model."""
        for base in node.bases:
            if isinstance(base, ast.Attribute):
                if (isinstance(base.value, ast.Name) and base.value.id == "models" and
                    base.attr == "Model"):
                    return True
            elif isinstance(base, ast.Name) and base.id == "Model":
                # Check if Model is imported from django.db
                return True
        return False

    def _extract_model_fields(self, node: ast.ClassDef) -> List[str]:
        """Extract field definitions from a Django model."""
        fields = []
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        field_name = target.id
                        if isinstance(item.value, ast.Call):
                            # This is likely a field definition
                            if isinstance(item.value.func, ast.Attribute):
                                field_type = item.value.func.attr
                                fields.append(f"{field_name}: {field_type}")
        return fields

    def _analyze_function(self, node: ast.FunctionDef, file_path: Path):
        """Analyze function definitions for database operations."""
        # Check for SQL-related functions
        sql_patterns = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"]

        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Str):
                # Check for SQL strings in function
                sql_content = stmt.s.upper()
                if any(pattern in sql_content for pattern in sql_patterns):
                    self.findings.append({
                        "type": "raw_sql",
                        "sql_type": self._identify_sql_type(sql_content),
                        "file": str(file_path),
                        "line": stmt.lineno,
                        "evidence": [stmt.s],
                        "confidence": 0.9,
                        "function": node.name
                    })

    def _analyze_assignment(self, node: ast.Assign, file_path: Path):
        """Analyze assignments for database connections and configurations."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id

                # Check for database URLs
                if "DATABASE" in var_name or "DB" in var_name or "SQL" in var_name:
                    if isinstance(node.value, ast.Str):
                        value = node.value.s
                        if self._looks_like_connection_string(value):
                            self.findings.append({
                                "type": "connection",
                                "provider": self._identify_provider(value),
                                "file": str(file_path),
                                "line": node.lineno,
                                "evidence": [f"{var_name} = \"{value}\""],
                                "confidence": 0.9
                            })

    def _analyze_call(self, node: ast.Call, file_path: Path):
        """Analyze function calls for database operations."""
        if isinstance(node.func, ast.Attribute):
            # Check for execute() calls
            if node.func.attr == "execute":
                # This might be a SQL execution
                if node.args and isinstance(node.args[0], ast.Str):
                    sql = node.args[0].s.upper()
                    if any(keyword in sql for keyword in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                        self.findings.append({
                            "type": "raw_sql",
                            "sql_type": self._identify_sql_type(sql),
                            "file": str(file_path),
                            "line": node.lineno,
                            "evidence": [node.args[0].s],
                            "confidence": 0.85
                        })

    def _looks_like_connection_string(self, value: str) -> bool:
        """Check if a string looks like a database connection string."""
        return any(protocol in value for protocol in [
            "postgresql://", "mysql://", "sqlite://", "mongodb://",
            "redis://", "oracle://", "mssql://"
        ])

    def _identify_provider(self, connection_string: str) -> str:
        """Identify the database provider from connection string."""
        if "postgresql://" in connection_string or "postgres://" in connection_string:
            return "postgresql"
        elif "mysql://" in connection_string:
            return "mysql"
        elif "mongodb://" in connection_string:
            return "mongodb"
        elif "redis://" in connection_string:
            return "redis"
        elif "sqlite://" in connection_string:
            return "sqlite"
        else:
            return "unknown"

    def _identify_sql_type(self, sql: str) -> str:
        """Identify the type of SQL statement."""
        sql = sql.strip().upper()
        if sql.startswith("SELECT"):
            return "SELECT"
        elif sql.startswith("INSERT"):
            return "INSERT"
        elif sql.startswith("UPDATE"):
            return "UPDATE"
        elif sql.startswith("DELETE"):
            return "DELETE"
        elif "CREATE TABLE" in sql:
            return "CREATE_TABLE"
        elif "ALTER TABLE" in sql:
            return "ALTER_TABLE"
        else:
            return "SQL"


# Integration with main detector system
def detect_with_ast(content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Use AST parsing for Python files, fall back to regex for others."""
    if file_path.suffix == '.py':
        parser = PythonASTParser()
        return parser.parse_content(content, file_path)
    else:
        # For non-Python files, return empty (will be handled by regex detectors)
        return []
