#!/usr/bin/env python3
"""Natural language description generator for DB Mapper findings."""

from typing import Dict, Any, Optional
import re


class DescriptionGenerator:
    """Generates human-readable descriptions for database findings."""

    def __init__(self):
        self.templates = {
            "connection": {
                "hardcoded": "Hardcoded {provider} database connection string found in {file_type}. This exposes sensitive connection details and should be moved to environment variables or configuration files.",
                "env_var": "Database connection configured via environment variable '{var_name}' pointing to {provider}. Ensure this variable is properly secured in production environments.",
                "config_file": "{provider} database connection defined in {file_type}. Verify this configuration file is not committed to version control with sensitive data.",
            },
            "orm_model": {
                "django": "Django model '{model_name}' defined with {field_count} fields. This model represents a database table and includes relationships to other models.",
                "sqlalchemy": "SQLAlchemy model '{model_name}' using declarative base. This ORM class maps to a database table with defined columns and relationships.",
                "entity_framework": "Entity Framework entity '{model_name}' with DbSet configuration. This C# class represents a database table with navigation properties.",
                "laravel": "Laravel Eloquent model '{model_name}' extending the base Model class. This PHP class provides ORM functionality for database operations.",
                "default": "ORM model '{model_name}' defined using {framework} framework. This class provides object-relational mapping capabilities.",
            },
            "raw_sql": {
                "select": "Raw SQL SELECT query found in {file_type}. This query retrieves data from {table_hint} and should be reviewed for potential SQL injection vulnerabilities.",
                "insert": "Raw SQL INSERT statement in {file_type}. This operation adds data to {table_hint} - ensure proper input validation to prevent SQL injection.",
                "update": "Raw SQL UPDATE query in {file_type}. This modifies existing data in {table_hint} - verify update conditions are properly sanitized.",
                "delete": "Raw SQL DELETE statement in {file_type}. This removes data from {table_hint} - extreme caution required as this operation cannot be undone.",
                "complex": "Complex raw SQL query spanning multiple operations. This {file_type} contains advanced database logic that may benefit from ORM migration.",
            },
            "secret": {
                "api_key": "API key '{masked_value}' found in {file_type}. This credential provides access to external services and should be stored securely.",
                "password": "Password credential '{masked_value}' detected in {file_type}. This authentication secret must be protected and never committed to version control.",
                "private_key": "Private cryptographic key found in {file_type}. This key material is extremely sensitive and requires secure storage with restricted access.",
                "jwt_token": "JSON Web Token '{masked_value}' present in {file_type}. This authentication token may contain sensitive user information.",
                "aws_access_key": "AWS access key ID found in {file_type}. This credential provides access to AWS services and should use IAM roles instead.",
                "aws_secret_key": "AWS secret access key found in {file_type}. This is part of AWS credentials and must be stored in secure credential management systems.",
                "hardcoded_credential": "Hardcoded database credential found in {file_type}. This '{masked_value}' exposes authentication secrets and should be externalized.",
                "bearer_token": "Bearer token '{masked_value}' found in {file_type}. This authentication token grants API access and should be handled securely.",
            },
            "migration": {
                "django": "Django database migration '{migration_name}' in {file_type}. This migration modifies the database schema using Django's migration framework.",
                "alembic": "Alembic database migration in {file_type}. This migration script manages database schema changes using SQLAlchemy's migration tool.",
                "laravel": "Laravel database migration in {file_type}. This migration class contains schema modifications for the application's database.",
                "flyway": "Flyway database migration script in {file_type}. This SQL file manages database versioning and schema evolution.",
                "create_table": "Database migration creating new table '{table_name}'. This schema change adds a new data structure to the database.",
                "drop_table": "Database migration dropping table '{table_name}'. This destructive operation will permanently remove data - use with extreme caution.",
                "add_column": "Database migration adding column to '{table_name}'. This schema modification extends the table structure.",
            },
            "schema_change": {
                "create_table": "Direct schema modification creating table '{table_name}' in {file_type}. This DDL operation defines a new database table structure.",
                "alter_table": "Schema alteration of table '{table_name}' in {file_type}. This DDL operation modifies existing table structure.",
                "drop_table": "Table drop operation on '{table_name}' in {file_type}. This destructive DDL operation permanently removes table and data.",
                "add_index": "Index creation on table '{table_name}' in {file_type}. This performance optimization adds database indexing.",
                "add_constraint": "Constraint addition to '{table_name}' in {file_type}. This data integrity rule enforces business logic at the database level.",
            }
        }

    def generate_description(self, finding: Dict[str, Any]) -> str:
        """Generate a natural language description for a finding."""
        finding_type = finding["type"]
        framework = finding.get("framework", "").lower()
        file_path = finding.get("file", "")

        # Determine file type context
        file_type = self._get_file_type_context(file_path)

        # Get base template
        template = self._get_template(finding, framework)

        if not template:
            return self._generate_generic_description(finding, file_type)

        # Fill in template variables
        try:
            description = self._fill_template(template, finding, file_type)
        except Exception as e:
            # If template filling fails, use generic
            return self._generate_generic_description(finding, file_type)

        # Add security context if applicable
        if finding.get("severity") in ["critical", "high"]:
            description += " " + self._add_security_context(finding)

        return description

    def _get_file_type_context(self, file_path: str) -> str:
        """Determine the context of the file type for descriptions."""
        if not file_path:
            return "source file"

        file_path = file_path.lower()

        if "config" in file_path or "settings" in file_path:
            return "configuration file"
        elif "model" in file_path or "entity" in file_path:
            return "model/entity file"
        elif "migration" in file_path or "migrate" in file_path:
            return "migration file"
        elif "controller" in file_path or "service" in file_path:
            return "service file"
        elif "test" in file_path or "spec" in file_path:
            return "test file"
        elif ".env" in file_path or "environment" in file_path:
            return "environment configuration"
        elif "script" in file_path or "util" in file_path:
            return "utility script"
        else:
            return "application file"

    def _get_template(self, finding: Dict[str, Any], framework: str) -> Optional[str]:
        """Get the appropriate template for the finding."""
        finding_type = finding["type"]
        type_templates = self.templates.get(finding_type, {})

        # Try framework-specific template first
        if framework and isinstance(type_templates, dict) and framework in type_templates:
            return type_templates[framework]

        # Try type-specific template
        if isinstance(type_templates, dict):
            # For some types, we need to determine subtype
            if finding_type == "raw_sql":
                template = self._get_sql_template(finding, type_templates)
                if template:
                    return template
            elif finding_type == "connection":
                template = self._get_connection_template(finding, type_templates)
                if template:
                    return template
            elif finding_type == "secret":
                template = self._get_secret_template(finding, type_templates)
                if template:
                    return template
            elif finding_type == "migration":
                template = self._get_migration_template(finding, type_templates)
                if template:
                    return template
            # Check if the type itself is a direct template
            elif finding_type in type_templates:
                return type_templates[finding_type]

        # Return the template directly if it's not a dict
        if isinstance(type_templates, str):
            return type_templates

        # Return default template for the type
        return type_templates.get("default") if isinstance(type_templates, dict) else None

    def _get_sql_template(self, finding: Dict[str, Any], templates: Dict[str, Any]) -> Optional[str]:
        """Get appropriate SQL template based on query type."""
        sql_type = finding.get("sql_type", "").upper()

        if "SELECT" in sql_type:
            return templates.get("select")
        elif "INSERT" in sql_type:
            return templates.get("insert")
        elif "UPDATE" in sql_type:
            return templates.get("update")
        elif "DELETE" in sql_type:
            return templates.get("delete")

        # Check if it's complex (multiple operations)
        evidence = " ".join(finding.get("evidence", []))
        if evidence.count("SELECT") + evidence.count("INSERT") + evidence.count("UPDATE") + evidence.count("DELETE") > 1:
            return templates.get("complex")

        return None

    def _get_connection_template(self, finding: Dict[str, Any], templates: Dict[str, Any]) -> Optional[str]:
        """Get appropriate connection template based on context."""
        evidence = " ".join(finding.get("evidence", []))
        file_path = finding.get("file", "").lower()

        # Check for environment variable pattern
        if "=" in evidence and ("DB_" in evidence.upper() or "DATABASE" in evidence.upper()):
            return templates.get("env_var")

        # Check for config files
        if any(file_path.endswith(ext) for ext in [".yml", ".yaml", ".json", ".xml", ".conf", ".ini"]):
            return templates.get("config_file")

        # Default to hardcoded for source files
        return templates.get("hardcoded")

    def _get_secret_template(self, finding: Dict[str, Any], templates: Dict[str, Any]) -> Optional[str]:
        """Get appropriate secret template based on secret type."""
        secret_type = finding.get("secret_type", "")
        return templates.get(secret_type)

    def _get_migration_template(self, finding: Dict[str, Any], templates: Dict[str, Any]) -> Optional[str]:
        """Get appropriate migration template."""
        migration_type = finding.get("migration_type", "")

        # Try migration type first
        if migration_type in templates:
            return templates[migration_type]

        # Fall back to framework
        framework = finding.get("framework", "").lower()
        return templates.get(framework)

    def _fill_template(self, template: str, finding: Dict[str, Any], file_type: str) -> str:
        """Fill in template variables with finding data."""
        # Extract variables from finding
        provider = finding.get("provider", "database")
        model_name = finding.get("model_name", "Unknown")
        var_name = finding.get("evidence", [""])[0].split("=")[0].strip() if "=" in finding.get("evidence", [""])[0] else "unknown"
        table_name = finding.get("table_name", "unknown")
        masked_value = "*" * 8  # Generic masked value

        # Count fields for models (rough estimate)
        evidence = " ".join(finding.get("evidence", []))
        field_count = max(1, evidence.count("Field(") + evidence.count("Column(") + evidence.count("= models."))

        # Replace variables in template
        description = template
        description = description.replace("{provider}", provider)
        description = description.replace("{file_type}", file_type)
        description = description.replace("{model_name}", model_name)
        description = description.replace("{var_name}", var_name)
        description = description.replace("{table_name}", table_name)
        description = description.replace("{masked_value}", masked_value)
        description = description.replace("{field_count}", str(field_count))
        description = description.replace("{table_hint}", f"table '{table_name}'" if table_name != "unknown" else "database tables")

        return description

    def _generate_generic_description(self, finding: Dict[str, Any], file_type: str) -> str:
        """Generate a generic description when no template matches."""
        finding_type = finding["type"]
        confidence = finding.get("confidence", 0)

        base_desc = f"{finding_type.replace('_', ' ').title()} found in {file_type}"

        if confidence > 0.8:
            base_desc += " with high confidence"
        elif confidence < 0.6:
            base_desc += " (requires verification)"

        return base_desc + ". This database-related artifact should be reviewed for security and best practices."

    def _add_security_context(self, finding: Dict[str, Any]) -> str:
        """Add security context information for high-severity findings."""
        finding_type = finding["type"]

        if finding_type == "secret":
            return "Immediate action required: This credential exposure poses a significant security risk and should be addressed immediately."
        elif finding_type == "connection":
            return "Security consideration: Ensure this connection does not expose sensitive authentication details in production environments."
        elif finding_type == "raw_sql":
            return "Security review needed: Raw SQL queries are susceptible to injection attacks - consider using parameterized queries or ORM methods."
        else:
            return "This finding requires security review to ensure compliance with data protection and security standards."


# Convenience function
def generate_finding_description(finding: Dict[str, Any]) -> str:
    """Generate a natural language description for a finding."""
    generator = DescriptionGenerator()
    return generator.generate_description(finding)
