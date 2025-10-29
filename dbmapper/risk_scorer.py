#!/usr/bin/env python3
"""Risk scoring and severity assessment module for DB Mapper findings."""

from typing import Dict, Any, List
import re
import concurrent.futures
import math
import os


class RiskScorer:
    """Advanced risk scoring system for database-related findings."""

    def __init__(self):
        # Risk weights for different finding types
        self.type_weights = {
            "secret": 10,
            "connection": 6,
            "orm_model": 4,
            "raw_sql": 7,
            "migration": 5,
            "schema_change": 8
        }

        # Risk multipliers based on context
        self.context_multipliers = {
            "production_env": 2.0,
            "exposed_port": 1.8,
            "weak_auth": 2.5,
            "hardcoded_creds": 3.0,
            "public_repo": 1.5,
            "large_query": 1.3,
            "complex_sql": 1.4,
            "no_encryption": 2.2
        }

        # Secret type risk scores
        self.secret_risks = {
            "aws_access_key": 10,
            "aws_secret_key": 10,
            "private_key": 9,
            "jwt_token": 7,
            "api_key": 6,
            "password": 8,
            "hardcoded_credential": 9,
            "base64_secret": 5,
            "bearer_token": 7,
            "db_password": 8
        }

    def score_findings(self, findings: List[Dict[str, Any]], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Calculate risk scores for all findings."""
        if context is None:
            context = {}

        # Determine number of threads to use
        num_threads = min(len(findings), os.cpu_count() or 4)
        if num_threads < 2:
            # For small number of findings, process sequentially
            return self._score_findings_sequential(findings, context)

        # Split findings into chunks for parallel processing
        chunk_size = math.ceil(len(findings) / num_threads)
        finding_chunks = [findings[i:i + chunk_size] for i in range(0, len(findings), chunk_size)]

        scored_findings = []

        def process_chunk(chunk):
            return [self._score_single_finding(finding, context) for finding in chunk]

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(process_chunk, chunk) for chunk in finding_chunks]
            for future in concurrent.futures.as_completed(futures):
                scored_findings.extend(future.result())

        return scored_findings

    def _score_findings_sequential(self, findings: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Sequential version of risk scoring."""
        scored_findings = []
        for finding in findings:
            scored_findings.append(self._score_single_finding(finding, context))
        return scored_findings

    def _score_single_finding(self, finding: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score for a single finding."""
        scored_finding = finding.copy()

        # Calculate base risk score
        base_score = self._calculate_base_score(finding)

        # Apply context multipliers
        context_multiplier = self._calculate_context_multiplier(finding, context)

        # Calculate final risk score
        risk_score = min(10, base_score * context_multiplier)

        # Determine severity level
        severity = self._score_to_severity(risk_score)

        # Add risk information
        scored_finding["risk_score"] = round(risk_score, 2)
        scored_finding["severity"] = severity
        scored_finding["risk_factors"] = self._identify_risk_factors(finding, context)

        return scored_finding

    def _calculate_base_score(self, finding: Dict[str, Any]) -> float:
        """Calculate the base risk score for a finding."""
        finding_type = finding["type"]
        confidence = finding.get("confidence", 0.5)

        # Start with type-based score
        base_score = self.type_weights.get(finding_type, 3)

        # Adjust based on confidence
        base_score *= confidence

        # Type-specific adjustments
        if finding_type == "secret":
            secret_type = finding.get("secret_type", "")
            base_score += self.secret_risks.get(secret_type, 3)

        elif finding_type == "connection":
            provider = finding.get("provider", "").lower()
            # Some providers are riskier than others
            if provider in ["sqlite", "h2"]:  # File-based, less secure
                base_score += 1
            elif provider in ["mongodb", "redis"]:  # NoSQL, different security model
                base_score += 0.5

        elif finding_type == "raw_sql":
            sql_content = " ".join(finding.get("evidence", [])).upper()
            # Dangerous SQL patterns
            if "DROP" in sql_content or "DELETE" in sql_content:
                base_score += 2
            if "UNION SELECT" in sql_content:  # Potential SQL injection
                base_score += 3
            if "--" in sql_content or "/*" in sql_content:  # Comments that might hide malicious code
                base_score += 1

        elif finding_type == "orm_model":
            # Check for potentially dangerous model configurations
            evidence = " ".join(finding.get("evidence", []))
            if "auto_now" in evidence or "auto_now_add" in evidence:
                base_score += 0.5  # Time-based fields can be sensitive

        elif finding_type == "migration":
            migration_type = finding.get("migration_type", "")
            if migration_type in ["drop_table", "drop_column"]:
                base_score += 2  # Destructive operations

        return min(10, base_score)

    def _calculate_context_multiplier(self, finding: Dict[str, Any], context: Dict[str, Any]) -> float:
        """Calculate context-based risk multipliers."""
        multiplier = 1.0

        # Environment context
        if context.get("environment") == "production":
            multiplier *= self.context_multipliers["production_env"]

        # File location context
        file_path = finding.get("file", "").lower()
        if any(keyword in file_path for keyword in ["config", "settings", "env"]):
            multiplier *= 1.2  # Configuration files are more critical

        if "test" in file_path or "spec" in file_path:
            multiplier *= 0.7  # Test files are less critical

        # Content-based context
        evidence = " ".join(finding.get("evidence", [])).lower()

        # Check for exposed ports
        if re.search(r':\d{4,5}', evidence):
            port = re.search(r':(\d{4,5})', evidence)
            if port:
                port_num = int(port.group(1))
                if port_num < 1024 or port_num in [3306, 5432, 27017, 6379]:  # Common DB ports
                    multiplier *= self.context_multipliers["exposed_port"]

        # Check for weak authentication
        if "password" in evidence and len(evidence) < 20:
            multiplier *= self.context_multipliers["weak_auth"]

        # Check for hardcoded credentials
        if finding["type"] == "connection" and "=" in evidence:
            multiplier *= self.context_multipliers["hardcoded_creds"]

        # Check for public repository indicators
        if context.get("is_public_repo", False):
            multiplier *= self.context_multipliers["public_repo"]

        # SQL complexity
        if finding["type"] == "raw_sql":
            sql_content = " ".join(finding.get("evidence", []))
            if len(sql_content.split()) > 20:
                multiplier *= self.context_multipliers["large_query"]
            if sql_content.upper().count("JOIN") > 2:
                multiplier *= self.context_multipliers["complex_sql"]

        # Encryption context
        if finding["type"] == "connection":
            if "ssl" not in evidence.lower() and "tls" not in evidence.lower():
                multiplier *= self.context_multipliers["no_encryption"]

        return multiplier

    def _score_to_severity(self, score: float) -> str:
        """Convert risk score to severity level."""
        if score >= 8.0:
            return "critical"
        elif score >= 6.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 2.0:
            return "low"
        else:
            return "info"

    def _identify_risk_factors(self, finding: Dict[str, Any], context: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors for a finding."""
        factors = []
        finding_type = finding["type"]
        evidence = " ".join(finding.get("evidence", [])).lower()

        # Common risk factors
        if finding.get("confidence", 0) < 0.7:
            factors.append("low_confidence")

        if finding_type == "secret":
            factors.append("credential_exposure")
            if "hardcoded" in finding.get("secret_type", ""):
                factors.append("hardcoded_credentials")

        elif finding_type == "connection":
            if "localhost" not in evidence and "127.0.0.1" not in evidence:
                factors.append("remote_connection")
            if "ssl" not in evidence:
                factors.append("unencrypted_connection")

        elif finding_type == "raw_sql":
            sql = evidence.upper()
            if "DROP" in sql:
                factors.append("destructive_operation")
            if "SELECT *" in sql:
                factors.append("inefficient_query")
            if "UNION" in sql and "SELECT" in sql:
                factors.append("potential_sql_injection")

        elif finding_type == "migration":
            if "drop" in finding.get("migration_type", ""):
                factors.append("destructive_migration")

        # Context-based factors
        if context.get("environment") == "production":
            factors.append("production_environment")

        if context.get("is_public_repo"):
            factors.append("public_repository")

        return factors


# Convenience function
def calculate_risk_scores(findings: List[Dict[str, Any]], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Calculate risk scores for findings using the RiskScorer."""
    scorer = RiskScorer()
    return scorer.score_findings(findings, context)
