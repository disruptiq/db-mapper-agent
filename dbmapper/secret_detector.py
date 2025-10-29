#!/usr/bin/env python3
"""Secret detection module for identifying potential credentials and sensitive data."""

import re
from pathlib import Path
from typing import List, Dict, Any


# Pre-compiled secret patterns for performance
SECRET_PATTERNS = [
    # API Keys and Tokens
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', "api_key", 0.8),
    (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', "secret_key", 0.8),
    (r'(?i)(access[_-]?token|accesstoken)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', "access_token", 0.8),
    (r'(?i)(bearer[_-]?token|bearertoken)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', "bearer_token", 0.8),

    # Passwords
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^"\s]{8,})["\']?', "password", 0.7),
    (r'(?i)(db[_-]?password|dbpasswd)\s*[=:]\s*["\']?([^"\s]{4,})["\']?', "db_password", 0.8),

    # Private Keys (basic patterns)
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "private_key", 0.95),
    (r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', "ec_private_key", 0.95),
    (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', "openssh_private_key", 0.95),

    # JWT Tokens
    (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "jwt_token", 0.9),

    # AWS Credentials
    (r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws_access_key_id)\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', "aws_access_key", 0.95),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key|aws_secret_access_key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', "aws_secret_key", 0.95),

    # Generic base64-like strings (potential secrets)
    (r'(?i)(key|token|secret)\s*[=:]\s*["\']?([a-zA-Z0-9+/=]{20,})["\']?', "base64_secret", 0.6),

    # Hardcoded credentials in code
    (r'(?i)["\']((?:admin|root|user|test)@[\w.-]+):([^"\s]{4,})["\']', "hardcoded_credential", 0.85),
    # Generic password patterns
    (r'(?i)password\s*[:=]\s*["\']([^"\']{8,})["\']', "password", 0.7),
]

# Allowlist patterns (false positives to ignore)
ALLOWLIST_PATTERNS = [
    r'(?i)example\.com',
    r'(?i)your[_-]?domain',
    r'(?i)placeholder',
    r'(?i)sample[_-]?data',
    r'(?i)test[_-]?key',
    r'(?i)dummy[_-]?value',
    r'(?i)CHANGE[_-]?ME',
    r'(?i)REPLACE[_-]?WITH',
    r'xxx+',  # Common placeholder
    r'\*+',  # Starred out values (one or more asterisks)
]


def detect_secrets(content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Detect potential secrets and sensitive data in file content."""
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip comments and documentation
        if _is_comment_or_docstring(line, file_path):
            continue

        for pattern, secret_type, confidence in SECRET_PATTERNS:
            matches = re.finditer(pattern, line)
            for match in matches:
                # Extract the secret value based on the pattern
                if len(match.groups()) >= 2:
                    secret_value = match.group(2)
                elif len(match.groups()) == 1:
                    secret_value = match.group(1)
                else:
                    # No capture groups, use the entire match
                    secret_value = match.group(0)

                # Apply allowlist filtering
                if _should_ignore_secret(secret_value):
                    continue

                # Skip variable references (e.g., object.property, variableName)
                if _looks_like_variable_reference(secret_value):
                    continue

                # Additional validation
                if not _validate_secret(secret_value, secret_type):
                    continue

                findings.append({
                    "type": "secret",
                    "secret_type": secret_type,
                    "file": str(file_path),
                    "line": line_num,
                    "evidence": [_mask_secret(line.strip(), secret_value)],
                    "confidence": confidence,
                    "severity": _calculate_severity(secret_type, file_path),
                })

    return findings


def _is_comment_or_docstring(line: str, file_path: Path) -> bool:
    """Check if line appears to be a comment or documentation."""
    line = line.strip()

    # File-specific comment patterns
    if file_path.suffix == '.py':
        return line.startswith('#') or '"""' in line or "'''" in line
    elif file_path.suffix in ['.js', '.ts', '.java', '.cpp', '.c', '.php']:
        return line.startswith('//') or line.startswith('/*') or line.startswith('*')
    elif file_path.suffix == '.rb':
        return line.startswith('#') or line.startswith('=begin')
    elif file_path.suffix == '.sql':
        return line.startswith('--')
    elif file_path.suffix in ['.yml', '.yaml']:
        return line.startswith('#')

    return False


def _looks_like_variable_reference(secret_value: str) -> bool:
    """Check if the secret value looks like a variable reference rather than a hardcoded secret."""
    # Variable references typically:
    # - Contain dots (object.property)
    # - Contain camelCase or snake_case patterns
    # - Don't contain spaces
    # - May contain special characters like underscores, dots

    if ' ' in secret_value:
        return False  # If it has spaces, it's likely not a variable reference

    # Check for object.property patterns
    if '.' in secret_value and not secret_value.startswith('http'):
        return True

    # Check for camelCase or PascalCase (common in programming)
    if re.search(r'[a-z][A-Z]|[A-Z][a-z]', secret_value):
        return True

    # Check for snake_case
    if '_' in secret_value and not secret_value.startswith('http'):
        return True

    return False


def _should_ignore_secret(secret_value: str) -> bool:
    """Check if secret should be ignored based on allowlist."""
    secret_lower = secret_value.lower()
    return any(re.search(pattern, secret_lower, re.IGNORECASE) for pattern in ALLOWLIST_PATTERNS)


def _validate_secret(secret_value: str, secret_type: str) -> bool:
    """Additional validation for detected secrets."""
    if secret_type == "jwt_token":
        # JWT should have exactly 3 parts
        return len(secret_value.split('.')) == 3

    if secret_type in ["aws_access_key", "aws_secret_key"]:
        # AWS keys have specific formats
        return True  # Already validated by regex

    if secret_type == "base64_secret":
        # Check if it's actually base64-like
        try:
            import base64
            # Simple validation: try to decode
            base64.b64decode(secret_value, validate=True)
            return len(secret_value) >= 20
        except:
            return False

    # For other types, basic length check
    return len(secret_value) >= 8


def _mask_secret(line: str, secret_value: str) -> str:
    """Mask the secret value in the evidence."""
    # Replace the secret with asterisks
    masked_value = '*' * min(len(secret_value), 20)
    return line.replace(secret_value, masked_value)


def _calculate_severity(secret_type: str, file_path: Path) -> str:
    """Calculate severity level for the finding."""
    high_severity = ["private_key", "aws_access_key", "aws_secret_key", "hardcoded_credential"]
    medium_severity = ["jwt_token", "api_key", "secret_key", "bearer_token", "db_password"]
    low_severity = ["password", "base64_secret"]

    if secret_type in high_severity:
        return "high"
    elif secret_type in medium_severity:
        return "medium"
    elif secret_type in low_severity:
        return "low"

    return "medium"
