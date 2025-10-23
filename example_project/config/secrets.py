# Example secrets file for testing (DO NOT USE IN PRODUCTION)

# API Keys
STRIPE_SECRET_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
OPENAI_API_KEY = "sk-proj-1234567890abcdef"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"

# JWT Secret
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# AWS Credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database credentials
DB_PASSWORD = "mySuperSecretDBPassword123!"
ROOT_PASSWORD = "admin123"

# Private key example (placeholder)
# PRIVATE_KEY = """
# -----BEGIN RSA PRIVATE KEY-----
# MIIEpAIBAAKCAQEAwJ8Z+YtF4+K...
# -----END RSA PRIVATE KEY-----
# """

# Hardcoded credentials (for testing detection)
def connect_to_db():
    # This would be flagged as hardcoded credentials
    return "postgresql://admin:password123@localhost/mydb"

# API call with embedded key (should be detected)
def call_external_api():
    import requests
    headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}
    return requests.get("https://api.example.com", headers=headers)
