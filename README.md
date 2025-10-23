# DB Mapper — Enterprise-Grade Database Security Scanner

> **DB Mapper** is a comprehensive, AI-powered static analysis tool that scans software repositories to discover, analyze, and secure all database-related artifacts. It provides intelligent detection of connection strings, ORM models, raw SQL queries, hardcoded secrets, migration files, schema changes, and generates natural language security reports with actionable recommendations.

This README describes the cutting-edge features, installation, usage, detection capabilities, and enterprise-grade security analysis of the project.

## Table of Contents

1. Project Overview
2. Goals & Non-goals
3. High-level Workflow
4. Design Principles
5. Architecture & Modules (Modular by design)
6. Detection Techniques & Heuristics
7. Supported Languages & Frameworks (out of the box)
8. CLI & Usage Examples
9. Configuration
10. Output Formats & Examples
11. Quality, Tests & Benchmarks
12. Security & Privacy Considerations
13. Extending the Scanner (Plugins & Rules)
14. Packaging & Distribution Recommendations
15. Contributing Guide
16. Roadmap & TODOs

## Project Overview

DB Mapper is a **static DB mapping tool** that analyzes source code and repository files (including configuration, IaC, and migration files) *without executing them*, to locate and classify database-related artifacts.

It outputs:

* **🔗 Database Connections**: Advanced DSN detection, environment variables, provider identification with connection validation
* **🏗️ ORM Models**: Comprehensive support for Django, SQLAlchemy, Sequelize, TypeORM, JPA/Hibernate, ActiveRecord, GORM, Entity Framework, Laravel Eloquent
* **💉 Raw SQL Queries**: Intelligent inline SQL detection with injection risk assessment and parameterized query recommendations
* **🔐 Secret Detection**: Enterprise-grade detection of API keys, tokens, passwords, private keys, JWT tokens, AWS credentials, database passwords with allowlist filtering
* **📋 Migration Files**: Framework-specific migration analysis for Django, Alembic, Flyway, Liquibase, Rails, Entity Framework migrations
* **⚡ Schema Changes**: DDL statement analysis with impact assessment for CREATE/ALTER/DROP operations
* **🕸️ Data Flow Visualization**: Interactive Graphviz DOT files showing component relationships and data flow
* **📊 Multiple Output Formats**: JSON (API-ready), CSV (SIEM integration), HTML (interactive reports), Graphviz (visualization)
* **🔍 Cross-file Analysis**: Intelligent model-to-query mapping, relationship inference, and usage context analysis
* **🧠 Natural Language Reports**: AI-generated descriptions with actionable security recommendations and risk explanations
* **⚠️ Risk Scoring**: Advanced risk assessment with severity classification, contextual multipliers, and compliance indicators
* **🚀 Parallel Processing**: High-performance multi-threaded scanning for large codebases

---

## Goals & Non-goals

### Goals

* Accurate static discovery of DB touchpoints
* Modular, language-extensible detectors
* Safe operation — no runtime execution
* Machine-readable reports

### Non-goals

* No runtime tracing or query capture
* No automatic schema or migration manipulation
* Not a replacement for full data lineage systems

---

## High-level Workflow

1. **🎯 Input Processing**: Accept repository path with advanced filtering, language selection, and configuration options.
2. **🔍 Intelligent File Discovery**: Multi-language file detection with extension and content-based heuristics across 7+ languages.
3. **🧠 Advanced Parsing**: Hybrid approach using AST parsing for Python and sophisticated regex patterns for all languages.
4. **🔬 Comprehensive Detection Engine**:
   - Database connections with provider validation
   - ORM models across 10+ frameworks with field analysis
   - Raw SQL queries with injection risk assessment
   - Enterprise-grade secret detection with allowlist filtering
   - Framework-specific migration file analysis
   - DDL statement parsing with impact assessment
5. **🔗 Intelligent Relationship Analysis**: Cross-file mapping, model-to-query relationships, and usage context inference.
6. **⚠️ Advanced Risk Assessment**: Multi-factor risk scoring with severity classification, contextual multipliers, and compliance indicators.
7. **📝 Natural Language Generation**: AI-powered descriptions with actionable security recommendations.
8. **📊 Multiple Output Generation**: Parallel processing for JSON, CSV, HTML, and Graphviz formats with enterprise integrations.

---

## Design Principles

* **🏗️ Modular Architecture:** Plugin-based detector system with easy extension and customization.
* **🌍 Language-Agnostic:** Universal support with language-specific optimizations (AST for Python, regex for others).
* **🔄 Deterministic Results:** Consistent output across runs with identical inputs.
* **⚙️ Enterprise Configurable:** Fine-tune confidence thresholds, risk scoring, language support, and output formats.
* **📖 Explainable AI:** Natural language descriptions with actionable security recommendations.
* **🚀 High Performance:** Parallel processing, memory-efficient streaming, and optimized algorithms.
* **🔒 Security-First:** Safe static analysis with comprehensive secret detection and risk assessment.

---

## Architecture & Modules

Recommended project layout:

```
db-mapper/
├── README.md
├── pyproject.toml
├── src/
│   ├── dbmapper/
│   │   ├── __main__.py         # CLI entry
│   │   ├── cli.py              # Argparse interface
│   │   ├── runner.py           # Core orchestrator
│   │   ├── scanner/            # File discovery
│   │   ├── parsers/            # AST / regex parsers
│   │   ├── detectors/          # DB/ORM/SQL detectors
│   │   ├── crosslinker/        # Model-query mapping
│   │   ├── normalizers/        # Normalize DSNs, providers
│   │   ├── output/             # Writers (JSON, HTML, Graph)
│   │   ├── plugins/            # Optional extensions
│   │   ├── rules/              # Rule signatures
│   │   └── utils/
│   └── tests/
└── docs/
```

---

## Core Components

**File discovery**
Walks repo, filters relevant files, detects languages.

**Parsers**
Wraps ASTs or uses text-based regex scanning.

**Core Detection Engine**

* **`detectors.py`**: Main orchestration engine with parallel processing
* **`ast_parser.py`**: Abstract Syntax Tree parsing for Python code accuracy
* **`secret_detector.py`**: Enterprise-grade secret detection with pattern matching and allowlist filtering
* **`migration_detector.py`**: Framework-specific migration file analysis
* **`csharp_detector.py`**: Entity Framework and .NET ORM detection
* **`php_detector.py`**: Laravel Eloquent and Doctrine ORM detection
* **`cross_references.py`**: Intelligent relationship mapping between components
* **`risk_scorer.py`**: Advanced risk assessment with contextual scoring
* **`description_generator.py`**: AI-powered natural language report generation

**Crosslinker**
Connects models and their usage in queries or services.

**Normalizers**
Canonicalizes connection URIs (e.g., all postgres variants → `postgresql`).

**Output Writers**

* JSON
* HTML (searchable, human-readable)
* Graphviz for visual data flows

**Plugins**
Third-party detectors added via plugin entry points.

---

## Detection Techniques & Heuristics

**Connection Detection**

* Regex match for DSNs like `postgres://`, `mysql://`
* Env variable lookups (`DB_URL`, `DATABASE_URL`)
* YAML/Terraform/Docker configs referencing DBs

**ORM Detection**

* Identify base classes (`class User(models.Model)`)
* Imports of ORM libs (SQLAlchemy, Sequelize, etc.)

**Raw SQL Detection**

* Regex for common SQL patterns (`SELECT`, `INSERT`, etc.)
* AST scan for `execute()` calls with literal SQL strings

**Migration Detection**

* Recognize framework-specific directories
* Parse for `create_table`, `add_column` patterns

**Secret Detection**

* Regexes for passwords, keys, base64 strings
* Avoid false positives using allowlists

---

## Supported Languages & Frameworks

Comprehensive multi-language support:

**Python**
* Django ORM, SQLAlchemy, Peewee
* Raw SQL queries, connection strings
* Alembic migrations, custom migration scripts

**JavaScript/TypeScript**
* Sequelize, TypeORM, Mongoose, Prisma
* Node.js database drivers, connection pooling
* GraphQL resolvers with database access

**Java**
* JPA/Hibernate, Spring Data JDBC
* MyBatis, jOOQ for type-safe SQL
* Flyway/Liquibase migrations

**Ruby**
* ActiveRecord (Rails), Sequel, ROM
* Sinatra/DataMapper applications
* Rails migrations and database tasks

**Go**
* GORM, database/sql driver
* Buntdb, Storm, custom ORM libraries
* Migration tools and schema management

**SQL & Database Scripts**
* Plain SQL files, stored procedures
* Database migration scripts
* Schema definition files

**Infrastructure & Configuration**
* Docker Compose database services with service discovery
* Terraform AWS RDS, GCP Cloud SQL, Azure Database infrastructure
* Kubernetes ConfigMaps and Secrets with security validation
* Environment files (.env, .env.local) with secret detection
* YAML/TOML/JSON configuration files with schema validation
* CloudFormation and ARM templates for cloud database resources

---

## CLI & Usage Examples

**Basic Scan**

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
db-mapper scan /path/to/repo --output findings.json
```

**Flags**

```
--path PATH                Repository path (required)
--output FILE              Output file base name (default: findings)
--formats json,csv,html,graph  Output formats (default: json)
--include GLOB             Glob patterns for files to include (e.g., "**/*.py")
--exclude GLOB             Glob patterns for files to exclude (e.g., "**/test/**") - additional to default exclusions
--languages python,js,java,csharp,php,ruby,go,sql  Limit to specific languages
--plugins PLUGINS          Enable additional detector plugins (future feature)
--min-confidence FLOAT     Filter results below confidence threshold (default: 0.5)
--verbose                  Enable verbose logging with progress indicators
--threads N                Number of parallel worker threads (default: 4, max: 16)
--config FILE              Path to YAML configuration file (future feature)
--risk-threshold critical,high,medium,low  Minimum risk level to report (default: low)
```

**Sample Output (JSON)**

```json
{
  "summary": {"files_scanned": 142, "findings": 29},
  "findings": [
    {
      "id": "f-0001",
      "type": "connection",
      "provider": "postgresql",
      "file": "config/.env",
      "line": 12,
      "evidence": ["DATABASE_URL=postgres://user:pass@db:5432/app"],
      "confidence": 0.98
    },
    {
      "id": "f-0002",
      "type": "orm_model",
      "framework": "django",
      "file": "models/user.py",
      "evidence": ["class User(models.Model):"],
      "confidence": 0.95
    }
  ]
}
```

### Enhanced JSON Schema with AI Descriptions

```json
{
  "summary": {
    "files_scanned": 150,
    "findings": 45,
    "severity_breakdown": {
      "critical": 3,
      "high": 12,
      "medium": 20,
      "low": 10
    }
  },
  "findings": [
    {
      "id": "f-0001",
      "type": "secret",
      "secret_type": "aws_access_key",
      "severity": "critical",
      "risk_score": 9.2,
      "file": "config/production.py",
      "line": 25,
      "evidence": ["AWS_ACCESS_KEY_ID = \"********\""],
      "confidence": 0.95,
      "description": "AWS access key ID found in configuration file. This credential provides access to AWS services and should be stored in secure credential management systems.",
      "relationships": [
        {
          "type": "used_by_connection",
          "target_id": "f-0002",
          "description": "This AWS key is used by database connection in the same file"
        }
      ],
      "usage_context": {
        "environment_indicators": ["production"],
        "security_implications": ["cloud_resource_access", "potential_data_exposure"]
      },
      "risk_factors": ["production_environment", "hardcoded_credentials", "cloud_resource_access"]
    }
  ]
}
```

---

## Configuration Example (`dbmapper.yml`)

```yaml
include:
  - "**/*.py"
  - "**/*.sql"
exclude:
- "**/node_modules/**"
- "**/.venv/**"
  # Note: Default exclusions already include common files like images, binaries, etc.
languages:
  - python
  - javascript
detectors:
  connection_detector: true
  orm_detector: true
  raw_sql_detector: true
  secret_detector: false
output:
  json: findings.json
  html: report.html
confidence_threshold: 0.5
```

---

## Output Formats

* **JSON:** Structured data with full metadata, confidence scores, and relationships
* **CSV:** Tabular format for import into spreadsheets, SIEM systems, or databases
* **HTML:** Interactive web report with filtering, sorting, and severity highlighting
* **Graphviz/DOT:** Visual data flow diagrams showing connections between components

### Enhanced JSON Schema

```json
{
  "summary": {
    "files_scanned": 150,
    "findings": 45,
    "high_severity": 3,
    "medium_severity": 12,
    "low_severity": 30
  },
  "findings": [
    {
      "id": "f-0001",
      "type": "secret",
      "secret_type": "aws_access_key",
      "severity": "high",
      "file": "config/production.py",
      "line": 25,
      "evidence": ["AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\""],
      "confidence": 0.95,
      "framework": null,
      "description": "AWS Access Key ID detected"
    }
  ]
}
```

---

## Quality & Testing

* Unit tests per detector
* End-to-end repo tests
* Benchmark scanning performance
* Type checks (mypy/tsc)
* CI/CD integration with GitHub Actions

---

## Security & Privacy

* No code execution
* Mask credentials in output
* Never upload code externally without consent
* Optional `--show-secrets` for controlled exposure

---

## Extending the Scanner

**Plugin Model**

* Plugins expose a `register(detector_registry)` API
* Discoverable via entry points in `pyproject.toml`

**Writing a Detector**
Implement detector functions that return findings:

```python
def detect_custom_patterns(content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Example custom detector for specific patterns."""
    findings = []
    # Your detection logic here
    return findings
```

Each finding includes:
- `id`: Unique identifier
- `type`: Detection type (connection, orm_model, raw_sql, secret, migration, schema_change)
- `file`: File path
- `line`: Line number
- `evidence`: Code snippets showing the finding
- `confidence`: Confidence score (0.0-1.0)
- `severity`: Risk level (high/medium/low)
- Additional type-specific fields

**Rule Pack Example**

```yaml
- id: R001
  name: Postgres DSN
  pattern: '(?i)postgres(?:ql)?://[\\w:@\\-\\.\\/%\\?=~&]+'
  description: 'Matches PostgreSQL connection strings'
  risk: high
  default_confidence: 0.7
```

---

## Packaging & Distribution

* Avoid `.egg` packaging.
* Use modern tooling: `poetry`, `flit`, or `setuptools` with wheels.
* Define CLI entry in `pyproject.toml`:

```toml
[project.scripts]
db-mapper = "dbmapper.__main__:main"
```

---

## Contributing

1. Fork repo and create a feature branch.
2. Run tests locally.
3. Add fixtures for any new detector or pattern.
4. Document new modules or CLI flags.
5. Submit PR with clear changelog entry.

---

## Roadmap & Future Enhancements

### ✅ **Implemented (v1.0)**
* **🔬 Advanced Detection Engine**: Multi-language support (Python, JS/TS, Java, C#, PHP, Ruby, Go, SQL) with 10+ ORM frameworks
* **🔐 Enterprise Secret Detection**: API keys, tokens, passwords, private keys, JWT, AWS credentials with intelligent allowlist filtering
* **📋 Migration Analysis**: Framework-specific migration detection (Django, Alembic, Flyway, Liquibase, Rails, Entity Framework)
* **🕸️ Data Flow Visualization**: Interactive Graphviz DOT files showing component relationships and data flow
* **📊 Multi-Format Outputs**: JSON (API-ready), CSV (SIEM integration), HTML (interactive reports), Graphviz (visualization)
* **🔍 Intelligent Cross-References**: Model-to-query mapping, relationship inference, and usage context analysis
* **🧠 AI-Powered Descriptions**: Natural language generation with actionable security recommendations
* **⚠️ Advanced Risk Assessment**: Multi-factor risk scoring with severity classification and contextual multipliers
* **🚀 High-Performance Processing**: Parallel multi-threaded scanning with optimized algorithms
* **🏗️ AST-Based Parsing**: Python AST parsing for enhanced accuracy with regex fallbacks for other languages

### 🔄 **In Development (v1.1)**
* Plugin architecture for custom detectors and rules
* YAML configuration file support
* Interactive HTML filtering and search capabilities
* Performance optimizations for large codebases

### 🚀 **Planned Features (v2.0+)**
* Tree-sitter integration for advanced multi-language parsing
* SQL AST analysis for column-level data flow and dependency mapping
* CI/CD integration with GitHub Actions, GitLab CI, Jenkins, Azure DevOps
* Cloud provider infrastructure detection (AWS RDS, GCP Cloud SQL, Azure Database)
* Real-time monitoring and alerting system
* Integration with commercial security scanners (SAST, DAST, SCA)
* Support for additional languages (Kotlin, Rust, Scala, Swift)
* Machine learning-based pattern recognition and anomaly detection
* Compliance reporting and audit trails (GDPR, HIPAA, SOX, PCI-DSS)
* GUI application for interactive analysis and remediation
* REST API for integration with security platforms
* Custom rule engine with domain-specific language

---

## Appendix — Useful Regex Patterns

**Generic DSN**

```
(?i)(postgres(?:ql)?|mysql|mariadb|mongodb|sqlite|mssql)://[\\w:@\\-\\.\\/%\\?=~&]+
```

**ENV Variable**

```
(?m)^(DB_URL|DATABASE_URL|[A-Z_]*DB[A-Z_]*)\\s*=\\s*(.+)$
```

**SQL Detection**

```
(?is)(SELECT|INSERT|UPDATE|DELETE|CREATE\\s+TABLE|ALTER\\s+TABLE)\\s+.+?
```

---

## JSON Schema (Simplified)

```json
{
  "type": "object",
  "properties": {
    "summary": {"type": "object"},
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "type": {"type": "string"},
          "file": {"type": "string"},
          "line": {"type": "integer"},
          "evidence": {"type": "array"},
          "confidence": {"type": "number"}
        }
      }
    }
  }
}
```
