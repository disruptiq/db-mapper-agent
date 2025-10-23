#!/usr/bin/env python3
"""Output writers for different formats."""

from pathlib import Path
import json
import csv
from typing import Dict, Any, List, Tuple


def write_outputs(results: Dict[str, Any], output_path: Path, formats: List[str]) -> None:
    """Write the scan results to the specified formats.

    Args:
        results: Scan results dictionary
        output_path: Base output path
        formats: List of formats to write
    """
    if "json" in formats:
        json_path = output_path.with_suffix(".json")
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"JSON output written to {json_path}")

    if "html" in formats:
        html_path = output_path.with_suffix(".html")
        write_html(results, html_path)
        print(f"HTML output written to {html_path}")

    if "graph" in formats:
        graph_path = output_path.with_suffix(".dot")
        write_graphviz(results, graph_path)
        print(f"Graphviz output written to {graph_path}")

    if "csv" in formats:
        csv_path = output_path.with_suffix(".csv")
        write_csv(results, csv_path)
        print(f"CSV output written to {csv_path}")


def write_html(results: Dict[str, Any], path: Path) -> None:
    """Write results as HTML report with detailed descriptions."""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DB Mapper Security Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
            }}
            .summary {{
                display: flex;
                gap: 20px;
                margin-bottom: 20px;
            }}
            .summary-card {{
                background: white;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                flex: 1;
            }}
            .findings {{
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                overflow-x: auto;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #f8f9fa;
                font-weight: 600;
            }}
            .severity-critical {{ background-color: #fee; }}
            .severity-high {{ background-color: #ffe; }}
            .severity-medium {{ background-color: #efe; }}
            .severity-low {{ background-color: #f9f9f9; }}
            .description {{
                max-width: 400px;
                word-wrap: break-word;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 DB Mapper Security Report</h1>
            <p>Comprehensive database artifact analysis and security assessment</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>📊 Scan Summary</h3>
                <p><strong>Files Scanned:</strong> {results['summary']['files_scanned']}</p>
                <p><strong>Total Findings:</strong> {results['summary']['findings']}</p>
            </div>
            <div class="summary-card">
                <h3>🚨 Severity Breakdown</h3>
                {"".join(f"<p><strong>{k.title()}:</strong> {v}</p>" for k, v in results['summary'].get('severity_breakdown', {}).items())}
            </div>
        </div>

        <div class="findings">
            <h2>🔎 Detailed Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Description</th>
                        <th>Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''
                        <tr class="severity-{f.get('severity', 'unknown').lower()}">
                            <td>{f.get('id', 'N/A')}</td>
                            <td>{f.get('type', 'unknown').replace('_', ' ').title()}</td>
                            <td>{f.get('severity', 'unknown').upper()}</td>
                            <td>{f.get('file', 'N/A').split('/')[-1]}</td>
                            <td>{f.get('line', 'N/A')}</td>
                            <td class="description">{f.get('description', 'No description available')}</td>
                            <td>{'; '.join(f.get('evidence', []))[:100]}{'...' if len('; '.join(f.get('evidence', []))) > 100 else ''}</td>
                        </tr>
                    ''' for f in results['findings'])}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    with open(path, "w", encoding='utf-8') as f:
        f.write(html_content)


def write_graphviz(results: Dict[str, Any], path: Path) -> None:
    """Write results as Graphviz DOT file for data flow visualization."""
    dot_content = generate_graphviz_dot(results)
    with open(path, "w") as f:
        f.write(dot_content)


def generate_graphviz_dot(results: Dict[str, Any]) -> str:
    """Generate Graphviz DOT content from scan results."""
    lines = ["digraph DBMapper {", "    rankdir=LR;", "    node [shape=box, style=filled];"]

    # Color scheme
    colors = {
        "connection": "lightblue",
        "orm_model": "lightgreen",
        "raw_sql": "orange",
        "migration": "yellow",
        "schema_change": "lightcoral",
        "secret": "red"
    }

    # Group findings by file for clustering
    file_groups = {}
    relationships = []

    for finding in results["findings"]:
        file_path = finding["file"]
        if file_path not in file_groups:
            file_groups[file_path] = []
        file_groups[file_path].append(finding)

    # Create subgraphs for each file
    for file_path, findings in file_groups.items():
        file_name = Path(file_path).name
        lines.append(f'    subgraph cluster_{hash(file_path) % 10000} {{')
        lines.append(f'        label="{file_name}";')
        lines.append(f'        color=gray;')

        for finding in findings:
            finding_id = finding["id"]
            finding_type = finding["type"]
            color = colors.get(finding_type, "white")

            # Create node label
            if finding_type == "connection":
                label = f"{finding['provider']}\\nconnection"
            elif finding_type == "orm_model":
                label = f"{finding.get('framework', 'ORM')}\\n{finding.get('evidence', [''])[0][:30]}"
            elif finding_type == "raw_sql":
                label = f"SQL\\n{finding.get('sql_type', 'SQL')}"
            elif finding_type == "migration":
                label = f"Migration\\n{finding.get('framework', '')}"
            elif finding_type == "secret":
                label = f"Secret\\n{finding.get('secret_type', '')}"
            else:
                label = finding_type

            lines.append(f'        "{finding_id}" [label="{label}", fillcolor={color}];')

        lines.append("    }")

    # Add relationships between findings
    relationships = infer_relationships(results["findings"])
    for rel in relationships:
        from_id, to_id, label = rel
        lines.append(f'    "{from_id}" -> "{to_id}" [label="{label}"];')

    lines.append("}")
    return "\n".join(lines)


def infer_relationships(findings: List[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    """Infer relationships between findings for the graph."""
    relationships = []

    # Group by file to find connections within the same file
    file_findings = {}
    for finding in findings:
        file_path = finding["file"]
        if file_path not in file_findings:
            file_findings[file_path] = []
        file_findings[file_path].append(finding)

    for file_path, file_findings_list in file_findings.items():
        # Connect models to SQL queries in the same file
        models = [f for f in file_findings_list if f["type"] == "orm_model"]
        sql_queries = [f for f in file_findings_list if f["type"] == "raw_sql"]

        for model in models:
            for sql in sql_queries:
                # Check if SQL might reference the model
                model_name = model.get("evidence", [""])[0].split()[1] if model.get("evidence") else ""
                sql_content = sql.get("evidence", [""])[0] if sql.get("evidence") else ""
                if model_name.lower() in sql_content.lower():
                    relationships.append((model["id"], sql["id"], "queries"))

        # Connect connections to models
        connections = [f for f in file_findings_list if f["type"] == "connection"]
        for conn in connections:
            for model in models:
                relationships.append((conn["id"], model["id"], "uses"))

    return relationships


def write_csv(results: Dict[str, Any], path: Path) -> None:
    """Write results as CSV file for easy import and analysis."""
    with open(path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'id', 'type', 'file', 'line', 'confidence',
            'provider', 'framework', 'sql_type', 'secret_type',
            'migration_type', 'change_type', 'severity',
            'evidence', 'table_name', 'natural_language_description'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for finding in results["findings"]:
            # Flatten the finding dictionary
            row = {
                'id': finding.get('id', ''),
                'type': finding.get('type', ''),
                'file': finding.get('file', ''),
                'line': finding.get('line', ''),
                'confidence': finding.get('confidence', ''),
                'evidence': '; '.join(finding.get('evidence', [])),
                'severity': finding.get('severity', ''),
                'natural_language_description': finding.get('description', 'No description available'),
            }

            # Add type-specific fields
            if finding['type'] == 'connection':
                row['provider'] = finding.get('provider', '')
            elif finding['type'] == 'orm_model':
                row['framework'] = finding.get('framework', '')
            elif finding['type'] == 'raw_sql':
                row['sql_type'] = finding.get('sql_type', '')
            elif finding['type'] == 'secret':
                row['secret_type'] = finding.get('secret_type', '')
            elif finding['type'] == 'migration':
                row['framework'] = finding.get('framework', '')
                row['migration_type'] = finding.get('migration_type', '')
            elif finding['type'] == 'schema_change':
                row['change_type'] = finding.get('change_type', '')
                row['table_name'] = finding.get('table_name', '')
                row['description'] = finding.get('description', '')

            # Only include fields that are in fieldnames
            filtered_row = {k: v for k, v in row.items() if k in fieldnames}
            writer.writerow(filtered_row)
