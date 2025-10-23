#!/usr/bin/env python3
"""Core orchestrator for the DB Mapper scanning process."""

from pathlib import Path
from typing import List, Dict, Any
import json
import concurrent.futures
import threading
import time

from .scanner import discover_files, DEFAULT_EXCLUDE_PATTERNS
from .detectors import run_detectors
from .cross_references import analyze_cross_references
from .risk_scorer import calculate_risk_scores
from .output import write_outputs


def run_scan(args) -> None:
    """Run the full scanning process.

    Args:
        args: Parsed command-line arguments
    """
    total_start_time = time.time()

    repo_path = args.path
    output_path = args.output
    formats = args.formats
    min_confidence = args.min_confidence
    include_patterns = args.include or ["**/*"]
    exclude_patterns = DEFAULT_EXCLUDE_PATTERNS + (args.exclude or [])
    languages = args.languages
    threads = args.threads

    print(f"Starting scan of {repo_path}")

    # 1. Discover files
    phase_start = time.time()
    files = discover_files(repo_path, include_patterns, exclude_patterns, languages)
    discovery_time = time.time() - phase_start
    print(f"Discovered {len(files)} files to scan ({discovery_time:.2f}s)")

    # 2. Run detectors
    phase_start = time.time()
    findings = run_detectors(files, threads)
    detector_time = time.time() - phase_start
    print(f"Found {len(findings)} raw findings ({detector_time:.2f}s)")

    # 3. Analyze cross-references
    phase_start = time.time()
    findings_with_refs = analyze_cross_references(findings)
    cross_ref_time = time.time() - phase_start
    print(f"Enhanced with cross-reference analysis ({cross_ref_time:.2f}s)")

    # 4. Calculate risk scores
    phase_start = time.time()
    context = {
        "environment": "development",  # Could be made configurable
        "is_public_repo": False  # Could be detected
    }
    findings_with_risks = calculate_risk_scores(findings_with_refs, context)
    risk_score_time = time.time() - phase_start
    print(f"Calculated risk scores for {len(findings_with_risks)} findings ({risk_score_time:.2f}s)")

    # 5. Filter by confidence
    phase_start = time.time()
    filtered_findings = [f for f in findings_with_risks if f.get("confidence", 0) >= min_confidence]
    filter_time = time.time() - phase_start
    print(f"Filtered to {len(filtered_findings)} findings above confidence {min_confidence} ({filter_time:.2f}s)")

    # 6. Prepare summary with severity counts
    severity_counts = {}
    for finding in filtered_findings:
        severity = finding.get("severity", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    summary = {
        "files_scanned": len(files),
        "findings": len(filtered_findings),
        "severity_breakdown": severity_counts,
    }

    results = {
        "summary": summary,
        "findings": filtered_findings,
    }

    # 7. Write outputs
    phase_start = time.time()
    write_outputs(results, output_path, formats)
    output_time = time.time() - phase_start

    total_time = time.time() - total_start_time

    print("\\nPerformance Summary:")
    print(f"  File Discovery:   {discovery_time:.2f}s ({len(files)} files)")
    print(f"  Detectors:        {detector_time:.2f}s ({len(findings)} findings, {threads} threads)")
    print(f"  Cross-References: {cross_ref_time:.2f}s")
    print(f"  Risk Scoring:     {risk_score_time:.2f}s")
    print(f"  Filtering:        {filter_time:.2f}s")
    print(f"  Output:           {output_time:.2f}s")
    print(f"  Total Time:       {total_time:.2f}s")

    print(f"\\nScan complete. Results written to {output_path}")

