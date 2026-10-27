"""
Persistence layer for the AI Security Simulator using SQLite.
Stores sanitized test metadata, findings, execution logs, and reports.
"""

import sqlite3
import json
import csv
import io
import os
import time
from typing import Dict, Any, List, Optional

DB_PATH = "cygeniq_security.db"

def init_db():
    """Initializes the security testing SQLite database schema."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table for storing test execution summaries
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS test_runs (
        test_id TEXT PRIMARY KEY,
        timestamp REAL,
        created_at TEXT,
        prompt TEXT,
        execution_mode TEXT,
        overall_status TEXT,
        duration_ms REAL,
        total_checks INTEGER,
        passed_checks INTEGER,
        failed_checks INTEGER,
        inconclusive_checks INTEGER,
        tools_called INTEGER,
        tools_blocked INTEGER,
        findings_count INTEGER,
        report_json TEXT
    )
    """)
    
    # Table for individual findings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_findings (
        finding_id TEXT PRIMARY KEY,
        test_id TEXT,
        check_id TEXT,
        category TEXT,
        severity TEXT,
        title TEXT,
        description TEXT,
        evidence TEXT,
        remediation TEXT,
        timestamp REAL,
        FOREIGN KEY(test_id) REFERENCES test_runs(test_id)
    )
    """)
    
    conn.commit()
    conn.close()

def save_test_run(report: Dict[str, Any]):
    """Persists a completed test run and its associated findings."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    test_id = report.get("test_id")
    timestamp = report.get("timestamp", time.time())
    created_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    prompt = report.get("prompt", "")
    execution_mode = report.get("execution_mode", "safe_simulation")
    overall_status = report.get("overall_status", "INCONCLUSIVE")
    duration_ms = report.get("duration_ms", 0.0)
    
    metrics = report.get("metrics", {})
    total_checks = metrics.get("total_checks", 0)
    passed_checks = metrics.get("passed_checks", 0)
    failed_checks = metrics.get("failed_checks", 0)
    inconclusive_checks = metrics.get("inconclusive_checks", 0)
    tools_called = metrics.get("tools_called", 0)
    tools_blocked = metrics.get("tools_blocked", 0)
    findings = report.get("findings", [])
    findings_count = len(findings)
    
    report_json = json.dumps(report)
    
    cursor.execute("""
    INSERT OR REPLACE INTO test_runs (
        test_id, timestamp, created_at, prompt, execution_mode, overall_status,
        duration_ms, total_checks, passed_checks, failed_checks, inconclusive_checks,
        tools_called, tools_blocked, findings_count, report_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        test_id, timestamp, created_at, prompt, execution_mode, overall_status,
        duration_ms, total_checks, passed_checks, failed_checks, inconclusive_checks,
        tools_called, tools_blocked, findings_count, report_json
    ))
    
    # Insert findings
    for finding in findings:
        cursor.execute("""
        INSERT OR REPLACE INTO security_findings (
            finding_id, test_id, check_id, category, severity,
            title, description, evidence, remediation, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.get("finding_id"),
            test_id,
            finding.get("check_id"),
            finding.get("category"),
            finding.get("severity"),
            finding.get("title"),
            finding.get("description"),
            finding.get("evidence"),
            finding.get("remediation"),
            finding.get("timestamp", timestamp)
        ))
    
    conn.commit()
    conn.close()

def get_test_run(test_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full report JSON for a given test ID."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT report_json FROM test_runs WHERE test_id = ?", (test_id,))
    row = cursor.fetchone()
    conn.close()
    if row and row[0]:
        return json.loads(row[0])
    return None

def list_test_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves list of past tests ordered by most recent."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
    SELECT test_id, timestamp, created_at, prompt, execution_mode, overall_status,
           duration_ms, total_checks, passed_checks, failed_checks, inconclusive_checks,
           tools_called, tools_blocked, findings_count
    FROM test_runs
    ORDER BY timestamp DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def clear_test_history():
    """Clears all stored test runs and findings."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM security_findings")
    cursor.execute("DELETE FROM test_runs")
    conn.commit()
    conn.close()

def export_report_csv(test_id: str) -> Optional[str]:
    """Generates a CSV string of the test checks and findings."""
    report = get_test_run(test_id)
    if not report:
        return None
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header summary
    writer.writerow(["Test ID", report.get("test_id")])
    writer.writerow(["Prompt", report.get("prompt")])
    writer.writerow(["Execution Mode", report.get("execution_mode")])
    writer.writerow(["Overall Status", report.get("overall_status")])
    writer.writerow(["Duration (ms)", report.get("duration_ms")])
    writer.writerow([])
    
    # Checks Section
    writer.writerow(["=== Security Checks Executed ==="])
    writer.writerow(["Check ID", "Name", "Category", "Status", "Severity", "Expected Behavior", "Actual Behavior", "Evidence"])
    for chk in report.get("checks", []):
        writer.writerow([
            chk.get("check_id"),
            chk.get("name"),
            chk.get("category"),
            chk.get("status"),
            chk.get("severity"),
            chk.get("expected_behavior"),
            chk.get("actual_behavior"),
            chk.get("evidence")
        ])
    writer.writerow([])
    
    # Findings Section
    writer.writerow(["=== Security Findings Detected ==="])
    writer.writerow(["Finding ID", "Check ID", "Severity", "Title", "Evidence", "Remediation"])
    for f in report.get("findings", []):
        writer.writerow([
            f.get("finding_id"),
            f.get("check_id"),
            f.get("severity"),
            f.get("title"),
            f.get("evidence"),
            f.get("remediation")
        ])
        
    return output.getvalue()
