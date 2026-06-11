"""
SQLite database manager for VK Scanner.
Stores local scan history and results. 100% offline.
Supports database migrations for forensic file previews and checklists.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scans.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the scans database and creates the scans table if it does not exist."""
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_score REAL NOT NULL,
                classification TEXT NOT NULL,
                confidence REAL NOT NULL,
                summary TEXT NOT NULL,
                findings TEXT NOT NULL, -- JSON String
                analyzer_breakdown TEXT NOT NULL, -- JSON String
                debug_trace TEXT NOT NULL, -- JSON String
                document_screenshot TEXT, -- Base64 PNG
                document_password_found TEXT,
                document_password_attempts INTEGER,
                document_file_previews TEXT, -- JSON String
                document_file_checks TEXT, -- JSON String
                document_file_metadata TEXT, -- JSON String
                document_file_contexts TEXT, -- JSON String
                document_file_deobfuscated TEXT, -- JSON String
                document_file_entropy TEXT, -- JSON String
                iocs TEXT -- JSON String
            )
        """)
        
        # Safe schema migrations for existing databases
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN document_file_previews TEXT")
        except Exception:
            pass # Column already exists
            
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN document_file_checks TEXT")
        except Exception:
            pass # Column already exists

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN document_file_metadata TEXT")
        except Exception:
            pass # Column already exists

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN document_file_contexts TEXT")
        except Exception:
            pass # Column already exists

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN document_file_deobfuscated TEXT")
        except Exception:
            pass # Column already exists

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN email_extracted_headers TEXT")
        except Exception:
            pass
            
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN email_extracted_ips TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN email_extracted_urls TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN email_attachment_tree TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN third_party_results TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN url_redirect_chain TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN url_resolved_ip TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN url_domain_created TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN url_technologies TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN url_extracted_scripts TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN url_site_preview TEXT")
        except Exception:
            pass
            
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN document_file_entropy TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE scans ADD COLUMN iocs TEXT")
        except Exception:
            pass
            
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN cache_key TEXT")
        except Exception:
            pass

        conn.commit()
    finally:
        conn.close()


def save_scan(result: Dict[str, Any]) -> None:
    """Saves a ScanResult to the local SQLite history database."""
    init_db()  # Ensure table exists
    conn = get_db_connection()
    try:
        # Convert Pydantic/dict complex objects to JSON strings
        findings = result.get("findings", [])
        if not isinstance(findings, str):
            findings_data = [f.model_dump() if hasattr(f, "model_dump") else f for f in findings]
            findings_json = json.dumps(findings_data)
        else:
            findings_json = findings

        breakdown = result.get("analyzer_breakdown", [])
        if not isinstance(breakdown, str):
            breakdown_data = [b.model_dump() if hasattr(b, "model_dump") else b for b in breakdown]
            breakdown_json = json.dumps(breakdown_data)
        else:
            breakdown_json = breakdown

        trace = result.get("debug_trace", [])
        if not isinstance(trace, str):
            trace_data = [t.model_dump() if hasattr(t, "model_dump") else t for t in trace]
            trace_json = json.dumps(trace_data)
        else:
            trace_json = trace

        # Serialize previews and checks
        previews = result.get("document_file_previews", {})
        previews_json = json.dumps(previews)

        checks = result.get("document_file_checks", {})
        checks_json = json.dumps(checks)

        metadata = result.get("document_file_metadata", {})
        metadata_json = json.dumps(metadata)

        contexts = result.get("document_file_contexts", {})
        contexts_json = json.dumps(contexts)

        deobf = result.get("document_file_deobfuscated", {})
        deobf_json = json.dumps(deobf)

        email_headers_data = result.get("email_extracted_headers", {})
        email_headers_json = json.dumps(email_headers_data)

        email_ips_data = result.get("email_extracted_ips", [])
        email_ips_json = json.dumps(email_ips_data)

        email_urls_data = result.get("email_extracted_urls", [])
        email_urls_json = json.dumps(email_urls_data)

        email_tree_data = result.get("email_attachment_tree", [])
        email_tree_json = json.dumps(email_tree_data)

        tp_data = result.get("third_party_results", {})
        tp_json = json.dumps(tp_data)

        # Handle UTC isoformat timestamp
        ts = result.get("timestamp")
        if not ts:
            ts = datetime.utcnow().isoformat()

        conn.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, scan_type, timestamp, target, risk_score, classification,
                confidence, summary, findings, analyzer_breakdown, debug_trace,
                document_screenshot, document_password_found, document_password_attempts,
                document_file_previews, document_file_checks,
                document_file_metadata, document_file_contexts, document_file_deobfuscated,
                email_extracted_headers, email_extracted_ips, email_extracted_urls, email_attachment_tree,
                third_party_results,
                url_redirect_chain, url_resolved_ip, url_domain_created, url_technologies, url_extracted_scripts, url_site_preview,
                document_file_entropy, iocs, cache_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("scan_id"),
            result.get("scan_type").value if hasattr(result.get("scan_type"), "value") else result.get("scan_type"),
            ts,
            result.get("target"),
            float(result.get("risk_score", 0.0)),
            result.get("classification").value if hasattr(result.get("classification"), "value") else result.get("classification"),
            float(result.get("confidence", 100.0)),
            result.get("summary", ""),
            findings_json,
            breakdown_json,
            trace_json,
            result.get("document_screenshot"),
            result.get("document_password_found"),
            result.get("document_password_attempts"),
            previews_json,
            checks_json,
            metadata_json,
            contexts_json,
            deobf_json,
            email_headers_json,
            email_ips_json,
            email_urls_json,
            email_tree_json,
            tp_json,
            json.dumps(result.get("url_redirect_chain", [])),
            result.get("url_resolved_ip"),
            result.get("url_domain_created"),
            json.dumps(result.get("url_technologies", [])),
            json.dumps(result.get("url_extracted_scripts", [])),
            json.dumps(result.get("url_site_preview", {})),
            json.dumps(result.get("document_file_entropy", {})),
            json.dumps(result.get("iocs", {})),
            result.get("cache_key")
        ))
        conn.commit()

    except Exception as e:
        print(f"Error saving scan to SQLite: {e}")
    finally:
        conn.close()

def get_history() -> List[Dict[str, Any]]:
    """Returns the list of past scans in chronological order (excluding heavy screenshots/traces)."""
    init_db()
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT scan_id, scan_type, timestamp, target, risk_score, classification, confidence, summary
            FROM scans
            ORDER BY timestamp DESC
        """).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def search_history(query: str) -> List[Dict[str, Any]]:
    """Searches past scans for a specific IoC, domain, or keyword."""
    init_db()
    conn = get_db_connection()
    try:
        q = f"%{query}%"
        rows = conn.execute("""
            SELECT scan_id, scan_type, timestamp, target, risk_score, classification, confidence, summary
            FROM scans
            WHERE target LIKE ? OR iocs LIKE ? OR summary LIKE ? OR email_extracted_ips LIKE ? OR email_extracted_urls LIKE ? OR url_resolved_ip LIKE ?
            ORDER BY timestamp DESC
            LIMIT 50
        """, (q, q, q, q, q, q)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Returns the complete details of a single scan by ID."""
    init_db()
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        
        data = dict(row)
        # Parse JSON strings back to lists/dicts
        data["findings"] = json.loads(data["findings"])
        data["analyzer_breakdown"] = json.loads(data["analyzer_breakdown"])
        data["debug_trace"] = json.loads(data["debug_trace"])
        data["document_file_previews"] = json.loads(data.get("document_file_previews") or "{}")
        data["document_file_checks"] = json.loads(data.get("document_file_checks") or "{}")
        data["document_file_metadata"] = json.loads(data.get("document_file_metadata") or "{}")
        data["document_file_contexts"] = json.loads(data.get("document_file_contexts") or "{}")
        data["document_file_deobfuscated"] = json.loads(data.get("document_file_deobfuscated") or "{}")
        data["email_extracted_headers"] = json.loads(data.get("email_extracted_headers") or "{}")
        data["email_extracted_ips"] = json.loads(data.get("email_extracted_ips") or "[]")
        data["email_extracted_urls"] = json.loads(data.get("email_extracted_urls") or "[]")
        data["email_attachment_tree"] = json.loads(data.get("email_attachment_tree") or "[]")
        data["third_party_results"] = json.loads(data.get("third_party_results") or "{}")
        data["url_redirect_chain"] = json.loads(data.get("url_redirect_chain") or "[]")
        data["url_resolved_ip"] = data.get("url_resolved_ip")
        data["url_domain_created"] = data.get("url_domain_created")
        data["url_technologies"] = json.loads(data.get("url_technologies") or "[]")
        data["url_extracted_scripts"] = json.loads(data.get("url_extracted_scripts") or "[]")
        data["url_site_preview"] = json.loads(data.get("url_site_preview") or "{}")
        data["document_file_entropy"] = json.loads(data.get("document_file_entropy") or "{}")
        data["iocs"] = json.loads(data.get("iocs") or "{}")
        return data

    finally:
        conn.close()

def get_cached_scan(cache_key: str) -> Optional[Dict[str, Any]]:
    """Returns the complete details of a single scan by cache_key."""
    if not cache_key:
        return None
    init_db()
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE cache_key = ?", (cache_key,)).fetchone()
        if not row:
            return None
        
        data = dict(row)
        # Parse JSON strings back to lists/dicts
        data["findings"] = json.loads(data["findings"])
        data["analyzer_breakdown"] = json.loads(data["analyzer_breakdown"])
        data["debug_trace"] = json.loads(data["debug_trace"])
        data["document_file_previews"] = json.loads(data.get("document_file_previews") or "{}")
        data["document_file_checks"] = json.loads(data.get("document_file_checks") or "{}")
        data["document_file_metadata"] = json.loads(data.get("document_file_metadata") or "{}")
        data["document_file_contexts"] = json.loads(data.get("document_file_contexts") or "{}")
        data["document_file_deobfuscated"] = json.loads(data.get("document_file_deobfuscated") or "{}")
        data["email_extracted_headers"] = json.loads(data.get("email_extracted_headers") or "{}")
        data["email_extracted_ips"] = json.loads(data.get("email_extracted_ips") or "[]")
        data["email_extracted_urls"] = json.loads(data.get("email_extracted_urls") or "[]")
        data["email_attachment_tree"] = json.loads(data.get("email_attachment_tree") or "[]")
        data["third_party_results"] = json.loads(data.get("third_party_results") or "{}")
        data["url_redirect_chain"] = json.loads(data.get("url_redirect_chain") or "[]")
        data["url_resolved_ip"] = data.get("url_resolved_ip")
        data["url_domain_created"] = data.get("url_domain_created")
        data["url_technologies"] = json.loads(data.get("url_technologies") or "[]")
        data["url_extracted_scripts"] = json.loads(data.get("url_extracted_scripts") or "[]")
        data["url_site_preview"] = json.loads(data.get("url_site_preview") or "{}")
        data["document_file_entropy"] = json.loads(data.get("document_file_entropy") or "{}")
        data["iocs"] = json.loads(data.get("iocs") or "{}")
        return data

    finally:
        conn.close()

def delete_scan(scan_id: str) -> bool:
    """Deletes a single scan by ID."""
    init_db()
    conn = get_db_connection()
    try:
        cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def clear_history() -> None:
    """Deletes all records from scans history."""
    init_db()
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM scans")
        conn.commit()
    finally:
        conn.close()
