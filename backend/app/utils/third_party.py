"""
Third-party APIs integrations for VK Scanner.
Queries VirusTotal, URLScan, and AbuseIPDB 100% optionally on demand.
"""

from __future__ import annotations

import httpx
from typing import Optional, Dict, Any

async def scan_virustotal_hash(file_hash: str, api_key: Optional[str]) -> Optional[Dict[str, Any]]:
    """Query VirusTotal for a file hash (MD5, SHA-256)."""
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                
                return {
                    "provider": "VirusTotal",
                    "found": True,
                    "malicious_count": positives,
                    "total_scanners": total,
                    "score": f"{positives}/{total}",
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                    "threat_label": attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
                }
            elif response.status_code == 404:
                return {
                    "provider": "VirusTotal",
                    "found": False,
                    "message": "Hash not found in VT database (clean/unknown)"
                }
    except Exception as e:
        return {"provider": "VirusTotal", "error": str(e)}
    return None


async def scan_urlscan(target_url: str, api_key: Optional[str]) -> Optional[Dict[str, Any]]:
    """Submit URL to urlscan.io for scanning and return details."""
    if not api_key:
        return None
    submit_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "url": target_url,
        "visibility": "public" # Alert the user that this publishes the URL!
    }
    
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.post(submit_url, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return {
                    "provider": "urlscan.io",
                    "success": True,
                    "message": data.get("message", "Scan submitted"),
                    "uuid": data.get("uuid"),
                    "result_url": data.get("result"),
                    "screenshot_url": f"https://urlscan.io/screenshots/{data.get('uuid')}.png"
                }
            else:
                return {
                    "provider": "urlscan.io",
                    "success": False,
                    "error": response.text
                }
    except Exception as e:
        return {"provider": "urlscan.io", "error": str(e)}


async def scan_abuseipdb(ip_address: str, api_key: Optional[str]) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB for an IP address threat score."""
    if not api_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90",
        "verbose": ""
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports_count = data.get("totalReports", 0)
                
                return {
                    "provider": "AbuseIPDB",
                    "ip": ip_address,
                    "score": score,
                    "total_reports": reports_count,
                    "country": data.get("countryCode"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "is_malicious": score > 20
                }
    except Exception as e:
        return {"provider": "AbuseIPDB", "error": str(e)}
    return None
