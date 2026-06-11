"""
Document analyzer for VK Scanner.
Analyzes PDF, Office, ZIP, SQL, Python, HTML, and Text files for phishing and malware indicators.
Integrates oletools (olevba, rtfobj) and pikepdf streams scanning (pdf-parser/peepdf simulation).
"""

from __future__ import annotations

import io
import re
import zipfile
import os
from pathlib import Path
from typing import Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from app.models import Finding, FindingSeverity
from app.utils.bruteforce import brute_force_password
from app.utils.debug_trace import DebugTracer

YARA_RULES_SRC = r"""
rule vk_maldoc_persistence {
    meta:
        category = "Autostart / Persistence"
        severity = "high"
        score_impact = 20
    strings:
        $autoopen = "AutoOpen" nocase
        $autoexec = "AutoExec" nocase
        $docopen = "Document_Open" nocase
        $workopen = "Workbook_Open" nocase
        $auto_open = "Auto_Open" nocase
        $docclose = "Document_Close" nocase
        $workclose = "Workbook_Close" nocase
        $autoclose = "AutoClose" nocase
    condition:
        any of them
}

rule vk_maldoc_execution {
    meta:
        category = "Command Execution"
        severity = "critical"
        score_impact = 35
    strings:
        $shell = /Shell[ \t]*\(/ nocase
        $wscript = "WScript.Shell" nocase
        $shell_app = "Shell.Application" nocase
        $powershell = "Powershell" nocase
        $cmd = "cmd.exe" nocase
        $rundll = "rundll32" nocase
        $regsvr = "regsvr32" nocase
        $mshta = "mshta" nocase
        $bitsadmin = "bitsadmin" nocase
        $certutil = "certutil" nocase
    condition:
        any of them
}

rule vk_maldoc_network {
    meta:
        category = "Network Downloader"
        severity = "critical"
        score_impact = 30
    strings:
        $url_down = "URLDownloadToFile" nocase
        $xmlhttp = "XMLHTTP" nocase
        $winhttp = "WinHttpRequest" nocase
        $net_open = "InternetOpen" nocase
        $net_url = "InternetOpenUrl" nocase
    condition:
        any of them
}

rule vk_maldoc_system {
    meta:
        category = "System Object Manipulation"
        severity = "medium"
        score_impact = 15
    strings:
        $adodb = "ADODB.Stream" nocase
        $environ = "environ" nocase
        $create = "CreateObject" nocase
        $get = "GetObject" nocase
        $callby = "CallByName" nocase
    condition:
        any of them
}

rule vk_maldoc_memory {
    meta:
        category = "Memory/Process Injection API"
        severity = "critical"
        score_impact = 40
    strings:
        $valloc = "VirtualAlloc" nocase
        $vprotect = "VirtualProtect" nocase
        $rtlmove = "RtlMoveMemory" nocase
        $copy = "CopyMemory" nocase
        $cthread = "CreateThread" nocase
        $wprocess = "WriteProcessMemory" nocase
    condition:
        any of them
}

rule vk_maldoc_obfuscation {
    meta:
        category = "Code Obfuscation"
        severity = "high"
        score_impact = 25
    strings:
        $reverse = "StrReverse" nocase
        $c_func = "Chr(" nocase
        $cw_func = "ChrW(" nocase
    condition:
        $reverse or #c_func >= 5 or #cw_func >= 5
}

rule vk_maldoc_embedded_pe {
    meta:
        category = "Embedded Executable (PE File)"
        severity = "critical"
        score_impact = 45
    strings:
        $dos_mode = "This program cannot be run in DOS mode" nocase
        $mz_hex = "4d5a900003000000" nocase
    condition:
        any of them
}

rule vk_offensive_impacket {
    meta:
        category = "Offensive Tool / Impacket"
        severity = "critical"
        score_impact = 45
    strings:
        $imp_dce = "impacket.dcerpc" nocase
        $imp_smb = "impacket.smb" nocase
        $imp_ntlm = "impacket.ntlm" nocase
        $imp_ldap = "impacket.ldap" nocase
        $imp_secrets = "secretsdump" nocase
        $imp_wmi = "wmiexec" nocase
        $imp_psexec = "psexec" nocase
    condition:
        any of them
}

rule vk_offensive_powershell {
    meta:
        category = "Offensive PowerShell Script"
        severity = "critical"
        score_impact = 40
    strings:
        $iex = "IEX" nocase
        $iex_full = "Invoke-Expression" nocase
        $bypass = "bypass" nocase
        $exec_pol = "ExecutionPolicy" nocase
        $webclient = "Net.WebClient" nocase
        $down_str = "DownloadString" nocase
        $down_file = "DownloadFile" nocase
        $tcp_client = "System.Net.Sockets.TCPClient" nocase
        $enc_cmd = "EncodedCommand" nocase
        $hidden = "-w hidden" nocase
        $nop = "-nop" nocase
    condition:
        (any of ($iex, $iex_full) and any of ($webclient, $down_str, $down_file)) or
        (any of ($tcp_client, $enc_cmd)) or
        (any of ($hidden, $nop) and any of ($bypass, $exec_pol))
}

rule vk_offensive_reverse_shell {
    meta:
        category = "Reverse Shell / Backdoor"
        severity = "critical"
        score_impact = 45
    strings:
        $rev_bash1 = "bash -i >& /dev/tcp/" nocase
        $rev_bash2 = "bash -i >& /dev/udp/" nocase
        $rev_sh = "sh -i" nocase
        $sock_conn = /socket\.connect\(\(\s*['\"][0-9\.]+['\"],\s*[0-9]+\s*\)\)/ nocase
        $py_sock = "import socket" nocase
        $py_sub = "subprocess.Popen" nocase
        $py_dup = "os.dup2" nocase
    condition:
        any of ($rev_bash1, $rev_bash2, $rev_sh, $sock_conn) or
        (all of ($py_sock, $py_sub, $py_dup))
}

rule vk_offensive_shell_script {
    meta:
        category = "Offensive Shell Script"
        severity = "high"
        score_impact = 35
    strings:
        $sh_bin = "#!/bin/sh"
        $bash_bin = "#!/bin/bash"
        $dev_tcp = "/dev/tcp/"
        $dev_udp = "/dev/udp/"
        $mkfifo = "mkfifo"
        $backpipe = "backpipe"
    condition:
        (any of ($sh_bin, $bash_bin) and any of ($dev_tcp, $dev_udp, $mkfifo, $backpipe))
}
"""

yara_rules = None

def compile_yara_rules():
    global yara_rules
    if not YARA_AVAILABLE:
        yara_rules = None
        return
    try:
        import os
        rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")
        os.makedirs(rules_dir, exist_ok=True)
        
        # Write builtin rules to file if it doesn't exist so the user can see them
        builtin_path = os.path.join(rules_dir, "builtin_vkscanner_rules.yara")
        if not os.path.exists(builtin_path):
            with open(builtin_path, "w", encoding="utf-8") as f:
                f.write(YARA_RULES_SRC)
        
        sources = {}
        
        # Scan for any custom YARA rules in rules folder recursively
        for root, _, files in os.walk(rules_dir):
            for filename in files:
                if filename.endswith((".yar", ".yara")):
                    path = os.path.join(root, filename)
                    # use relative path as key or full path so keys are unique
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            sources[path] = f.read()
                    except Exception:
                        pass
        externals = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
        yara_rules = yara.compile(sources=sources, externals=externals)
    except Exception as e:
        # Fallback to built-in rules string
        try:
            externals = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
            yara_rules = yara.compile(source=YARA_RULES_SRC, externals=externals)
        except Exception:
            yara_rules = None

if YARA_AVAILABLE:
    compile_yara_rules()


# List of supported file extensions
SUPPORTED_EXTENSIONS = {
    ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".rtf", 
    ".zip", ".sql", ".py", ".html", ".htm", ".txt", ".xlsm", ".xlm",
    ".sh", ".ps1", ".ps", ".bat", ".cmd", ".dll", ".exe", ".elf", ".macho",
    ".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".gif"
}


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll", ".hta",
    ".cpl", ".reg", ".inf", ".lnk", ".elf", ".macho"
}

# Maldoc signature groups
MALDOC_PERSISTENCE = [
    (r"AutoOpen", "AutoOpen autostart trigger"),
    (r"AutoExec", "AutoExec autostart trigger"),
    (r"Document_Open", "Document_Open autostart trigger"),
    (r"Workbook_Open", "Workbook_Open autostart trigger"),
    (r"Auto_Open", "Auto_Open autostart trigger"),
    (r"Document_Close", "Document_Close exit trigger"),
    (r"Workbook_Close", "Workbook_Close exit trigger"),
    (r"AutoClose", "AutoClose exit trigger"),
]

MALDOC_EXECUTION = [
    (r"Shell\s*\(", "VBA Shell function execution"),
    (r"WScript\.Shell", "WScript.Shell COM object creation"),
    (r"Shell\.Application", "Shell.Application COM object creation"),
    (r"Powershell", "Powershell execution"),
    (r"cmd\.exe", "Command prompt spawning"),
    (r"rundll32", "Rundll32 DLL execution"),
    (r"regsvr32", "Regsvr32 DLL registration"),
    (r"mshta", "Mshta HTA execution"),
    (r"bitsadmin", "Bitsadmin file transfer tool usage"),
    (r"certutil", "Certutil tool usage (often used for decoding payloads)"),
]

MALDOC_NETWORK = [
    (r"URLDownloadToFile", "URLDownloadToFile WinAPI call (direct download)"),
    (r"XMLHTTP", "XMLHTTP object (network requests)"),
    (r"WinHttpRequest", "WinHttpRequest object (network requests)"),
    (r"InternetOpen", "InternetOpen network API call"),
    (r"InternetOpenUrl", "InternetOpenUrl network API call"),
]

MALDOC_SYSTEM = [
    (r"ADODB\.Stream", "ADODB.Stream object (writing files to disk)"),
    (r"environ", "Environ function (accessing system environment paths)"),
    (r"CreateObject", "CreateObject call (dynamic object instantiation)"),
    (r"GetObject", "GetObject call (dynamic COM retrieval)"),
    (r"CallByName", "CallByName dynamic API resolution"),
]

MALDOC_MEMORY = [
    (r"VirtualAlloc", "VirtualAlloc WinAPI (allocating execution memory)"),
    (r"VirtualProtect", "VirtualProtect WinAPI (modifying memory protections)"),
    (r"RtlMoveMemory", "RtlMoveMemory/CopyMemory WinAPI (writing payload to memory)"),
    (r"CreateThread", "CreateThread WinAPI (starting shellcode execution)"),
    (r"WriteProcessMemory", "WriteProcessMemory WinAPI (process injection)"),
]

MALDOC_OBFUSCATION = [
    (r"StrReverse", "String reversal obfuscation (StrReverse)"),
    (r"(?:Chr[W]?\s*\(\s*\d+\s*\)\s*&\s*){5,}", "Extensive string concatenation via Chr/ChrW codes"),
]

SQL_INJECTION_PATTERNS = [
    r";\s*DROP\s+TABLE", r";\s*DELETE\s+FROM", r"UNION\s+SELECT",
    r"EXEC\s*\(", r"xp_cmdshell", r"LOAD_FILE\s*\(",
    r"INTO\s+OUTFILE", r"INTO\s+DUMPFILE", r"BENCHMARK\s*\(",
    r"SLEEP\s*\(", r"WAITFOR\s+DELAY",
]


def detect_extension_by_magic(file_bytes: bytes, filename: str) -> str:
    """
    Checks the file magic bytes to determine the actual file type.
    Falls back to the filename extension if magic bytes are not recognized.
    """
    ext = Path(filename).suffix.lower()
    if not file_bytes:
        return ext

    # Check first 8 bytes for signature
    magic = file_bytes[:8]

    # 1. PDF
    if magic.startswith(b"%PDF"):
        return ".pdf"

    # PE Executable / DLL
    if magic.startswith(b"MZ"):
        if ext in (".exe", ".dll"):
            return ext
        return ".exe"

    # ELF Executable
    if magic.startswith(b"\x7fELF"):
        return ".elf"

    # Mach-O Executable
    if magic.startswith(b"\xfe\xed\xfa\xce") or magic.startswith(b"\xce\xfa\xed\xfe") or magic.startswith(b"\xfe\xed\xfa\xcf") or magic.startswith(b"\xcf\xfa\xed\xfe"):
        return ".macho"

    # 2. ZIP / OpenXML (docx, xlsx, pptx, xlsm)
    if magic.startswith(b"PK\x03\x04"):
        if ext in (".docx", ".xlsx", ".pptx", ".xlsm", ".zip"):
            return ext
        return ".zip"

    # 3. OLE / Office legacy (doc, xls, xlm, ppt)
    if magic.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if ext in (".doc", ".xls", ".xlm", ".ppt"):
            return ext
        return ".doc"

    # 4. RTF
    if magic.startswith(b"{\\rtf"):
        return ".rtf"

    # 5. HTML
    if magic.lower().startswith(b"<!doctype html") or b"<html" in magic.lower():
        return ".html"

    # 6. Python script (check if text starts with common Python elements)
    try:
        text_start = file_bytes[:100].decode("utf-8", errors="ignore").strip()
        if text_start.startswith("#!") and "python" in text_start:
            return ".py"
        if text_start.startswith("import ") or text_start.startswith("def ") or text_start.startswith("from "):
            return ".py"
    except Exception:
        pass

    return ext


def deobfuscate_macro_code(code: str) -> str:
    """
    Automatically deobfuscates common VBS/VBA macro obfuscation techniques:
    - StrReverse("...")
    - Chr(x) & Chr(y) & Chr(z) concatenated ASCII codes
    - Concatenation cleanups: "a" & "b" -> "ab"
    """
    if not code:
        return ""

    deobf = code

    # 1. Reverse StrReverse("...")
    def replace_str_reverse(match):
        content = match.group(1)
        return f'"{content[::-1]}"'

    deobf = re.sub(r'StrReverse\(\s*"([^"]*)"\s*\)', replace_str_reverse, deobf, flags=re.IGNORECASE)
    deobf = re.sub(r"StrReverse\(\s*'([^']*)'\s*\)", replace_str_reverse, deobf, flags=re.IGNORECASE)

    # 2. Resolve Chr/ChrW concatenations
    chr_pattern = r'Chr[W]?\(\s*(\d+)\s*\)'

    def replace_chr_sequence(match):
        digits = re.findall(r'\d+', match.group(0))
        chars = []
        for d in digits:
            try:
                chars.append(chr(int(d)))
            except Exception:
                pass
        return '"' + "".join(chars) + '"'

    concat_pattern = r'(?:Chr[W]?\(\s*\d+\s*\)\s*&\s*){1,}(?:Chr[W]?\(\s*\d+\s*\))'
    deobf = re.sub(concat_pattern, replace_chr_sequence, deobf, flags=re.IGNORECASE)

    # Replace single isolated ones
    def replace_single_chr(match):
        try:
            return f'"{chr(int(match.group(1)))}"'
        except Exception:
            return match.group(0)
    deobf = re.sub(chr_pattern, replace_single_chr, deobf, flags=re.IGNORECASE)

    # Clean up concatenated strings like "ht" & "tp" -> "http"
    deobf = re.sub(r'"\s*&\s*"', '', deobf)

    return deobf


def _check_suspicious_patterns(content: str, source_name: str, findings: list[Finding], tracer: DebugTracer) -> None:
    """Helper to scan content (VBA macro strings or raw files) for deep maldoc signatures."""
    yara_success = False
    
    # Split content into lines to lookup exact matched line numbers
    lines = content.splitlines()
    
    if YARA_AVAILABLE and yara_rules:
        try:
            content_bytes = content.encode("utf-8", errors="ignore")
            externals = {
                "filename": source_name or "",
                "filepath": source_name or "",
                "extension": os.path.splitext(source_name)[1] if source_name else "",
                "filetype": "",
                "owner": ""
            }
            matches = yara_rules.match(data=content_bytes, externals=externals)
            if matches:
                for match in matches:
                    category = match.meta.get("category", "Suspicious Pattern")
                    severity_str = match.meta.get("severity", "high")
                    score_impact = float(match.meta.get("score_impact", 20.0))
                    
                    severity = FindingSeverity.HIGH
                    if severity_str == "critical":
                        severity = FindingSeverity.CRITICAL
                    elif severity_str == "medium":
                        severity = FindingSeverity.MEDIUM
                    elif severity_str == "low":
                        severity = FindingSeverity.LOW
                    elif severity_str == "info":
                        severity = FindingSeverity.INFO
                    
                    # Extract matched strings and search for their exact line numbers
                    matched_strings = []
                    matched_lines_detail = []
                    
                    for string_match in match.strings:
                        try:
                            # string_match is a tuple (offset, string_identifier, string_data)
                            identifier = string_match[1]
                            data_bytes = string_match[2]
                            matched_strings.append(identifier)
                            
                            # Search the code to find the exact line numbers and context
                            try:
                                data_str = data_bytes.decode("utf-8", errors="ignore")
                                for line_idx, line_content in enumerate(lines, 1):
                                    if data_str.lower() in line_content.lower():
                                        matched_lines_detail.append(f"Line {line_idx}: {line_content.strip()}")
                            except Exception:
                                pass
                        except Exception:
                            pass
                    
                    # Dedup matched strings
                    unique_strings = []
                    seen_strs = set()
                    for ms in matched_strings:
                        if ms not in seen_strs:
                            seen_strs.add(ms)
                            unique_strings.append(ms)
                            
                    # Dedup matched lines
                    unique_lines = []
                    seen_lines = set()
                    for ml in matched_lines_detail:
                        if ml not in seen_lines:
                            seen_lines.add(ml)
                            unique_lines.append(ml)

                    evidence_parts = []
                    evidence_parts.append(f"YARA match '{match.rule}' ({', '.join(unique_strings) if unique_strings else 'any'}) in {source_name}")
                    if unique_lines:
                        evidence_parts.append("\nSuspicious Code Context:")
                        evidence_parts.extend(unique_lines[:5])  # Cap at 5 lines to keep readable
                        
                    evidence_detail = "\n".join(evidence_parts)
                    
                    findings.append(Finding(
                        category="document",
                        title=f"Maldoc: {category}" if "PE File" not in category else category,
                        description=f"Static YARA rule matching detected malicious indicators.",
                        severity=severity,
                        score_impact=score_impact,
                        evidence=evidence_detail
                    ))
                    tracer.step("document_analyzer", "pattern_triggered", 
                                detail=f"Maldoc '{category}' YARA rule '{match.rule}' found in {source_name}",
                                score_impact=score_impact)
            yara_success = True
        except Exception as e:
            tracer.step("document_analyzer", "yara_error", detail=f"YARA matching failed, falling back to regex: {str(e)}")
            yara_success = False

    if not yara_success:
        def run_check_group(group_list, category_title, base_severity, base_score):
            for pattern, label in group_list:
                # Find matching lines
                matched_lines = []
                for line_idx, line_content in enumerate(lines, 1):
                    if re.search(pattern, line_content, re.IGNORECASE):
                        matched_lines.append(f"Line {line_idx}: {line_content.strip()}")
                
                if matched_lines:
                    evidence_parts = []
                    evidence_parts.append(f"Match '{pattern}' in {source_name}")
                    evidence_parts.append("\nSuspicious Code Context:")
                    evidence_parts.extend(matched_lines[:5])
                    
                    evidence_detail = "\n".join(evidence_parts)
                    
                    findings.append(Finding(
                        category="document",
                        title=f"Maldoc: {category_title}",
                        description=f"Suspicious capability: {label}",
                        severity=base_severity,
                        score_impact=base_score,
                        evidence=evidence_detail
                    ))
                    tracer.step("document_analyzer", "pattern_triggered", 
                                detail=f"Maldoc '{category_title}' ({label}) found in {source_name}",
                                score_impact=base_score)

        run_check_group(MALDOC_PERSISTENCE, "Autostart / Persistence", FindingSeverity.HIGH, 20.0)
        run_check_group(MALDOC_EXECUTION, "Command Execution", FindingSeverity.CRITICAL, 35.0)
        run_check_group(MALDOC_NETWORK, "Network Downloader", FindingSeverity.CRITICAL, 30.0)
        run_check_group(MALDOC_SYSTEM, "System Object Manipulation", FindingSeverity.MEDIUM, 15.0)
        run_check_group(MALDOC_MEMORY, "Memory/Process Injection API", FindingSeverity.CRITICAL, 40.0)
        run_check_group(MALDOC_OBFUSCATION, "Code Obfuscation", FindingSeverity.HIGH, 25.0)

        # PE (Executable) signature check
        if "This program cannot be run in DOS mode" in content or re.search(r"4d5a900003000000", content, re.I):
            findings.append(Finding(
                category="document",
                title="Embedded Executable (PE File)",
                description="Document appears to contain an embedded executable binary, a severe threat indicator.",
                severity=FindingSeverity.CRITICAL,
                score_impact=45.0,
                evidence=f"MZ/PE header signature found in {source_name}"
            ))
            tracer.step("document_analyzer", "embedded_pe_found", detail=f"Embedded executable detected in {source_name}", score_impact=45.0)




import hashlib
from datetime import datetime

def extract_file_metadata(file_bytes: bytes, filename: str, ext: str) -> dict:
    """Extracts hashes (MD5, SHA256, SHA512), size, dates, and author metadata from uploaded document/script."""
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    sha512_hash = hashlib.sha512(file_bytes).hexdigest()
    
    metadata = {
        "filename": filename,
        "extension": ext,
        "file_size_bytes": len(file_bytes),
        "md5": md5_hash,
        "sha256": sha256_hash,
        "sha512": sha512_hash,
        "author": "Unknown",
        "created_at": datetime.now().isoformat(),
        "last_modified": "N/A"
    }
    
    if ext == ".pdf":
        try:
            import fitz
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            meta = doc.metadata or {}
            metadata["author"] = meta.get("author") or "Unknown"
            metadata["created_at"] = meta.get("creationDate") or metadata["created_at"]
            metadata["last_modified"] = meta.get("modDate") or "N/A"
        except Exception:
            pass
            
    elif ext in (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".xlsm", ".xlm"):
        try:
            if file_bytes.startswith(b"PK\x03\x04"):
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                    if "docProps/core.xml" in z.namelist():
                        core_xml = z.read("docProps/core.xml").decode("utf-8", errors="ignore")
                        author_match = re.search(r"<dc:creator>([^<]+)</dc:creator>", core_xml)
                        created_match = re.search(r"<dcterms:created[^>]*>([^<]+)</dcterms:created>", core_xml)
                        modified_match = re.search(r"<dcterms:modified[^>]*>([^<]+)</dcterms:modified>", core_xml)
                        if author_match:
                            metadata["author"] = author_match.group(1)
                        if created_match:
                            metadata["created_at"] = created_match.group(1)
                        if modified_match:
                            metadata["last_modified"] = modified_match.group(1)
        except Exception:
            pass
            
    return metadata


def auto_deobfuscate_content(content_str: str) -> list[dict]:
    """
    Recursively scans the given script/file content for obfuscated payloads (Base64, Hex, Reversed, XOR, CharCodes, URL-percent, Unicode/Octal escapes).
    Returns a list of dictionaries with type, raw obfuscated string, and decoded payload.
    """
    import base64
    import binascii
    import urllib.parse
    
    deobfuscated_results = []
    seen_payloads = set()

    # 0. Check if the content is HTML and extract JS script tags/inline events for deep analysis
    if "<html" in content_str.lower() or "<script" in content_str.lower() or "onload=" in content_str.lower() or "onerror=" in content_str.lower():
        js_blocks = []
        script_pattern = re.compile(r'<script\b[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for match in script_pattern.finditer(content_str):
            js = match.group(1).strip()
            if js:
                js_blocks.append(js)
        handler_pattern = re.compile(r'\bon[a-z]+\s*=\s*(["\'])(.*?)\1', re.IGNORECASE)
        for match in handler_pattern.finditer(content_str):
            js = match.group(2).strip()
            if js and not js.startswith('javascript:'):
                js_blocks.append(js)
            elif js.startswith('javascript:'):
                js_blocks.append(js[11:].strip())
        
        for block in js_blocks:
            # Look for Base64 strings in quotes (shorter threshold since they are JS string values)
            q_b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{8,}(?:==|=)??)["\']')
            for match in q_b64_pattern.finditer(block):
                candidate = match.group(1)
                if len(candidate) % 4 != 0:
                    padding_needed = 4 - (len(candidate) % 4)
                    if padding_needed < 3:
                        candidate += "=" * padding_needed
                    else:
                        continue
                if candidate in seen_payloads:
                    continue
                try:
                    decoded_bytes = base64.b64decode(candidate)
                    decoded_str = decoded_bytes.decode('utf-8', errors='replace')
                    if len(decoded_str.strip()) >= 4 and any(c.isalnum() for c in decoded_str):
                        seen_payloads.add(candidate)
                        deobfuscated_results.append({
                            "type": "Base64 String in JS Decoded",
                            "obfuscated": match.group(0),
                            "decoded": decoded_str
                        })
                        nested = auto_deobfuscate_content(decoded_str)
                        if nested:
                            deobfuscated_results.extend(nested)
                except Exception:
                    pass
                    
            # String concatenation resolver: e.g. "co" + "nso" + "le" -> "console"
            concat_pattern = re.compile(r'(["\'])(.*?)\1(?:\s*\+\s*(["\'])(.*?)\3)+')
            for match in concat_pattern.finditer(block):
                full_match = match.group(0)
                if full_match in seen_payloads:
                    continue
                parts = re.findall(r'["\'](.*?)["\']', full_match)
                combined = "".join(parts)
                if len(combined) >= 6 and combined != full_match:
                    seen_payloads.add(full_match)
                    deobfuscated_results.append({
                        "type": "JS String Concatenation Resolved",
                        "obfuscated": full_match[:80] + ("..." if len(full_match) > 80 else ""),
                        "decoded": combined
                    })
                    nested = auto_deobfuscate_content(combined)
                    if nested:
                        deobfuscated_results.extend(nested)
                        
            # unescape / decodeURIComponent resolver
            unescape_pattern = re.compile(r'(?:unescape|decodeURIComponent)\s*\(\s*["\'](%.*?)["\']\s*\)', re.I)
            for match in unescape_pattern.finditer(block):
                candidate = match.group(1)
                if candidate in seen_payloads:
                    continue
                try:
                    decoded_str = urllib.parse.unquote(candidate)
                    if decoded_str:
                        seen_payloads.add(candidate)
                        deobfuscated_results.append({
                            "type": "JS unescape() Call Decoded",
                            "obfuscated": match.group(0),
                            "decoded": decoded_str
                        })
                        nested = auto_deobfuscate_content(decoded_str)
                        if nested:
                            deobfuscated_results.extend(nested)
                except Exception:
                    pass
    
    # 1. Look for Base64 patterns (Standard alphanumeric matching, length >= 16, padding support)
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    for match in b64_pattern.finditer(content_str):
        b64_candidate = match.group(0)
        # Avoid simple short word matching or obvious non-b64 strings
        if len(b64_candidate) < 16 or b64_candidate in seen_payloads:
            continue
            
        try:
            decoded_bytes = base64.b64decode(b64_candidate)
            decoded_str = decoded_bytes.decode('utf-8', errors='replace')
            # Verify if it contains readable text with high printable ratio to avoid false positives
            printable_count = sum(1 for c in decoded_str if c.isprintable() and c.isascii())
            if len(decoded_str.strip()) >= 8 and (printable_count / max(1, len(decoded_str))) > 0.85:
                seen_payloads.add(b64_candidate)
                deobfuscated_results.append({
                    "type": "Base64 Payload Decoded",
                    "obfuscated": b64_candidate[:80] + ("..." if len(b64_candidate) > 80 else ""),
                    "decoded": decoded_str
                })
                # Recurse on the decoded string to find nested obfuscations
                nested = auto_deobfuscate_content(decoded_str)
                if nested:
                    deobfuscated_results.extend(nested)
        except Exception:
            pass

    # 2. Look for Hex obfuscation patterns (e.g. \x41\x42 or 0x41,0x42 or contiguous hex sequences)
    hex_pattern_escape = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')
    for match in hex_pattern_escape.finditer(content_str):
        hex_candidate = match.group(0)
        if hex_candidate in seen_payloads:
            continue
        try:
            hex_cleaned = hex_candidate.replace('\\x', '')
            decoded_bytes = binascii.unhexlify(hex_cleaned)
            decoded_str = decoded_bytes.decode('utf-8', errors='replace')
            if len(decoded_str.strip()) >= 6:
                seen_payloads.add(hex_candidate)
                deobfuscated_results.append({
                    "type": "Hex Escaped Payload Decoded",
                    "obfuscated": hex_candidate[:80] + ("..." if len(hex_candidate) > 80 else ""),
                    "decoded": decoded_str
                })
                nested = auto_deobfuscate_content(decoded_str)
                if nested:
                    deobfuscated_results.extend(nested)
        except Exception:
            pass

    # 3. Look for reversed malicious strings (e.g. llehsvrever or exetpircs)
    common_obfuscated_reversed = ["llehs", "tcepsni", "exe.", "lld.", "etpircs"]
    for rev in common_obfuscated_reversed:
        if rev in content_str.lower():
            # Try to extract the word surrounding it and reverse
            pattern_rev = re.compile(r'[a-zA-Z\.\_\\\/]{6,}')
            for match in pattern_rev.finditer(content_str):
                word = match.group(0)
                if word in seen_payloads:
                    continue
                reversed_word = word[::-1]
                if any(k in reversed_word.lower() for k in ["shell", "socket", "http", "cmd", "powershell"]):
                    seen_payloads.add(word)
                    deobfuscated_results.append({
                        "type": "Reversed String Detected",
                        "obfuscated": word,
                        "decoded": reversed_word
                    })

    # 4. Look for contiguous Hex strings representing encrypted data, and brute-force single-byte XOR keys
    hex_sequence_pattern = re.compile(r'\b[0-9a-fA-F]{32,}\b')
    for match in hex_sequence_pattern.finditer(content_str):
        hex_candidate = match.group(0)
        if hex_candidate in seen_payloads:
            continue
        try:
            candidate_bytes = binascii.unhexlify(hex_candidate)
            # Brute force 1-byte XOR
            for key in range(1, 256):
                xored = bytes(b ^ key for b in candidate_bytes)
                try:
                    decoded_str = xored.decode('utf-8')
                    # Heuristic: check if the string contains common readable plaintext keywords
                    if len(decoded_str.strip()) >= 10 and any(kw in decoded_str.lower() for kw in ["var ", "function", "http", "document", "eval", "window", "cmd.exe", "powershell"]):
                        seen_payloads.add(hex_candidate)
                        deobfuscated_results.append({
                            "type": f"XOR Encrypted Payload (Key: 0x{key:02X}) Decoded",
                            "obfuscated": hex_candidate[:80] + ("..." if len(hex_candidate) > 80 else ""),
                            "decoded": decoded_str
                        })
                        nested = auto_deobfuscate_content(decoded_str)
                        if nested:
                            deobfuscated_results.extend(nested)
                        break # Found the correct key
                except Exception:
                    pass
        except Exception:
            pass

    # 5. Look for character code arrays: String.fromCharCode(...) or just lists of numbers
    char_code_pattern = re.compile(r'(?:String\.fromCharCode|fromCharCode)\s*\(\s*([\d\s,\x08]+)\s*\)')
    for match in char_code_pattern.finditer(content_str):
        candidate_str = match.group(0)
        if candidate_str in seen_payloads:
            continue
        try:
            numbers = [int(n.strip()) for n in match.group(1).split(',') if n.strip().isdigit()]
            if len(numbers) >= 8:
                decoded_str = "".join(chr(n) for n in numbers)
                seen_payloads.add(candidate_str)
                deobfuscated_results.append({
                    "type": "String.fromCharCode Array Decoded",
                    "obfuscated": candidate_str[:80] + ("..." if len(candidate_str) > 80 else ""),
                    "decoded": decoded_str
                })
                nested = auto_deobfuscate_content(decoded_str)
                if nested:
                    deobfuscated_results.extend(nested)
        except Exception:
            pass

    # 6. General lists of integers representing characters (commonly used for obfuscation)
    array_pattern = re.compile(r'\[\s*(?:\d+\s*,\s*){8,}\d+\s*\]')
    for match in array_pattern.finditer(content_str):
        candidate_str = match.group(0)
        if candidate_str in seen_payloads:
            continue
        try:
            cleaned_nums = candidate_str.strip('[] \n\r')
            numbers = [int(n.strip()) for n in cleaned_nums.split(',') if n.strip().isdigit()]
            if len(numbers) >= 8:
                # First check direct ASCII decoding
                if len(numbers) >= 12 and all(31 <= n <= 126 or n in (9, 10, 13) for n in numbers[:10]):
                    decoded_str = "".join(chr(n) for n in numbers)
                    seen_payloads.add(candidate_str)
                    deobfuscated_results.append({
                        "type": "Integer Array ASCII Characters Decoded",
                        "obfuscated": candidate_str[:80] + ("..." if len(candidate_str) > 80 else ""),
                        "decoded": decoded_str
                    })
                    nested = auto_deobfuscate_content(decoded_str)
                    if nested:
                        deobfuscated_results.extend(nested)
                else:
                    # Try XOR brute-force key on integer array
                    for key in range(1, 256):
                        try:
                            xored_chars = [chr(n ^ key) for n in numbers]
                            if all(31 <= ord(c) <= 126 or ord(c) in (9, 10, 13) for c in xored_chars):
                                decoded_str = "".join(xored_chars)
                                if any(kw in decoded_str.lower() for kw in ["var ", "function", "http", "document", "eval", "window", "cmd", "powershell", "script"]):
                                    seen_payloads.add(candidate_str)
                                    deobfuscated_results.append({
                                        "type": f"XOR-Encrypted Integer Array (Key: 0x{key:02X}) Decoded",
                                        "obfuscated": candidate_str[:80] + ("..." if len(candidate_str) > 80 else ""),
                                        "decoded": decoded_str
                                    })
                                    nested = auto_deobfuscate_content(decoded_str)
                                    if nested:
                                        deobfuscated_results.extend(nested)
                                    break
                        except Exception:
                            pass
        except Exception:
            pass

    # 7. Look for URL-encoded strings (percent encoding) commonly used to hide commands
    url_enc_pattern = re.compile(r'(?:%[0-9a-fA-F]{2}){8,}')
    for match in url_enc_pattern.finditer(content_str):
        candidate = match.group(0)
        if candidate in seen_payloads:
            continue
        try:
            decoded_str = urllib.parse.unquote(candidate)
            # Verify if it contains readable text with standard scripts/keywords
            if len(decoded_str.strip()) >= 8 and any(c.isalnum() for c in decoded_str):
                # Avoid matching simple text that has % symbols but is not code
                if any(kw in decoded_str.lower() for kw in ["var ", "function", "http", "document", "eval", "window", "script", "onload", "onerror", "unescape"]):
                    seen_payloads.add(candidate)
                    deobfuscated_results.append({
                        "type": "URL-Encoded Payload Decoded",
                        "obfuscated": candidate[:80] + ("..." if len(candidate) > 80 else ""),
                        "decoded": decoded_str
                    })
                    nested = auto_deobfuscate_content(decoded_str)
                    if nested:
                        deobfuscated_results.extend(nested)
        except Exception:
            pass

    # 8. Look for Unicode escape sequences (e.g., \u0065\u0076\u0061\u006c)
    unicode_pattern = re.compile(r'(?:\\u[0-9a-fA-F]{4}){3,}')
    for match in unicode_pattern.finditer(content_str):
        candidate = match.group(0)
        if candidate in seen_payloads:
            continue
        try:
            # Decode unicode escape sequence safely
            decoded_str = candidate.encode().decode('unicode-escape')
            if len(decoded_str.strip()) >= 6 and any(c.isalnum() for c in decoded_str):
                seen_payloads.add(candidate)
                deobfuscated_results.append({
                    "type": "Unicode-Escaped JS Code Decoded",
                    "obfuscated": candidate[:80] + ("..." if len(candidate) > 80 else ""),
                    "decoded": decoded_str
                })
                nested = auto_deobfuscate_content(decoded_str)
                if nested:
                    deobfuscated_results.extend(nested)
        except Exception:
            pass

    # 9. Look for Octal escape sequences (e.g., \145\166\141\154)
    octal_pattern = re.compile(r'(?:\\[0-7]{3}){3,}')
    for match in octal_pattern.finditer(content_str):
        candidate = match.group(0)
        if candidate in seen_payloads:
            continue
        try:
            octal_bytes = bytearray()
            octals = [o for o in candidate.split('\\') if o]
            for oct_str in octals:
                octal_bytes.append(int(oct_str, 8))
            decoded_str = octal_bytes.decode('utf-8', errors='replace')
            if len(decoded_str.strip()) >= 6 and any(c.isalnum() for c in decoded_str):
                seen_payloads.add(candidate)
                deobfuscated_results.append({
                    "type": "Octal-Escaped Payload Decoded",
                    "obfuscated": candidate[:80] + ("..." if len(candidate) > 80 else ""),
                    "decoded": decoded_str
                })
                nested = auto_deobfuscate_content(decoded_str)
                if nested:
                    deobfuscated_results.extend(nested)
        except Exception:
            pass
            
    return deobfuscated_results



def classify_context(content: str, findings: list[Finding], ext: str) -> str:
    """Categorizes the target document/script context to explain its nature (AI, ReverseShell, SOCKS5, Downloader, etc.)."""
    # 1. High-severity offensive scripts
    if any("Reverse Shell" in f.title or "reverse_shell" in (f.evidence or "") for f in findings):
        return "Reverse Shell & Remote Access Backdoor"
        
    if any("Impacket" in f.title for f in findings):
        return "Offensive Lateral Movement / Impacket Execution"

    content_lower = content.lower()
    
    # AI & AI Agent contexts
    ai_keywords = ["openai", "langchain", "gemini", "anthropic", "langgraph", "llama_index", "crewai", "agent", "llm", "rag_pipeline"]
    if any(kw in content_lower for kw in ai_keywords):
        return "AI Agent & LLM Orchestration Context"

    # Reverse Shell Context
    rev_keywords = ["/dev/tcp/", "/dev/udp/", "dup2", "subprocess.popen", "socket.connect", "sh -i", "bash -i"]
    if any(kw in content_lower for kw in rev_keywords):
        return "Reverse Shell & Network Socket Redirection"

    # SOCKS5 Tunnels
    socks_keywords = ["socks5", "socks4", "socks", "proxy", "socket.socket", "socket.connect", "sockslistener"]
    if any(kw in content_lower for kw in socks_keywords):
        return "SOCKS5 Proxy & Network Tunneling Context"

    # Mass Downloader
    down_keywords = ["downloadstring", "downloadfile", "urldownloadtofile", "xmlhttp", "winhttprequest", "bitsadmin", "certutil", "wget", "curl"]
    if any(kw in content_lower for kw in down_keywords):
        return "Mass Payload Downloader / Stager"

    # SQL Injection / Databases
    sql_keywords = ["drop table", "delete from", "union select", "xp_cmdshell", "database", "select * from"]
    if any(kw in content_lower for kw in sql_keywords):
        return "Database Schema & SQL Query Context"

    # Office Maldoc autostarts
    vba_keywords = ["autoopen", "autoexec", "document_open", "workbook_open"]
    if any(kw in content_lower for kw in vba_keywords):
        return "Office Macro Autostart Maldoc Context"

    # Binary contexts
    if ext in (".exe", ".dll") or content.startswith("4d5a") or "This program cannot be run in DOS mode" in content:
        return "Compiled PE Payload Binary / DLL"

    # Email
    if ext in (".eml", ".msg"):
        return "Email Archive Communication Context"

    # Fallback to extensions
    if ext == ".py":
        return "Generic Python Script"
    elif ext in (".ps1", ".ps"):
        return "Generic PowerShell script"
    elif ext == ".sh":
        return "Generic Linux Shell script"
    elif ext in (".bat", ".cmd"):
        return "Generic Windows Batch script"
    elif ext == ".html" or ext == ".htm":
        return "HTML Web Layout Context"
    elif ext == ".zip":
        return "Compressed Zip Archive Bundle"
        
    return "Generic Document / Text Content"


def analyze_document(
    file_bytes: bytes,
    filename: str,
    tracer: DebugTracer,
    password: Optional[str] = None,
    custom_wordlist: Optional[list[str]] = None,
    do_brute: bool = True,
) -> tuple[list[Finding], Optional[str], Optional[int], Optional[str]]:
    """
    Analyze a document for phishing/malicious indicators.
    Returns (findings, password_found, brute_attempts, screenshot_base64).
    """
    findings: list[Finding] = []
    
    # Store filename in tracer context
    tracer.current_file = filename
    
    # Forensic dynamic extension detection
    real_ext = detect_extension_by_magic(file_bytes, filename)
    ext = Path(filename).suffix.lower()

    if real_ext != ext:
        findings.append(Finding(
            category="document", title="Disguised file extension",
            description=f"File was uploaded as '{ext}' but forensic analysis of magic bytes reveals it is actually '{real_ext}'. This is a common evasion tactic.",
            severity=FindingSeverity.CRITICAL, score_impact=30.0,
            evidence=f"Claimed={ext}, Actual={real_ext}"
        ))
        tracer.step("document_analyzer", "spoofed_extension", detail=f"Claimed={ext}, Detected={real_ext}", score_impact=30.0)
        ext = real_ext  # Proceed with forensic extension type

    # Safe dynamic metadata extraction
    try:
        metadata = extract_file_metadata(file_bytes, filename, ext)
        tracer.file_metadata[filename] = metadata
    except Exception as e:
        tracer.step("document_analyzer", "metadata_error", detail=f"Failed to extract metadata: {str(e)}")

    # Extract Strings
    try:
        strings_pattern = re.compile(rb"[\x20-\x7E]{6,}")
        extracted_strings = strings_pattern.findall(file_bytes)
        if extracted_strings:
            tracer.file_strings[filename] = "\n".join([s.decode("ascii", errors="ignore") for s in extracted_strings])
    except Exception as e:
        pass

    # Calculate Shannon Entropy
    try:
        import math
        from collections import Counter
        if file_bytes:
            freq = Counter(file_bytes)
            entropy = -sum(count / len(file_bytes) * math.log2(count / len(file_bytes)) for count in freq.values())
            tracer.file_entropy[filename] = round(entropy, 2)
            tracer.step("document_analyzer", "entropy_calc", detail=f"Shannon entropy: {entropy:.2f}/8.0")
            
            if entropy > 7.5 and ext not in [".zip", ".png", ".jpg", ".jpeg", ".pdf"]:
                findings.append(Finding(
                    category="document", title="High File Entropy",
                    description=f"File entropy is {entropy:.2f}/8.0. This indicates the content is highly packed or encrypted, a common evasion technique for executables and scripts.",
                    severity=FindingSeverity.HIGH, score_impact=15.0,
                    evidence=f"Entropy: {entropy:.2f}"
                ))
    except Exception as e:
        tracer.step("document_analyzer", "entropy_error", detail=f"Failed to calculate entropy: {str(e)}")

    password_found = None
    brute_attempts = None
    screenshot_base64 = None

    tracer.step("document_analyzer", "start", detail=f"File: {filename}, size: {len(file_bytes)} bytes, ext: {ext}")

    # Check double extension
    stem = Path(filename).stem
    if "." in stem:
        findings.append(Finding(
            category="document", title="Double file extension",
            description=f"File '{filename}' has a double extension, commonly used to disguise executables.",
            severity=FindingSeverity.HIGH, score_impact=20.0,
            evidence=filename,
        ))

    # Route based on extension
    if ext == ".pdf":
        pdf_findings, screenshot_base64 = _analyze_pdf(file_bytes, tracer, password, custom_wordlist, do_brute)
        findings.extend(pdf_findings)
    elif ext in (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".xlsm", ".xlm"):
        findings.extend(_analyze_office(file_bytes, ext, tracer, password, custom_wordlist, do_brute))
    elif ext == ".rtf":
        findings.extend(_analyze_rtf(file_bytes, tracer))
    elif ext == ".zip":
        findings.extend(_analyze_zip(file_bytes, tracer, password, custom_wordlist, do_brute))
    elif ext == ".sql":
        findings.extend(_analyze_sql(file_bytes, tracer))
    elif ext == ".py":
        findings.extend(_analyze_python(file_bytes, tracer))
    elif ext in (".ps1", ".ps"):
        findings.extend(_analyze_powershell(file_bytes, tracer))
    elif ext == ".sh":
        findings.extend(_analyze_shell(file_bytes, tracer))
    elif ext in (".bat", ".cmd"):
        findings.extend(_analyze_batch(file_bytes, tracer))
    elif ext in (".dll", ".exe"):
        findings.extend(_analyze_pe(file_bytes, tracer))
    elif ext == ".elf":
        findings.extend(_analyze_elf(file_bytes, tracer))
    elif ext == ".macho":
        findings.extend(_analyze_macho(file_bytes, tracer))
    elif ext == ".html" or ext == ".htm":
        findings.extend(_analyze_html(file_bytes, tracer))
    elif ext == ".lnk":
        findings.extend(_analyze_lnk(file_bytes, tracer))
    elif ext == ".txt":
        findings.extend(_analyze_txt(file_bytes, tracer))
    elif ext in (".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".gif"):
        findings.extend(_analyze_image(file_bytes, tracer))
    else:
        tracer.step("document_analyzer", "unsupported", detail=f"Extension {ext} omitted (unsupported)")

    # Extract password details if successfully cracked
    for step in tracer.get_steps():
        if step.analyzer == "bruteforce" and step.action == "found" and "password:" in step.result:
            password_found = step.result.split("password:")[-1]
            match = re.search(r"After (\d+) attempts", step.detail, re.I)
            if match:
                brute_attempts = int(match.group(1))

    # Classify the file context based on findings and content and run recursive auto-deobfuscator
    try:
        if ext in (".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".gif"):
            content_str = tracer.file_previews.get(filename, "")
            if content_str.startswith("--- OCR EXTRACTED TEXT ---\n\n"):
                content_str = content_str.replace("--- OCR EXTRACTED TEXT ---\n\n", "")
        else:
            content_str = file_bytes.decode("utf-8", errors="ignore")
            
        file_context = classify_context(content_str, findings, ext)
        tracer.file_contexts[filename] = file_context
        
        # Safe recursive decoding search
        deobfuscated_payloads = auto_deobfuscate_content(content_str)
        if deobfuscated_payloads:
            tracer.file_deobfuscated[filename] = deobfuscated_payloads
            tracer.step("document_analyzer", "deobfuscator", 
                        detail=f"Deobfuscated {len(deobfuscated_payloads)} payloads in {filename}", 
                        result=f"Decoded: {', '.join([r['type'] for r in deobfuscated_payloads])}")
            
            # Highlight detected types in the findings list
            types = list(set([r['type'].replace(" Decoded", "").replace(" Detected", "") for r in deobfuscated_payloads]))
            types_str = ", ".join(types)
            is_high_risk = any("XOR" in t or "Hex" in t for t in types)
            finding_severity = FindingSeverity.HIGH if is_high_risk else FindingSeverity.LOW
            finding_score = 25.0 if is_high_risk else 0.0
            
            findings.append(Finding(
                category="deobfuscation",
                title=f"Obfuscated / Encoded Payloads ({types_str})",
                description=f"The file '{filename}' contains encoded/obfuscated strings (using {types_str}) which were automatically recovered.",
                severity=finding_severity,
                score_impact=finding_score,
                evidence=f"Method(s) detected: {types_str}\nTotal recovered segments: {len(deobfuscated_payloads)}"
            ))
    except Exception as e:
        tracer.step("document_analyzer", "context_error", detail=f"Failed to classify context/deobfuscate: {str(e)}")

    tracer.step("document_analyzer", "complete", detail=f"{len(findings)} findings")
    return findings, password_found, brute_attempts, screenshot_base64


def _analyze_image(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    """Analyze a raw image using local pytesseract OCR and run maldoc/phishing pattern heuristics."""
    findings: list[Finding] = []
    tracer.step("document_analyzer", "image_ocr_start", detail="Starting offline OCR scanning of the image...")
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(io.BytesIO(file_bytes))
        ocr_text = pytesseract.image_to_string(img)
        if ocr_text.strip():
            tracer.file_previews[tracer.current_file] = f"--- OCR EXTRACTED TEXT ---\n\n{ocr_text}"
            tracer.step("document_analyzer", "image_ocr_success", detail=f"OCR extracted {len(ocr_text)} characters from image")
            findings.append(Finding(
                category="document", title="Image analyzed via local OCR",
                description="The uploaded image was processed using the local Optical Character Recognition (OCR) engine.",
                severity=FindingSeverity.INFO, score_impact=0.0
            ))
            # Run general pattern matching (YARA / Keywords / Heuristics) on the extracted text
            _check_suspicious_patterns(ocr_text, "OCR text", findings, tracer)
        else:
            tracer.step("document_analyzer", "image_ocr_empty", detail="OCR yielded no text from image")
    except ImportError:
        tracer.step("document_analyzer", "image_ocr_skip", detail="pytesseract/Pillow not available. Skipping image OCR.")
    except Exception as e:
        tracer.step("document_analyzer", "image_ocr_error", detail=f"OCR engine failure: {str(e)}")

    # Quishing Check (QR Code Detection)
    try:
        import cv2
        import numpy as np
        nparr = np.frombuffer(file_bytes, np.uint8)
        img_cv2 = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img_cv2 is not None:
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(img_cv2)
            if data:
                findings.append(Finding(
                    category="document", title="QR Code in Image (Potential Quishing)",
                    description=f"The image contains an embedded QR code redirecting to: {data}. This is commonly used in phishing campaigns.",
                    severity=FindingSeverity.CRITICAL, score_impact=35.0,
                    evidence=f"QR Target: {data}",
                ))
                tracer.step("document_analyzer", "quishing_detected", 
                            detail=f"QR redirects to {data}", score_impact=35.0)
    except Exception as e:
        tracer.step("document_analyzer", "quishing_check_error", detail=f"Failed to scan image for QR codes: {str(e)}")

    return findings


def _analyze_pdf(
    file_bytes: bytes, tracer: DebugTracer,
    password: Optional[str] = None,
    custom_wordlist: Optional[list[str]] = None,
    do_brute: bool = True,
) -> tuple[list[Finding], Optional[str]]:
    findings: list[Finding] = []
    decrypted_bytes = file_bytes
    screenshot_base64 = None

    try:
        import fitz  # PyMuPDF
    except ImportError:
        tracer.step("document_analyzer", "pdf_skip", result="PyMuPDF not installed")
        findings.append(Finding(
            category="document", title="PDF analysis limited",
            description="PyMuPDF not installed.",
            severity=FindingSeverity.INFO, score_impact=0,
        ))
        return findings, None

    # Try opening the PDF
    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
    except Exception:
        # Might be encrypted
        tracer.step("document_analyzer", "pdf_encrypted", detail="PDF appears encrypted")
        if password:
            try:
                doc = fitz.open(stream=file_bytes, filetype="pdf")
                doc.authenticate(password)
                if doc.is_encrypted:
                    raise ValueError("Password didn't work")
            except Exception:
                if do_brute:
                    pw, attempts, dec = brute_force_password(file_bytes, ".pdf", tracer, custom_wordlist)
                    if pw is not None and dec:
                        decrypted_bytes = dec
                        doc = fitz.open(stream=decrypted_bytes, filetype="pdf")
                        findings.append(Finding(
                            category="document", title="Password-protected PDF cracked",
                            description=f"PDF password was cracked after {attempts} attempts.",
                            severity=FindingSeverity.HIGH, score_impact=15.0,
                        ))
                    else:
                        findings.append(Finding(
                            category="document", title="Encrypted PDF - password not found",
                            description=f"Could not crack PDF password after {attempts} attempts.",
                            severity=FindingSeverity.MEDIUM, score_impact=10.0,
                        ))
                        return findings, None
                else:
                    findings.append(Finding(
                        category="document", title="Encrypted PDF - incorrect password",
                        description="PDF is password-protected and the provided password was incorrect.",
                        severity=FindingSeverity.MEDIUM, score_impact=10.0,
                    ))
                    return findings, None
        else:
            if do_brute:
                pw, attempts, dec = brute_force_password(file_bytes, ".pdf", tracer, custom_wordlist)
                if pw is not None and dec:
                    decrypted_bytes = dec
                    doc = fitz.open(stream=decrypted_bytes, filetype="pdf")
                    findings.append(Finding(
                        category="document", title="Password-protected PDF cracked",
                        description=f"PDF password was cracked after {attempts} attempts.",
                        severity=FindingSeverity.HIGH, score_impact=15.0,
                    ))
                else:
                    findings.append(Finding(
                        category="document", title="Encrypted PDF",
                        description="PDF is password-protected and could not be cracked.",
                        severity=FindingSeverity.MEDIUM, score_impact=10.0,
                    ))
                    return findings, None
            else:
                findings.append(Finding(
                    category="document", title="Encrypted PDF",
                    description="PDF is password-protected. Provide a password or enable brute-force.",
                    severity=FindingSeverity.MEDIUM, score_impact=10.0,
                ))
                return findings, None

    tracer.step("document_analyzer", "pdf_opened", detail=f"Pages: {len(doc)}")

    # Extract text and analyze
    full_text = ""
    for page_num in range(len(doc)):
        page = doc[page_num]
        text = page.get_text()
        full_text += text

        # Check for links
        for link in page.get_links():
            uri = link.get("uri", "")
            if uri:
                tracer.step("document_analyzer", "pdf_link_found", detail=f"Page {page_num+1}: {uri[:80]}")
                full_text += "\n" + uri

    # Fallback: Scanned PDF / Image OCR via pytesseract
    if len(full_text.strip()) < 10:
        tracer.step("document_analyzer", "pdf_ocr_check", detail="No standard text extracted from PDF. Triggering offline OCR analysis...")
        try:
            import pytesseract
            from PIL import Image
            
            ocr_texts = []
            for page_num in range(len(doc)):
                page = doc[page_num]
                # Render PDF page to a high-res image
                pix = page.get_pixmap(dpi=150)
                img_data = pix.tobytes("png")
                img = Image.open(io.BytesIO(img_data))
                
                # Perform OCR
                page_text = pytesseract.image_to_string(img)
                if page_text.strip():
                    ocr_texts.append(page_text)
                    
            if ocr_texts:
                full_text = "\n\n--- OCR EXTRACTED TEXT ---\n\n" + "\n".join(ocr_texts)
                tracer.step("document_analyzer", "pdf_ocr_success", detail=f"OCR extracted {len(full_text)} characters across {len(ocr_texts)} pages")
                findings.append(Finding(
                    category="document", title="Image-based PDF processed via OCR",
                    description="The PDF contains no digital text stream. Text was successfully extracted using offline Optical Character Recognition (OCR) heuristics.",
                    severity=FindingSeverity.INFO, score_impact=0.0
                ))
        except ImportError:
            tracer.step("document_analyzer", "pdf_ocr_skip", detail="pytesseract/Pillow not available. Skipping image OCR.")
        except Exception as e:
            tracer.step("document_analyzer", "pdf_ocr_error", detail=f"OCR engine failure: {str(e)}")

    # Simulating peepdf / pdf-parser streams analysis using pikepdf
    tracer.step("document_analyzer", "pdf_pikepdf_start", detail="Running pikepdf stream decoders (FlateDecode, LZWDecode, etc.)")
    
    js_found_in_stream = False
    launch_found = False
    open_action_found = False
    embedded_files_found = False
    
    try:
        import pikepdf
        pdf_obj = pikepdf.open(io.BytesIO(decrypted_bytes))
        
        # 1. Structural catalog checks
        catalog = pdf_obj.Root
        if "/OpenAction" in catalog:
            open_action_found = True
            findings.append(Finding(
                category="document", title="PDF Catalog: Auto-Open Action",
                description="PDF catalog contains an /OpenAction trigger, executing actions automatically upon opening.",
                severity=FindingSeverity.CRITICAL, score_impact=35.0,
                evidence=str(catalog["/OpenAction"])[:200]
            ))
            tracer.step("document_analyzer", "pdf_open_action", detail="/OpenAction detected", score_impact=35.0)
            
        if "/Names" in catalog and "/EmbeddedFiles" in catalog.Names:
            embedded_files_found = True
            findings.append(Finding(
                category="document", title="PDF Catalog: Embedded Files",
                description="PDF catalog contains /EmbeddedFiles. Attackers often embed secondary malware inside PDFs.",
                severity=FindingSeverity.HIGH, score_impact=20.0,
                evidence="/EmbeddedFiles catalog key found"
            ))
            tracer.step("document_analyzer", "pdf_embedded_files", detail="/EmbeddedFiles detected", score_impact=20.0)

        # 2. Iterate streams & decode
        stream_count = 0
        
        for obj_id, obj in pdf_obj.objects.items():
            if isinstance(obj, pikepdf.Stream):
                stream_count += 1
                try:
                    # Automatically decompresses /FlateDecode, /LZWDecode, /ASCIIHexDecode, etc.
                    stream_data = obj.read_bytes()
                    stream_text = stream_data.decode("utf-8", errors="ignore")
                    
                    if stream_text:
                        _check_suspicious_patterns(stream_text, f"PDF Object Stream {obj_id}", findings, tracer)
                        if "javascript" in stream_text.lower() or "eval(" in stream_text.lower():
                            js_found_in_stream = True
                except Exception:
                    pass
        
        tracer.step("document_analyzer", "pdf_streams_scanned", detail=f"Decoded and scanned {stream_count} streams")
        
        if js_found_in_stream:
            findings.append(Finding(
                category="document", title="JavaScript code in PDF Stream",
                description="Detected active JavaScript patterns (eval, unescape) inside a decompressed PDF object stream.",
                severity=FindingSeverity.CRITICAL, score_impact=30.0,
                evidence="JavaScript/eval code patterns found in stream objects"
            ))
            tracer.step("document_analyzer", "pdf_js_stream", score_impact=30.0)
            
    except Exception as e:
        tracer.step("document_analyzer", "pikepdf_error", detail=str(e))

    # Basic PDF parsing hooks for backward compatibility
    try:
        xref_count = doc.xref_length()
        for i in range(1, xref_count):
            try:
                obj_str = doc.xref_object(i)
                if "/JavaScript" in obj_str or "/JS" in obj_str:
                    js_found_in_stream = True
                    findings.append(Finding(
                        category="document", title="JavaScript in PDF",
                        description="PDF contains embedded JavaScript, which can be used for exploitation.",
                        severity=FindingSeverity.CRITICAL, score_impact=30.0,
                    ))
                    tracer.step("document_analyzer", "pdf_js_found", score_impact=30.0)
                    break
                if "/Launch" in obj_str or "/SubmitForm" in obj_str:
                    launch_found = True
                    findings.append(Finding(
                        category="document", title="Action trigger in PDF",
                        description="PDF contains Launch/SubmitForm actions that can execute commands.",
                        severity=FindingSeverity.HIGH, score_impact=20.0,
                    ))
                    break
            except Exception:
                continue
    except Exception:
        pass

    # Save previews and checks for this PDF
    current_fn = getattr(tracer, "current_file", "document.pdf")
    tracer.file_previews[current_fn] = full_text
    
    checks = [
        {"name": "Embedded JavaScript execution streams (/JS, /JavaScript)", "checked": True, "found": js_found_in_stream},
        {"name": "Command launcher actions (/Launch, /SubmitForm)", "checked": True, "found": launch_found},
        {"name": "Catalog Auto-Open Triggers (/OpenAction)", "checked": True, "found": open_action_found},
        {"name": "Embedded secondary payloads (/EmbeddedFiles)", "checked": True, "found": embedded_files_found},
    ]
    tracer.file_checks[current_fn] = checks

    # 1. Render first page to base64 PNG as a document "screenshot"
    if len(doc) > 0:
        try:
            import base64
            page = doc[0]
            pix = page.get_pixmap(dpi=120)
            png_bytes = pix.tobytes("png")
            screenshot_base64 = base64.b64encode(png_bytes).decode("utf-8")
            tracer.step("document_analyzer", "screenshot_generated", detail=f"Rendered page 1 of {len(doc)}")
        except Exception as e:
            tracer.step("document_analyzer", "screenshot_error", detail=str(e))

    # 2. Render and scan all pages locally via OpenCV to detect Quishing (QR Phishing)
    try:
        import cv2
        import numpy as np
        qr_found = False
        for page_num in range(len(doc)):
            page = doc[page_num]
            pix = page.get_pixmap(dpi=150)
            png_bytes = pix.tobytes("png")
            
            nparr = np.frombuffer(png_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(img)
            if data:
                findings.append(Finding(
                    category="document", title="QR Code in PDF (Potential Quishing)",
                    description=f"PDF contains an embedded QR code redirecting to: {data}. This is commonly used in phishing campaigns.",
                    severity=FindingSeverity.CRITICAL, score_impact=35.0,
                    evidence=f"QR Target: {data}",
                ))
                tracer.step("document_analyzer", "quishing_detected", 
                            detail=f"Page {page_num+1}: QR redirects to {data}", score_impact=35.0)
                qr_found = True
        if not qr_found:
            tracer.step("document_analyzer", "quishing_check", result="No QR codes found")
    except Exception as e:
        tracer.step("document_analyzer", "quishing_check_error", detail=str(e))

    doc.close()
    return findings, screenshot_base64


def _analyze_office(
    file_bytes: bytes, ext: str, tracer: DebugTracer,
    password: Optional[str] = None,
    custom_wordlist: Optional[list[str]] = None,
    do_brute: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []

    # Check if encrypted
    try:
        import msoffcrypto
        f = io.BytesIO(file_bytes)
        office_file = msoffcrypto.OfficeFile(f)
        if office_file.is_encrypted():
            tracer.step("document_analyzer", "office_encrypted", detail="Office document is encrypted")
            if password:
                try:
                    office_file.load_key(password=password)
                    dec = io.BytesIO()
                    office_file.decrypt(dec)
                    file_bytes = dec.getvalue()
                    tracer.step("document_analyzer", "office_decrypted", detail="Decrypted with provided password")
                except Exception:
                    if do_brute:
                        pw, attempts, dec_bytes = brute_force_password(file_bytes, ext, tracer, custom_wordlist)
                        if pw is not None and dec_bytes:
                            file_bytes = dec_bytes
                            findings.append(Finding(
                                category="document", title="Office document password cracked",
                                description=f"Password cracked after {attempts} attempts.",
                                severity=FindingSeverity.HIGH, score_impact=15.0,
                            ))
                        else:
                            findings.append(Finding(
                                category="document", title="Encrypted Office document",
                                description="Could not decrypt the document.",
                                severity=FindingSeverity.MEDIUM, score_impact=10.0,
                            ))
                            return findings
                    else:
                        findings.append(Finding(
                            category="document", title="Encrypted Office document",
                            description="Office document is encrypted and the provided password was incorrect.",
                            severity=FindingSeverity.MEDIUM, score_impact=10.0,
                        ))
                        return findings
            else:
                if do_brute:
                    pw, attempts, dec_bytes = brute_force_password(file_bytes, ext, tracer, custom_wordlist)
                    if pw is not None and dec_bytes:
                        file_bytes = dec_bytes
                        findings.append(Finding(
                            category="document", title="Office document password cracked",
                            description=f"Password cracked after {attempts} attempts.",
                            severity=FindingSeverity.HIGH, score_impact=15.0,
                        ))
                    else:
                        findings.append(Finding(
                            category="document", title="Encrypted Office document",
                            description="Could not decrypt the document.",
                            severity=FindingSeverity.MEDIUM, score_impact=10.0,
                        ))
                        return findings
                else:
                    findings.append(Finding(
                        category="document", title="Encrypted Office document",
                        description="Office document is password-protected. Provide a password or enable brute-force.",
                        severity=FindingSeverity.MEDIUM, score_impact=10.0,
                    ))
                    return findings
    except ImportError:
        tracer.step("document_analyzer", "msoffcrypto_missing", result="msoffcrypto not installed")
    except Exception:
        pass  # Not an Office file or not encrypted

    # Integración de olevba para análisis profundo de macros
    all_macro_code = ""
    vba_autostart = False
    vba_exec = False
    vba_disk = False
    vba_net = False
    vba_mem = False
    
    tracer.step("document_analyzer", "olevba_start", detail="Running olevba macro checking on document")
    try:
        from oletools.olevba import VBA_Parser
        vba_parser = VBA_Parser(filename=f"temp_doc{ext}", data=file_bytes)
        if vba_parser.detect_mp_macros():
            findings.append(Finding(
                category="document", title="VBA Macros Detected",
                description="This Office document contains embedded VBA macros, which are heavily used in phishing attacks to deliver payloads.",
                severity=FindingSeverity.HIGH, score_impact=20.0,
                evidence="olevba detected VBA macros"
            ))
            tracer.step("document_analyzer", "vba_macros_detected", detail="Macros found! Parsing VBA code...", score_impact=20.0)
            
            vba_parser.analyze_macros()
            
            # Combine all macro code
            for _, _, _, code in vba_parser.extract_macros():
                all_macro_code += code + "\n"
                
            # Deobfuscate
            deobf_code = deobfuscate_macro_code(all_macro_code)
            if deobf_code != all_macro_code:
                tracer.step("document_analyzer", "vba_deobfuscated", detail="Automatically reverted string reversals or ASCII Chr code sequences.")
            
            # Scan both raw and deobfuscated code
            _check_suspicious_patterns(all_macro_code, "VBA macro code", findings, tracer)
            if deobf_code != all_macro_code:
                _check_suspicious_patterns(deobf_code, "Deobfuscated VBA macro code", findings, tracer)

            # Map olevba indicators
            if vba_parser.analysis_results:
                for kw_type, keyword, description in vba_parser.analysis_results:
                    severity = FindingSeverity.MEDIUM
                    score_impact = 10.0
                    if kw_type == 'AutoExec':
                        vba_autostart = True
                        severity = FindingSeverity.CRITICAL
                        score_impact = 25.0
                    elif kw_type == 'Suspicious':
                        vba_exec = True
                        severity = FindingSeverity.HIGH
                        score_impact = 20.0
                    elif kw_type == 'IOC':
                        vba_net = True
                        severity = FindingSeverity.HIGH
                        score_impact = 15.0
                        
                    findings.append(Finding(
                        category="document",
                        title=f"Maldoc capability: {keyword}",
                        description=f"Macro capability found by olevba: {description} (Type: {kw_type})",
                        severity=severity,
                        score_impact=score_impact,
                        evidence=f"olevba keyword: {keyword}"
                    ))
                    tracer.step("document_analyzer", "olevba_indicator", detail=f"Indicator '{keyword}' ({kw_type}) found", score_impact=score_impact)
        else:
            tracer.step("document_analyzer", "olevba_check", result="No macros detected")
    except Exception as e:
        tracer.step("document_analyzer", "olevba_error", detail=str(e))

    # Fallback to check raw content for structural pattern checks (for backward compatibility)
    try:
        content_str = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        content_str = ""

    if content_str:
        _check_suspicious_patterns(content_str, "Office raw content", findings, tracer)

    # Check inside ZIP structure for vbaProject.bin and external relationships (.rels)
    relationships_urls = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            names = zf.namelist()
            for name in names:
                if "vbaProject" in name or name.endswith(".bin"):
                    bin_content = zf.read(name).decode("utf-8", errors="ignore")
                    _check_suspicious_patterns(bin_content, name, findings, tracer)
                if name.endswith(".rels"):
                    rel_content = zf.read(name).decode("utf-8", errors="ignore")
                    if "External" in rel_content or "http" in rel_content.lower():
                        ext_urls = re.findall(r'Target="(https?://[^"]+)"', rel_content)
                        if ext_urls:
                            relationships_urls.extend(ext_urls)
                            findings.append(Finding(
                                category="document", title="External references in document",
                                description=f"Document references external URLs: {', '.join(ext_urls[:3])}",
                                severity=FindingSeverity.HIGH, score_impact=15.0,
                                evidence=", ".join(ext_urls[:5]),
                            ))
    except (zipfile.BadZipFile, Exception):
        pass

    # Save previews and checks
    current_fn = getattr(tracer, "current_file", "document.docx")
    
    preview_text = ""
    if all_macro_code:
        preview_text = all_macro_code
    else:
        preview_text = content_str if content_str else "Office XML structure (No text extracted)."
        
    if relationships_urls:
        preview_text += "\n\n--- EXTRACTED XML HYPERLINKS ---\n" + "\n".join(relationships_urls)
        
    tracer.file_previews[current_fn] = preview_text

    # Scan for other OS command/network keywords
    if all_macro_code:
        code_check = all_macro_code.lower()
        vba_autostart = vba_autostart or any(re.search(p, all_macro_code, re.I) for p, _ in MALDOC_PERSISTENCE)
        vba_exec = vba_exec or any(re.search(p, all_macro_code, re.I) for p, _ in MALDOC_EXECUTION)
        vba_disk = vba_disk or any(re.search(p, all_macro_code, re.I) for p, _ in MALDOC_SYSTEM) or "adodb.stream" in code_check
        vba_net = vba_net or any(re.search(p, all_macro_code, re.I) for p, _ in MALDOC_NETWORK) or "http" in code_check
        vba_mem = vba_mem or any(re.search(p, all_macro_code, re.I) for p, _ in MALDOC_MEMORY) or "virtualalloc" in code_check

    checks = [
        {"name": "AutoExec / Autostart trigger macros (Workbook_Open)", "checked": True, "found": vba_autostart},
        {"name": "Shell / cmd.exe OS command execution calls", "checked": True, "found": vba_exec},
        {"name": "ADODB.Stream payload writing to disk", "checked": True, "found": vba_disk},
        {"name": "HTTP web downloaders (URLDownloadToFile, GET/POST)", "checked": True, "found": vba_net},
        {"name": "VirtualAlloc WinAPI Memory Injection (VirtualAlloc)", "checked": True, "found": vba_mem},
    ]
    tracer.file_checks[current_fn] = checks

    return findings


def _analyze_rtf(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    """Analyze RTF documents using rtfobj and keyword patterns."""
    findings: list[Finding] = []
    try:
        content = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "rtf_analysis", detail=f"Analyzing {len(content)} chars of RTF")

    has_ole_objects = False
    has_template_inj = False
    has_auto_update = False

    # Integración de rtfobj para análisis estructurado de objetos OLE
    tracer.step("document_analyzer", "rtfobj_start", detail="Running rtfobj parser on RTF file")
    try:
        from oletools.rtfobj import RtfObjParser
        rtf_parser = RtfObjParser(file_bytes)
        rtf_parser.parse()
        if rtf_parser.objects:
            has_ole_objects = True
            tracer.step("document_analyzer", "rtfobj_objects_found", detail=f"Found {len(rtf_parser.objects)} embedded OLE object(s)")
            for obj in rtf_parser.objects:
                class_name = getattr(obj, "class_name", "Unknown") or "Unknown"
                ole_size = len(obj.oledata) if getattr(obj, "oledata", None) else 0
                
                severity = FindingSeverity.HIGH
                score_impact = 20.0
                if "Equation" in str(class_name):
                    severity = FindingSeverity.CRITICAL
                    score_impact = 30.0
                    
                findings.append(Finding(
                    category="document",
                    title=f"RTF Embedded OLE: {class_name}",
                    description=f"RTF document contains an embedded OLE object of class '{class_name}'. This is commonly used in RTF exploits (e.g. Equation Editor CVE-2017-11882) or template injections.",
                    severity=severity,
                    score_impact=score_impact,
                    evidence=f"Class: {class_name}, Size: {ole_size} bytes"
                ))
                tracer.step("document_analyzer", "rtfobj_ole", detail=f"OLE Object: Class={class_name}, Size={ole_size} bytes", score_impact=score_impact)
        else:
            tracer.step("document_analyzer", "rtfobj_check", result="No OLE objects found")
    except Exception as e:
        tracer.step("document_analyzer", "rtfobj_error", detail=str(e))

    # Basic pattern matching for backup
    if "\\object" in content or "\\objdata" in content:
        has_ole_objects = True
        findings.append(Finding(
            category="document", title="Embedded OLE Object in RTF",
            description="RTF contains an embedded OLE object, heavily abused in Equation Editor exploits.",
            severity=FindingSeverity.HIGH, score_impact=20.0,
            evidence="Found '\\object' or '\\objdata'"
        ))

    if "\\objupdate" in content:
        has_auto_update = True
        findings.append(Finding(
            category="document", title="RTF Automatic OLE Update",
            description="RTF contains automatic update trigger (\\objupdate), executing embedded objects on load.",
            severity=FindingSeverity.CRITICAL, score_impact=30.0,
            evidence="Found '\\objupdate'"
        ))

    if "template" in content.lower() and "http" in content.lower():
        has_template_inj = True
        findings.append(Finding(
            category="document", title="RTF Template Injection",
            description="RTF document contains template injection links pointing to remote resources.",
            severity=FindingSeverity.HIGH, score_impact=25.0,
        ))

    # Save previews and checks
    current_fn = getattr(tracer, "current_file", "document.rtf")
    tracer.file_previews[current_fn] = content
    
    checks = [
        {"name": "Embedded OLE objects (Equation Editor CVE-2017-11882)", "checked": True, "found": has_ole_objects},
        {"name": "RTF remote template injections (HTTP layout link)", "checked": True, "found": has_template_inj},
        {"name": "Automatic OLE Update triggers (\\objupdate auto-run)", "checked": True, "found": has_auto_update},
    ]
    tracer.file_checks[current_fn] = checks

    # Run general patterns
    _check_suspicious_patterns(content, "RTF raw body", findings, tracer)
    return findings


def _analyze_zip(
    file_bytes: bytes, tracer: DebugTracer,
    password: Optional[str] = None,
    custom_wordlist: Optional[list[str]] = None,
    do_brute: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    decrypted_zip_bytes = file_bytes
    is_encrypted = False

    try:
        # Check if zip is encrypted
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as test_zf:
            for info in test_zf.infolist():
                if info.flag_bits & 0x1:
                    is_encrypted = True
                    break

        if is_encrypted:
            tracer.step("document_analyzer", "zip_encrypted", detail="ZIP has encrypted contents")
            success = False
            cracked = None
            if password:
                try:
                    with zipfile.ZipFile(io.BytesIO(file_bytes)) as test_zf:
                        test_zf.setpassword(password.encode("utf-8"))
                        for name in test_zf.namelist():
                            test_zf.read(name)
                            success = True
                            cracked = file_bytes
                            break
                except Exception:
                    pass

            if not success and do_brute:
                pw, attempts, cracked_bytes = brute_force_password(file_bytes, ".zip", tracer, custom_wordlist)
                if pw is not None and cracked_bytes:
                    decrypted_zip_bytes = cracked_bytes
                    success = True
                    findings.append(Finding(
                        category="document", title="ZIP password cracked",
                        description=f"ZIP archive password cracked after {attempts} attempts.",
                        severity=FindingSeverity.HIGH, score_impact=15.0,
                    ))
                else:
                    findings.append(Finding(
                        category="document", title="Encrypted ZIP - password not found",
                        description="ZIP archive is password protected and could not be decrypted.",
                        severity=FindingSeverity.MEDIUM, score_impact=10.0,
                    ))
                    return findings
            elif not success:
                findings.append(Finding(
                    category="document", title="Encrypted ZIP",
                    description="ZIP archive is password-protected. Provide a password or enable brute-force.",
                    severity=FindingSeverity.MEDIUM, score_impact=10.0,
                ))
                return findings

        # Now extract and scan recursively
        with zipfile.ZipFile(io.BytesIO(decrypted_zip_bytes)) as active_zf:
            # Set the password if cracked/provided
            if password:
                active_zf.setpassword(password.encode("utf-8"))
            for step in tracer.get_steps():
                if step.analyzer == "bruteforce" and step.action == "found" and "password:" in step.result:
                    crack_pw = step.result.split("password:")[-1]
                    active_zf.setpassword(crack_pw.encode("utf-8"))
                    break

            names = active_zf.namelist()
            tracer.step("document_analyzer", "zip_opened", detail=f"{len(names)} files inside ZIP")

            for name in names:
                info = active_zf.getinfo(name)
                # Skip directories
                if info.is_dir():
                    continue

                name_ext = Path(name).suffix.lower()

                # Read inner bytes
                try:
                    inner_bytes = active_zf.read(name)
                except Exception as e:
                    tracer.step("document_analyzer", "zip_read_error", detail=f"Could not read '{name}': {str(e)}")
                    continue

                # Forensic type check of the inner file
                inner_real_ext = detect_extension_by_magic(inner_bytes, name)
                
                # Check for double extension
                stem = Path(name).stem
                if "." in stem:
                    findings.append(Finding(
                        category="document", title=f"Double extension in ZIP: {name}",
                        description=f"File '{name}' inside the ZIP has a double extension, commonly used to disguise files.",
                        severity=FindingSeverity.HIGH, score_impact=18.0,
                        evidence=name,
                    ))

                # Check double extensions / suspicious extensions
                if inner_real_ext in SUSPICIOUS_EXTENSIONS:
                    findings.append(Finding(
                        category="document", title=f"Suspicious file in ZIP: {name}",
                        description=f"ZIP archive contains '{name}' which is an executable or script extension ({inner_real_ext}).",
                        severity=FindingSeverity.CRITICAL, score_impact=25.0,
                        evidence=name,
                    ))
                    tracer.step("document_analyzer", "zip_suspicious_file", detail=f"Executable in ZIP: {name}", score_impact=25.0)

                # Very large decompressed size (zip bomb)
                if info.file_size > 100_000_000 and info.compress_size < 1_000_000:
                    findings.append(Finding(
                        category="document", title="Possible ZIP bomb",
                        description=f"File '{name}' has compression ratio of {info.file_size / max(info.compress_size, 1):.0f}x.",
                        severity=FindingSeverity.CRITICAL, score_impact=30.0,
                    ))

                # Scan images for QR codes
                if inner_real_ext in (".png", ".jpg", ".jpeg"):
                    try:
                        import cv2
                        import numpy as np
                        nparr = np.frombuffer(inner_bytes, np.uint8)
                        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                        if img is not None:
                            detector = cv2.QRCodeDetector()
                            data, bbox, _ = detector.detectAndDecode(img)
                            if data:
                                findings.append(Finding(
                                    category="document", title=f"QR Code in ZIP: {name}",
                                    description=f"ZIP image '{name}' contains a QR code redirecting to: {data}.",
                                    severity=FindingSeverity.CRITICAL, score_impact=30.0,
                                    evidence=data,
                                ))
                    except Exception:
                        pass

                # Recursive scan of supported documents / codes / scripts
                if inner_real_ext in SUPPORTED_EXTENSIONS:
                    tracer.step("document_analyzer", "zip_recursive_scan", detail=f"Extracting and recursively scanning: {name} (Detected type: {inner_real_ext})")
                    # Do not run another crack attempt inside the zip to avoid infinite looping
                    inner_findings, _, _, _ = analyze_document(
                        inner_bytes, name, tracer, password=password, custom_wordlist=custom_wordlist, do_brute=False
                    )
                    findings.extend(inner_findings)
                else:
                    tracer.step("document_analyzer", "zip_skip_inner", detail=f"Omit inner file: {name} (Unsupported type: {inner_real_ext})")

    except zipfile.BadZipFile:
        findings.append(Finding(
            category="document", title="Invalid ZIP file",
            description="ZIP archive is corrupted or invalid.",
            severity=FindingSeverity.MEDIUM, score_impact=8.0,
        ))
    except Exception as e:
        tracer.step("document_analyzer", "zip_error", detail=str(e))

    return findings


def _analyze_sql(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "sql_analysis", detail=f"Analyzing {len(content)} chars of SQL")

    sql_inj = False
    sql_url = False

    lines = content.splitlines()

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            sql_inj = True
            
            matched_lines = []
            for line_idx, line_content in enumerate(lines, 1):
                if re.search(pattern, line_content, re.IGNORECASE):
                    matched_lines.append(f"Line {line_idx}: {line_content.strip()}")
            
            evidence_parts = [f"Match '{pattern}'"]
            if matched_lines:
                evidence_parts.append("\nSuspicious Code Context:")
                evidence_parts.extend(matched_lines[:5])
            evidence_detail = "\n".join(evidence_parts)

            findings.append(Finding(
                category="document", title=f"Suspicious SQL pattern: {pattern}",
                description=f"SQL file contains pattern '{pattern}' which could be malicious.",
                severity=FindingSeverity.HIGH, score_impact=15.0,
                evidence=evidence_detail,
            ))

    # Check for URLs in SQL
    urls = re.findall(r"https?://[^\s'\"]+", content)
    if urls:
        sql_url = True
        
        matched_lines = []
        for line_idx, line_content in enumerate(lines, 1):
            if any(url in line_content for url in urls):
                matched_lines.append(f"Line {line_idx}: {line_content.strip()}")

        evidence_parts = [f"URLs: {', '.join(urls[:5])}"]
        if matched_lines:
            evidence_parts.append("\nSuspicious Code Context:")
            evidence_parts.extend(matched_lines[:5])
        evidence_detail = "\n".join(evidence_parts)

        findings.append(Finding(
            category="document", title="URLs found in SQL file",
            description=f"SQL file contains {len(urls)} URL(s) that may download malicious payloads.",
            severity=FindingSeverity.MEDIUM, score_impact=10.0,
            evidence=evidence_detail,
        ))

    # Save previews and checks (NO TRUNCATION in backend!)
    current_fn = getattr(tracer, "current_file", "query.sql")
    tracer.file_previews[current_fn] = content
    
    checks = [
        {"name": "SQL Injection command drops (DROP, DELETE)", "checked": True, "found": sql_inj},
        {"name": "Embedded URL links pointing to download payloads", "checked": True, "found": sql_url},
    ]
    tracer.file_checks[current_fn] = checks

    return findings


def _analyze_python(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    try:
        code = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "python_analysis", detail=f"Analyzing Python script ({len(code)} chars)")

    # Suspicious capabilities in Python scripts
    py_patterns = [
        (r"socket\.socket", "Network socket creation (possible reverse shell)", FindingSeverity.HIGH, 20.0),
        (r"subprocess\.Popen|subprocess\.run|os\.system|os\.popen", "System command execution", FindingSeverity.HIGH, 20.0),
        (r"eval\(|exec\(", "Dynamic execution (eval/exec)", FindingSeverity.MEDIUM, 15.0),
        (r"base64\.b64decode|binascii\.a2b", "Base64 payload decoding", FindingSeverity.MEDIUM, 10.0),
        (r"requests\.get|urllib\.request|http\.client", "Remote download capabilities", FindingSeverity.MEDIUM, 12.0),
        (r"ctypes\.windll|kernel32|VirtualAlloc", "Direct WinAPI / Memory manipulation calls", FindingSeverity.CRITICAL, 35.0),
    ]

    lines = code.splitlines()

    for pattern, label, severity, score_impact in py_patterns:
        if re.search(pattern, code):
            # Find matching lines
            matched_lines = []
            for line_idx, line_content in enumerate(lines, 1):
                if re.search(pattern, line_content):
                    matched_lines.append(f"Line {line_idx}: {line_content.strip()}")
            
            evidence_parts = [f"Match '{pattern}'"]
            if matched_lines:
                evidence_parts.append("\nSuspicious Code Context:")
                evidence_parts.extend(matched_lines[:5])
            evidence_detail = "\n".join(evidence_parts)

            findings.append(Finding(
                category="document", title=f"Python: {label}",
                description=f"Script contains capability: {label}",
                severity=severity, score_impact=score_impact,
                evidence=evidence_detail
            ))
            tracer.step("document_analyzer", "python_pattern", detail=f"Python capability '{label}' found", score_impact=score_impact)

    # Save previews and checks (NO TRUNCATION in backend!)
    current_fn = getattr(tracer, "current_file", "script.py")
    tracer.file_previews[current_fn] = code
    
    checks = [
        {"name": "Sensitive OS Libraries & System Commands (subprocess, os.system, cmd.exe, ps)", "checked": True, "found": bool(re.search(r"subprocess|os\.system|os\.popen|cmd\.exe|powershell\.exe", code))},
        {"name": "Network Socket Calls & Connects (socket.socket, socket.connect)", "checked": True, "found": bool(re.search(r"socket\.socket|socket\.connect", code))},
        {"name": "Dynamic Code Injection Indicators (eval, exec)", "checked": True, "found": bool(re.search(r"eval\(|exec\(", code))},
        {"name": "Base64 Obfuscation & Payloads (base64.b64decode, binascii)", "checked": True, "found": bool(re.search(r"base64\.b64decode|binascii", code))},
        {"name": "HTTP Request Downloader (GET/POST, requests, http, urllib)", "checked": True, "found": bool(re.search(r"requests\.get|requests\.post|urllib|http\.client|wget", code))},
        {"name": "WinAPI / Memory Process Injection (VirtualAlloc, ctypes)", "checked": True, "found": bool(re.search(r"VirtualAlloc|ctypes", code))},
    ]
    tracer.file_checks[current_fn] = checks

    # General pattern check
    _check_suspicious_patterns(code, "Python script body", findings, tracer)
    return findings


def _analyze_powershell(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    try:
        code = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "powershell_analysis", detail=f"Analyzing PowerShell script ({len(code)} chars)")

    # General pattern / YARA check
    _check_suspicious_patterns(code, "PowerShell script body", findings, tracer)

    # Save previews and checks
    current_fn = getattr(tracer, "current_file", "script.ps1")
    tracer.file_previews[current_fn] = code
    
    checks = [
        {"name": "Invoke-Expression / IEX dynamic command execution", "checked": True, "found": bool(re.search(r"\biex\b|invoke-expression", code, re.I))},
        {"name": "ExecutionPolicy Bypass flag used in parameters", "checked": True, "found": bool(re.search(r"bypass|executionpolicy|-ep", code, re.I))},
        {"name": "Web downloader requests (WebClient, DownloadString)", "checked": True, "found": bool(re.search(r"webclient|downloadstring|downloadfile", code, re.I))},
        {"name": "TCP Socket reverse shell connection attempt", "checked": True, "found": bool(re.search(r"tcpclient|sockets|socket", code, re.I))},
        {"name": "Base64 Encoded Command execution flag (-enc, -e)", "checked": True, "found": bool(re.search(r"-enc|-e\s+|-encodedcommand", code, re.I))},
    ]
    tracer.file_checks[current_fn] = checks
    return findings


def _analyze_shell(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    try:
        code = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "shell_analysis", detail=f"Analyzing Shell script ({len(code)} chars)")

    # General pattern / YARA check
    _check_suspicious_patterns(code, "Shell script body", findings, tracer)

    current_fn = getattr(tracer, "current_file", "script.sh")
    tracer.file_previews[current_fn] = code
    
    checks = [
        {"name": "Reverse TCP network redirection (/dev/tcp or /dev/udp)", "checked": True, "found": bool(re.search(r"/dev/tcp/|/dev/udp/", code, re.I))},
        {"name": "Netcat reverse shell flags or listeners (-e /bin/sh)", "checked": True, "found": bool(re.search(r"nc\s+-|netcat\s+-", code, re.I))},
        {"name": "FIFO backpipe creation for shell redirect (mkfifo)", "checked": True, "found": bool(re.search(r"mkfifo|backpipe", code, re.I))},
    ]
    tracer.file_checks[current_fn] = checks
    return findings


def _analyze_batch(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    try:
        code = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "batch_analysis", detail=f"Analyzing Batch script ({len(code)} chars)")

    # General pattern / YARA check
    _check_suspicious_patterns(code, "Batch script body", findings, tracer)

    current_fn = getattr(tracer, "current_file", "script.bat")
    tracer.file_previews[current_fn] = code
    
    checks = [
        {"name": "Hidden command execution or Echo off", "checked": True, "found": bool(re.search(r"@echo\s+off", code, re.I))},
        {"name": "System executable downloads (powershell, certutil)", "checked": True, "found": bool(re.search(r"powershell|certutil|bitsadmin|curl|wget", code, re.I))},
    ]
    tracer.file_checks[current_fn] = checks
    return findings


def _analyze_pe(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    
    tracer.step("document_analyzer", "pe_analysis", detail=f"Analyzing PE Executable/DLL ({len(file_bytes)} bytes)")

    # Hex and ASCII representations for signature search
    hex_rep = file_bytes[:8000].hex()
    ascii_rep = file_bytes[:8000].decode("utf-8", errors="ignore")

    _check_suspicious_patterns(ascii_rep + "\n" + hex_rep, "PE Executable binary", findings, tracer)

    current_fn = getattr(tracer, "current_file", "binary.dll")
    
    # Generate structured hex dump for visual inspection
    hex_dump = []
    for i in range(0, min(len(file_bytes), 1536), 16):
        chunk = file_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_dump.append(f"{i:08x}:  {hex_part:<48}  |{ascii_part}|")
    
    tracer.file_previews[current_fn] = "\n".join(hex_dump) + ("\n... [BINARY CODES TRUNCATED FOR VISUAL PERFORMANCE]" if len(file_bytes) > 1536 else "")
    
    checks = [
        {"name": "MZ Header signature present at offset 0", "checked": True, "found": file_bytes.startswith(b"MZ")},
        {"name": "PE Signature present in DOS header", "checked": True, "found": b"PE\x00\x00" in file_bytes[:1024]},
        {"name": "Standard DOS error string (This program cannot be run in DOS mode)", "checked": True, "found": b"This program cannot be run in DOS mode" in file_bytes[:1024]},
    ]

    # Deep static PE import analysis via pefile
    pe_imports = []
    suspicious_apis_found = []
    
    sensitive_apis = {
        "Injection & Execution": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext", "RtlCreateUserThread"],
        "Anti-Analysis & Evasion": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString", "FindWindow", "Sleep", "QueryPerformanceCounter"],
        "Process Manipulation": ["CreateProcess", "CreateProcessAsUser", "ShellExecute", "WinExec", "TerminateProcess", "OpenProcess"],
        "Networking & Sockets": ["WSAStartup", "socket", "connect", "send", "recv", "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"],
        "Registry Persistence": ["RegOpenKeyEx", "RegSetValueEx", "RegCreateKeyEx", "RegDeleteValue"]
    }
    
    try:
        import pefile
        pe = pefile.PE(data=file_bytes)
        
        # Extract imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', errors='ignore')
                        pe_imports.append(f"{dll_name}!{api_name}")
                        
                        # Match with sensitive API patterns
                        for category, apis in sensitive_apis.items():
                            for s_api in apis:
                                if s_api.lower() in api_name.lower():
                                    suspicious_apis_found.append(f"{api_name} ({category})")
                                    
        if suspicious_apis_found:
            findings.append(Finding(
                category="document",
                title="Suspicious PE Imports Detected",
                description=f"PE binary imports sensitive Windows APIs: {', '.join(suspicious_apis_found[:8])}.",
                severity=FindingSeverity.HIGH,
                score_impact=30.0,
                evidence=f"Imported APIs: {', '.join(suspicious_apis_found)}"
            ))
            tracer.step("document_analyzer", "pe_suspicious_imports", 
                        detail=f"Found {len(suspicious_apis_found)} highly sensitive imports", 
                        result="HIGH RISK API IMPORTS")
    except Exception as e:
        tracer.step("document_analyzer", "pefile_error", detail=f"Skipping IAT analysis: {str(e)}")
        
    for cat, apis in sensitive_apis.items():
        found_in_cat = [api for api in suspicious_apis_found if cat in api]
        checks.append({
            "name": f"Imports APIs for {cat} ({', '.join(apis[:3])})",
            "checked": True,
            "found": len(found_in_cat) > 0
        })

    tracer.file_checks[current_fn] = checks
    return findings


def _analyze_html(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "html_analysis", detail=f"Analyzing HTML page ({len(content)} chars)")

    # HTML Phishing & redirect features
    html_patterns = [
        (r"<form[^>]*action=\"https?://", "Form submitting to external URL (possible credential harvesting)", FindingSeverity.HIGH, 25.0),
        (r"http-equiv=\"refresh\"", "Automatic meta-refresh redirect", FindingSeverity.HIGH, 20.0),
        (r"<iframe[^>]*src=\"https?://", "Embedded external iframe (possible drive-by download)", FindingSeverity.MEDIUM, 15.0),
        (r"data:text/html;base64", "Data URI redirect/obfuscation", FindingSeverity.HIGH, 25.0),
        (r"unescape\s*\(|eval\s*\(|document\.write\s*\(", "JavaScript dynamic evaluation/obfuscation", FindingSeverity.MEDIUM, 15.0),
        (r"password", "Password input fields detected (phishing check)", FindingSeverity.LOW, 5.0),
        (r"\b(?:fetch|XMLHttpRequest|ActiveXObject\(['\"]Microsoft\.XMLHTTP['\"]\)|WebSocket)\b", "JavaScript suspicious network request/connection call", FindingSeverity.MEDIUM, 15.0),
        (r"\b(?:createElement\(['\"]a['\"]\)|\.download\s*=|URL\.createObjectURL|msSaveOrOpenBlob|ActiveXObject\(['\"]Adodb\.Stream['\"]\))\b", "JavaScript dynamic payload download/trigger", FindingSeverity.HIGH, 25.0),
        (r"\b(?:eval|Function|execScript|setTimeout\s*\(\s*['\"].*?['\"]|setInterval\s*\(\s*['\"].*?['\"]|document\.write|document\.writeln)\b", "Dangerous dynamic JS code execution (eval/Function/document.write)", FindingSeverity.HIGH, 25.0),
        (r"\b(?:CryptoJS|AES|DES|RC4|atob|btoa|String\.fromCharCode)\b", "Suspected custom JS encryption/obfuscation library", FindingSeverity.MEDIUM, 15.0),
        (r"(?:\s*\[\]\s*|\s*\(\)\s*|\s*\{\}\s*|\s*!\s*|\s*\+\s*){50,}", "JSFuck obfuscated code sequence detected", FindingSeverity.HIGH, 25.0),
        (r"\bcreateElement\(['\"]script['\"]\)", "JavaScript dynamic script tag creation/injection", FindingSeverity.HIGH, 25.0),
        (r"\bon(?:load|error|click|submit|mouseover)\s*=\s*['\"]javascript:|src\s*=\s*['\"]javascript:", "Dynamic inline JS execution handler", FindingSeverity.HIGH, 20.0),
        (r"\b(?:location\.replace|location\.assign|location\.href)\b", "JavaScript location redirection method", FindingSeverity.MEDIUM, 15.0),
    ]

    lines = content.splitlines()

    for pattern, label, severity, score_impact in html_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            # Find matching lines
            matched_lines = []
            for line_idx, line_content in enumerate(lines, 1):
                if re.search(pattern, line_content, re.IGNORECASE):
                    matched_lines.append(f"Line {line_idx}: {line_content.strip()}")
            
            evidence_parts = [f"Match '{pattern}'"]
            if matched_lines:
                evidence_parts.append("\n".join(matched_lines[:3]))
                if len(matched_lines) > 3:
                    evidence_parts.append(f"... and {len(matched_lines)-3} more lines")
            
            findings.append(Finding(
                category="document",
                title=label,
                description=f"HTML content matches '{pattern}' which is commonly associated with malicious behavior.",
                severity=severity,
                score_impact=score_impact,
                evidence="\n".join(evidence_parts)
            ))
            tracer.step("document_analyzer", "html_pattern", detail=f"Found: {label}", score_impact=score_impact)

    # HTML Smuggling specific checks
    smuggling_indicators = [
        r"new\s+Blob",
        r"URL\.createObjectURL",
        r"window\.navigator\.msSaveOrOpenBlob",
        r"\.download\s*=",
        r"atob\(",
        r"application/octet-stream"
    ]
    matches = [ind for ind in smuggling_indicators if re.search(ind, content, re.IGNORECASE)]
    if len(matches) >= 3:
        findings.append(Finding(
            category="document", title="HTML Smuggling Detected",
            description="Found multiple indicators of HTML Smuggling, a technique used to assemble malware dynamically inside the browser.",
            severity=FindingSeverity.CRITICAL, score_impact=35.0,
            evidence=f"Matched indicators: {', '.join(matches)}"
        ))
        tracer.step("document_analyzer", "html_smuggling", detail=f"Smuggling indicators: {matches}")

    # Save previews and checks (NO TRUNCATION in backend!)
    current_fn = getattr(tracer, "current_file", "page.html")
    tracer.file_previews[current_fn] = content
    
    checks = [
        {"name": "Phishing External Form Actions (Form Submit to HTTP)", "checked": True, "found": bool(re.search(r"<form[^>]*action=\"https?://", content, re.I))},
        {"name": "Automatic Redirect scripts (meta refresh, window.location)", "checked": True, "found": bool(re.search(r"http-equiv=\"refresh\"|window\.location", content, re.I))},
        {"name": "Drive-by downloads / Hidden frames (<iframe src=>)", "checked": True, "found": bool(re.search(r"<iframe[^>]*src=\"https?://", content, re.I))},
        {"name": "Embedded data redirects (data:text/html;base64)", "checked": True, "found": bool(re.search(r"data:text/html;base64", content, re.I))},
        {"name": "Obfuscated Javascript dynamic execution (eval, unescape)", "checked": True, "found": bool(re.search(r"unescape\s*\(|eval\s*\(", content, re.I))},
        {"name": "Password Input Fields (credential harvesting check)", "checked": True, "found": bool(re.search(r"type=\"password\"|name=\"password\"", content, re.I))},
        {"name": "Suspicious JavaScript Network Request (fetch/XHR/WS)", "checked": True, "found": bool(re.search(r"\b(?:fetch|XMLHttpRequest|ActiveXObject\(['\"]Microsoft\.XMLHTTP['\"]\)|WebSocket)\b", content, re.I))},
        {"name": "Dynamic File Download Trigger (blob download)", "checked": True, "found": bool(re.search(r"\b(?:createElement\(['\"]a['\"]\)|\.download\s*=|URL\.createObjectURL|msSaveOrOpenBlob|ActiveXObject\(['\"]Adodb\.Stream['\"]\))\b", content, re.I))},
        {"name": "Dangerous JavaScript Dynamic Code Execution (Function)", "checked": True, "found": bool(re.search(r"\b(?:eval|Function|execScript|setTimeout\s*\(\s*['\"].*?['\"]|setInterval\s*\(\s*['\"].*?['\"]|document\.write|document\.writeln)\b", content, re.I))},
        {"name": "Encryption / Decryption functions (atob/fromCharCode)", "checked": True, "found": bool(re.search(r"\b(?:CryptoJS|AES|DES|RC4|atob|btoa|String\.fromCharCode)\b", content, re.I))},
        {"name": "JSFuck Obfuscated JavaScript Code Block", "checked": True, "found": bool(re.search(r"(?:\s*\[\]\s*|\s*\(\)\s*|\s*\{\}\s*|\s*!\s*|\s*\+\s*){50,}", content, re.I))},
        {"name": "Dynamic script element injection (createElement('script'))", "checked": True, "found": bool(re.search(r"\bcreateElement\(['\"]script['\"]\)", content, re.I))},
        {"name": "Dynamic inline JS execution handler (onload, onerror)", "checked": True, "found": bool(re.search(r"\bon(?:load|error|click|submit|mouseover)\s*=\s*['\"]javascript:|src\s*=\s*['\"]javascript:", content, re.I))},
    ]
    tracer.file_checks[current_fn] = checks

    # General pattern check
    _check_suspicious_patterns(content, "HTML body", findings, tracer)
    return findings


def _analyze_txt(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    tracer.step("document_analyzer", "text_analysis", detail=f"Analyzing plain text file ({len(content)} chars)")

    lines = content.splitlines()

    # Search for URLs
    urls = re.findall(r"https?://[^\s'\"]+", content)
    if urls:
        matched_lines = []
        for line_idx, line_content in enumerate(lines, 1):
            if any(url in line_content for url in urls):
                matched_lines.append(f"Line {line_idx}: {line_content.strip()}")
        
        evidence_parts = [f"URLs found: {', '.join(urls[:5])}"]
        if matched_lines:
            evidence_parts.append("\nSuspicious Code Context:")
            evidence_parts.extend(matched_lines[:5])
        evidence_detail = "\n".join(evidence_parts)

        findings.append(Finding(
            category="document", title="URLs found in text file",
            description=f"Text file contains {len(urls)} URLs that may link to malicious sites.",
            severity=FindingSeverity.MEDIUM, score_impact=10.0,
            evidence=evidence_detail,
        ))
        tracer.step("document_analyzer", "txt_urls", detail=f"Found {len(urls)} URL(s) in text", score_impact=10.0)

    # Check for long base64 blocks (common in staging)
    base64_blobs = re.findall(r"(?:[A-Za-z0-9+/]{80,}\s*){3,}", content)
    if base64_blobs:
        matched_lines = []
        for line_idx, line_content in enumerate(lines, 1):
            if any(blob[:30] in line_content for blob in base64_blobs):
                matched_lines.append(f"Line {line_idx}: {line_content.strip()}")

        evidence_parts = [f"Base64 snippet: {base64_blobs[0][:150]}"]
        if matched_lines:
            evidence_parts.append("\nSuspicious Code Context:")
            evidence_parts.extend(matched_lines[:5])
        evidence_detail = "\n".join(evidence_parts)

        findings.append(Finding(
            category="document", title="Base64 obfuscated blob in text",
            description="Found a large consecutive base64 block. Attackers frequently use base64 in text logs to store payloads.",
            severity=FindingSeverity.HIGH, score_impact=18.0,
            evidence=evidence_detail
        ))
        tracer.step("document_analyzer", "txt_base64", detail="Large base64 blob found", score_impact=18.0)

    # Save previews and checks (NO TRUNCATION in backend!)
    current_fn = getattr(tracer, "current_file", "document.txt")
    tracer.file_previews[current_fn] = content
    
    checks = [
        {"name": "Phishing URLs & Embedded HTTP/HTTPS Links", "checked": True, "found": bool(len(urls) > 0)},
        {"name": "Large Base64 payload blocks (obfuscated staging)", "checked": True, "found": bool(len(base64_blobs) > 0)},
    ]
    tracer.file_checks[current_fn] = checks

    # General pattern check
    _check_suspicious_patterns(content, "Text body", findings, tracer)
    return findings


def _analyze_elf(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    tracer.step("document_analyzer", "elf_analysis", detail=f"Analyzing ELF Executable ({len(file_bytes)} bytes)")

    # Decode hex and extract printable strings
    hex_rep = file_bytes[:8000].hex()
    
    # Simple strings utility implementation
    printable = set(bytes(range(32, 127)))
    current = []
    strings = []
    for b in file_bytes[:50000]: # scan up to 50KB for performance
        if b in printable:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    if len(current) >= 4:
        strings.append("".join(current))
        
    strings_content = "\n".join(strings)
    
    # Run general pattern matching (YARA/Keywords) on the printable strings
    _check_suspicious_patterns(strings_content + "\n" + hex_rep, "ELF Executable binary", findings, tracer)

    current_fn = getattr(tracer, "current_file", "binary.elf")
    
    # Generate structured hex dump for visual inspection
    hex_dump = []
    for i in range(0, min(len(file_bytes), 1536), 16):
        chunk = file_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_dump.append(f"{i:08x}:  {hex_part:<48}  |{ascii_part}|")
    
    tracer.file_previews[current_fn] = "\n".join(hex_dump) + ("\n... [BINARY CODES TRUNCATED FOR VISUAL PERFORMANCE]" if len(file_bytes) > 1536 else "")
    
    # System call analyses
    process_spawning = any(x in strings_content.lower() for x in ["execve", "system", "popen", "fork", "vfork", "clone"])
    injection = any(x in strings_content.lower() for x in ["mmap", "mprotect", "munmap", "ptrace"])
    networking = any(x in strings_content.lower() for x in ["socket", "connect", "send", "recv", "bind", "listen"])
    antidebug = "ptrace" in strings_content.lower() or "sys_ptrace" in strings_content.lower()
    upx_packed = b"UPX!" in file_bytes

    if process_spawning:
        findings.append(Finding(
            category="document",
            title="Suspicious Linux Process Spawning Detected",
            description="ELF binary references system calls or functions for process spawning (execve, system, popen, fork, clone).",
            severity=FindingSeverity.HIGH,
            score_impact=20.0,
            evidence="Spawning calls referenced in binary strings."
        ))

    if injection:
        findings.append(Finding(
            category="document",
            title="Potential Memory Modification Symbols Detected",
            description="ELF binary contains symbols related to memory mapping or protection modification (mmap, mprotect), often used for shellcode injection.",
            severity=FindingSeverity.HIGH,
            score_impact=25.0,
            evidence="mmap/mprotect functions present in strings."
        ))

    if upx_packed:
        findings.append(Finding(
            category="document",
            title="ELF Packed with UPX",
            description="ELF executable is packed using the UPX compressor. Malware authors frequently use UPX packing to evade simple static signature scanners.",
            severity=FindingSeverity.HIGH,
            score_impact=25.0,
            evidence="Found UPX! magic signature inside binary."
        ))

    checks = [
        {"name": "ELF Header signature present at offset 0", "checked": True, "found": file_bytes.startswith(b"\x7fELF")},
        {"name": "UPX packed binary detected", "checked": True, "found": upx_packed},
        {"name": "Contains Linux process spawning functions (execve/system)", "checked": True, "found": process_spawning},
        {"name": "Contains memory allocation & protection modifications (mmap/mprotect)", "checked": True, "found": injection},
        {"name": "Network socket communications referenced (socket/connect)", "checked": True, "found": networking},
        {"name": "Anti-debugging capabilities checked (ptrace)", "checked": True, "found": antidebug},
    ]

    tracer.file_checks[current_fn] = checks
    return findings


def _analyze_macho(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    tracer.step("document_analyzer", "macho_analysis", detail=f"Analyzing Mach-O Executable ({len(file_bytes)} bytes)")

    # Decode hex and extract printable strings
    hex_rep = file_bytes[:8000].hex()
    
    # Simple strings utility implementation
    printable = set(bytes(range(32, 127)))
    current = []
    strings = []
    for b in file_bytes[:50000]: # scan up to 50KB for performance
        if b in printable:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    if len(current) >= 4:
        strings.append("".join(current))
        
    strings_content = "\n".join(strings)
    
    # Run general pattern matching (YARA/Keywords) on the printable strings
    _check_suspicious_patterns(strings_content + "\n" + hex_rep, "Mach-O Executable binary", findings, tracer)

    current_fn = getattr(tracer, "current_file", "binary.macho")
    
    # Generate structured hex dump for visual inspection
    hex_dump = []
    for i in range(0, min(len(file_bytes), 1536), 16):
        chunk = file_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_dump.append(f"{i:08x}:  {hex_part:<48}  |{ascii_part}|")
    
    tracer.file_previews[current_fn] = "\n".join(hex_dump) + ("\n... [BINARY CODES TRUNCATED FOR VISUAL PERFORMANCE]" if len(file_bytes) > 1536 else "")
    
    # System call analyses
    process_spawning = any(x in strings_content.lower() for x in ["execve", "system", "popen", "fork", "vfork", "clone"])
    networking = any(x in strings_content.lower() for x in ["socket", "connect", "send", "recv", "bind", "listen"])
    antidebug = any(x in strings_content.lower() for x in ["ptrace", "sysctl", "sysctlbyname"])
    upx_packed = b"UPX!" in file_bytes
    is_macho_magic = file_bytes.startswith(b"\xfe\xed\xfa\xce") or file_bytes.startswith(b"\xce\xfa\xed\xfe") or file_bytes.startswith(b"\xfe\xed\xfa\xcf") or file_bytes.startswith(b"\xcf\xfa\xed\xfe")

    if process_spawning:
        findings.append(Finding(
            category="document",
            title="Suspicious Mach-O Process Spawning Detected",
            description="Mach-O binary references functions for process spawning (execve, system, popen, fork, clone).",
            severity=FindingSeverity.HIGH,
            score_impact=20.0,
            evidence="Spawning calls referenced in binary strings."
        ))

    if upx_packed:
        findings.append(Finding(
            category="document",
            title="Mach-O Packed with UPX",
            description="Mach-O executable is packed using the UPX compressor.",
            severity=FindingSeverity.HIGH,
            score_impact=25.0,
            evidence="Found UPX! magic signature inside binary."
        ))

    checks = [
        {"name": "Mach-O Header signature present at offset 0", "checked": True, "found": is_macho_magic},
        {"name": "UPX packed binary detected", "checked": True, "found": upx_packed},
        {"name": "Contains process spawning functions (execve/system)", "checked": True, "found": process_spawning},
        {"name": "Network socket communications referenced (socket/connect)", "checked": True, "found": networking},
        {"name": "Anti-debugging capabilities checked (ptrace/sysctl)", "checked": True, "found": antidebug},
    ]

    tracer.file_checks[current_fn] = checks
    return findings


def _analyze_lnk(file_bytes: bytes, tracer: DebugTracer) -> list[Finding]:
    findings: list[Finding] = []
    current_fn = getattr(tracer, "current_file", "unknown.lnk")
    try:
        import LnkParse3
        lnk = LnkParse3.lnk_file(indata=file_bytes)
        lnk_data = lnk.get_json()
        
        target = lnk_data.get("link_info", {}).get("local_base_path", "")
        args = lnk_data.get("string_data", {}).get("command_line_arguments", "")
        
        tracer.step("document_analyzer", "lnk_analysis", detail=f"Target: {target}, Args: {args}")
        
        full_cmd = f"{target} {args}".lower()
        if "powershell" in full_cmd or "cmd.exe" in full_cmd or "mshta" in full_cmd or "certutil" in full_cmd or "wscript" in full_cmd or "cscript" in full_cmd or "rundll32" in full_cmd:
            findings.append(Finding(
                category="document", title="Malicious LNK Execution",
                description="LNK file points to a dangerous system executable (Living off the Land binary).",
                severity=FindingSeverity.CRITICAL, score_impact=35.0,
                evidence=f"Target: {target}\nArgs: {args}"
            ))
            
        if current_fn in tracer.file_metadata:
            tracer.file_metadata[current_fn]["LNK Target"] = target
            tracer.file_metadata[current_fn]["LNK Arguments"] = args
        else:
            tracer.file_metadata[current_fn] = {"LNK Target": target, "LNK Arguments": args}
            
        checks = [
            {"name": "Valid LNK file structure parsed", "checked": True, "found": True},
            {"name": "LNK points to LOLBin (powershell, cmd, mshta)", "checked": True, "found": "powershell" in full_cmd or "cmd.exe" in full_cmd or "mshta" in full_cmd},
        ]
        tracer.file_checks[current_fn] = checks
        
    except ImportError:
        tracer.step("document_analyzer", "lnk_analysis", detail="LnkParse3 not installed, skipping advanced LNK parsing")
    except Exception as e:
        tracer.step("document_analyzer", "lnk_error", detail=str(e))
        
    return findings
