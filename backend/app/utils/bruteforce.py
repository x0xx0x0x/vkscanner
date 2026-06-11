"""
Brute-force password cracker for protected documents.
Supports PDF (pikepdf), ZIP (zipfile), Office (msoffcrypto-tool).
"""

from __future__ import annotations

import io
import time
import zipfile
from typing import Optional

from app.utils.debug_trace import DebugTracer

COMMON_PASSWORDS: list[str] = [
    "", "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
    "football", "monkey", "letmein", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
    "123qwe", "killer", "trustno1", "jordan", "zxcvbnm", "asdfgh",
    "hunter", "buster", "soccer", "batman", "sunshine", "iloveyou",
    "charlie", "robert", "hockey", "ranger", "daniel", "starwars",
    "112233", "computer", "jessica", "pepper", "1111", "zxcvbn",
    "555555", "11111111", "131313", "freedom", "777777", "pass",
    "princess", "cheese", "amanda", "summer", "love", "infected",
    "nicole", "chelsea", "biteme", "access", "987654321", "dallas",
    "thunder", "taylor", "matrix", "password1", "password123", "admin",
    "admin123", "root", "toor", "pass123", "test", "test123", "guest",
    "changeme", "welcome", "welcome1", "p@ssw0rd", "P@ssw0rd",
    "Password1", "Password123", "abc1234", "default", "hello", "secret",
    "1q2w3e4r", "qwerty123", "login", "user", "user123", "1234abcd",
    "passwd", "temp", "123abc", "a1b2c3", "internet", "service",
    "passpass", "12341234", "22222222", "99999999", "asdfjkl",
    "Password1!", "Passw0rd!", "contraseña", "clave", "clave123", "hola",
]


def _try_pdf(file_bytes: bytes, password: str) -> bool:
    try:
        import pikepdf
        with pikepdf.open(io.BytesIO(file_bytes), password=password):
            return True
    except Exception:
        return False


def _try_zip(file_bytes: bytes, password: str) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            for name in zf.namelist():
                zf.read(name, pwd=password.encode("utf-8") if password else None)
                return True
        return False
    except Exception:
        return False


def _try_office(file_bytes: bytes, password: str) -> bool:
    try:
        import msoffcrypto
        f = io.BytesIO(file_bytes)
        office_file = msoffcrypto.OfficeFile(f)
        if not office_file.is_encrypted():
            return True
        decrypted = io.BytesIO()
        office_file.load_key(password=password)
        office_file.decrypt(decrypted)
        return True
    except Exception:
        return False


CRACKERS = {
    ".pdf": _try_pdf, ".zip": _try_zip,
    ".docx": _try_office, ".xlsx": _try_office, ".pptx": _try_office,
    ".doc": _try_office, ".xls": _try_office, ".ppt": _try_office,
}


def _get_decrypted_content(file_bytes: bytes, ext: str, password: str) -> Optional[bytes]:
    try:
        if ext == ".pdf":
            import pikepdf
            pdf = pikepdf.open(io.BytesIO(file_bytes), password=password)
            output = io.BytesIO()
            pdf.save(output)
            return output.getvalue()
        elif ext == ".zip":
            return file_bytes
        elif ext in (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"):
            import msoffcrypto
            f = io.BytesIO(file_bytes)
            office_file = msoffcrypto.OfficeFile(f)
            office_file.load_key(password=password)
            decrypted = io.BytesIO()
            office_file.decrypt(decrypted)
            return decrypted.getvalue()
    except Exception:
        pass
    return None


def brute_force_password(
    file_bytes: bytes,
    file_extension: str,
    tracer: DebugTracer,
    custom_wordlist: Optional[list[str]] = None,
    max_attempts: int = 10000,
    timeout_seconds: float = 60.0,
) -> tuple[Optional[str], int, Optional[bytes]]:
    """Attempt to crack the password of a protected document."""
    ext = file_extension.lower()
    cracker = CRACKERS.get(ext)
    if cracker is None:
        tracer.step("bruteforce", "skip", detail=f"No cracker for {ext}", result="unsupported")
        return None, 0, None

    tracer.step("bruteforce", "start", detail=f"Brute-force {ext}", result=f"max={max_attempts}")

    passwords = list(COMMON_PASSWORDS)
    if custom_wordlist:
        passwords.extend(custom_wordlist)
    seen: set[str] = set()
    unique: list[str] = []
    for p in passwords:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    start_time = time.time()
    attempts = 0
    for password in unique:
        if attempts >= max_attempts or (time.time() - start_time) >= timeout_seconds:
            break
        attempts += 1
        if cracker(file_bytes, password):
            tracer.step("bruteforce", "found", detail=f"After {attempts} attempts", result=f"password:{password}", score_impact=15.0)
            return password, attempts, _get_decrypted_content(file_bytes, ext, password)
        if attempts % 100 == 0:
            tracer.step("bruteforce", "progress", detail=f"{attempts} tried")

    tracer.step("bruteforce", "complete", detail=f"{attempts} tried", result="not_found")
    return None, attempts, None
