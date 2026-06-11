#!/usr/bin/env python3
"""
VK Scanner (Voight-Kampff) — Command Line Interface (API Client wrapper)
Suite de Inteligencia de Amenazas y Detección de Phishing 100% Local.
"""

import sys
import os
import argparse
from pathlib import Path
import json

try:
    import requests
except ImportError:
    print("Error: El paquete 'requests' no está instalado. Ejecute: pip install requests")
    sys.exit(1)

# Colores para el formateo de consola (ANSI)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

if os.environ.get('NO_COLOR') or not sys.stdout.isatty():
    for attr in dir(Colors):
        if not attr.startswith('__'): setattr(Colors, attr, '')

def print_banner():
    banner = (
        f"{Colors.RED}{Colors.BOLD}\n"
        "        __                                         \n"
        " _   __/ /________________ _____  ____  ___  _____\n"
        "| | / / //_/ ___/ ___/ __ `/ __ \\/ __ \\/ _ \\/ ___/\n"
        "| |/ / ,< (__  ) /__/ /_/ / / / / / / /  __/ /    \n"
        "|___/_/|_/____/\\___/\\__,_/_/ /_/_/ /_/\\___/_/     \n"
        f"{Colors.END}{Colors.CYAN}{Colors.BOLD}\n"
        "  [ vkscanner — voight-kampff threat intelligence suite ]\n"
        "  [          API Client Local Wrapper v2.5              ]\n"
        f"{Colors.END}"
    )
    print(banner)

def start_web_suite():
    import subprocess
    import webbrowser
    import time
    print(f"{Colors.BLUE}🔄 Iniciando la Suite Web de Voight-Kampff (Docker)...{Colors.END}")
    project_dir = os.path.dirname(os.path.realpath(__file__))
    try:
        subprocess.run(["docker", "compose", "up", "-d"], cwd=project_dir, check=True)
        print(f"{Colors.GREEN}✓ Contenedores levantados exitosamente.{Colors.END}")
        print(f"{Colors.CYAN}🌐 Abriendo http://localhost:3000 en su navegador por defecto...{Colors.END}")
        time.sleep(2)
        webbrowser.open("http://localhost:3000")
    except Exception as e:
        print(f"{Colors.RED}✖ Error al iniciar Docker Compose: {e}{Colors.END}")

def get_risk_color(classification: str) -> str:
    c = classification.upper()
    if c == "LOW": return Colors.GREEN
    elif c == "MEDIUM": return Colors.YELLOW
    elif c == "HIGH": return Colors.RED
    else: return Colors.RED + Colors.BOLD

def render_score_bar(score: float, color: str) -> str:
    filled = int(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    return f"{color}[{bar}] {score:.1f}/100{Colors.END}"

def print_box_title(title: str, color=Colors.CYAN):
    print(f"\n{color}┌── {Colors.BOLD}{title}{Colors.END}{color} " + "─" * (76 - len(title)) + "┐")

def print_box_footer(color=Colors.CYAN):
    print(f"{color}└" + "─" * 78 + "┘")

def display_results(result: dict, show_trace=False):
    classification = result.get('classification', 'UNKNOWN')
    risk_color = get_risk_color(classification)
    score = result.get('risk_score', 0.0)
    
    print_box_title("DATOS CLAVE DEL OBJETIVO", Colors.CYAN)
    print(f" {Colors.CYAN}│{Colors.END} {Colors.BOLD}Objetivo:{Colors.END} {result.get('target', 'N/A')}")
    print(f" {Colors.CYAN}│{Colors.END} {Colors.BOLD}ID de Escaneo:{Colors.END} {Colors.BLUE}{result.get('scan_id', 'N/A')}{Colors.END} | {Colors.BOLD}Tipo:{Colors.END} {result.get('scan_type', 'N/A').upper()}")
    print(f" {Colors.CYAN}│{Colors.END} {Colors.BOLD}Clasificación:{Colors.END} {risk_color}{classification}{Colors.END} | {Colors.BOLD}Confianza:{Colors.END} {Colors.CYAN}{result.get('confidence', 0.0):.1f}%{Colors.END}")
    print_box_footer(Colors.CYAN)

    print_box_title("MEDIDOR DE RIESGO", Colors.CYAN)
    print(f" {Colors.CYAN}│{Colors.END} {Colors.BOLD}Score de Riesgo:{Colors.END} {risk_color}{score:.1f}/100{Colors.END}")
    print(f" {Colors.CYAN}│{Colors.END} {render_score_bar(score, risk_color)}")
    print_box_footer(Colors.CYAN)

    print_box_title("RESUMEN EJECUTIVO", Colors.CYAN)
    summary = result.get('summary', '')
    for line in summary.split('\n'):
        if line.strip():
            print(f" {Colors.CYAN}│{Colors.END} {line}")
    print_box_footer(Colors.CYAN)
    
    findings = result.get('findings', [])
    if findings:
        print_box_title("HALLAZGOS DETECTADOS", Colors.YELLOW)
        for f in findings:
            f_color = get_risk_color(f.get('severity', 'LOW'))
            print(f" {Colors.YELLOW}│{Colors.END} {f_color}■ {f.get('severity', 'LOW').upper()}{Colors.END}: {f.get('title')}")
            print(f" {Colors.YELLOW}│{Colors.END}   {f.get('description')}")
        print_box_footer(Colors.YELLOW)

    if show_trace and 'debug_trace' in result:
        print_box_title("TRAZA FORENSE Y DEBUGGING", Colors.MAGENTA)
        for step in result['debug_trace']:
            print(f" {Colors.MAGENTA}│{Colors.END} [{step.get('timestamp', '')[11:19]}] {Colors.CYAN}{step.get('analyzer')}{Colors.END} -> {step.get('action')}")
            if step.get('detail'):
                print(f" {Colors.MAGENTA}│{Colors.END}    └─ {step.get('detail')}")
        print_box_footer(Colors.MAGENTA)

API_BASE = "http://localhost:8000/api"

def check_api_health():
    try:
        requests.get(f"{API_BASE}/health", timeout=3)
        return True
    except requests.exceptions.RequestException:
        return False

def run_url_scan(url, follow_redirects=True, use_whois=True, show_trace=False):
    if not check_api_health():
        print(f"{Colors.RED}✖ Error: La API local no está respondiendo. Asegúrese de que el contenedor de Docker esté ejecutándose con 'docker compose up -d' o 'vkscanner -w'{Colors.END}")
        sys.exit(1)
        
    print(f"{Colors.BLUE}🔄 Enviando URL a la API local de VK Scanner...{Colors.END}")
    payload = {
        "url": url,
        "follow_redirects": follow_redirects
    }
    
    try:
        r = requests.post(f"{API_BASE}/scan/url", json=payload)
        r.raise_for_status()
        display_results(r.json(), show_trace)
    except Exception as e:
        print(f"{Colors.RED}✖ Error en el análisis: {e}{Colors.END}")

def run_email_scan(file_path, show_trace=False):
    if not check_api_health():
        print(f"{Colors.RED}✖ Error: La API local no está respondiendo.{Colors.END}")
        sys.exit(1)
        
    print(f"{Colors.BLUE}🔄 Enviando EML a la API local de VK Scanner...{Colors.END}")
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            r = requests.post(f"{API_BASE}/scan/email-file", files=files)
            r.raise_for_status()
            display_results(r.json(), show_trace)
    except Exception as e:
        print(f"{Colors.RED}✖ Error en el análisis: {e}{Colors.END}")

def run_document_scan(file_path, password=None, wordlist_file=None, do_brute=False, show_trace=False):
    if not check_api_health():
        print(f"{Colors.RED}✖ Error: La API local no está respondiendo.{Colors.END}")
        sys.exit(1)
        
    print(f"{Colors.BLUE}🔄 Enviando documento a la API local de VK Scanner...{Colors.END}")
    try:
        data = {}
        if password: data['password'] = password
        if wordlist_file:
            with open(wordlist_file, 'r') as wf:
                data['custom_passwords'] = wf.read()
                
        with open(file_path, 'rb') as f:
            files = {'file': f}
            r = requests.post(f"{API_BASE}/scan/document", files=files, data=data)
            r.raise_for_status()
            display_results(r.json(), show_trace)
    except Exception as e:
        print(f"{Colors.RED}✖ Error en el análisis: {e}{Colors.END}")

def main():
    class CustomFormatter(argparse.RawDescriptionHelpFormatter):
        pass

    description = f"""
{Colors.RED}{Colors.BOLD}🛡️  VK SCANNER (VOIGHT-KAMPFF) CLI — HERRAMIENTA DE ANÁLISIS PHISHING Y MALDOCS{Colors.END}
{Colors.CYAN}================================================================================{Colors.END}
Suite interactiva y automatizada para evaluar la reputación de URLs, descomponer 
correos estructurados (.eml/.msg) y extraer macros maliciosas, APIs sospechosas o 
explotación de formatos de oficina, todo ejecutado de forma {Colors.GREEN}{Colors.BOLD}100% LOCAL Y PRIVADA{Colors.END}.

{Colors.BOLD}EJEMPLOS DE EJECUCIÓN PRÁCTICA:{Colors.END}
  
  {Colors.CYAN}1. Iniciar la suite web completa (contenedores Docker) y abrir el navegador:{Colors.END}
     {Colors.GREEN}vkscanner -w{Colors.END} (o {Colors.GREEN}python vkscanner.py -w{Colors.END})

  {Colors.CYAN}2. Análisis de URLs (incluyendo WHOIS y edad de registro por defecto):{Colors.END}
     {Colors.GREEN}vkscanner url "http://paypal-verification-account-update.tk" --trace{Colors.END}
  
  {Colors.CYAN}3. Análisis rápido de una URL evitando la latencia de red de WHOIS:{Colors.END}
     {Colors.GREEN}vkscanner url "https://google.com" --no-whois{Colors.END}
  
  {Colors.CYAN}4. Análisis de correos (.eml o .msg) extrayendo adjuntos y SPF/DMARC:{Colors.END}
     {Colors.GREEN}vkscanner email "/home/usuario/Descargas/phishing_alert.eml"{Colors.END}
  
  {Colors.CYAN}5. Apertura rápida de un documento protegido con contraseña manual conocida:{Colors.END}
     {Colors.GREEN}vkscanner document "factura_protegida.pdf" --password "Factura2026!"{Colors.END}
  
  {Colors.CYAN}6. Análisis eficiente de un documento cifrado activando fuerza bruta por diccionario:{Colors.END}
     {Colors.GREEN}vkscanner document "adjunto_malicioso.zip" --brute-force{Colors.END}
"""

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=CustomFormatter,
        add_help=False
    )
    
    parser.add_argument('-h', '--help', action='store_true', help='Muestra este mensaje de ayuda y ejemplos de uso')
    parser.add_argument('-w', '--web', action='store_true', help='Iniciar la suite web (Docker Compose) y abrir la interfaz en el navegador')
    
    subparsers = parser.add_subparsers(dest="command", help="Subcomandos disponibles para escaneo")
    
    # URL Subcommand Parser
    url_parser = subparsers.add_parser(
        "url", 
        help="Analizar reputación, patrones, redirecciones y edad de una URL",
        formatter_class=CustomFormatter,
        description=f"{Colors.BOLD}SUBCOMANDO: url{Colors.END}\nEvalúa anomalías en caracteres Unicode, keywords de phishing, SSL y registros de registro."
    )
    url_parser.add_argument("target_url", help="Dirección URL completa a escanear (ej: https://suspicious-site.xyz/login)")
    url_parser.add_argument("--no-redirects", action="store_false", dest="redirects", help="Evitar seguir redirecciones HTTP del servidor")
    url_parser.add_argument("--no-whois", action="store_false", dest="whois", help="Omitir consulta WHOIS de red para evaluar antigüedad del dominio")
    url_parser.add_argument("-t", "--trace", action="store_true", help="Imprimir la traza de evaluación detallada de reglas internas")
    
    # Email Subcommand Parser
    email_parser = subparsers.add_parser(
        "email", 
        help="Analizar un archivo de correo (.eml / .msg) e inspeccionar sus adjuntos",
        formatter_class=CustomFormatter,
        description=f"{Colors.BOLD}SUBCOMANDO: email{Colors.END}\nDecodifica el correo, analiza cabeceras de seguridad (SPF, DKIM, DMARC) y extrae/escanea archivos adjuntos."
    )
    email_parser.add_argument("file_path", help="Ruta local al archivo del correo .eml o .msg")
    email_parser.add_argument("-t", "--trace", action="store_true", help="Imprimir la traza de evaluación detallada de reglas internas")
    
    # Document Subcommand Parser
    doc_parser = subparsers.add_parser(
        "document", 
        help="Analizar exploits, PE embebidos, RTF y macros VBA de un documento o binario",
        formatter_class=CustomFormatter,
        description=f"{Colors.BOLD}SUBCOMANDO: document{Colors.END}\nBusca macros maliciosas, inyección de API de Win32, PE/MZ ejecutables embebidos, OLE exploits y UPX packing."
    )
    doc_parser.add_argument("file_path", help="Ruta local al documento (.pdf, .docx, .xlsx, .xlsm, .rtf, .zip, .sql, .exe, ELF, etc.)")
    doc_parser.add_argument("-p", "--password", help="Contraseña manual para la desencriptación del archivo protegido")
    doc_parser.add_argument("-b", "--brute-force", action="store_true", dest="brute", help="Habilitar el cracking de contraseña automatizado usando diccionario común")
    doc_parser.add_argument("-w", "--wordlist", help="Ruta a un archivo .txt con contraseñas personalizado (activa fuerza bruta automáticamente)")
    doc_parser.add_argument("-t", "--trace", action="store_true", help="Imprimir la traza de evaluación detallada de reglas internas")
    
    args, unknown = parser.parse_known_args()
    
    if getattr(args, 'web', False):
        start_web_suite()
        sys.exit(0)
    
    if args.help or (not args.command and len(sys.argv) == 1):
        print_banner()
        parser.print_help()
        sys.exit(0)
        
    print_banner()
    
    if args.command == "url":
        run_url_scan(args.target_url, args.redirects, args.whois, args.trace)
    elif args.command == "email":
        run_email_scan(args.file_path, args.trace)
    elif args.command == "document":
        run_document_scan(args.file_path, args.password, args.wordlist, args.brute, args.trace)

if __name__ == "__main__":
    main()
