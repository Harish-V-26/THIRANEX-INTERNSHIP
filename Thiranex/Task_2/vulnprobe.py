#!/usr/bin/env python3
"""
VulnProbe - Main Entry Point
Usage: python vulnprobe.py <target> [options]
"""

import sys
import os
import argparse
import json
from datetime import datetime

# Add parent dir to path
sys.path.insert(0, os.path.dirname(__file__))

from scanner_core import VulnProbe
from report_generator import print_console_report, save_json_report, save_pdf_report

BANNER = r"""
 __   __      _       ____            _
 \ \ / /     | |     |  _ \          | |
  \ V / _   _| |_ __ | |_) |_ __ ___ | |__   ___
   > < | | | | | '_ \|  __/| '__/ _ \| '_ \ / _ \
  / . \| |_| | | | | | |   | | | (_) | |_) |  __/
 /_/ \_\\__,_|_|_| |_|_|   |_|  \___/|_.__/ \___|

  Vulnerability Scanner v1.0  |  For Authorized Use Only
"""

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="VulnProbe - Web & Network Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vulnprobe.py example.com
  python vulnprobe.py https://testphp.vulnweb.com --pdf
  python vulnprobe.py 192.168.1.1 --no-dns --no-paths
  python vulnprobe.py example.com --output report --pdf --json

⚠  Only scan systems you own or have written permission to test.
        """
    )

    parser.add_argument("target",          help="Target URL, hostname, or IP address")
    parser.add_argument("--output",  "-o", default="vulnprobe_report",
                        help="Output filename prefix (default: vulnprobe_report)")
    parser.add_argument("--pdf",           action="store_true", help="Generate PDF report")
    parser.add_argument("--json",          action="store_true", help="Save JSON report")
    parser.add_argument("--no-ports",      action="store_true", help="Skip port scanning")
    parser.add_argument("--no-http",       action="store_true", help="Skip HTTP header scan")
    parser.add_argument("--no-ssl",        action="store_true", help="Skip SSL/TLS scan")
    parser.add_argument("--no-paths",      action="store_true", help="Skip path scanning")
    parser.add_argument("--no-dns",        action="store_true", help="Skip DNS scan")
    parser.add_argument("--all",           action="store_true", help="Enable all modules (default)")

    args = parser.parse_args()

    # ── Run scanner
    scanner = VulnProbe(
        target     = args.target,
        scan_ports = not args.no_ports,
        scan_http  = not args.no_http,
        scan_ssl   = not args.no_ssl,
        scan_paths = not args.no_paths,
        scan_dns   = not args.no_dns,
    )

    findings = scanner.run()
    summary  = scanner.summary()

    # ── Console report
    print_console_report(summary)

    # ── Save reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{args.output}_{timestamp}"

    if args.json or True:  # Always save JSON
        json_path = f"{base}.json"
        save_json_report(summary, json_path)

    if args.pdf:
        pdf_path = f"{base}.pdf"
        save_pdf_report(summary, pdf_path)

    print(f"\n  Scan complete. {summary['total_findings']} findings | Risk: {summary['risk_score']}/100 ({summary['risk_label']})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
