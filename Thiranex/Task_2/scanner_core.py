"""
VulnProbe - Vulnerability Scanner Core
Internship Project - Penetration Testing & Vulnerability Assessment
"""

import socket
import ssl
import requests
import subprocess
import re
import json
import time
import threading
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# DATA: Known vulnerable software versions & CVE references
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_VERSIONS = {
    "Apache": {
        "2.4.49": {"cve": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Path traversal & RCE"},
        "2.4.50": {"cve": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Path traversal bypass"},
        "2.2.x":  {"cve": "CVE-2017-7679",  "severity": "HIGH",     "desc": "mod_mime buffer overread"},
    },
    "nginx": {
        "1.3.9":  {"cve": "CVE-2013-2028", "severity": "CRITICAL", "desc": "Stack buffer overflow"},
        "1.4.0":  {"cve": "CVE-2013-2028", "severity": "CRITICAL", "desc": "Stack buffer overflow"},
        "1.16.0": {"cve": "CVE-2019-9511", "severity": "HIGH",     "desc": "HTTP/2 DoS vulnerability"},
    },
    "OpenSSL": {
        "1.0.1":  {"cve": "CVE-2014-0160", "severity": "CRITICAL", "desc": "Heartbleed - memory disclosure"},
        "1.0.2":  {"cve": "CVE-2016-0800", "severity": "HIGH",     "desc": "DROWN attack"},
        "1.1.0":  {"cve": "CVE-2017-3735", "severity": "MEDIUM",   "desc": "OOB read in X.509"},
    },
    "PHP": {
        "5.x":    {"cve": "CVE-2019-11043", "severity": "CRITICAL", "desc": "RCE via FPM/FastCGI"},
        "7.0":    {"cve": "CVE-2019-9641",  "severity": "HIGH",     "desc": "Use-after-free in exif"},
        "7.1":    {"cve": "CVE-2019-9024",  "severity": "HIGH",     "desc": "xmlrpc_decode memory leak"},
    },
    "WordPress": {
        "4.x":    {"cve": "CVE-2019-8942",  "severity": "HIGH",     "desc": "RCE via image meta"},
        "5.0":    {"cve": "CVE-2019-8942",  "severity": "HIGH",     "desc": "Path traversal + RCE"},
        "5.6":    {"cve": "CVE-2021-29447", "severity": "HIGH",     "desc": "XXE in media library"},
    },
    "IIS": {
        "6.0":    {"cve": "CVE-2017-7269",  "severity": "CRITICAL", "desc": "WebDAV buffer overflow RCE"},
        "5.1":    {"cve": "CVE-2003-0109",  "severity": "HIGH",     "desc": "WebDAV ntdll.dll overflow"},
    },
}

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "TLS_RSA_WITH_RC4", "SSL_CK_RC4", "TLS_NULL"
]

DANGEROUS_HEADERS = {
    "X-Powered-By":        ("INFO_DISCLOSURE", "MEDIUM", "Reveals server technology stack"),
    "Server":              ("INFO_DISCLOSURE", "LOW",    "May reveal server version"),
    "X-AspNet-Version":    ("INFO_DISCLOSURE", "MEDIUM", "Reveals .NET version"),
    "X-AspNetMvc-Version": ("INFO_DISCLOSURE", "MEDIUM", "Reveals ASP.NET MVC version"),
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("MISSING_HSTS",       "HIGH",   "Enables HTTPS downgrade attacks"),
    "Content-Security-Policy":   ("MISSING_CSP",        "HIGH",   "No XSS protection policy"),
    "X-Frame-Options":           ("MISSING_XFRAME",     "MEDIUM", "Clickjacking possible"),
    "X-Content-Type-Options":    ("MISSING_XCTO",       "MEDIUM", "MIME-type sniffing allowed"),
    "Referrer-Policy":           ("MISSING_REFPOL",     "LOW",    "Referrer info may leak"),
    "Permissions-Policy":        ("MISSING_PERMPOL",    "LOW",    "Browser permissions uncontrolled"),
}

COMMON_SENSITIVE_PATHS = [
    ("/.git/config",        "GIT_EXPOSED",      "CRITICAL", "Git repository exposed"),
    ("/.env",               "ENV_EXPOSED",      "CRITICAL", ".env config file exposed"),
    ("/wp-config.php.bak",  "WPCONFIG_BACKUP",  "CRITICAL", "WordPress config backup exposed"),
    ("/phpinfo.php",        "PHPINFO_EXPOSED",  "HIGH",     "PHP info page exposed"),
    ("/adminer.php",        "ADMINER_EXPOSED",  "HIGH",     "DB admin panel exposed"),
    ("/debug",              "DEBUG_ENDPOINT",   "HIGH",     "Debug endpoint accessible"),
    ("/api/v1/users",       "API_USERS_OPEN",   "HIGH",     "User API may be unauthenticated"),
    ("/server-status",      "SERVER_STATUS",    "MEDIUM",   "Apache server-status exposed"),
    ("/robots.txt",         "ROBOTS_EXPOSED",   "INFO",     "robots.txt may reveal hidden paths"),
    ("/.htaccess",          "HTACCESS_EXPOSED", "MEDIUM",   ".htaccess configuration exposed"),
    ("/backup.zip",         "BACKUP_EXPOSED",   "CRITICAL", "Backup archive potentially exposed"),
    ("/config.json",        "CONFIG_EXPOSED",   "HIGH",     "JSON config file accessible"),
    ("/wp-login.php",       "WP_LOGIN",         "INFO",     "WordPress login page detected"),
    ("/admin",              "ADMIN_PANEL",      "INFO",     "Admin panel detected"),
    ("/phpmyadmin",         "PHPMYADMIN",       "HIGH",     "phpMyAdmin panel detected"),
    ("/manager/html",       "TOMCAT_MANAGER",   "HIGH",     "Tomcat manager panel detected"),
]

COMMON_PORTS = {
    21:    ("FTP",         "File Transfer Protocol - check for anonymous login"),
    22:    ("SSH",         "Secure Shell - check for weak credentials"),
    23:    ("Telnet",      "INSECURE - plain text protocol"),
    25:    ("SMTP",        "Mail server - check for open relay"),
    53:    ("DNS",         "Domain Name System - check zone transfer"),
    80:    ("HTTP",        "Web server - check for HTTPS redirect"),
    110:   ("POP3",        "Mail retrieval - unencrypted"),
    111:   ("RPC",         "Remote Procedure Call"),
    135:   ("MSRPC",       "Microsoft RPC - Windows attack surface"),
    139:   ("NetBIOS",     "NetBIOS - Windows file sharing"),
    143:   ("IMAP",        "Mail - unencrypted"),
    443:   ("HTTPS",       "Encrypted web traffic"),
    445:   ("SMB",         "Windows file sharing - EternalBlue risk"),
    1433:  ("MSSQL",       "Microsoft SQL Server - check credentials"),
    1521:  ("Oracle DB",   "Oracle Database"),
    3306:  ("MySQL",       "MySQL database - check external access"),
    3389:  ("RDP",         "Remote Desktop - brute force risk"),
    5432:  ("PostgreSQL",  "PostgreSQL database"),
    5900:  ("VNC",         "Virtual Network Computing - check auth"),
    6379:  ("Redis",       "Redis cache - often no auth by default"),
    8080:  ("HTTP-Alt",    "Alternate HTTP - check for test configs"),
    8443:  ("HTTPS-Alt",   "Alternate HTTPS"),
    27017: ("MongoDB",     "MongoDB - often no auth in default config"),
}

HIGH_RISK_PORTS = {23, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017}


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY SCORING
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH":     7,
    "MEDIUM":   4,
    "LOW":      2,
    "INFO":     0,
}

def severity_color(sev):
    colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH":     "\033[93m",  # Yellow
        "MEDIUM":   "\033[33m",  # Orange-ish
        "LOW":      "\033[94m",  # Blue
        "INFO":     "\033[96m",  # Cyan
    }
    return colors.get(sev, "\033[0m") + sev + "\033[0m"


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY FINDING CLASS
# ─────────────────────────────────────────────────────────────────────────────

class VulnFinding:
    def __init__(self, vuln_id, category, severity, title, description,
                 evidence=None, recommendation=None, cve=None, port=None):
        self.vuln_id      = vuln_id
        self.category     = category
        self.severity     = severity
        self.title        = title
        self.description  = description
        self.evidence     = evidence or ""
        self.recommendation = recommendation or ""
        self.cve          = cve or ""
        self.port         = port
        self.timestamp    = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return self.__dict__

    def score(self):
        return SEVERITY_SCORE.get(self.severity, 0)


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER MODULES
# ─────────────────────────────────────────────────────────────────────────────

class PortScanner:
    """TCP Port Scanner with service fingerprinting"""

    def __init__(self, host, timeout=1.5):
        self.host    = host
        self.timeout = timeout
        self.findings = []

    def _probe_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()
            return port if result == 0 else None
        except Exception:
            return None

    def scan(self, ports=None):
        if ports is None:
            ports = list(COMMON_PORTS.keys())

        open_ports = []
        print(f"  [*] Scanning {len(ports)} ports on {self.host}...")

        with ThreadPoolExecutor(max_workers=100) as ex:
            futures = {ex.submit(self._probe_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort()

        for port in open_ports:
            service, desc = COMMON_PORTS.get(port, ("Unknown", "Unknown service"))
            is_risky = port in HIGH_RISK_PORTS
            severity  = "HIGH" if is_risky else "INFO"

            self.findings.append(VulnFinding(
                vuln_id=f"PORT-{port}",
                category="Open Port",
                severity=severity,
                title=f"Open Port {port}/{service}",
                description=desc,
                evidence=f"Port {port} ({service}) is open and accepting connections",
                recommendation=self._recommend(port, service),
                port=port
            ))

        return open_ports, self.findings

    def _recommend(self, port, service):
        recs = {
            23:    "Disable Telnet immediately. Use SSH instead.",
            135:   "Block MSRPC from external access. Apply Windows patches.",
            139:   "Disable NetBIOS if not needed. Block at firewall.",
            445:   "Patch MS17-010 (EternalBlue). Block SMB externally.",
            1433:  "Restrict SQL Server to internal network only.",
            3306:  "Bind MySQL to 127.0.0.1, not 0.0.0.0.",
            3389:  "Enable NLA for RDP. Use VPN + strong passwords.",
            5900:  "Add VNC password and restrict by IP.",
            6379:  "Enable Redis requirepass. Bind to localhost.",
            27017: "Enable MongoDB authentication. Restrict network access.",
        }
        return recs.get(port, f"Review if {service} needs external exposure. Use firewall rules.")


class HTTPScanner:
    """HTTP/HTTPS Security Header & Configuration Scanner"""

    def __init__(self, target_url, timeout=10):
        self.url     = target_url
        self.timeout = timeout
        self.findings = []
        self.headers  = {}
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "VulnProbe/1.0 (Security Scanner - Authorized Use Only)"
        })

    def scan(self):
        print(f"  [*] Scanning HTTP headers and configuration...")
        try:
            resp = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            self.headers = dict(resp.headers)
            self._check_security_headers(resp)
            self._check_info_disclosure(resp)
            self._check_cookies(resp)
            self._check_ssl_redirect(resp)
        except requests.exceptions.ConnectionError:
            self.findings.append(VulnFinding(
                vuln_id="HTTP-CONN-FAIL",
                category="Connectivity",
                severity="INFO",
                title="HTTP Connection Failed",
                description=f"Could not connect to {self.url}",
                evidence="Connection refused or host unreachable"
            ))
        except Exception as e:
            print(f"  [!] HTTP scan error: {e}")

        return self.findings

    def _check_security_headers(self, resp):
        for header, (vuln_id, sev, impact) in SECURITY_HEADERS.items():
            if header not in resp.headers:
                self.findings.append(VulnFinding(
                    vuln_id=vuln_id,
                    category="Missing Security Header",
                    severity=sev,
                    title=f"Missing Header: {header}",
                    description=impact,
                    evidence=f"Response does not include '{header}' header",
                    recommendation=f"Add '{header}' header to all HTTP responses."
                ))

    def _check_info_disclosure(self, resp):
        for header, (vuln_id, sev, impact) in DANGEROUS_HEADERS.items():
            if header in resp.headers:
                value = resp.headers[header]
                self.findings.append(VulnFinding(
                    vuln_id=vuln_id,
                    category="Information Disclosure",
                    severity=sev,
                    title=f"Information Disclosure: {header}",
                    description=impact,
                    evidence=f"{header}: {value}",
                    recommendation=f"Remove or mask the '{header}' response header."
                ))

        # Check for version strings in Server header
        if "Server" in resp.headers:
            srv = resp.headers["Server"]
            self._check_version_disclosure(srv)

    def _check_version_disclosure(self, server_string):
        for software, versions in VULNERABLE_VERSIONS.items():
            if software.lower() in server_string.lower():
                for ver, info in versions.items():
                    if ver in server_string:
                        self.findings.append(VulnFinding(
                            vuln_id=f"VULN-VER-{software.upper()}",
                            category="Vulnerable Software Version",
                            severity=info["severity"],
                            title=f"Vulnerable {software} Version Detected",
                            description=info["desc"],
                            evidence=f"Server header: {server_string}",
                            recommendation=f"Upgrade {software} immediately. See {info['cve']}",
                            cve=info["cve"]
                        ))

    def _check_cookies(self, resp):
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite attribute")

            if issues:
                self.findings.append(VulnFinding(
                    vuln_id=f"COOKIE-{cookie.name.upper()[:20]}",
                    category="Insecure Cookie",
                    severity="MEDIUM",
                    title=f"Insecure Cookie: {cookie.name}",
                    description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                    evidence=f"Set-Cookie: {cookie.name}=... ({', '.join(issues)})",
                    recommendation="Set Secure, HttpOnly, and SameSite=Strict on all cookies."
                ))

    def _check_ssl_redirect(self, resp):
        if self.url.startswith("http://"):
            if not any("https" in str(r.url) for r in resp.history):
                self.findings.append(VulnFinding(
                    vuln_id="NO-HTTPS-REDIRECT",
                    category="SSL/TLS",
                    severity="HIGH",
                    title="No HTTPS Redirect",
                    description="HTTP traffic is not automatically redirected to HTTPS",
                    evidence=f"Request to {self.url} stayed on HTTP",
                    recommendation="Configure server to redirect all HTTP to HTTPS (301)."
                ))


class SSLScanner:
    """SSL/TLS Configuration Scanner"""

    def __init__(self, host, port=443):
        self.host     = host
        self.port     = port
        self.findings = []

    def scan(self):
        print(f"  [*] Scanning SSL/TLS configuration on {self.host}:{self.port}...")
        try:
            self._check_certificate()
            self._check_tls_versions()
        except Exception as e:
            print(f"  [!] SSL scan error: {e}")
        return self.findings

    def _check_certificate(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert    = ssock.getpeercert()
                    version = ssock.version()
                    cipher  = ssock.cipher()

                    # Check TLS version
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        self.findings.append(VulnFinding(
                            vuln_id="SSL-OLD-PROTOCOL",
                            category="SSL/TLS",
                            severity="HIGH",
                            title=f"Outdated TLS Protocol: {version}",
                            description=f"Server supports deprecated {version} protocol",
                            evidence=f"Connected using {version}",
                            recommendation="Disable TLSv1.0/1.1. Require TLSv1.2 or TLSv1.3.",
                            cve="CVE-2011-3389"
                        ))

                    # Check cipher
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in WEAK_CIPHERS:
                            if weak in cipher_name.upper():
                                self.findings.append(VulnFinding(
                                    vuln_id="SSL-WEAK-CIPHER",
                                    category="SSL/TLS",
                                    severity="HIGH",
                                    title=f"Weak Cipher Suite: {cipher_name}",
                                    description="Weak encryption cipher in use",
                                    evidence=f"Negotiated cipher: {cipher_name}",
                                    recommendation="Disable weak ciphers. Use AES-256-GCM, ChaCha20."
                                ))

                    # Check cert expiry
                    if cert and "notAfter" in cert:
                        expiry = ssl.cert_time_to_seconds(cert["notAfter"])
                        now    = time.time()
                        days_left = (expiry - now) / 86400

                        if days_left < 0:
                            self.findings.append(VulnFinding(
                                vuln_id="SSL-CERT-EXPIRED",
                                category="SSL/TLS",
                                severity="CRITICAL",
                                title="SSL Certificate EXPIRED",
                                description=f"Certificate expired {abs(int(days_left))} days ago",
                                evidence=f"Certificate expired on {cert['notAfter']}",
                                recommendation="Renew SSL certificate immediately."
                            ))
                        elif days_left < 30:
                            self.findings.append(VulnFinding(
                                vuln_id="SSL-CERT-EXPIRING",
                                category="SSL/TLS",
                                severity="HIGH",
                                title=f"SSL Certificate Expiring Soon ({int(days_left)} days)",
                                description="Certificate will expire soon, causing browser warnings",
                                evidence=f"Expires: {cert['notAfter']}",
                                recommendation="Renew certificate before it expires."
                            ))

                    # Self-signed check
                    if cert:
                        issuer  = dict(x[0] for x in cert.get("issuer", []))
                        subject = dict(x[0] for x in cert.get("subject", []))
                        if issuer.get("commonName") == subject.get("commonName"):
                            self.findings.append(VulnFinding(
                                vuln_id="SSL-SELF-SIGNED",
                                category="SSL/TLS",
                                severity="MEDIUM",
                                title="Self-Signed SSL Certificate",
                                description="Certificate is self-signed and not trusted by browsers",
                                evidence=f"Issuer CN == Subject CN: {issuer.get('commonName')}",
                                recommendation="Use a certificate from a trusted CA (e.g. Let's Encrypt)."
                            ))

        except ssl.SSLError as e:
            self.findings.append(VulnFinding(
                vuln_id="SSL-ERROR",
                category="SSL/TLS",
                severity="HIGH",
                title="SSL Configuration Error",
                description=str(e),
                evidence=str(e),
                recommendation="Review and fix SSL/TLS server configuration."
            ))
        except (socket.timeout, ConnectionRefusedError):
            pass  # Port not open, handled by port scanner

    def _check_tls_versions(self):
        """Try to negotiate old TLS versions"""
        old_versions = [
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.0"),
        ]
        for _, ver_name in old_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1

                with socket.create_connection((self.host, self.port), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.host):
                        self.findings.append(VulnFinding(
                            vuln_id="SSL-TLS10-ENABLED",
                            category="SSL/TLS",
                            severity="HIGH",
                            title="TLS 1.0 Supported (Deprecated)",
                            description="Server accepts TLS 1.0 connections (deprecated since 2020)",
                            evidence=f"Successfully negotiated TLS 1.0 with {self.host}:{self.port}",
                            recommendation="Disable TLS 1.0 and 1.1. Only support TLS 1.2+.",
                            cve="CVE-2011-3389"
                        ))
            except Exception:
                pass


class PathScanner:
    """Sensitive Path & Directory Scanner"""

    def __init__(self, base_url, timeout=5):
        self.base_url  = base_url.rstrip("/")
        self.timeout   = timeout
        self.findings  = []
        self.session   = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "VulnProbe/1.0 (Security Scanner - Authorized Use Only)"
        })

    def scan(self):
        print(f"  [*] Scanning {len(COMMON_SENSITIVE_PATHS)} sensitive paths...")
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {
                ex.submit(self._probe_path, path, vuln_id, sev, desc): path
                for path, vuln_id, sev, desc in COMMON_SENSITIVE_PATHS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.findings.append(result)

        return self.findings

    def _probe_path(self, path, vuln_id, severity, description):
        url = self.base_url + path
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            status = resp.status_code

            if status == 200:
                # Validate it's not a generic 404 page disguised as 200
                body = resp.text[:500].lower()
                fake_404 = any(x in body for x in ["not found", "404", "page not found"])
                if not fake_404:
                    return VulnFinding(
                        vuln_id=vuln_id,
                        category="Sensitive Path Exposure",
                        severity=severity,
                        title=f"Exposed Resource: {path}",
                        description=description,
                        evidence=f"HTTP {status} at {url} | Preview: {resp.text[:100].strip()}",
                        recommendation=f"Restrict access to {path}. Add authentication or block via server config."
                    )
            elif status in (401, 403):
                # Still worth noting – it exists but is protected
                if severity in ("CRITICAL", "HIGH"):
                    return VulnFinding(
                        vuln_id=vuln_id + "-PROTECTED",
                        category="Sensitive Path (Protected)",
                        severity="INFO",
                        title=f"Protected Sensitive Path: {path}",
                        description=f"{description} (access restricted – HTTP {status})",
                        evidence=f"HTTP {status} at {url}",
                        recommendation="Verify access controls are correctly configured."
                    )
        except Exception:
            pass
        return None


class DNSScanner:
    """DNS Configuration & Zone Transfer Scanner"""

    def __init__(self, domain):
        self.domain   = domain
        self.findings = []

    def scan(self):
        print(f"  [*] Scanning DNS configuration for {self.domain}...")
        self._check_zone_transfer()
        self._check_spf_dmarc()
        return self.findings

    def _check_zone_transfer(self):
        try:
            import dns.resolver, dns.zone, dns.query
            try:
                ns_records = dns.resolver.resolve(self.domain, "NS")
                for ns in ns_records:
                    ns_host = str(ns.target).rstrip(".")
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ns_host, self.domain, timeout=5))
                        if zone:
                            self.findings.append(VulnFinding(
                                vuln_id="DNS-ZONE-TRANSFER",
                                category="DNS",
                                severity="HIGH",
                                title=f"DNS Zone Transfer Allowed ({ns_host})",
                                description="Zone transfer reveals all DNS records (subdomains, IPs, infrastructure)",
                                evidence=f"AXFR successful from {ns_host} for {self.domain}",
                                recommendation="Restrict zone transfers to authorized secondary nameservers only."
                            ))
                    except Exception:
                        pass
            except Exception:
                pass
        except ImportError:
            self._check_zone_transfer_native()

    def _check_zone_transfer_native(self):
        try:
            result = subprocess.run(
                ["dig", "+short", "AXFR", self.domain],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and len(result.stdout) > 50:
                self.findings.append(VulnFinding(
                    vuln_id="DNS-ZONE-TRANSFER",
                    category="DNS",
                    severity="HIGH",
                    title="DNS Zone Transfer Allowed",
                    description="Zone transfer reveals all DNS records",
                    evidence=result.stdout[:300],
                    recommendation="Restrict AXFR to authorized secondary nameservers."
                ))
        except Exception:
            pass

    def _check_spf_dmarc(self):
        records_to_check = [
            (f"_dmarc.{self.domain}", "TXT", "DNS-NO-DMARC", "HIGH",
             "No DMARC record – email spoofing possible",
             "dmarc", "Add a DMARC TXT record (e.g. v=DMARC1; p=reject)."),
            (self.domain, "TXT", "DNS-NO-SPF", "HIGH",
             "No SPF record – email spoofing possible",
             "spf", "Add an SPF TXT record to specify authorized mail senders."),
        ]
        for name, rtype, vid, sev, desc, keyword, rec in records_to_check:
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, name],
                    capture_output=True, text=True, timeout=5
                )
                if keyword not in result.stdout.lower():
                    self.findings.append(VulnFinding(
                        vuln_id=vid, category="DNS", severity=sev,
                        title=desc.split("–")[0].strip(),
                        description=desc,
                        evidence=f"No {keyword.upper()} record found for {name}",
                        recommendation=rec
                    ))
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(findings):
    """CVSS-inspired risk score 0–100"""
    if not findings:
        return 0, "MINIMAL"

    total = sum(f.score() for f in findings)
    max_possible = len(findings) * 10
    raw_score = (total / max_possible) * 100 if max_possible > 0 else 0

    # Bonus weight for critical findings
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    raw_score = min(100, raw_score + critical_count * 5)

    score = round(raw_score)
    if score >= 80:    label = "CRITICAL"
    elif score >= 60:  label = "HIGH"
    elif score >= 40:  label = "MEDIUM"
    elif score >= 20:  label = "LOW"
    else:              label = "MINIMAL"

    return score, label


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class VulnProbe:
    def __init__(self, target, scan_ports=True, scan_http=True,
                 scan_ssl=True, scan_paths=True, scan_dns=True):
        self.target     = target
        self.scan_ports = scan_ports
        self.scan_http  = scan_http
        self.scan_ssl   = scan_ssl
        self.scan_paths = scan_paths
        self.scan_dns   = scan_dns
        self.all_findings = []
        self.start_time   = None
        self.end_time     = None
        self.open_ports   = []

    def _resolve_target(self):
        """Extract host, build URLs, resolve IP"""
        raw = self.target
        if not raw.startswith(("http://", "https://")):
            raw = "http://" + raw

        parsed   = urllib.parse.urlparse(raw)
        self.host     = parsed.hostname
        self.base_url = raw

        # Attempt IP resolution
        try:
            self.ip = socket.gethostbyname(self.host)
        except Exception:
            self.ip = self.host

        self.domain = self.host

    def run(self):
        self.start_time = datetime.now(timezone.utc)
        self._resolve_target()

        print(f"\n{'='*60}")
        print(f"  VulnProbe - Vulnerability Scanner")
        print(f"  Target : {self.target}")
        print(f"  Host   : {self.host} ({self.ip})")
        print(f"  Time   : {self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*60}\n")

        if self.scan_ports:
            print("[MODULE 1/5] Port Scanner")
            ps = PortScanner(self.ip)
            self.open_ports, port_findings = ps.scan()
            self.all_findings.extend(port_findings)
            print(f"  [+] Found {len(self.open_ports)} open ports\n")

        if self.scan_http:
            print("[MODULE 2/5] HTTP Security Scanner")
            hs = HTTPScanner(self.base_url)
            http_findings = hs.scan()
            self.all_findings.extend(http_findings)
            print(f"  [+] Found {len(http_findings)} HTTP issues\n")

        if self.scan_ssl and self.host:
            print("[MODULE 3/5] SSL/TLS Scanner")
            ss = SSLScanner(self.host)
            ssl_findings = ss.scan()
            self.all_findings.extend(ssl_findings)
            print(f"  [+] Found {len(ssl_findings)} SSL/TLS issues\n")

        if self.scan_paths:
            print("[MODULE 4/5] Sensitive Path Scanner")
            psc = PathScanner(self.base_url)
            path_findings = psc.scan()
            self.all_findings.extend(path_findings)
            print(f"  [+] Found {len(path_findings)} path exposures\n")

        if self.scan_dns and self.domain:
            print("[MODULE 5/5] DNS Scanner")
            ds = DNSScanner(self.domain)
            dns_findings = ds.scan()
            self.all_findings.extend(dns_findings)
            print(f"  [+] Found {len(dns_findings)} DNS issues\n")

        self.end_time = datetime.now(timezone.utc)
        self.risk_score, self.risk_label = calculate_risk_score(self.all_findings)

        return self.all_findings

    def summary(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        duration = (self.end_time - self.start_time).seconds

        return {
            "target":       self.target,
            "host":         self.host,
            "ip":           self.ip,
            "scan_time":    self.start_time.isoformat(),
            "duration_sec": duration,
            "open_ports":   self.open_ports,
            "total_findings": len(self.all_findings),
            "severity_counts": counts,
            "risk_score":   self.risk_score,
            "risk_label":   self.risk_label,
            "findings":     [f.to_dict() for f in self.all_findings],
        }
