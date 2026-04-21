#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  Basilic - Advanced Subdomain Intelligence Tool
#  Author  : Pr0fessor_Snape
#  Version : 1.0.0
#  New in v2: Subdomain Takeover, WAF/CDN Detection, DNS Zone Transfer,
#             CORS Misconfiguration, Technology Fingerprinting, Screenshots
#

import urllib3
import argparse
import csv
import json
import os
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from colorama import Fore, Style, init

init(autoreset=True)

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = f"""
{Fore.GREEN}
██████╗  █████╗ ███████╗██╗██╗     ██╗ ██████╗
██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝
██████╔╝███████║███████╗██║██║     ██║██║
██╔══██╗██╔══██║╚════██║██║██║     ██║██║
██████╔╝██║  ██║███████║██║███████╗██║╚██████╗
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝ ╚═════╝
{Style.RESET_ALL}
{Fore.CYAN}        [ Advanced Subdomain Intelligence Tool ]{Style.RESET_ALL}
{Fore.YELLOW}        [ by Pr0fessor_Snape ]  v1.0.0{Style.RESET_ALL}
{Fore.MAGENTA}        [ Takeover | WAF | ZoneXfer | CORS | Tech | Screenshots ]{Style.RESET_ALL}
{Fore.WHITE}  ──────────────────────────────────────────────{Style.RESET_ALL}
"""

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────


def info(msg): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def success(msg): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def error(msg): print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def vuln(msg): print(f"{Fore.RED}{Style.BRIGHT}[VULN]{Style.RESET_ALL} {msg}")


def section(title):
    print(f"\n{Fore.MAGENTA}{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}{Style.RESET_ALL}")


HEADERS = {"User-Agent": "Basilic/2.0 (Subdomain Intelligence Tool)"}

# ─────────────────────────────────────────────
#  DEFAULT WORDLIST
# ─────────────────────────────────────────────

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote",
    "dev", "staging", "test", "prod", "api", "app", "admin", "portal",
    "blog", "shop", "store", "cdn", "static", "assets", "media",
    "img", "images", "video", "docs", "wiki", "help", "support",
    "m", "mobile", "web", "ww2", "ns1", "ns2", "dns", "mx",
    "cloud", "login", "auth", "sso", "beta", "alpha", "demo",
    "dev1", "dev2", "stage", "uat", "qa", "sandbox", "internal",
    "intranet", "extranet", "git", "gitlab", "github", "jenkins",
    "jira", "confluence", "monitor", "grafana", "kibana", "es",
    "elastic", "redis", "db", "database", "mysql", "postgres", "mongo",
    "s3", "backup", "files", "download", "uploads", "smtp2",
    "webmail", "cpanel", "whm", "plesk", "panel", "dashboard",
    "manage", "management", "secure", "safe", "server", "host",
    "new", "old", "v1", "v2", "client", "clients", "partner",
    "partners", "news", "forum", "forums", "community", "chat",
    "status", "stats", "metrics", "report", "reports", "analytics",
    "track", "tracker", "crm", "erp", "hr", "helpdesk", "ticket",
    "tickets", "pay", "payment", "billing", "invoice", "accounts",
    "office", "corporate", "careers", "jobs", "recruitment",
]


# ─────────────────────────────────────────────
#  DNS RESOLVER
# ─────────────────────────────────────────────

def resolve_subdomain(subdomain, domain, resolver):
    fqdn = f"{subdomain}.{domain}"
    result = {"subdomain": fqdn, "ips": [],
              "cname": None, "source": "bruteforce"}
    try:
        answers = resolver.resolve(fqdn, "A")
        result["ips"] = [str(r) for r in answers]
        return result
    except dns.exception.DNSException:
        pass
    try:
        answers = resolver.resolve(fqdn, "CNAME")
        result["cname"] = str(answers[0].target)
        return result
    except dns.exception.DNSException:
        pass
    return None


def get_dns_records(domain, resolver):
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except dns.exception.DNSException:
            pass
    return records


# ─────────────────────────────────────────────
#  NEW: DNS ZONE TRANSFER
# ─────────────────────────────────────────────

def attempt_zone_transfer(domain, resolver):
    """
    Attempt DNS Zone Transfer (AXFR) against all NS servers.
    A successful transfer is a critical misconfiguration.
    """
    section("DNS Zone Transfer (AXFR)")
    results = []
    try:
        ns_records = resolver.resolve(domain, "NS")
        nameservers = [str(r).rstrip(".") for r in ns_records]
    except Exception as e:
        warn(f"Could not retrieve NS records: {e}")
        return results

    info(f"Found {len(nameservers)} nameserver(s): {', '.join(nameservers)}")

    for ns in nameservers:
        try:
            info(f"Attempting AXFR from {ns} ...")
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            names = [str(n) for n in z.nodes.keys()]
            vuln(f"ZONE TRANSFER SUCCEEDED on {ns}!")
            vuln(f"  This is a CRITICAL misconfiguration — all DNS records exposed!")
            for name in names[:30]:
                fqdn = f"{name}.{domain}" if name != "@" else domain
                success(f"  {fqdn}")
            results.append({
                "nameserver": ns,
                "status": "VULNERABLE",
                "records_count": len(names),
                "sample": names[:10]
            })
        except dns.exception.FormError:
            success(f"  {ns} — AXFR refused (secure)")
            results.append({"nameserver": ns, "status": "REFUSED"})
        except Exception as e:
            error(f"  {ns} — failed: {e}")
            results.append({"nameserver": ns, "status": f"ERROR: {e}"})

    return results


# ─────────────────────────────────────────────
#  NEW: SUBDOMAIN TAKEOVER DETECTION
# ─────────────────────────────────────────────

# Fingerprints for dangling CNAME services
TAKEOVER_FINGERPRINTS = {
    "github.io":           ["There isn't a GitHub Pages site here", "For root URLs"],
    "herokuapp.com":       ["No such app", "herokucdn.com/error-pages/no-such-app"],
    "amazonaws.com":       ["NoSuchBucket", "The specified bucket does not exist"],
    "azurewebsites.net":   ["404 Web Site not found"],
    "cloudapp.net":        ["404 Not Found"],
    "fastly.net":          ["Fastly error: unknown domain"],
    "ghost.io":            ["The thing you were looking for is no longer here"],
    "helpjuice.com":       ["We could not find what you're looking for"],
    "helpscoutdocs.com":   ["No settings were found for this company"],
    "myshopify.com":       ["Sorry, this shop is currently unavailable"],
    "statuspage.io":       ["You are being redirected"],
    "tumblr.com":          ["There's nothing here"],
    "wordpress.com":       ["Do you want to register"],
    "zendesk.com":         ["Help Center Closed"],
    "surge.sh":            ["project not found"],
    "bitbucket.io":        ["Repository not found"],
    "unbounce.com":        ["The requested URL was not found"],
    "teamwork.com":        ["Oops - We didn't find your site"],
    "readme.io":           ["Project doesnt exist"],
    "feedpress.me":        ["The feed has not been found"],
    "pantheon.io":         ["404 error unknown site"],
    "acquia-sites.com":    ["If you are an Acquia Cloud customer"],
    "ngrok.io":            ["Tunnel .* not found"],
    "tilda.ws":            ["Please renew your subscription"],
    "wishpond.com":        ["https://www.wishpond.com/"],
    "aftership.com":       ["Oops."],
    "aha.io":              ["There is no portal here"],
    "brightcove.com":      ["<p class=\"bc-gallery-error-code\">"],
    "bigcartel.com":       ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
    "campaignmonitor.com": ["Double check the URL"],
    "cargocollective.com": ["404 Not Found"],
    "hatena.ne.jp":        ["404 Blog is not found"],
    "webflow.io":          ["The page you are looking for doesn't exist"],
    "simplebooklet.com":   ["We can't find this"],
    "uservoice.com":       ["This UserVoice subdomain is currently available"],
}


def check_subdomain_takeover(entry):
    """Check if a subdomain with a CNAME is vulnerable to takeover."""
    cname = entry.get("cname", "")
    subdomain = entry.get("subdomain", "")
    result = {"vulnerable": False, "service": None, "reason": None}

    if not cname:
        return result

    cname_lower = cname.lower()
    matched_service = None
    for service_domain in TAKEOVER_FINGERPRINTS:
        if service_domain in cname_lower:
            matched_service = service_domain
            break

    if not matched_service:
        return result

    # Try to fetch the subdomain and look for error fingerprints
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=6, headers=HEADERS,
                verify=False, allow_redirects=True
            )
            body = resp.text
            for fingerprint in TAKEOVER_FINGERPRINTS[matched_service]:
                if re.search(fingerprint, body, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["service"] = matched_service
                    result["reason"] = f"CNAME → {cname} | Fingerprint matched: '{fingerprint}'"
                    return result
        except Exception:
            pass

    return result


def run_takeover_scan(found):
    section("Subdomain Takeover Detection")
    vulnerable = []
    candidates = [e for e in found if e.get("cname")]
    info(f"Checking {len(candidates)} subdomains with CNAMEs for takeover...")

    if not candidates:
        info("No CNAME subdomains found to check.")
        return vulnerable

    for entry in candidates:
        result = check_subdomain_takeover(entry)
        entry["takeover"] = result
        if result["vulnerable"]:
            vuln(f"TAKEOVER POSSIBLE: {entry['subdomain']}")
            vuln(f"  {result['reason']}")
            vuln(f"  Action: Register/claim the {result['service']} resource!")
            vulnerable.append(entry)
        else:
            info(f"  {entry['subdomain']} → {entry['cname']} (safe)")

    if not vulnerable:
        success("No subdomain takeover vulnerabilities found.")
    else:
        vuln(f"{len(vulnerable)} subdomain(s) potentially vulnerable to takeover!")

    return vulnerable


# ─────────────────────────────────────────────
#  NEW: WAF / CDN DETECTION
# ─────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "body": ["cloudflare", "Attention Required! | Cloudflare"],
        "server": ["cloudflare"]
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid"],
        "body": ["Request blocked", "AWS WAF"],
        "server": ["cloudfront", "awselb"]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop", "x-check-cacheable"],
        "body": ["AkamaiGHost", "Reference #"],
        "server": ["akamai"]
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "x-served-by", "fastly-restarts"],
        "body": [],
        "server": ["fastly"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": ["Sucuri WebSite Firewall", "Access Denied - Sucuri"],
        "server": ["sucuri"]
    },
    "Imperva / Incapsula": {
        "headers": ["x-cdn", "incap-ses", "visid-incap"],
        "body": ["Incapsula incident", "_Incapsula_Resource"],
        "server": ["incapsula"]
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection", "x-wa-info"],
        "body": ["The requested URL was rejected", "Your support ID is"],
        "server": ["BigIP"]
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "body": ["You are not authorized to view this page", "Barracuda"],
        "server": []
    },
    "ModSecurity": {
        "headers": [],
        "body": ["ModSecurity", "This error was generated by Mod_Security"],
        "server": ["mod_security", "modsecurity"]
    },
    "Nginx + naxsi": {
        "headers": [],
        "body": ["NAXSI", "nginx"],
        "server": ["nginx"]
    },
}


def detect_waf_cdn(subdomain):
    """Detect WAF/CDN by analyzing HTTP headers and response body."""
    detected = []
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=6, headers=HEADERS,
                verify=False, allow_redirects=True
            )
            resp_headers = {k.lower(): v.lower()
                            for k, v in resp.headers.items()}
            server_header = resp_headers.get("server", "")
            body = resp.text.lower()

            for waf_name, sigs in WAF_SIGNATURES.items():
                matched = False
                for h in sigs["headers"]:
                    if h.lower() in resp_headers:
                        matched = True
                        break
                if not matched:
                    for s in sigs["server"]:
                        if s.lower() in server_header:
                            matched = True
                            break
                if not matched:
                    for b in sigs["body"]:
                        if b.lower() in body:
                            matched = True
                            break
                if matched and waf_name not in detected:
                    detected.append(waf_name)

            return detected
        except Exception:
            pass
    return detected


def run_waf_detection(found):
    section("WAF / CDN Detection")
    for entry in found:
        if not entry.get("live"):
            continue
        waf_list = detect_waf_cdn(entry["subdomain"])
        entry["waf_cdn"] = waf_list
        if waf_list:
            success(f"{entry['subdomain']:<45} 🛡  {', '.join(waf_list)}")
        else:
            info(f"{entry['subdomain']:<45} No WAF/CDN detected")


# ─────────────────────────────────────────────
#  NEW: CORS MISCONFIGURATION CHECK
# ─────────────────────────────────────────────

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def check_cors(subdomain):
    """
    Test for CORS misconfigurations:
    - Wildcard origin (*)
    - Arbitrary origin reflection
    - null origin acceptance
    """
    issues = []
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        for origin in CORS_TEST_ORIGINS:
            try:
                resp = requests.get(
                    url, timeout=6,
                    headers={**HEADERS, "Origin": origin},
                    verify=False, allow_redirects=True
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    issues.append({
                        "type": "Wildcard Origin",
                        "severity": "MEDIUM",
                        "detail": "Access-Control-Allow-Origin: * — any site can read responses"
                    })
                elif acao == origin:
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                    issues.append({
                        "type": "Origin Reflection",
                        "severity": severity,
                        "detail": f"Origin '{origin}' reflected. Credentials: {acac or 'false'}",
                        "exploit": (
                            "CRITICAL: With credentials=true, attacker can make authenticated "
                            "requests on behalf of victim. Use: fetch(url, {credentials:'include'})"
                            if acac.lower() == "true" else
                            "Attacker can read responses cross-origin from evil.com"
                        )
                    })
                elif acao == "null" and origin == "null":
                    issues.append({
                        "type": "Null Origin Accepted",
                        "severity": "HIGH",
                        "detail": "null origin accepted — can be exploited via sandboxed iframes"
                    })
            except Exception:
                pass
        if issues:
            break
    return issues


def run_cors_scan(found):
    section("CORS Misconfiguration Check")
    vulnerable = []
    live_hosts = [e for e in found if e.get("live")]
    info(f"Testing {len(live_hosts)} live host(s) for CORS issues...")

    for entry in live_hosts:
        issues = check_cors(entry["subdomain"])
        entry["cors_issues"] = issues
        if issues:
            for issue in issues:
                sev_color = Fore.RED if issue["severity"] == "HIGH" else Fore.YELLOW
                vuln(
                    f"{entry['subdomain']} — [{issue['severity']}] {issue['type']}")
                info(f"  {issue['detail']}")
                if issue.get("exploit"):
                    print(
                        f"  {Fore.MAGENTA}Exploit: {issue['exploit']}{Style.RESET_ALL}")
            vulnerable.append(entry)
        else:
            success(f"{entry['subdomain']:<45} CORS OK")

    if not vulnerable:
        success("No CORS misconfigurations found.")
    return vulnerable


# ─────────────────────────────────────────────
#  NEW: TECHNOLOGY FINGERPRINTING
# ─────────────────────────────────────────────

TECH_SIGNATURES = {
    # CMS
    "WordPress":      {"headers": [], "body": ["wp-content", "wp-includes", "wordpress"], "cookies": ["wordpress_", "wp-settings"]},
    "Joomla":         {"headers": [], "body": ["/components/com_", "joomla"], "cookies": ["joomla_"]},
    "Drupal":         {"headers": ["x-drupal-cache", "x-generator"], "body": ["drupal.js", "Drupal.settings"], "cookies": ["drupal"]},
    "Magento":        {"headers": [], "body": ["mage/cookies.js", "Magento"], "cookies": ["frontend", "PHPSESSID"]},
    "Shopify":        {"headers": [], "body": ["cdn.shopify.com", "Shopify.theme"], "cookies": ["_shopify"]},
    "Wix":            {"headers": [], "body": ["wixsite.com", "X-Wix-"], "cookies": []},
    "Squarespace":    {"headers": [], "body": ["squarespace.com", "static.squarespace"], "cookies": []},
    "Ghost":          {"headers": ["x-ghost-cache-status"], "body": ["ghost.io", "content/themes/casper"], "cookies": []},
    # Frameworks
    "Laravel":        {"headers": [], "body": [], "cookies": ["laravel_session", "XSRF-TOKEN"]},
    "Django":         {"headers": [], "body": ["csrfmiddlewaretoken", "django"], "cookies": ["csrftoken", "sessionid"]},
    "Ruby on Rails":  {"headers": ["x-powered-by"], "body": ["csrf-token", "_rails"], "cookies": ["_session_id"]},
    "ASP.NET":        {"headers": ["x-aspnet-version", "x-aspnetmvc-version"], "body": ["__VIEWSTATE", "__EVENTVALIDATION"], "cookies": ["ASP.NET_SessionId"]},
    "Spring Boot":    {"headers": ["x-application-context"], "body": ["spring", "Whitelabel Error Page"], "cookies": []},
    # Servers
    "Nginx":          {"headers": ["server:nginx"], "body": ["nginx"], "cookies": []},
    "Apache":         {"headers": ["server:apache"], "body": ["apache"], "cookies": []},
    "IIS":            {"headers": ["server:microsoft-iis", "x-powered-by:asp.net"], "body": [], "cookies": []},
    "Cloudflare":     {"headers": ["cf-ray"], "body": [], "cookies": ["__cfduid", "cf_clearance"]},
    # JS Frameworks
    "React":          {"headers": [], "body": ["react.development.js", "react.production.min.js", "_reactRoot", "__REACT"], "cookies": []},
    "Angular":        {"headers": [], "body": ["ng-version", "angular.min.js", "ng-app"], "cookies": []},
    "Vue.js":         {"headers": [], "body": ["vue.min.js", "vue.js", "__vue__"], "cookies": []},
    "Next.js":        {"headers": ["x-nextjs-page", "x-powered-by:next.js"], "body": ["__NEXT_DATA__", "_next/static"], "cookies": []},
    # Analytics / Services
    "Google Analytics": {"headers": [], "body": ["google-analytics.com/analytics.js", "gtag(", "UA-", "G-"], "cookies": []},
    "Google Tag Manager": {"headers": [], "body": ["googletagmanager.com/gtm.js"], "cookies": []},
    "Cloudfront CDN": {"headers": ["x-amz-cf-id"], "body": [], "cookies": []},
    "jQuery":         {"headers": [], "body": ["jquery.min.js", "jquery-"], "cookies": []},
    # Security
    "reCAPTCHA":      {"headers": [], "body": ["google.com/recaptcha", "recaptcha/api.js"], "cookies": []},
    "Stripe":         {"headers": [], "body": ["js.stripe.com", "Stripe("], "cookies": []},
}


def fingerprint_tech(subdomain):
    """Identify technologies used by a subdomain."""
    detected = []
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=7, headers=HEADERS,
                verify=False, allow_redirects=True
            )
            resp_headers_str = " ".join(
                [f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items()])
            body = resp.text.lower()
            cookies_str = " ".join([c.lower() for c in resp.cookies.keys()])

            for tech, sigs in TECH_SIGNATURES.items():
                matched = False
                for h in sigs["headers"]:
                    if h.lower() in resp_headers_str:
                        matched = True
                        break
                if not matched:
                    for b in sigs["body"]:
                        if b.lower() in body:
                            matched = True
                            break
                if not matched:
                    for c in sigs["cookies"]:
                        if c.lower() in cookies_str:
                            matched = True
                            break
                if matched and tech not in detected:
                    detected.append(tech)
            return detected
        except Exception:
            pass
    return detected


def run_tech_fingerprinting(found):
    section("Technology Fingerprinting")
    live_hosts = [e for e in found if e.get("live")]
    info(f"Fingerprinting {len(live_hosts)} live host(s)...")

    for entry in live_hosts:
        techs = fingerprint_tech(entry["subdomain"])
        entry["technologies"] = techs
        if techs:
            success(f"{entry['subdomain']:<45} → {', '.join(techs)}")
        else:
            info(f"{entry['subdomain']:<45} → No tech identified")


# ─────────────────────────────────────────────
#  NEW: SCREENSHOT CAPTURE
# ─────────────────────────────────────────────

def take_screenshot(subdomain, output_dir):
    """
    Take a screenshot using cutycapt, chromium-browser, or
    a lightweight fallback that saves the HTML source.
    Returns the file path or None.
    """
    filename = subdomain.replace(".", "_").replace(":", "_")
    screenshot_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    # Try chromium headless
    for browser in ["chromium-browser", "chromium", "google-chrome", "google-chrome-stable"]:
        if os.system(f"which {browser} > /dev/null 2>&1") == 0:
            outfile = os.path.join(screenshot_dir, f"{filename}.png")
            cmd = (
                f"{browser} --headless --disable-gpu --no-sandbox "
                f"--screenshot={outfile} "
                f"--window-size=1280,800 "
                f"https://{subdomain} > /dev/null 2>&1"
            )
            ret = os.system(cmd)
            if ret == 0 and os.path.exists(outfile):
                return outfile

    # Try cutycapt
    if os.system("which cutycapt > /dev/null 2>&1") == 0:
        outfile = os.path.join(screenshot_dir, f"{filename}.png")
        cmd = f"cutycapt --url=https://{subdomain} --out={outfile} > /dev/null 2>&1"
        ret = os.system(cmd)
        if ret == 0 and os.path.exists(outfile):
            return outfile

    # Fallback: save HTML source
    try:
        for scheme in ["https", "http"]:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=7, headers=HEADERS, verify=False
            )
            outfile = os.path.join(screenshot_dir, f"{filename}.html")
            with open(outfile, "w", encoding="utf-8", errors="ignore") as f:
                f.write(resp.text)
            return outfile
    except Exception:
        pass

    return None


def run_screenshots(found, output_dir):
    section("Screenshot Capture")
    live_hosts = [e for e in found if e.get("live")]
    info(f"Capturing {len(live_hosts)} live host(s)...")
    info("(Uses chromium/cutycapt if available, falls back to HTML source save)")

    for entry in live_hosts:
        path = take_screenshot(entry["subdomain"], output_dir)
        entry["screenshot"] = path
        if path:
            success(f"{entry['subdomain']:<45} → {path}")
        else:
            warn(f"{entry['subdomain']:<45} → Screenshot failed")


# ─────────────────────────────────────────────
#  ORIGINAL: CERTIFICATE TRANSPARENCY
# ─────────────────────────────────────────────

def fetch_ct_subdomains(domain):
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        info("Querying Certificate Transparency logs (crt.sh)...")
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(f".{domain}") or line == domain:
                        subdomains.add(line)
            success(f"Found {len(subdomains)} subdomains from CT logs")
        else:
            warn(f"crt.sh returned status {resp.status_code}")
    except requests.exceptions.RequestException as e:
        warn(f"CT log query failed: {e}")
    return subdomains


# ─────────────────────────────────────────────
#  ORIGINAL: HTTP CHECK
# ─────────────────────────────────────────────

def check_http(subdomain):
    result = {"http": None, "https": None, "title": None, "live": False}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(url, timeout=5, headers=HEADERS,
                                verify=False, allow_redirects=True)
            result[scheme] = resp.status_code
            result["live"] = True
            if result["title"] is None:
                content = resp.text[:2000]
                if "<title>" in content.lower():
                    start = content.lower().find("<title>") + 7
                    end = content.lower().find("</title>", start)
                    if end > start:
                        result["title"] = content[start:end].strip()[:80]
            break
        except Exception:
            pass
    return result


# ─────────────────────────────────────────────
#  ORIGINAL: PORT SCAN
# ─────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 27017: "MongoDB",
}


def scan_ports(ip, ports=None, timeout=1):
    open_ports = []
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(
                    {"port": port, "service": COMMON_PORTS.get(port, "Unknown")})
            sock.close()
        except Exception:
            pass
    return open_ports


# ─────────────────────────────────────────────
#  ORIGINAL: IP INFO
# ─────────────────────────────────────────────

def get_ip_info(ip):
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as",
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                }
    except Exception:
        pass
    return {}


# ─────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────

def export_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    success(f"JSON exported → {filename}")


def export_csv(results, filename):
    if not results:
        return
    fieldnames = ["subdomain", "ips", "cname", "source", "http_status",
                  "https_status", "live", "title", "open_ports",
                  "country", "asn", "isp", "waf_cdn", "technologies",
                  "cors_issues", "takeover_vulnerable"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row = dict(r)
            row["ips"] = ", ".join(r.get("ips", []))
            row["open_ports"] = ", ".join(
                [f"{p['port']}/{p['service']}" for p in r.get("open_ports", [])])
            row["waf_cdn"] = ", ".join(r.get("waf_cdn", []))
            row["technologies"] = ", ".join(r.get("technologies", []))
            row["cors_issues"] = "; ".join(
                [i.get("type", "") for i in r.get("cors_issues", [])])
            row["takeover_vulnerable"] = r.get(
                "takeover", {}).get("vulnerable", False)
            writer.writerow(row)
    success(f"CSV exported → {filename}")


def export_html(results, domain, filename, zone_transfer_results=None):
    rows = ""
    for r in results:
        ips = "<br>".join(r.get("ips", []))
        ports = ", ".join(
            [f"{p['port']}/{p['service']}" for p in r.get("open_ports", [])])
        live_badge = (
            '<span style="color:#00ff9d;font-weight:bold;">LIVE</span>'
            if r.get("live") else
            '<span style="color:#666;">DEAD</span>'
        )
        http_s = r.get("https_status") or r.get("http_status") or "-"
        waf = ", ".join(r.get("waf_cdn", [])) or "-"
        techs = ", ".join(r.get("technologies", [])) or "-"
        cors = "; ".join(
            [f"[{i['severity']}] {i['type']}" for i in r.get("cors_issues", [])]) or "OK"
        cors_color = "#ff6b6b" if r.get("cors_issues") else "#00ff9d"
        takeover = r.get("takeover", {})
        to_badge = (
            f'<span style="color:#ff4444;font-weight:bold;">⚠ POSSIBLE</span><br>'
            f'<small>{takeover.get("service", "")}</small>'
            if takeover.get("vulnerable") else "-"
        )

        rows += f"""
        <tr>
          <td>{r.get('subdomain', '')}</td>
          <td>{ips or r.get('cname', '')}</td>
          <td>{live_badge}</td>
          <td>{http_s}</td>
          <td>{r.get('title') or '-'}</td>
          <td>{waf}</td>
          <td style="font-size:11px;">{techs}</td>
          <td style="color:{cors_color};font-size:11px;">{cors}</td>
          <td>{to_badge}</td>
          <td style="font-size:11px;">{ports or '-'}</td>
          <td>{r.get('asn') or '-'}</td>
          <td><span style="color:#aaa;font-size:11px;">{r.get('source', '')}</span></td>
        </tr>"""

    zt_section = ""
    if zone_transfer_results:
        zt_rows = ""
        for zt in zone_transfer_results:
            color = "#ff4444" if zt["status"] == "VULNERABLE" else "#00ff9d"
            zt_rows += f"<tr><td>{zt['nameserver']}</td><td style='color:{color};'>{zt['status']}</td><td>{zt.get('records_count', '')}</td></tr>"
        zt_section = f"""
        <h2>DNS Zone Transfer Results</h2>
        <table>
          <thead><tr><th>Nameserver</th><th>Status</th><th>Records</th></tr></thead>
          <tbody>{zt_rows}</tbody>
        </table>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Basilic v2 Report — {domain}</title>
  <style>
    body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; padding:30px; }}
    h1 {{ color:#00ff9d; }} h2 {{ color:#58a6ff; margin-top:40px; }}
    table {{ width:100%; border-collapse:collapse; margin-top:20px; font-size:12px; }}
    th {{ background:#161b22; color:#58a6ff; padding:10px; border:1px solid #30363d; text-align:left; }}
    td {{ padding:8px 10px; border:1px solid #21262d; vertical-align:top; }}
    tr:nth-child(even) {{ background:#161b22; }}
    tr:hover {{ background:#1c2128; }}
    .meta {{ color:#8b949e; font-size:12px; margin-bottom:20px; }}
    .badge {{ display:inline-block; padding:2px 6px; border-radius:3px; font-size:11px; }}
  </style>
</head>
<body>
  <h1>&#9670; Basilic v1.0 — Subdomain Intelligence Report</h1>
  <p class="meta">
    Target: <b>{domain}</b> &nbsp;|&nbsp;
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    Total found: <b>{len(results)}</b> &nbsp;|&nbsp;
    Live: <b>{sum(1 for r in results if r.get('live'))}</b> &nbsp;|&nbsp;
    by <b>Pr0fessor_Snape</b>
  </p>
  {zt_section}
  <h2>Subdomain Results</h2>
  <table>
    <thead>
      <tr>
        <th>Subdomain</th><th>IP / CNAME</th><th>Live</th>
        <th>HTTP</th><th>Title</th><th>WAF/CDN</th>
        <th>Technologies</th><th>CORS</th><th>Takeover</th>
        <th>Ports</th><th>ASN</th><th>Source</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    success(f"HTML report exported → {filename}")


# ─────────────────────────────────────────────
#  MAIN SCAN ENGINE
# ─────────────────────────────────────────────

def run_scan(args):
    print(BANNER)

    domain = args.domain.lower().strip()
    threads = args.threads
    output_dir = args.output or f"basilic_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)

    section(f"Target: {domain}")
    info(f"Threads        : {threads}")
    info(f"Port scan      : {'Yes' if args.ports else 'No'}")
    info(f"Screenshots    : {'Yes' if args.screenshots else 'No'}")
    info(f"HTTP check     : {'Yes' if not args.no_http else 'No'}")
    info(f"Output dir     : {output_dir}")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # ── Step 1: DNS Records ──
    section("DNS Records")
    dns_records = get_dns_records(domain, resolver)
    for rtype, values in dns_records.items():
        for v in values:
            success(f"{rtype:<6} {v}")

    # ── Step 2: Zone Transfer ──
    zone_transfer_results = attempt_zone_transfer(domain, resolver)

    # ── Step 3: Certificate Transparency ──
    section("Certificate Transparency Logs")
    ct_subdomains = fetch_ct_subdomains(domain)
    ct_prefixes = set()
    for sub in ct_subdomains:
        if sub != domain:
            prefix = sub.replace(f".{domain}", "")
            ct_prefixes.add(prefix)

    # ── Step 4: Brute Force ──
    section("Brute Force Enumeration")
    wordlist = DEFAULT_WORDLIST
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            info(f"Loaded wordlist: {len(wordlist)} words")
        except FileNotFoundError:
            warn(f"Wordlist not found, using built-in ({len(wordlist)} words)")
    else:
        info(f"Using built-in wordlist ({len(wordlist)} words)")

    all_prefixes = set(wordlist) | ct_prefixes
    info(f"Total candidates: {len(all_prefixes)}")

    found = []
    found_lock = threading.Lock()

    def check_sub(prefix):
        result = resolve_subdomain(prefix, domain, resolver)
        if result:
            result["source"] = "ct_logs" if prefix in ct_prefixes else "bruteforce"
            with found_lock:
                found.append(result)
            ips = ", ".join(
                result["ips"]) if result["ips"] else result.get("cname", "")
            tag = "CT" if prefix in ct_prefixes else "BF"
            success(f"[{tag}] {result['subdomain']:<45} {ips}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        list(executor.map(check_sub, all_prefixes))

    info(f"\nEnumeration complete — {len(found)} subdomains found")
    if not found:
        warn("No subdomains found. Try a larger wordlist with -w")
        return

    # ── Step 5: HTTP Checking ──
    if not args.no_http:
        section("HTTP Status Check")

        def http_check_sub(entry):
            http_result = check_http(entry["subdomain"])
            entry.update({
                "live": http_result["live"],
                "http_status": http_result.get("http"),
                "https_status": http_result.get("https"),
                "title": http_result.get("title"),
            })
            if http_result["live"]:
                status = http_result.get(
                    "https_status") or http_result.get("http_status")
                title = http_result.get("title") or ""
                success(f"{entry['subdomain']:<45} [{status}] {title[:40]}")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(http_check_sub, found))
        live_count = sum(1 for e in found if e.get("live"))
        info(f"Live hosts: {live_count}/{len(found)}")

    # ── Step 6: Port Scanning ──
    if args.ports:
        section("Port Scanning")

        def port_scan_entry(entry):
            if not entry.get("ips"):
                return
            ip = entry["ips"][0]
            open_ports = scan_ports(ip)
            entry["open_ports"] = open_ports
            if open_ports:
                ports_str = ", ".join(
                    [f"{p['port']}/{p['service']}" for p in open_ports])
                success(f"{entry['subdomain']:<45} {ip} → {ports_str}")
        with ThreadPoolExecutor(max_workers=min(threads, 10)) as executor:
            list(executor.map(port_scan_entry, found))

    # ── Step 7: IP / ASN Info ──
    section("IP Intelligence")
    ip_cache = {}
    for entry in found:
        if entry.get("ips"):
            ip = entry["ips"][0]
            if ip not in ip_cache:
                ip_cache[ip] = get_ip_info(ip)
                time.sleep(0.1)
            entry.update(ip_cache.get(ip, {}))
            if ip_cache.get(ip):
                d = ip_cache[ip]
                success(
                    f"{entry['subdomain']:<45} {ip:<18} {d.get('asn', '')[:30]} | {d.get('country', '')}")

    # ── NEW Step 8: WAF / CDN Detection ──
    run_waf_detection(found)

    # ── NEW Step 9: Technology Fingerprinting ──
    run_tech_fingerprinting(found)

    # ── NEW Step 10: CORS Check ──
    run_cors_scan(found)

    # ── NEW Step 11: Subdomain Takeover ──
    run_takeover_scan(found)

    # ── NEW Step 12: Screenshots ──
    if args.screenshots:
        run_screenshots(found, output_dir)

    # ── Step 13: Export ──
    section("Exporting Results")
    base = os.path.join(output_dir, "basilic_results")
    export_json(found, f"{base}.json")
    export_csv(found, f"{base}.csv")
    export_html(found, domain, f"{base}.html", zone_transfer_results)

    # ── Summary ──
    section("FINAL SUMMARY")
    success(f"Domain            : {domain}")
    success(f"Subdomains found  : {len(found)}")
    if not args.no_http:
        live = sum(1 for e in found if e.get("live"))
        success(f"Live hosts        : {live}")
    takeovers = sum(1 for e in found if e.get(
        "takeover", {}).get("vulnerable"))
    cors_issues = sum(1 for e in found if e.get("cors_issues"))
    zt_vuln = sum(1 for z in zone_transfer_results if z.get(
        "status") == "VULNERABLE")
    if takeovers:
        vuln(f"Takeover risks    : {takeovers}")
    if cors_issues:
        warn(f"CORS issues       : {cors_issues}")
    if zt_vuln:
        vuln(f"Zone Transfer     : {zt_vuln} NS vulnerable!")
    success(f"Output            : {output_dir}/")
    print(f"\n{Fore.GREEN}  Basilic v1.0 scan complete. Stay ethical. — Pr0fessor_Snape{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Basilic v1.0 — Advanced Subdomain Intelligence Tool by Pr0fessor_Snape",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True,
                        help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-t", "--threads", type=int,
                        default=50, help="Threads (default: 50)")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--ports", action="store_true",
                        help="Enable port scanning")
    parser.add_argument("--no-http", action="store_true",
                        help="Skip HTTP checking")
    parser.add_argument("--screenshots", action="store_true",
                        help="Capture screenshots of live hosts")
    args = parser.parse_args()
    run_scan(args)


if __name__ == "__main__":
    main()
