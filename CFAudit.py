import requests
import json
import logging
import os
import io
import base64
import random
import time
from datetime import datetime, timedelta, timezone
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import jinja2
import pypandoc

# --- CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.FileHandler('audit.log'), logging.StreamHandler()]
)
logger = logging.getLogger("CloudflareAudit")

CLOUDFLARE_API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_API_EMAIL = os.getenv('CLOUDFLARE_API_EMAIL')
BASE_URL = "https://api.cloudflare.com/client/v4"
GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

# Set this to True to force mock data even if real data exists
FORCE_DEMO_MODE = False 

if not CLOUDFLARE_API_TOKEN:
    logger.error("Missing CLOUDFLARE_API_TOKEN environment variable.")
    exit(1)

HEADERS = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "Content-Type": "application/json"
}
if CLOUDFLARE_API_EMAIL:
    HEADERS["X-Auth-Email"] = CLOUDFLARE_API_EMAIL

# --- BEST PRACTICES DEFINITIONS ---
# Note: Severity is dynamically adjusted based on Plan Level in the logic now
BEST_PRACTICES = {
    "min_tls_version": {"expected": "1.2", "severity": "Critical"},
    "always_use_https": {"expected": "on", "severity": "High"},
    "dnssec": {"expected": "active", "severity": "Medium"},
    "browser_check": {"expected": "on", "severity": "Low"},
    "security_level": {"expected": ["medium", "high", "under_attack"], "severity": "Medium"},
    "waf": {"expected": True, "severity": "Critical"},
    "bot_management": {"expected": True, "severity": "High"},
    "rate_limiting": {"expected": True, "severity": "High"},
    "brotli": {"expected": "on", "severity": "Low"},
    "http3": {"expected": "on", "severity": "Low"},
    "always_online": {"expected": "on", "severity": "Low"},
    "minify": {"expected": "on", "severity": "Low"},
    "automatic_https_rewrites": {"expected": "on", "severity": "Medium"},
    "opportunistic_encryption": {"expected": "on", "severity": "Low"},
    "hotlink_protection": {"expected": "on", "severity": "Low"},
    "email_spf": {"expected": True, "severity": "High"},
    "email_dmarc": {"expected": True, "severity": "High"},
    "page_shield": {"expected": True, "severity": "Medium"}
}

# --- EXECUTIVE RISK CONTEXT ---
RISK_CATALOG = {
    "TLS Version": {
        "impact": "Using legacy TLS versions (1.0/1.1) exposes traffic to decryption attacks (e.g., POODLE, BEAST). It also violates compliance standards like PCI DSS.",
        "fix": "Navigate to SSL/TLS > Edge Certificates and set Minimum TLS Version to 1.2."
    },
    "Managed WAF": {
        "impact": "Without Managed WAF rules, applications are exposed to Top 10 web vulnerabilities like SQL Injection and Cross-Site Scripting (XSS).",
        "fix": "Enable the 'Cloudflare Managed Ruleset' in the WAF configuration."
    },
    "Rate Limiting": {
        "impact": "Lack of rate limiting leaves login pages and APIs vulnerable to Brute Force attacks, Credential Stuffing, and Denial of Service (DoS).",
        "fix": "Configure Rate Limiting rules for sensitive endpoints (e.g., /login, /api)."
    },
    "Always Use HTTPS": {
        "impact": "Allowing HTTP connections enables attackers to intercept sensitive data (Man-in-the-Middle attacks).",
        "fix": "Enable 'Always Use HTTPS' in the Edge Certificates settings."
    },
    "DNSSEC": {
        "impact": "Inactive DNSSEC allows attackers to spoof DNS responses and redirect users to malicious clones of your site.",
        "fix": "Enable DNSSEC in the DNS settings tab."
    },
    "OWASP WAF": {
        "impact": "Missing OWASP Core Rules reduces protection against the most common web application vulnerabilities identified by security researchers.",
        "fix": "Enable the OWASP ModSecurity Core Rule Set in the WAF."
    },
    "Brotli Compression": {
        "impact": "Disabling compression increases bandwidth usage and slows down page load times for end users.",
        "fix": "Enable Brotli in Speed > Optimization settings."
    },
    "HTTP/3": {
        "impact": "Legacy HTTP protocols are slower and less secure. HTTP/3 improves performance significantly, especially on mobile networks.",
        "fix": "Enable HTTP/3 (QUIC) in Network settings."
    },
    "Asset Minification": {
        "impact": "Unminified code (JS/CSS) increases payload size, resulting in slower Largest Contentful Paint (LCP) scores.",
        "fix": "Enable Auto Minify for JavaScript, CSS, and HTML."
    },
    "WAF Rule Override": {
        "impact": "Disabling specific managed rules weakens the security posture and may leave known vulnerabilities exposed.",
        "fix": "Review disabled rules and re-enable them if they are not false positives."
    },
    "Whitelisted IP List": {
        "impact": "Whitelisting entire IP lists can inadvertently allow malicious traffic if the list contains compromised IPs.",
        "fix": "Review IP lists and ensure only trusted IPs are whitelisted."
    },
    "Email Security (SPF/DMARC)": {
        "impact": "Missing SPF or DMARC records allows attackers to easily spoof emails from your domain, leading to phishing attacks against your customers.",
        "fix": "Add valid SPF and DMARC TXT records in the DNS tab."
    },
    "Automatic HTTPS Rewrites": {
        "impact": "Mixed content (HTTP resources on HTTPS pages) creates security warnings for users and can block content loading.",
        "fix": "Enable Automatic HTTPS Rewrites in SSL/TLS > Edge Certificates."
    },
    "Hotlink Protection": {
        "impact": "Without hotlink protection, third-party sites can embed your images, stealing your bandwidth and increasing your costs.",
        "fix": "Enable Hotlink Protection in Scrape Shield."
    },
    "WAF Permissive Config": {
        "impact": "High traffic volume with ZERO threats detected usually indicates WAF rules are missing or turned off, leaving the site exposed.",
        "fix": "Enable Cloudflare Managed Rulesets and review Firewall Events."
    },
    "Unused Feature (ROI)": {
        "impact": "This feature is included in your plan but is currently disabled. You are paying for security/performance capabilities you are not using.",
        "fix": "Enable and configure this feature to maximize the value of your subscription."
    }
}

# --- TEMPLATES ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit - {{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function toggleDarkMode() {
            document.body.classList.toggle('dark-mode');
            const isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('darkMode', isDark);
            document.getElementById('darkModeBtn').innerText = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
        }
        window.onload = function() {
            if (localStorage.getItem('darkMode') === 'true') {
                document.body.classList.add('dark-mode');
                document.getElementById('darkModeBtn').innerText = '☀️ Light Mode';
            }
        }
    </script>
    <style>
        body { background-color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; transition: background-color 0.3s, color 0.3s; }
        .container { max-width: 1200px; margin-top: 30px; }
        .card { margin-bottom: 20px; border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: background-color 0.3s, color 0.3s; }
        .card-header { background-color: #2c3e50; color: white; font-weight: bold; }
        .severity-Critical { background-color: #dc3545; color: white; }
        .severity-High { background-color: #fd7e14; color: white; }
        .severity-Medium { background-color: #ffc107; color: black; }
        .severity-Low { background-color: #28a745; color: white; }
        .severity-Pass { background-color: #198754; color: white; }
        .severity-Info { background-color: #17a2b8; color: white; }
        .table th { background-color: #343a40; color: white; }
        .chart-container { text-align: center; margin: 20px 0; }
        img { max-width: 100%; height: auto; border-radius: 4px; }
        .badge { font-size: 0.9em; padding: 8px 12px; }
        
        /* Dark Mode Overrides */
        body.dark-mode { background-color: #121212; color: #e0e0e0; }
        body.dark-mode .card { background-color: #1e1e1e; color: #e0e0e0; box-shadow: 0 4px 6px rgba(255,255,255,0.05); }
        body.dark-mode .card-header { background-color: #333; color: #fff; }
        
        /* Flawless Table Dark Mode */
        body.dark-mode .table { 
            color: #e0e0e0 !important; 
            border-color: #444; 
            --bs-table-bg: transparent;
            --bs-table-color: #e0e0e0;
            --bs-table-hover-color: #fff;
        }
        body.dark-mode .table thead th { 
            background-color: #2c2c2c; 
            color: #fff; 
            border-color: #444; 
        }
        body.dark-mode .table td, 
        body.dark-mode .table th { 
            border-color: #444; 
            color: inherit; 
        }
        
        /* Fix Striped Rows in Dark Mode */
        body.dark-mode .table-striped > tbody > tr:nth-of-type(odd) > * {
            background-color: rgba(255, 255, 255, 0.05);
            color: #e0e0e0;
        }
        
        /* Fix Hover State in Dark Mode */
        body.dark-mode .table-hover tbody tr:hover > * { 
            color: #fff !important; 
            background-color: rgba(255, 255, 255, 0.1); 
        }
        
        body.dark-mode .list-group-item { background-color: #1e1e1e; color: #e0e0e0; border-color: #444; }
        body.dark-mode .alert-warning { background-color: #332701; color: #ffda6a; border-color: #664d03; }
        body.dark-mode .alert-info { background-color: #032830; color: #6edff6; border-color: #055160; }
        body.dark-mode .text-muted { color: #adb5bd !important; }
    </style>
</head>
<body>
    <div class="container">
        <div class="d-flex justify-content-between align-items-center mb-5">
            <div class="text-center w-100">
                <h1 class="display-4">Cloudflare Security Audit</h1>
                <p class="lead">Zone: <strong>{{ title }}</strong> | Plan: <strong>{{ plan }}</strong> | Date: {{ date }}</p>
            </div>
            <button id="darkModeBtn" class="btn btn-outline-secondary position-absolute end-0 me-5" onclick="toggleDarkMode()">
                🌙 Dark Mode
            </button>
        </div>

        {% if is_mock %}
        <div class="alert alert-warning">
            <strong>DEMO MODE:</strong> No real traffic detected. Showing sample data for visualization purposes.
        </div>
        {% endif %}
        
        <a href="Portfolio_Executive_Summary.html" class="btn btn-outline-primary mb-3">&larr; Back to Portfolio Summary</a>

        <!-- LEGEND SECTION -->
        <div class="card mb-4">
            <div class="card-header">Report Legend & Key</div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6>Severity Levels</h6>
                        <ul class="list-unstyled">
                            <li><span class="badge severity-Critical">Critical</span> Immediate risk.</li>
                            <li><span class="badge severity-High">High</span> Serious vulnerability or ROI Loss.</li>
                            <li><span class="badge severity-Medium">Medium</span> Best practice violation.</li>
                            <li><span class="badge severity-Info">Info</span> Plan limitation or FYIs.</li>
                            <li><span class="badge severity-Pass">Pass</span> Configuration meets best practices.</li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6>WAF Actions</h6>
                        <ul class="list-unstyled">
                            <li><span class="badge bg-danger">Block</span> Request stopped.</li>
                            <li><span class="badge bg-warning text-dark">Challenge</span> Captcha/JS Challenge.</li>
                            <li><span class="badge bg-info text-dark">Log</span> Allowed but tracked.</li>
                            <li><span class="badge bg-warning text-dark" style="background-color: #ffc107;">Score</span> OWASP Anomaly Score increase.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Security Scorecard</div>
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h3>Score: {{ score }}%</h3>
                            <span class="badge {% if score > 80 %}bg-success{% elif score > 50 %}bg-warning{% else %}bg-danger{% endif %}">
                                {% if score > 80 %}Excellent{% elif score > 50 %}Fair{% else %}Poor{% endif %}
                            </span>
                        </div>
                        <div class="progress mb-3" style="height: 25px;">
                            <div class="progress-bar {% if score > 80 %}bg-success{% elif score > 50 %}bg-warning{% else %}bg-danger{% endif %}" 
                                 role="progressbar" style="width: {{ score }}%"></div>
                        </div>
                        <ul class="list-group">
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                Critical Issues
                                <span class="badge bg-danger rounded-pill">{{ summary_counts.Critical }}</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                High Issues
                                <span class="badge bg-warning text-dark rounded-pill">{{ summary_counts.High }}</span>
                            </li>
                             <li class="list-group-item d-flex justify-content-between align-items-center">
                                Passing Checks
                                <span class="badge bg-success rounded-pill">{{ summary_counts.Pass }}</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                 <div class="card">
                    <div class="card-header">Traffic & Threats (Last 24h)</div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-6">
                                <h5>Total Requests</h5>
                                <p class="display-6">{{ analytics.total_requests }}</p>
                            </div>
                            <div class="col-6">
                                <h5>Total Threats</h5>
                                <p class="display-6 text-danger">{{ analytics.total_threats }}</p>
                            </div>
                        </div>
                        <hr>
                        <p><strong>Top Attack Vector:</strong> {{ analytics.top_threat_source }}</p>
                        <p><strong>WAF Action Ratio:</strong> {{ analytics.block_rate }}% Blocked</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">Detailed Findings</div>
            <div class="card-body">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th style="width: 15%">Severity</th>
                            <th style="width: 25%">Check</th>
                            <th style="width: 35%">Description</th>
                            <th style="width: 25%">Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in findings %}
                        <tr>
                            <td><span class="badge severity-{{ finding.severity }}">{{ finding.severity }}</span></td>
                            <td><strong>{{ finding.check }}</strong></td>
                            <td>{{ finding.description }}</td>
                            <td>{{ finding.recommendation }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card mt-4">
            <div class="card-header">WAF & Custom Rules Detail</div>
            <div class="card-body">
                <h5>Managed Rule Overrides</h5>
                {% if managed_overrides %}
                    {% if managed_overrides|length > 20 %}
                        <div class="alert alert-info">
                            <strong>Note:</strong> High volume of overrides detected ({{ managed_overrides|length }}). Displaying summary by action.
                        </div>
                        <ul class="list-group mb-3">
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                Total Overrides
                                <span class="badge bg-secondary">{{ managed_overrides|length }}</span>
                            </li>
                        </ul>
                    {% else %}
                        <ul class="list-group mb-3">
                            {% for override in managed_overrides %}
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                {{ override.description }}
                                <span class="badge bg-warning text-dark">{{ override.action }}</span>
                            </li>
                            {% endfor %}
                        </ul>
                    {% endif %}
                {% else %}
                <p class="text-muted">No managed rule overrides found (or WAF is operating at default settings).</p>
                {% endif %}

                <h5 class="mt-4">Custom Rules</h5>
                {% if custom_rules %}
                <table class="table table-sm">
                    <thead><tr><th>Description</th><th>Expression</th><th>Action</th></tr></thead>
                    <tbody>
                    {% for rule in custom_rules %}
                        <tr>
                            <td>{{ rule.description }}</td>
                            <td><code>{{ rule.expression }}</code></td>
                            <td><span class="badge bg-info text-dark">{{ rule.action }}</span></td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p class="text-muted">No custom rules configured.</p>
                {% endif %}
            </div>
        </div>

        <div class="card mt-4">
            <div class="card-header">IP Access & Lists Audit</div>
            <div class="card-body">
                <h5>IP Lists Usage</h5>
                {% if ip_list_findings %}
                <ul class="list-group mb-3">
                    {% for item in ip_list_findings %}
                    <li class="list-group-item">{{ item }}</li>
                    {% endfor %}
                </ul>
                {% else %}
                <p class="text-muted">No specific IP list issues found.</p>
                {% endif %}

                <h5 class="mt-4">Zone IP Access Rules</h5>
                {% if ip_access_rules %}
                <table class="table table-sm table-striped">
                    <thead><tr><th>Target</th><th>Value</th><th>Action</th><th>Notes</th></tr></thead>
                    <tbody>
                    {% for rule in ip_access_rules %}
                        <tr>
                            <td>{{ rule.target }}</td>
                            <td>{{ rule.value }}</td>
                            <td>
                                <span class="badge {% if rule.mode == 'block' %}bg-danger{% elif rule.mode == 'whitelist' %}bg-success{% else %}bg-secondary{% endif %}">
                                    {{ rule.mode }}
                                </span>
                            </td>
                            <td>{{ rule.notes }}</td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p class="text-muted">No IP Access Rules found for this zone.</p>
                {% endif %}
            </div>
        </div>

        <div class="row mt-4">
             <div class="col-md-6">
                <div class="card">
                    <div class="card-header">WAF Activity (Last 24h)</div>
                    <div class="card-body chart-container">
                        <img src="{{ charts.waf }}" alt="WAF Distribution">
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">DNS Records</div>
                    <div class="card-body">
                         <div style="max-height: 400px; overflow-y: auto;">
                            <table class="table table-sm table-striped">
                                <thead><tr><th>Type</th><th>Name</th><th>Proxied</th></tr></thead>
                                <tbody>
                                {% for r in dns_records %}
                                    <tr>
                                        <td><span class="badge bg-secondary">{{ r.type }}</span></td>
                                        <td>{{ r.name }}</td>
                                        <td>
                                            {% if r.proxied == True %}
                                            <span class="badge bg-warning text-dark">Proxied</span>
                                            {% else %}
                                            <span class="badge bg-light text-dark border">DNS Only</span>
                                            {% endif %}
                                        </td>
                                    </tr>
                                {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

SUMMARY_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Portfolio</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function toggleDarkMode() {
            document.body.classList.toggle('dark-mode');
            const isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('darkMode', isDark);
            document.getElementById('darkModeBtn').innerText = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
        }
        window.onload = function() {
            if (localStorage.getItem('darkMode') === 'true') {
                document.body.classList.add('dark-mode');
                document.getElementById('darkModeBtn').innerText = '☀️ Light Mode';
            }
        }
    </script>
    <style>
        body { background-color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; transition: background-color 0.3s, color 0.3s; }
        .container { max-width: 1400px; margin-top: 30px; }
        .header-section { background-color: #0d1b2a; color: white; padding: 40px; border-radius: 8px; margin-bottom: 30px; position: relative; }
        .score-display { font-size: 3.5rem; font-weight: bold; }
        .metric-label { font-size: 1.1rem; text-transform: uppercase; letter-spacing: 1px; opacity: 0.8; }
        .card { border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.05); transition: transform 0.2s; }
        .card:hover { transform: translateY(-5px); }
        .status-pass { color: #198754; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-warn { color: #fd7e14; font-weight: bold; }

        /* Dark Mode Overrides */
        body.dark-mode { background-color: #121212; color: #e0e0e0; }
        body.dark-mode .card { background-color: #1e1e1e; color: #e0e0e0; box-shadow: 0 4px 6px rgba(255,255,255,0.05); }
        body.dark-mode .card-header { background-color: #333; color: #fff; }
        body.dark-mode .header-section { background-color: #050a10; border: 1px solid #333; }
        
        /* Flawless Table Dark Mode */
        body.dark-mode .table { 
            color: #e0e0e0 !important; 
            border-color: #444; 
            --bs-table-bg: transparent;
            --bs-table-color: #e0e0e0;
            --bs-table-hover-color: #fff;
        }
        body.dark-mode .table thead th { 
            background-color: #2c2c2c; 
            color: #fff; 
            border-color: #444; 
        }
        body.dark-mode .table td, 
        body.dark-mode .table th { 
            border-color: #444; 
            color: inherit; 
        }
        body.dark-mode .table-hover tbody tr:hover { color: #fff; background-color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-section text-center">
            <button id="darkModeBtn" class="btn btn-outline-light position-absolute top-0 end-0 m-3" onclick="toggleDarkMode()">
                🌙 Dark Mode
            </button>
            <h1>Executive Security Portfolio</h1>
            <p>Generated: {{ date }}</p>
            <div class="row mt-4">
                <div class="col-md-4">
                    <div class="score-display {{ 'text-success' if avg_score > 80 else 'text-warning' if avg_score > 50 else 'text-danger' }}">
                        {{ avg_score }}
                    </div>
                    <div class="metric-label">Global Health Score</div>
                </div>
                <div class="col-md-4 align-self-center">
                    <h3>{{ total_zones }}</h3>
                    <div class="metric-label">Zones Audited</div>
                </div>
                <div class="col-md-4 align-self-center">
                    <h3 class="text-danger">{{ total_critical }}</h3>
                    <div class="metric-label">Critical Risks Detected</div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-white">
                <h4 class="mb-0">Zone Performance Matrix</h4>
            </div>
            <div class="card-body p-0">
                <table class="table table-hover mb-0 align-middle">
                    <thead class="table-light">
                        <tr>
                            <th>Zone Name</th>
                            <th>Plan</th>
                            <th class="text-center">Security Score</th>
                            <th class="text-center">Critical</th>
                            <th class="text-center">High</th>
                            <th class="text-center">Status</th>
                            <th class="text-center">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for zone in zones %}
                        <tr>
                            <td class="fw-bold">{{ zone.zone }}</td>
                            <td><span class="badge bg-secondary">{{ zone.plan }}</span></td>
                            <td class="text-center">
                                <span class="badge rounded-pill {{ 'bg-success' if zone.score > 80 else 'bg-warning' if zone.score > 50 else 'bg-danger' }}">
                                    {{ zone.score }}
                                </span>
                            </td>
                            <td class="text-center {{ 'text-danger fw-bold' if zone.counts.Critical > 0 else 'text-muted' }}">
                                {{ zone.counts.Critical }}
                            </td>
                            <td class="text-center {{ 'text-warning fw-bold' if zone.counts.High > 0 else 'text-muted' }}">
                                {{ zone.counts.High }}
                            </td>
                            <td class="text-center">
                                {% if zone.counts.Critical > 0 %}
                                    <span class="status-fail">CRITICAL</span>
                                {% elif zone.counts.High > 0 %}
                                    <span class="status-warn">AT RISK</span>
                                {% else %}
                                    <span class="status-pass">SECURE</span>
                                {% endif %}
                            </td>
                            <td class="text-center">
                                <a href="{{ zone.zone }}_audit.html" class="btn btn-sm btn-primary">View Report</a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

# --- CORE FUNCTIONS ---

def get_mock_analytics():
    """Generates fake data for demo purposes."""
    actions = ['block'] * 150 + ['managed_challenge'] * 50 + ['js_challenge'] * 30 + ['log'] * 20
    sources = ['WAF'] * 100 + ['Bot Management'] * 80 + ['Rate Limit'] * 40 + ['IP Reputation'] * 30
    
    events = []
    mock_data = {
        'block': 4532,
        'managed_challenge': 1205,
        'js_challenge': 890,
        'log': 300
    }
    
    for action, count in mock_data.items():
        events.append({
            'count': count,
            'dimensions': {
                'action': action,
                'source': random.choice(sources)
            }
        })
        
    return {
        "events": events,
        "total_requests": 1450320,
        "total_threats": sum(mock_data.values()),
        "is_mock": True
    }

def get_graphql_analytics(zone_id):
    """Fetches security events via GraphQL."""
    # FIX: Use timezone-aware UTC object
    now = datetime.now(timezone.utc)
    one_day_ago = now - timedelta(days=1)
    
    query = """
    query GetFirewallEvents($zoneTag: string, $datetimeStart: String, $datetimeEnd: String) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          firewallEventsAdaptiveGroups(
            limit: 10,
            filter: {datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd},
            orderBy: [count_DESC]
          ) {
            count
            dimensions {
              action
              source
            }
          }
          httpRequests1dGroups(
            limit: 1,
            filter: {date_geq: $datetimeStartStr}
          ) {
            sum {
              requests
              threats
            }
          }
        }
      }
    }
    """
    
    variables = {
        "zoneTag": zone_id,
        "datetimeStart": one_day_ago.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "datetimeEnd": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "datetimeStartStr": one_day_ago.strftime("%Y-%m-%d")
    }
    
    empty_result = {"events": [], "total_requests": 0, "total_threats": 0, "is_mock": False}

    try:
        response = requests.post(GRAPHQL_URL, headers=HEADERS, json={"query": query, "variables": variables})
        if response.status_code == 200:
            data = response.json()
            if not data or 'data' not in data or not data['data']:
                return empty_result
            
            viewer = data['data'].get('viewer')
            if not viewer or not viewer.get('zones'):
                return empty_result

            zone_data = viewer['zones'][0]
            events = zone_data.get('firewallEventsAdaptiveGroups', [])
            traffic_groups = zone_data.get('httpRequests1dGroups', [])
            
            if traffic_groups:
                traffic = traffic_groups[0].get('sum', {})
                reqs = traffic.get('requests', 0)
                threats = traffic.get('threats', 0)
                
                # If we have 0 requests, switch to Mock Data for the user report
                if reqs == 0 or FORCE_DEMO_MODE:
                    logger.info(f"Zero traffic detected for {zone_id}. Switching to DEMO MODE for reporting.")
                    return get_mock_analytics()
                    
                return {
                    "events": events,
                    "total_requests": reqs,
                    "total_threats": threats,
                    "is_mock": False
                }
            else:
                return get_mock_analytics() # Default to mock if no traffic group found
                
    except Exception as e:
        logger.error(f"GraphQL Error for {zone_id}: {e}")
        
    return empty_result

def get_zone_settings(zone_id):
    settings = {}
    endpoints = {
        "min_tls_version": "settings/min_tls_version",
        "always_use_https": "settings/always_use_https",
        "security_level": "settings/security_level",
        "browser_check": "settings/browser_check",
        # New CDN/Performance Endpoints
        "brotli": "settings/brotli",
        "http3": "settings/http3",
        "always_online": "settings/always_online",
        "minify": "settings/minify",
        # Advanced Security
        "automatic_https_rewrites": "settings/automatic_https_rewrites",
        "opportunistic_encryption": "settings/opportunistic_encryption",
        "hotlink_protection": "settings/hotlink_protection",
        "ipv6": "settings/ipv6"
    }
    
    for key, path in endpoints.items():
        try:
            r = requests.get(f"{BASE_URL}/zones/{zone_id}/{path}", headers=HEADERS)
            if r.status_code == 200:
                settings[key] = r.json()['result']['value']
        except:
            settings[key] = "unknown"
            
    try:
        r = requests.get(f"{BASE_URL}/zones/{zone_id}/dnssec", headers=HEADERS)
        if r.status_code == 200:
            settings["dnssec"] = r.json()['result']['status']
    except:
        settings["dnssec"] = "unknown"
        
    return settings

def get_rulesets(zone_id):
    """Fetches full ruleset definitions to analyze rules."""
    try:
        r = requests.get(f"{BASE_URL}/zones/{zone_id}/rulesets", headers=HEADERS)
        if r.status_code == 200:
            ruleset_list = r.json()['result']
            detailed_rulesets = []
            
            # Fetch details for relevant rulesets (Managed and Custom)
            for rs in ruleset_list:
                if rs['kind'] in ['managed', 'zone', 'custom']:
                    try:
                        detail_resp = requests.get(f"{BASE_URL}/zones/{zone_id}/rulesets/{rs['id']}", headers=HEADERS)
                        if detail_resp.status_code == 200:
                            detailed_rulesets.append(detail_resp.json()['result'])
                        else:
                            detailed_rulesets.append(rs)
                    except Exception:
                        detailed_rulesets.append(rs)
            return detailed_rulesets
    except Exception as e:
        logger.error(f"Error fetching rulesets: {e}")
    return []

def get_ip_access_rules(zone_id):
    """Fetches IP Access Rules (Firewall > Tools)."""
    try:
        r = requests.get(f"{BASE_URL}/zones/{zone_id}/firewall/access_rules/rules", headers=HEADERS)
        if r.status_code == 200:
            return r.json().get('result', [])
    except Exception as e:
        logger.error(f"Error fetching IP access rules: {e}")
    return []

def get_ip_lists(account_id):
    """Fetches IP Lists defined at the account level."""
    if not account_id: return []
    try:
        r = requests.get(f"{BASE_URL}/accounts/{account_id}/rules/lists", headers=HEADERS)
        if r.status_code == 200:
            return r.json().get('result', [])
    except Exception as e:
        logger.error(f"Error fetching IP lists: {e}")
    return []

def check_compliance(zone_name, zone_id, account_id, settings, rulesets, analytics, ip_access_rules, dns_records, plan_name):
    """
    Core Compliance Logic
    Now accepts 'plan_name' (free, pro, business, enterprise) to adjust expectations.
    """
    findings = []
    managed_overrides = []
    custom_rules = []
    ip_list_findings = []
    
    plan_slug = plan_name.lower()
    is_paid = "free" not in plan_slug
    is_biz_ent = "business" in plan_slug or "enterprise" in plan_slug
    is_ent = "enterprise" in plan_slug

    # --- TLS ---
    tls = settings.get('min_tls_version')
    if tls != BEST_PRACTICES['min_tls_version']['expected']:
        findings.append({
            "check": "TLS Version", "severity": "Critical",
            "description": f"Current TLS is {tls}", "recommendation": "Set Minimum TLS to 1.2"
        })
    else:
        findings.append({
            "check": "TLS Version", "severity": "Pass",
            "description": "TLS 1.2+ is enforced", "recommendation": "None"
        })
        
    # --- HTTPS ---
    if settings.get('always_use_https') != 'on':
         findings.append({
            "check": "Always Use HTTPS", "severity": "High",
            "description": "Redirect is disabled", "recommendation": "Enable Always Use HTTPS"
        })
    else:
        findings.append({
            "check": "Always Use HTTPS", "severity": "Pass",
            "description": "HTTPS Redirect is active", "recommendation": "None"
        })

    # --- DNSSEC ---
    if settings.get('dnssec') != 'active':
         findings.append({
            "check": "DNSSEC", "severity": "Medium",
            "description": "DNSSEC is not active", "recommendation": "Enable DNSSEC"
        })
    else:
        findings.append({
            "check": "DNSSEC", "severity": "Pass",
            "description": "DNSSEC is protecting the zone", "recommendation": "None"
        })
        
    # --- WAF (Managed Rules Analysis) ---
    cf_managed_active = False
    owasp_active = False
    
    for rs in rulesets:
        if rs['kind'] == 'managed':
            # Check for Cloudflare Managed
            if 'Cloudflare Managed Ruleset' in rs.get('name', '') or rs['phase'] == 'http_request_firewall_managed':
                cf_managed_active = True
                if 'rules' in rs:
                    for rule in rs['rules']:
                        rule_action = rule.get('action', 'unknown')
                        is_enabled = rule.get('enabled', True)
                        status_label = None
                        if is_enabled is False: status_label = "Disabled"
                        elif rule_action == 'skip': status_label = "Skipped"
                        elif rule_action != 'unknown': status_label = rule_action.capitalize()
                        if status_label:
                            managed_overrides.append({'id': rule['id'], 'description': f"Rule {rule.get('id')} (CF Managed)", 'action': status_label})
            
            # Check for OWASP
            if 'OWASP' in rs.get('name', ''):
                owasp_active = True
                if 'rules' in rs:
                    for rule in rs['rules']:
                        rule_action = rule.get('action', 'unknown')
                        is_enabled = rule.get('enabled', True)
                        status_label = None
                        if is_enabled is False: status_label = "Disabled"
                        elif rule_action != 'unknown': status_label = rule_action.capitalize()
                        if status_label:
                            managed_overrides.append({'id': rule['id'], 'description': f"Rule {rule.get('id')} (OWASP)", 'action': status_label})

        # --- Custom Rules Analysis ---
        if rs['kind'] == 'zone' and rs['phase'] == 'http_request_firewall_custom':
            if 'rules' in rs:
                for rule in rs['rules']:
                    if rule.get('enabled', True):
                        custom_rules.append({
                            'description': rule.get('description', 'No description'),
                            'expression': rule.get('expression', ''),
                            'action': rule.get('action', 'unknown')
                        })
                        if rule.get('action') == 'skip' or rule.get('action') == 'allow':
                            if 'ip.src in $' in rule.get('expression', ''):
                                list_name = rule['expression'].split('$')[1].split(' ')[0].replace('}', '')
                                ip_list_findings.append(f"Whitelist audit: IP List '{list_name}' is allowed/skipped by custom rule.")

    # WAF Logic Based on Plan
    if not cf_managed_active:
        # Critical on paid, High on Free (since Free has limited WAF capabilities but still has some)
        sev = "Critical" if is_paid else "High"
        findings.append({
            "check": "Managed WAF", "severity": sev,
            "description": "Cloudflare Managed Ruleset missing/disabled", "recommendation": "Enable Managed Rules"
        })
    else:
        findings.append({
            "check": "Managed WAF", "severity": "Pass",
            "description": "Cloudflare Managed Ruleset is active", "recommendation": "None"
        })

    if not owasp_active:
        # OWASP is Pro+ feature. If not detected on Free, it's Info (Plan Limit).
        if is_paid:
            findings.append({
                "check": "OWASP WAF", "severity": "Medium",
                "description": "OWASP Ruleset not detected", "recommendation": "Consider enabling OWASP Core Rules"
            })
        else:
            findings.append({
                "check": "OWASP WAF", "severity": "Info",
                "description": "OWASP Ruleset not available on Free Plan", "recommendation": "Upgrade to Pro to enable"
            })

    if managed_overrides:
        findings.append({
            "check": "WAF Rule Override", "severity": "Info",
            "description": f"{len(managed_overrides)} managed rules are disabled/overridden", 
            "recommendation": "Review disabled rules to ensure they are valid false positives"
        })

    # --- Rate Limiting ---
    # Rate Limiting is much more powerful on paid plans.
    has_rate_limit = any(rs['phase'] == 'http_ratelimit' for rs in rulesets)
    if not has_rate_limit:
        if is_biz_ent:
            # Business/Ent paying for Advanced RL but not using it? That's an ROI issue.
            findings.append({
                "check": "Rate Limiting", "severity": "High",
                "description": "Paid Plan Active but No Rate Limiting Rules (ROI Risk)", 
                "recommendation": "Configure Rate Limiting to protect login/API endpoints"
            })
        elif is_paid:
             findings.append({
                "check": "Rate Limiting", "severity": "Medium",
                "description": "No Rate Limiting rules found", "recommendation": "Add Login Protection Rules"
            })
        else:
             findings.append({
                "check": "Rate Limiting", "severity": "Low",
                "description": "No Rate Limiting rules (Free plan limited)", "recommendation": "Consider simple IP rate limits"
            })
    else:
        findings.append({
            "check": "Rate Limiting", "severity": "Pass",
            "description": "Rate Limiting rules are configured", "recommendation": "None"
        })
        
    # --- IP Access Rules Audit ---
    whitelisted_ips = [r for r in ip_access_rules if r['mode'] == 'whitelist']
    if len(whitelisted_ips) > 5:
        findings.append({
            "check": "Whitelisted IP List", "severity": "Medium",
            "description": f"High number of IP Access Rule whitelists ({len(whitelisted_ips)})",
            "recommendation": "Review IP Access Rules for stale entries"
        })

    # --- CDN / Performance Checks ---
    if settings.get('brotli') != 'on':
        findings.append({
            "check": "Brotli Compression", "severity": "Low",
            "description": "Brotli compression is disabled", "recommendation": "Enable Brotli for better performance"
        })
    else:
         findings.append({
            "check": "Brotli Compression", "severity": "Pass",
            "description": "Brotli is enabled", "recommendation": "None"
        })

    if settings.get('http3') != 'on':
        findings.append({
            "check": "HTTP/3", "severity": "Low",
            "description": "HTTP/3 (QUIC) is disabled", "recommendation": "Enable HTTP/3 for speed improvements"
        })
    else:
         findings.append({
            "check": "HTTP/3", "severity": "Pass",
            "description": "HTTP/3 is enabled", "recommendation": "None"
        })

    minify_settings = settings.get('minify', {})
    if isinstance(minify_settings, dict):
        if not all(v == 'on' for v in minify_settings.values()):
             findings.append({
                "check": "Asset Minification", "severity": "Low",
                "description": "One or more auto-minify settings are off", "recommendation": "Enable Auto Minify for JS, CSS, and HTML"
            })
        else:
            findings.append({
                "check": "Asset Minification", "severity": "Pass",
                "description": "Auto Minify is fully enabled", "recommendation": "None"
            })

    # --- Email Security (DNS Check) ---
    has_spf = False
    has_dmarc = False
    for r in dns_records:
        if r['type'] == 'TXT':
            if 'v=spf1' in r.get('content', ''):
                has_spf = True
            if '_dmarc' in r.get('name', ''):
                has_dmarc = True
                
    if not has_spf or not has_dmarc:
        missing = []
        if not has_spf: missing.append("SPF")
        if not has_dmarc: missing.append("DMARC")
        findings.append({
            "check": "Email Security (SPF/DMARC)", "severity": "High",
            "description": f"Missing DNS records: {', '.join(missing)}",
            "recommendation": "Add SPF/DMARC records to prevent email spoofing"
        })
    else:
        findings.append({
            "check": "Email Security (SPF/DMARC)", "severity": "Pass",
            "description": "SPF and DMARC records are present", "recommendation": "None"
        })

    # --- Advanced Security ---
    if settings.get('automatic_https_rewrites') != 'on':
        findings.append({
            "check": "Automatic HTTPS Rewrites", "severity": "Medium",
            "description": "HTTPS Rewrites disabled (Mixed Content risk)", "recommendation": "Enable Automatic HTTPS Rewrites"
        })
    else:
        findings.append({
            "check": "Automatic HTTPS Rewrites", "severity": "Pass",
            "description": "Automatic HTTPS Rewrites enabled", "recommendation": "None"
        })

    if settings.get('hotlink_protection') != 'on':
        findings.append({
            "check": "Hotlink Protection", "severity": "Low",
            "description": "Hotlink Protection disabled", "recommendation": "Enable to prevent bandwidth theft"
        })
    else:
        findings.append({
            "check": "Hotlink Protection", "severity": "Pass",
            "description": "Hotlink Protection enabled", "recommendation": "None"
        })

    # --- TRAFFIC / CONFIG ANALYSIS ---
    total_reqs = analytics.get('total_requests', 0)
    total_threats = analytics.get('total_threats', 0)
    
    if total_reqs > 1000 and total_threats == 0:
        findings.append({
            "check": "WAF Permissive Config", "severity": "High",
            "description": "High traffic but ZERO threats detected. Rules may be too permissive.",
            "recommendation": "Review WAF configuration and ensure Managed Rules are blocking effectively."
        })
        
    if total_reqs == 0:
        # Mark all findings as "Config Only" since we can't verify efficacy
        for f in findings:
            if f['severity'] != 'Pass':
                f['description'] += " (Note: No Traffic to Verify)"

    # --- ROI CHECKS (Bought but Unused) ---
    # Check Bot Management (Super Bot Fight Mode for Pro/Biz)
    # Check if Bot Fight Mode is enabled? (This requires checking the specific setting which we didn't fetch above, assume inferred from ruleset or add if needed)
    
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4, 'Pass': 5}
    findings.sort(key=lambda x: severity_order.get(x['severity'], 6))
    
    return findings, managed_overrides, custom_rules, ip_list_findings

# --- REPORTING ---

def generate_charts(analytics, zone_name):
    charts = {}
    events = analytics.get('events', [])
    
    if events:
        df = pd.DataFrame([
            {'Action': e['dimensions']['action'], 'Count': e['count']} 
            for e in events
        ])
        
        plt.figure(figsize=(8, 4))
        sns.set_style("whitegrid")
        palette = sns.color_palette("viridis", len(df))
        ax = sns.barplot(x='Action', y='Count', data=df, palette=palette)
        plt.title(f'Threat Mitigation Actions (24h) - {zone_name}')
        plt.ylabel("Events")
        plt.xticks(rotation=45)
        for i in ax.containers:
            ax.bar_label(i,)
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)
        plt.close()
        charts['waf'] = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode('utf-8')
    else:
        plt.figure(figsize=(8, 4))
        plt.text(0.5, 0.5, 'No Data', ha='center')
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        plt.close()
        charts['waf'] = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode('utf-8')
        
    return charts

def create_pdf_report(filename, zone_name, plan, findings, analytics, dns_records, charts, score, 
                      managed_overrides, custom_rules, ip_list_findings, ip_access_rules):
    doc = SimpleDocTemplate(filename, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    story = []

    # Colors
    cf_orange = colors.Color(0.96, 0.51, 0.19)
    dark_header = colors.Color(0.17, 0.24, 0.31)
    
    # Styles
    title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=24, textColor=dark_header, spaceAfter=10, leading=28)
    meta_style = ParagraphStyle('M', parent=styles['Normal'], fontSize=10, textColor=colors.grey)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, textColor=cf_orange, spaceBefore=15, spaceAfter=8)
    h3_style = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12, textColor=dark_header, spaceBefore=10, spaceAfter=5)
    body_style = ParagraphStyle('B', parent=styles['BodyText'], fontSize=9)

    # Header
    story.append(Paragraph(f"Security Audit Report", title_style))
    is_mock_text = " (DEMO DATA)" if analytics.get('is_mock') else ""
    story.append(Paragraph(f"Zone: <b>{zone_name}</b> | Plan: <b>{plan}</b>{is_mock_text} | Date: {datetime.now().strftime('%Y-%m-%d')}", meta_style))
    story.append(Spacer(1, 20))

    # Score Box
    score_bg = colors.green if score > 80 else colors.orange if score > 50 else colors.red
    
    t_data = [[
        Paragraph(f"Security Score<br/><font size=20>{score}/100</font>", ParagraphStyle('C', alignment=TA_CENTER, textColor=colors.white, leading=24)),
        Paragraph(f"Requests (24h): {analytics['total_requests']:,}<br/>Threats (24h): {analytics['total_threats']:,}", ParagraphStyle('L', textColor=colors.white))
    ]]
    t = Table(t_data, colWidths=[3.5*inch, 3.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), score_bg),
        ('BACKGROUND', (1,0), (1,0), dark_header),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [6,6,6,6]),
        ('TOPPADDING', (0,0), (-1,-1), 15),
        ('BOTTOMPADDING', (0,0), (-1,-1), 15),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # --- LEGEND SECTION ---
    story.append(Paragraph("Report Legend & Key", h2_style))
    legend_data = [
        [Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Critical</b>: Immediate risk. <b>High</b>: Serious vulnerability. <b>Medium</b>: Best practice gap. <b>Info</b>: Plan limit or FYI.", body_style)],
        [Paragraph("<b>WAF Actions</b>", body_style), Paragraph("<b>Block</b>: Request stopped. <b>Challenge</b>: Captcha presented. <b>Log</b>: Allowed but tracked.<br/><b>Score (OWASP)</b>: Rule matched & increased Anomaly Score. Does NOT block individually.", body_style)]
    ]
    t_legend = Table(legend_data, colWidths=[1.5*inch, 5.5*inch])
    t_legend.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BACKGROUND', (0,0), (0,-1), colors.whitesmoke),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_legend)
    story.append(Spacer(1, 20))
    
    # Findings
    story.append(Paragraph("Compliance Checks", h2_style))
    if findings:
        data = [["Severity", "Check", "Status/Recommendation"]]
        for f in findings:
            sev_color = colors.black
            if f['severity'] == 'Critical': sev_color = colors.red
            elif f['severity'] == 'High': sev_color = colors.orange
            elif f['severity'] == 'Pass': sev_color = colors.green
            elif f['severity'] == 'Info': sev_color = colors.blue
            
            desc = f"<b>{f['description']}</b><br/><i>{f['recommendation']}</i>"
            data.append([
                Paragraph(f"<b>{f['severity']}</b>", ParagraphStyle('S', textColor=sev_color)),
                Paragraph(f['check'], styles['BodyText']),
                Paragraph(desc, styles['BodyText'])
            ])
            
        t_find = Table(data, colWidths=[1*inch, 2*inch, 4*inch])
        t_find.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_find)
    
    story.append(PageBreak())

    # --- New Detailed WAF Section ---
    story.append(Paragraph("WAF & Rule Details", h2_style))
    
    if managed_overrides:
        story.append(Paragraph("Managed Rule Overrides", h3_style))
        
        if len(managed_overrides) > 15:
            story.append(Paragraph(f"<b>Summary View:</b> Found {len(managed_overrides)} rule overrides. Grouped by action below to reduce report length.", body_style))
            action_counts = {}
            for o in managed_overrides:
                act = o['action']
                action_counts[act] = action_counts.get(act, 0) + 1
            summary_data = [["Action Type", "Count"]]
            for act, count in action_counts.items():
                summary_data.append([act, str(count)])
            t_sum = Table(summary_data, colWidths=[3*inch, 1*inch])
            t_sum.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('BACKGROUND', (0,0), (-1,0), colors.lightgrey)]))
            story.append(t_sum)
            story.append(Spacer(1, 10))
            
            disabled_rules = [o for o in managed_overrides if o['action'] == 'Disabled']
            if disabled_rules:
                story.append(Paragraph(f"<b>Critical: Disabled Rules ({len(disabled_rules)})</b>", h3_style))
                override_data = [["Rule ID", "Description"]]
                for o in disabled_rules:
                    override_data.append([Paragraph(str(o['id']), body_style), Paragraph(o['description'], body_style)])
                t_over = Table(override_data, colWidths=[2*inch, 5*inch])
                t_over.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
                story.append(t_over)
        else:
            override_data = [["Rule ID", "Description", "Action"]]
            for o in managed_overrides:
                override_data.append([Paragraph(str(o['id']), body_style), Paragraph(o['description'], body_style), Paragraph(o['action'], body_style)])
            t_over = Table(override_data, colWidths=[1.5*inch, 4*inch, 1.5*inch])
            t_over.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.lightgrey), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(t_over)
            story.append(Spacer(1, 10))

    if custom_rules:
        story.append(Paragraph("Custom Rules", h3_style))
        custom_data = [["Description", "Expression", "Action"]]
        for r in custom_rules:
            custom_data.append([Paragraph(r['description'], body_style), Paragraph(f"<font fontName='Courier' size=8>{r['expression'][:50]}...</font>", body_style), Paragraph(str(r['action']), body_style)])
        t_cust = Table(custom_data, colWidths=[2.5*inch, 3*inch, 1.5*inch])
        t_cust.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.lightgrey), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
        story.append(t_cust)
        story.append(Spacer(1, 10))

    if ip_list_findings:
        story.append(Paragraph("IP List Audit", h3_style))
        for item in ip_list_findings:
            story.append(Paragraph(f"• {item}", body_style))
        story.append(Spacer(1, 10))

    story.append(Paragraph("Zone IP Access Rules", h2_style))
    if ip_access_rules:
        ip_data = [["Target", "Value", "Action", "Notes"]]
        for rule in ip_access_rules[:20]: 
            ip_data.append([Paragraph(rule.get('configuration', {}).get('target', 'ip'), body_style), Paragraph(rule.get('configuration', {}).get('value', ''), body_style), Paragraph(rule.get('mode', ''), body_style), Paragraph(rule.get('notes', ''), body_style)])
        t_ip = Table(ip_data, colWidths=[1*inch, 2*inch, 1*inch, 3*inch])
        t_ip.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.lightgrey), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
        story.append(t_ip)
    else:
        story.append(Paragraph("No IP Access Rules configured.", body_style))

    story.append(Spacer(1, 15))
    
    story.append(Paragraph("Threat Intelligence", h2_style))
    if 'waf' in charts:
        img_data = base64.b64decode(charts['waf'].split(',')[1])
        img = Image(io.BytesIO(img_data), width=7*inch, height=3.5*inch)
        story.append(img)
        
    doc.build(story)

def generate_portfolio_report(audit_results, output_dir):
    logger.info("Generating Portfolio Executive Summary PDF...")
    filename = f"{output_dir}/Portfolio_Executive_Summary.pdf"
    
    total_zones = len(audit_results)
    avg_score = int(sum(r['score'] for r in audit_results) / total_zones) if total_zones > 0 else 0
    total_critical = sum(r['counts']['Critical'] for r in audit_results)
    total_high = sum(r['counts']['High'] for r in audit_results)
    
    grouped_issues = {}
    for r in audit_results:
        for f in r['findings']:
            if f['severity'] in ['Critical', 'High']:
                if f['check'] not in grouped_issues:
                    grouped_issues[f['check']] = {"count": 0, "zones": [], "severity": f['severity']}
                grouped_issues[f['check']]["count"] += 1
                grouped_issues[f['check']]["zones"].append(r['zone'])

    doc = SimpleDocTemplate(filename, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    story = []

    cf_orange = colors.Color(0.96, 0.51, 0.19)
    dark_blue = colors.Color(0.12, 0.18, 0.25)
    
    title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=28, textColor=dark_blue, alignment=TA_CENTER, spaceAfter=20)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=16, textColor=cf_orange, spaceBefore=20, spaceAfter=10)
    body_style = ParagraphStyle('B', parent=styles['BodyText'], fontSize=11, leading=14)
    
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("Executive Security Summary", title_style))
    story.append(Paragraph(f"Organization Portfolio Report | {datetime.now().strftime('%Y-%m-%d')}", ParagraphStyle('sub', parent=styles['Normal'], alignment=TA_CENTER, fontSize=12)))
    story.append(Spacer(1, 0.5*inch))

    dash_data = [[
        Paragraph(f"Global Health Score<br/><font size=30>{avg_score}/100</font>", ParagraphStyle('C', alignment=TA_CENTER, textColor=colors.white, leading=36)),
        Paragraph(f"Zones Audited: {total_zones}<br/>Critical Risks: {total_critical}<br/>High Risks: {total_high}", ParagraphStyle('stats', textColor=colors.white, leading=16))
    ]]
    score_color = colors.green if avg_score > 80 else colors.orange if avg_score > 50 else colors.red
    t_dash = Table(dash_data, colWidths=[3.5*inch, 3.5*inch])
    t_dash.setStyle(TableStyle([('BACKGROUND', (0,0), (0,0), score_color), ('BACKGROUND', (1,0), (1,0), dark_blue), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'), ('ROUNDEDCORNERS', [8,8,8,8]), ('TOPPADDING', (0,0), (-1,-1), 25), ('BOTTOMPADDING', (0,0), (-1,-1), 25)]))
    story.append(t_dash)
    story.append(Spacer(1, 0.5*inch))
    
    story.append(Paragraph("Critical & High Risk Analysis", h2_style))
    story.append(Paragraph("The following issues represent the most significant risks to the organization's security posture. Immediate remediation is recommended.", body_style))
    story.append(Spacer(1, 10))

    if grouped_issues:
        for check, data in grouped_issues.items():
            context = RISK_CATALOG.get(check, {"impact": "Security best practice violation.", "fix": "Follow standard remediation guidelines."})
            sev_color = colors.red if data['severity'] == "Critical" else colors.orange
            story.append(Paragraph(f"<b>{check}</b> ({data['severity']}) - Found in {data['count']} Zones", ParagraphStyle('IH', parent=styles['Heading3'], textColor=sev_color)))
            risk_data = [
                [Paragraph("<b>Business Impact:</b>", body_style), Paragraph(context['impact'], body_style)],
                [Paragraph("<b>Recommendation:</b>", body_style), Paragraph(context['fix'], body_style)],
                [Paragraph("<b>Affected Zones:</b>", body_style), Paragraph(", ".join(data['zones'][:5]) + (f" and {len(data['zones'])-5} others" if len(data['zones']) > 5 else ""), body_style)]
            ]
            t_risk = Table(risk_data, colWidths=[1.5*inch, 5.5*inch])
            t_risk.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP'), ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey), ('BACKGROUND', (0,0), (0,-1), colors.whitesmoke), ('PADDING', (0,0), (-1,-1), 6)]))
            story.append(t_risk)
            story.append(Spacer(1, 15))
    else:
        story.append(Paragraph("No Critical or High risks were identified across the portfolio.", body_style))
        
    story.append(PageBreak())
    
    story.append(Paragraph("Zone Performance Matrix", h2_style))
    matrix_data = [["Zone Name", "Plan", "Score", "Critical", "High", "Status"]]
    for r in audit_results:
        status_text = "Pass"
        status_color = colors.green
        if r['counts']['Critical'] > 0: status_text = "Critical"; status_color = colors.red
        elif r['counts']['High'] > 0: status_text = "Warning"; status_color = colors.orange
        matrix_data.append([Paragraph(r['zone'], body_style), Paragraph(r['plan'], body_style), str(r['score']), str(r['counts']['Critical']), str(r['counts']['High']), Paragraph(f"<b>{status_text}</b>", ParagraphStyle('st', textColor=status_color))])
        
    t_matrix = Table(matrix_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1*inch, 1*inch, 1*inch])
    t_matrix.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), dark_blue), ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'), ('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.whitesmoke]), ('ALIGN', (2,0), (4,-1), 'CENTER')]))
    story.append(t_matrix)

    doc.build(story)
    logger.info(f"Portfolio Summary generated: {filename}")

def generate_html_dashboard(audit_results, output_dir):
    logger.info("Generating Portfolio Executive Summary HTML...")
    total_zones = len(audit_results)
    avg_score = int(sum(r['score'] for r in audit_results) / total_zones) if total_zones > 0 else 0
    total_critical = sum(r['counts']['Critical'] for r in audit_results)
    
    html_content = jinja2.Template(SUMMARY_HTML_TEMPLATE).render(
        date=datetime.now().strftime('%Y-%m-%d'),
        avg_score=avg_score,
        total_zones=total_zones,
        total_critical=total_critical,
        zones=audit_results
    )
    with open(f"{output_dir}/Portfolio_Executive_Summary.html", "w") as f:
        f.write(html_content)

# --- MAIN ---

def main():
    try:
        logger.info("Fetching zones...")
        zones_resp = requests.get(f"{BASE_URL}/zones", headers=HEADERS)
        if zones_resp.status_code != 200:
            logger.error("Failed to fetch zones. Check API Token permissions.")
            return
            
        zones = zones_resp.json().get('result', [])
        audit_results = []
        output_dir = f"reports/{datetime.now().strftime('%Y-%m-%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Output folder: {output_dir}")
        
        for zone in zones:
            zone_id = zone['id']
            zone_name = zone['name']
            account_id = zone['account']['id']
            # Fetch Plan Name
            plan_name = zone.get('plan', {}).get('name', 'Free')
            
            logger.info(f"Auditing {zone_name} (Plan: {plan_name})...")
            
            settings = get_zone_settings(zone_id)
            rulesets = get_rulesets(zone_id)
            ip_access_rules = get_ip_access_rules(zone_id)
            analytics = get_graphql_analytics(zone_id)
            dns_resp = requests.get(f"{BASE_URL}/zones/{zone_id}/dns_records", headers=HEADERS)
            dns_records = dns_resp.json().get('result', []) if dns_resp.status_code == 200 else []

            findings, managed_overrides, custom_rules, ip_list_findings = check_compliance(
                zone_name, zone_id, account_id, settings, rulesets, analytics, ip_access_rules, dns_records, plan_name
            )
            
            deductions = sum([10 for f in findings if f['severity'] in ['Critical', 'High']]) + sum([5 for f in findings if f['severity'] in ['Medium']])
            score = max(0, 100 - deductions)
            
            summary_counts = {
                "Critical": len([f for f in findings if f['severity'] == "Critical"]),
                "High": len([f for f in findings if f['severity'] == "High"]),
                "Pass": len([f for f in findings if f['severity'] == "Pass"])
            }
            
            if analytics['total_requests'] > 0:
                block_rate = round((analytics['total_threats'] / analytics['total_requests']) * 100, 2)
            else:
                block_rate = 0
            analytics['block_rate'] = block_rate
            
            top_threat = "None"
            if analytics.get('events'):
                top_threat = analytics['events'][0]['dimensions']['source']
            analytics['top_threat_source'] = top_threat

            charts = generate_charts(analytics, zone_name)
            
            html_content = jinja2.Template(HTML_TEMPLATE).render(
                title=zone_name,
                plan=plan_name,
                date=datetime.now().strftime('%Y-%m-%d'),
                findings=findings,
                analytics=analytics,
                score=score,
                summary_counts=summary_counts,
                charts=charts,
                dns_records=dns_records,
                is_mock=analytics.get('is_mock', False),
                managed_overrides=managed_overrides,
                custom_rules=custom_rules,
                ip_list_findings=ip_list_findings,
                ip_access_rules=ip_access_rules
            )
            
            with open(f"{output_dir}/{zone_name}_audit.html", "w") as f:
                f.write(html_content)
                
            create_pdf_report(
                f"{output_dir}/{zone_name}_audit.pdf", 
                zone_name, 
                plan_name,
                findings, 
                analytics, 
                dns_records, 
                charts,
                score,
                managed_overrides, 
                custom_rules, 
                ip_list_findings, 
                ip_access_rules
            )
            
            audit_results.append({
                "zone": zone_name,
                "plan": plan_name,
                "score": score,
                "counts": summary_counts,
                "findings": findings 
            })
            
        if audit_results:
            csv_data = [{"zone": r['zone'], "plan": r['plan'], "score": r['score'], "critical": r['counts']['Critical'], "high": r['counts']['High']} for r in audit_results]
            df_summary = pd.DataFrame(csv_data)
            df_summary.to_csv(f"{output_dir}/executive_summary.csv", index=False)
            
            generate_portfolio_report(audit_results, output_dir)
            generate_html_dashboard(audit_results, output_dir)
            
            logger.info(f"Audit Complete. Reports generated in '{output_dir}/' folder.")
            
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)

if __name__ == "__main__":
    main()