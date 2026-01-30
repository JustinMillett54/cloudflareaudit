import requests
import json
import logging
import os
import csv
import argparse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import pypandoc
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for PDF generation
import matplotlib.pyplot as plt
import io
import jinja2
import time
import base64
from datetime import datetime
from collections import defaultdict

# Version
VERSION = "2.0.0"

# Logging setup - good for debugging API calls and errors
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cloudflare_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# API configuration - pull from env vars for security
CLOUDFLARE_API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_API_EMAIL = os.getenv('CLOUDFLARE_API_EMAIL')
BASE_URL = "https://api.cloudflare.com/client/v4"

# Headers for API requests - auth stuff here
headers = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "X-Auth-Email": CLOUDFLARE_API_EMAIL,
    "Content-Type": "application/json"
}

# Cloudflare Managed Ruleset IDs (well-known rulesets that should be enabled by default)
CLOUDFLARE_MANAGED_RULESETS = {
    "efb7b8c949ac4650a09736fc376e9aee": {
        "name": "Cloudflare Managed Ruleset",
        "description": "Created by the Cloudflare security team, this ruleset provides fast and effective protection for all of your applications.",
        "default_enabled": True,
        "severity": "Critical"
    },
    "c2e184081120413c86c3ab7e14069605": {
        "name": "Cloudflare OWASP Core Ruleset",
        "description": "Cloudflare's implementation of the OWASP ModSecurity Core Rule Set. Rules are assigned a score that will be applied if triggered.",
        "default_enabled": True,
        "severity": "Critical"
    },
    "4a1e0e20e3f34eb5a96cc46ac2f0cbb0": {
        "name": "Cloudflare Exposed Credentials Check",
        "description": "Deploy an automated credentials check on your end-user authentication endpoints.",
        "default_enabled": True,
        "severity": "High"
    }
}

# Enterprise SKUs and features to check for
ENTERPRISE_FEATURES = {
    "api_shield": {"name": "API Shield", "endpoint": "/zones/{zone_id}/api_gateway/configuration"},
    "bot_management": {"name": "Bot Management", "endpoint": "/zones/{zone_id}/bot_management"},
    "rate_limiting": {"name": "Advanced Rate Limiting", "endpoint": "/zones/{zone_id}/rate_limits"},
    "waf_managed": {"name": "WAF Managed Rules", "endpoint": "/zones/{zone_id}/rulesets"},
    "load_balancing": {"name": "Load Balancing", "endpoint": "/zones/{zone_id}/load_balancers"},
    "spectrum": {"name": "Spectrum", "endpoint": "/zones/{zone_id}/spectrum/apps"},
    "argo": {"name": "Argo Smart Routing", "endpoint": "/zones/{zone_id}/argo/smart_routing"},
    "image_optimization": {"name": "Image Optimization", "endpoint": "/zones/{zone_id}/settings/polish"},
    "cache_reserve": {"name": "Cache Reserve", "endpoint": "/zones/{zone_id}/cache/tiered_cache_smart_topology_enable"},
    "zaraz": {"name": "Zaraz", "endpoint": "/zones/{zone_id}/zaraz/config"}
}

# Best practice settings and their expected values
BEST_PRACTICE_SETTINGS = {
    "min_tls_version": {"expected": ["1.2", "1.3"], "severity": "Critical", "description": "Minimum TLS version should be 1.2 or higher"},
    "always_use_https": {"expected": "on", "severity": "High", "description": "Always Use HTTPS should be enabled"},
    "true_client_ip_header": {"expected": "on", "severity": "High", "description": "True Client IP Header should be enabled for proper client identification"},
    "security_level": {"expected": ["medium", "high", "under_attack"], "severity": "High", "description": "Security level should be medium or higher"},
    "browser_check": {"expected": "on", "severity": "Medium", "description": "Browser Integrity Check should be enabled"},
    "challenge_ttl": {"expected": [1800, 3600, 7200, 14400, 28800, 57600, 86400], "severity": "Low", "description": "Challenge TTL should be configured appropriately"},
    "ssl": {"expected": ["full", "strict"], "severity": "Critical", "description": "SSL mode should be Full or Full (Strict)"},
    "automatic_https_rewrites": {"expected": "on", "severity": "Medium", "description": "Automatic HTTPS Rewrites should be enabled"},
    "opportunistic_encryption": {"expected": "on", "severity": "Low", "description": "Opportunistic Encryption should be enabled"},
    "email_obfuscation": {"expected": "on", "severity": "Low", "description": "Email Obfuscation should be enabled"},
    "server_side_exclude": {"expected": "on", "severity": "Low", "description": "Server Side Excludes should be enabled"},
    "hotlink_protection": {"expected": "on", "severity": "Low", "description": "Hotlink Protection should be enabled"},
    "early_hints": {"expected": "on", "severity": "Low", "description": "Early Hints should be enabled for better performance"},
    "http3": {"expected": "on", "severity": "Low", "description": "HTTP/3 should be enabled for improved performance"},
    "0rtt": {"expected": "on", "severity": "Low", "description": "0-RTT should be enabled for faster TLS resumption"},
    "websockets": {"expected": "on", "severity": "Low", "description": "WebSockets should be enabled if needed"},
}

# Risk register template for disabled rules
class RiskRegister:
    def __init__(self):
        self.entries = []
    
    def add_entry(self, zone_name, rule_id, rule_name, risk_level, description, recommendation, client_justification="Pending client input"):
        self.entries.append({
            "timestamp": datetime.now().isoformat(),
            "zone_name": zone_name,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "risk_level": risk_level,
            "description": description,
            "recommendation": recommendation,
            "client_justification": client_justification,
            "status": "Open"
        })
    
    def to_csv(self, filepath):
        if not self.entries:
            return
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.entries[0].keys())
            writer.writeheader()
            writer.writerows(self.entries)

# Jinja2 environment setup - using this for HTML templates
env = jinja2.Environment(autoescape=True)

# HTML template for zone and summary reports - this is the base structure for reports
template_string = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare Security Audit Report - {{ title }}</title>
    <style>
        :root {
            --primary-color: #f6821f;
            --secondary-color: #404040;
            --critical-color: #dc2626;
            --high-color: #ea580c;
            --medium-color: #ca8a04;
            --low-color: #16a34a;
            --compliant-color: #2563eb;
            --info-color: #6b7280;
            --bg-light: #f8fafc;
            --border-color: #e2e8f0;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            background-color: #f1f5f9;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, #e65c00 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .header .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px 40px;
            background: var(--bg-light);
            border-bottom: 1px solid var(--border-color);
        }
        
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        
        .meta-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #64748b;
            margin-bottom: 4px;
        }
        
        .meta-value {
            font-size: 1rem;
            font-weight: 600;
            color: var(--secondary-color);
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--primary-color);
        }
        
        .section-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--secondary-color);
        }
        
        .section-badge {
            margin-left: auto;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            background: var(--bg-light);
        }
        
        /* Executive Summary Cards */
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .summary-card.critical { background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-left: 4px solid var(--critical-color); }
        .summary-card.high { background: linear-gradient(135deg, #ffedd5 0%, #fed7aa 100%); border-left: 4px solid var(--high-color); }
        .summary-card.medium { background: linear-gradient(135deg, #fef9c3 0%, #fef08a 100%); border-left: 4px solid var(--medium-color); }
        .summary-card.low { background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%); border-left: 4px solid var(--low-color); }
        .summary-card.compliant { background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%); border-left: 4px solid var(--compliant-color); }
        .summary-card.info { background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%); border-left: 4px solid var(--info-color); }
        
        .summary-card .count {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 8px;
        }
        
        .summary-card .label {
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .summary-card.critical .count { color: var(--critical-color); }
        .summary-card.high .count { color: var(--high-color); }
        .summary-card.medium .count { color: var(--medium-color); }
        .summary-card.low .count { color: var(--low-color); }
        .summary-card.compliant .count { color: var(--compliant-color); }
        .summary-card.info .count { color: var(--info-color); }
        
        /* Tables */
        .table-container {
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        th {
            background: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);
            font-weight: 600;
            text-align: left;
            padding: 14px 16px;
            border-bottom: 2px solid var(--border-color);
            white-space: nowrap;
        }
        
        td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover {
            background-color: #f8fafc;
        }
        
        /* Severity badges */
        .severity-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        
        .severity-badge.critical { background-color: var(--critical-color); color: white; }
        .severity-badge.high { background-color: var(--high-color); color: white; }
        .severity-badge.medium { background-color: var(--medium-color); color: white; }
        .severity-badge.low { background-color: var(--low-color); color: white; }
        .severity-badge.compliant { background-color: var(--compliant-color); color: white; }
        .severity-badge.info { background-color: var(--info-color); color: white; }
        
        /* Zone inventory styling */
        .zone-inventory {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 16px;
        }
        
        .zone-card {
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            background: white;
            transition: box-shadow 0.2s;
        }
        
        .zone-card:hover {
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        .zone-name {
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 8px;
        }
        
        .zone-id {
            font-family: monospace;
            font-size: 0.8rem;
            color: #64748b;
            margin-bottom: 8px;
        }
        
        .zone-features {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }
        
        .feature-tag {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        
        .feature-tag.enabled { background: #dcfce7; color: #166534; }
        .feature-tag.disabled { background: #fee2e2; color: #991b1b; }
        .feature-tag.unknown { background: #f3f4f6; color: #374151; }
        
        /* Charts */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 20px;
        }
        
        .chart-container {
            text-align: center;
            padding: 20px;
            background: var(--bg-light);
            border-radius: 8px;
        }
        
        .chart-container img {
            max-width: 100%;
            height: auto;
        }
        
        /* Risk Register styling */
        .risk-entry {
            background: #fffbeb;
            border: 1px solid #fbbf24;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }
        
        .risk-entry.open { border-left: 4px solid var(--critical-color); }
        .risk-entry.acknowledged { border-left: 4px solid var(--medium-color); }
        .risk-entry.resolved { border-left: 4px solid var(--compliant-color); }
        
        /* SKU/Entitlements */
        .entitlements-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
        }
        
        .entitlement-item {
            display: flex;
            align-items: center;
            padding: 12px;
            background: var(--bg-light);
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }
        
        .entitlement-status {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }
        
        .entitlement-status.available { background: var(--low-color); }
        .entitlement-status.unavailable { background: #d1d5db; }
        .entitlement-status.enabled { background: var(--compliant-color); }
        
        .break-words {
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-width: 400px;
        }
        
        .no-data {
            padding: 40px;
            text-align: center;
            color: #64748b;
            background: var(--bg-light);
            border-radius: 8px;
        }
        
        /* Footer */
        .footer {
            padding: 30px 40px;
            background: var(--secondary-color);
            color: white;
            text-align: center;
            font-size: 0.875rem;
        }
        
        .footer a {
            color: var(--primary-color);
        }
        
        /* Print styles */
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
            }
            .section {
                page-break-inside: avoid;
            }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.75rem;
            }
            .meta-info {
                padding: 20px;
            }
            .content {
                padding: 20px;
            }
            .charts-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Cloudflare Security Audit Report</h1>
            <div class="subtitle">{{ title }}</div>
        </div>
        
        <div class="meta-info">
            <div class="meta-item">
                <span class="meta-label">Prepared By</span>
                <span class="meta-value">{{ prepared_by | default('Security Team') }}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Report Date</span>
                <span class="meta-value">{{ date }}</span>
            </div>
            {% if zone_name %}
            <div class="meta-item">
                <span class="meta-label">Domain</span>
                <span class="meta-value">{{ zone_name }}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Zone ID</span>
                <span class="meta-value" style="font-family: monospace; font-size: 0.85rem;">{{ zone_id }}</span>
            </div>
            {% endif %}
            {% if total_zones %}
            <div class="meta-item">
                <span class="meta-label">Total Zones Audited</span>
                <span class="meta-value">{{ total_zones }}</span>
            </div>
            {% endif %}
            <div class="meta-item">
                <span class="meta-label">Audit Version</span>
                <span class="meta-value">{{ version | default('2.0.0') }}</span>
            </div>
        </div>
        
        <div class="content">
            {% if executive_summary %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">📊 Executive Summary</h2>
                </div>
                <div class="summary-cards">
                    <div class="summary-card critical">
                        <div class="count">{{ executive_summary.critical | default(0) }}</div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="summary-card high">
                        <div class="count">{{ executive_summary.high | default(0) }}</div>
                        <div class="label">High</div>
                    </div>
                    <div class="summary-card medium">
                        <div class="count">{{ executive_summary.medium | default(0) }}</div>
                        <div class="label">Medium</div>
                    </div>
                    <div class="summary-card low">
                        <div class="count">{{ executive_summary.low | default(0) }}</div>
                        <div class="label">Low</div>
                    </div>
                    <div class="summary-card info">
                        <div class="count">{{ executive_summary.info | default(0) }}</div>
                        <div class="label">Info</div>
                    </div>
                    <div class="summary-card compliant">
                        <div class="count">{{ executive_summary.compliant | default(0) }}</div>
                        <div class="label">Compliant</div>
                    </div>
                </div>
            </div>
            {% endif %}
            
            {% if zone_inventory %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">🌐 Zone Inventory</h2>
                    <span class="section-badge">{{ zone_inventory | length }} Zones</span>
                </div>
                <div class="zone-inventory">
                    {% for zone in zone_inventory %}
                    <div class="zone-card">
                        <div class="zone-name">{{ zone.name }}</div>
                        <div class="zone-id">{{ zone.id }}</div>
                        <div class="zone-features">
                            <span class="feature-tag {{ 'enabled' if zone.plan == 'enterprise' else 'unknown' }}">{{ zone.plan | upper }}</span>
                            {% if zone.ssl_status %}
                            <span class="feature-tag {{ 'enabled' if zone.ssl_status == 'active' else 'disabled' }}">SSL: {{ zone.ssl_status }}</span>
                            {% endif %}
                            {% if zone.status %}
                            <span class="feature-tag {{ 'enabled' if zone.status == 'active' else 'disabled' }}">{{ zone.status }}</span>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            
            {% if entitlements %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">🎫 SKU & Entitlements Discovery</h2>
                </div>
                <div class="entitlements-grid">
                    {% for ent in entitlements %}
                    <div class="entitlement-item">
                        <span class="entitlement-status {{ ent.status }}"></span>
                        <span>{{ ent.name }}</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            
            {% if zone_name %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">🔍 Security Findings</h2>
                    <span class="section-badge">{{ findings | length }} Findings</span>
                </div>
                {% if findings %}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 100px;">Severity</th>
                                <th style="width: 50%;">Description</th>
                                <th>Recommendation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for finding in findings %}
                            <tr>
                                <td><span class="severity-badge {{ finding.severity.lower() }}">{{ finding.severity }}</span></td>
                                <td class="break-words">{{ finding.description }}</td>
                                <td class="break-words">{{ finding.recommendation }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="no-data">No findings available for this zone.</div>
                {% endif %}
            </div>
            
            {% if managed_rulesets_audit %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">🛡️ Managed Rulesets Audit</h2>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Ruleset Name</th>
                                <th>Status</th>
                                <th>Default</th>
                                <th>Rules Enabled</th>
                                <th>Rules Disabled</th>
                                <th>Action Required</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ruleset in managed_rulesets_audit %}
                            <tr>
                                <td><strong>{{ ruleset.name }}</strong></td>
                                <td><span class="severity-badge {{ 'compliant' if ruleset.enabled else 'critical' }}">{{ 'Enabled' if ruleset.enabled else 'Disabled' }}</span></td>
                                <td>{{ 'Yes' if ruleset.should_be_default else 'Optional' }}</td>
                                <td>{{ ruleset.rules_enabled }}</td>
                                <td>{{ ruleset.rules_disabled }}</td>
                                <td>{{ ruleset.recommendation }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endif %}
            
            {% if logpush_status %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">📤 Logpush / SIEM Integration</h2>
                </div>
                {% if logpush_status.jobs %}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Job ID</th>
                                <th>Dataset</th>
                                <th>Destination</th>
                                <th>Status</th>
                                <th>Last Success</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for job in logpush_status.jobs %}
                            <tr>
                                <td>{{ job.id }}</td>
                                <td>{{ job.dataset }}</td>
                                <td class="break-words">{{ job.destination_conf }}</td>
                                <td><span class="severity-badge {{ 'compliant' if job.enabled else 'high' }}">{{ 'Active' if job.enabled else 'Disabled' }}</span></td>
                                <td>{{ job.last_complete | default('N/A') }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="no-data">
                    <p><strong>⚠️ No Logpush jobs configured</strong></p>
                    <p>It is recommended to configure Logpush to send logs to your SIEM platform for security monitoring and compliance.</p>
                </div>
                {% endif %}
            </div>
            {% endif %}
            
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">🔒 IP Access Rules</h2>
                    <span class="section-badge">{{ ip_access_rules | length }} Rules</span>
                </div>
                {% if ip_access_rules %}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Target</th>
                                <th>Value</th>
                                <th>Action</th>
                                <th>Notes</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for rule in ip_access_rules %}
                            <tr>
                                <td>{{ rule.target }}</td>
                                <td class="break-words">{{ rule.value }}</td>
                                <td><span class="severity-badge {{ 'compliant' if rule.action == 'whitelist' else 'high' if rule.action == 'block' else 'medium' }}">{{ rule.action }}</span></td>
                                <td class="break-words">{{ rule.notes }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="no-data">No IP Access Rules configured for this zone.</div>
                {% endif %}
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">📋 DNS Records</h2>
                    <span class="section-badge">{{ dns_records | length }} Records</span>
                </div>
                {% if dns_records %}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Record Name</th>
                                <th>Type</th>
                                <th>Content</th>
                                <th>Proxied</th>
                                <th>TTL</th>
                                <th>Comment</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for record in dns_records %}
                            <tr>
                                <td class="break-words">{{ record.name }}</td>
                                <td><span class="severity-badge info">{{ record.type }}</span></td>
                                <td class="break-words">{{ record.content }}</td>
                                <td><span class="severity-badge {{ 'compliant' if record.proxied == 'True' else 'medium' }}">{{ record.proxied }}</span></td>
                                <td>{{ record.ttl }}</td>
                                <td class="break-words">{{ record.comment }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="no-data">{{ dns_records_message | default('No DNS records found.') }}</div>
                {% endif %}
            </div>
            {% endif %}
            
            {% if risk_register %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">⚠️ Risk Register</h2>
                    <span class="section-badge">{{ risk_register | length }} Open Risks</span>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>Rule/Setting</th>
                                <th>Risk Level</th>
                                <th>Description</th>
                                <th>Recommendation</th>
                                <th>Client Justification</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for risk in risk_register %}
                            <tr>
                                <td>{{ risk.zone_name }}</td>
                                <td>{{ risk.rule_name }}</td>
                                <td><span class="severity-badge {{ risk.risk_level.lower() }}">{{ risk.risk_level }}</span></td>
                                <td class="break-words">{{ risk.description }}</td>
                                <td class="break-words">{{ risk.recommendation }}</td>
                                <td class="break-words">{{ risk.client_justification }}</td>
                                <td><span class="severity-badge {{ 'high' if risk.status == 'Open' else 'compliant' }}">{{ risk.status }}</span></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endif %}
            
            {% if zones_data %}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">📈 Zone Summary</h2>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone Name</th>
                                <th>Critical</th>
                                <th>High</th>
                                <th>Medium</th>
                                <th>Low</th>
                                <th>Info</th>
                                <th>Compliant</th>
                                <th>IP Rules</th>
                                <th>Legacy WAF</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for zone in zones_data %}
                            <tr>
                                <td class="break-words"><strong>{{ zone.name }}</strong></td>
                                <td><span class="severity-badge critical">{{ zone.critical }}</span></td>
                                <td><span class="severity-badge high">{{ zone.high }}</span></td>
                                <td><span class="severity-badge medium">{{ zone.medium }}</span></td>
                                <td><span class="severity-badge low">{{ zone.low }}</span></td>
                                <td><span class="severity-badge info">{{ zone.info }}</span></td>
                                <td><span class="severity-badge compliant">{{ zone.compliant }}</span></td>
                                <td>{{ zone.ip_access_rules }}</td>
                                <td><span class="severity-badge {{ 'critical' if zone.old_waf == 'Enabled' else 'compliant' }}">{{ zone.old_waf }}</span></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">📊 Visualization</h2>
                </div>
                <div class="charts-grid">
                    <div class="chart-container">
                        <h3 style="margin-bottom: 15px;">Severity Distribution</h3>
                        <img src="{{ pie_chart }}" alt="Severity Distribution Pie Chart">
                    </div>
                    <div class="chart-container">
                        <h3 style="margin-bottom: 15px;">Critical & High Findings by Zone</h3>
                        <img src="{{ bar_chart }}" alt="Critical and High Findings Bar Chart">
                    </div>
                </div>
            </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Generated by Cloudflare Security Audit Tool v{{ version | default('2.0.0') }}</p>
            <p>Report generated on {{ date }} | Confidential - For Internal Use Only</p>
        </div>
    </div>
</body>
</html>
"""

# Paragraph style for table cells (PDF) - tweaking this for better wrapping in PDFs
styles = getSampleStyleSheet()
cell_style = ParagraphStyle(
    name='CellStyle',
    parent=styles['BodyText'],
    fontSize=8,
    leading=10,
    wordWrap='CJK'
)

def check_min_tls_version(zone_id, zone_name):
    # Checking if TLS is at least 1.2 - old versions are a big no-no
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/min_tls_version"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            tls_version = data['result']['value']
            if tls_version in ["1.0", "1.1"]:
                findings.append({
                    'severity': 'Critical',
                    'description': f"{zone_name}: Minimum TLS version is {tls_version}.",
                    'recommendation': "Set minimum TLS version to 1.2 or higher."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Minimum TLS version is {tls_version}.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve TLS version: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching TLS version for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching TLS version: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_true_client_ip_header(zone_id, zone_name):
    # Make sure we're getting the real client IP - important for logging and security
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/true_client_ip_header"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: True Client IP Header is disabled.",
                    'recommendation': "Enable True Client IP Header."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: True Client IP Header is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve True Client IP: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching True Client IP for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching True Client IP: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_bot_management(zone_id, zone_name):
    # Bot management - nice to have, but not critical unless you're getting hammered by bots
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/bot_management"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: Bot Management is disabled.",
                    'recommendation': "Consider enabling Bot Management."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Bot Management is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'Low',
                'description': f"{zone_name}: Bot Management unavailable: {response.status_code} {response.reason}",
                'recommendation': "Consider upgrading plan."
            })
    except Exception as e:
        logger.error(f"Error fetching Bot Management for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'Low',
            'description': f"{zone_name}: Error fetching Bot Management: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_security_level(zone_id, zone_name):
    # Security level - don't want it too lax
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/security_level"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            level = data['result']['value']
            if level in ["low", "essentially_off"]:
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: Security level is {level}.",
                    'recommendation': "Set security level to 'medium' or higher."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Security level is {level}.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve security level: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching security level for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching security level: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_http3(zone_id, zone_name):
    # HTTP/3 - performance thing, but good to enable if possible
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/http3"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: HTTP/3 with QUIC is disabled.",
                    'recommendation': "Consider enabling HTTP/3."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: HTTP/3 with QUIC is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve HTTP/3: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching HTTP/3 for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching HTTP/3: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_dnssec(zone_id, zone_name):
    # DNSSEC - really should be on to prevent spoofing
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/dnssec"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            status = data['result']['status']
            if status == "disabled":
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: DNSSEC is disabled.",
                    'recommendation': "Enable DNSSEC."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: DNSSEC is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve DNSSEC: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching DNSSEC for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching DNSSEC: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_always_use_https(zone_id, zone_name):
    # Force HTTPS - no excuses for not having this on
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/always_use_https"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: Always Use HTTPS is disabled.",
                    'recommendation': "Enable Always Use HTTPS."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Always Use HTTPS is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve Always Use HTTPS: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching Always Use HTTPS for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching Always Use HTTPS: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_waf(zone_id, zone_name):
    # Legacy WAF - if this is on, time to migrate
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/waf"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "on":
                findings.append({
                    'severity': 'Critical',
                    'description': f"{zone_name}: Legacy WAF is enabled.",
                    'recommendation': "Migrate to new WAF rulesets."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Legacy WAF is disabled.",
                    'recommendation': "Ensure modern WAF rulesets are configured."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve WAF: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching WAF for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching WAF: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_ip_access_rules(zone_id, zone_name):
    # Pulling IP rules - these can be allow/block, flag if none or issues
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/firewall/access_rules/rules"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rules = data.get('result', [])
            if not rules:
                findings.append({
                    'severity': 'Medium',
                    'description': f"{zone_name}: No IP Access Rules configured.",
                    'recommendation': "Consider configuring IP Access Rules."
                })
            for rule in rules:
                target = rule.get('configuration', {}).get('target', 'N/A')
                value = rule.get('configuration', {}).get('value', 'N/A')
                mode = rule.get('mode', 'N/A')
                notes = rule.get('notes', 'None')
                severity = 'Compliant' if mode == 'allow' else 'High' if mode == 'block' else 'Medium'
                findings.append({
                    'severity': severity,
                    'description': f"{zone_name}: IP Access Rule - Target: {target}, Value: {value}, Action: {mode}, Notes: {notes}",
                    'recommendation': "Review rule alignment with security policies."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve IP Access Rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching IP Access Rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching IP Access Rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_firewall_rules(zone_id, zone_name):
    # Firewall rules - at least make sure some exist
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/rulesets"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rulesets = data.get('result', [])
            if not rulesets:
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: No firewall rules found.",
                    'recommendation': "Configure firewall rules."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: {len(rulesets)} firewall rulesets found.",
                    'recommendation': "Review rulesets."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve firewall rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching firewall rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching firewall rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_managed_rules(zone_id, zone_name):
    # Managed rules - Cloudflare's pre-built ones, should be using them
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/rulesets"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rulesets = data.get('result', [])
            managed_rulesets = [r for r in rulesets if r.get('kind') == 'managed']
            if not managed_rulesets:
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: No managed rulesets found.",
                    'recommendation': "Enable managed rulesets."
                })
            else:
                for ruleset in managed_rulesets:
                    ruleset_id = ruleset.get('id', 'N/A')
                    status = ruleset.get('phase', 'N/A')
                    findings.append({
                        'severity': 'Compliant' if status != 'disabled' else 'High',
                        'description': f"{zone_name}: Managed ruleset {ruleset_id} is {status}.",
                        'recommendation': "Ensure managed rulesets are enabled."
                    })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve managed rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching managed rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching managed rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_rate_limiting(zone_id, zone_name):
    # Rate limiting - optional but useful for DDoS protection
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/rulesets?phase=http_ratelimit"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rulesets = data.get('result', [])
            if not rulesets:
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: No rate limiting rules configured.",
                    'recommendation': "Consider configuring rate limiting rules."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: {len(rulesets)} rate limiting rulesets found.",
                    'recommendation': "Review rate limiting rules."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve rate limiting rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching rate limiting rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching rate limiting rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_logpush(zone_id, zone_name):
    """Check Logpush configuration for SIEM integration"""
    findings = []
    logpush_data = {"jobs": []}
    try:
        url = f"{BASE_URL}/zones/{zone_id}/logpush/jobs"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            jobs = data.get('result', [])
            if not jobs:
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: No Logpush jobs configured for SIEM integration.",
                    'recommendation': "Configure Logpush to send logs to your SIEM platform for security monitoring."
                })
            else:
                enabled_jobs = [j for j in jobs if j.get('enabled', False)]
                disabled_jobs = [j for j in jobs if not j.get('enabled', False)]
                logpush_data["jobs"] = jobs
                
                if enabled_jobs:
                    findings.append({
                        'severity': 'Compliant',
                        'description': f"{zone_name}: {len(enabled_jobs)} active Logpush job(s) configured.",
                        'recommendation': "Review log destinations periodically."
                    })
                
                if disabled_jobs:
                    findings.append({
                        'severity': 'Medium',
                        'description': f"{zone_name}: {len(disabled_jobs)} Logpush job(s) are disabled.",
                        'recommendation': "Review and enable disabled Logpush jobs or remove if not needed."
                    })
        elif response.status_code == 403:
            findings.append({
                'severity': 'Info',
                'description': f"{zone_name}: Logpush feature not available (may require Enterprise plan).",
                'recommendation': "Consider upgrading to Enterprise for Logpush capabilities."
            })
        else:
            findings.append({
                'severity': 'Medium',
                'description': f"{zone_name}: Could not check Logpush status: {response.status_code}",
                'recommendation': "Verify API permissions include Logpush read access."
            })
    except Exception as e:
        logger.error(f"Error checking Logpush for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'Medium',
            'description': f"{zone_name}: Error checking Logpush: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings, logpush_data

def check_ssl_mode(zone_id, zone_name):
    """Check SSL/TLS encryption mode"""
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/ssl"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            ssl_mode = data['result']['value']
            if ssl_mode in ["off", "flexible"]:
                findings.append({
                    'severity': 'Critical',
                    'description': f"{zone_name}: SSL mode is '{ssl_mode}' - traffic between Cloudflare and origin is not encrypted.",
                    'recommendation': "Set SSL mode to 'Full' or 'Full (Strict)' to ensure end-to-end encryption."
                })
            elif ssl_mode == "full":
                findings.append({
                    'severity': 'Medium',
                    'description': f"{zone_name}: SSL mode is 'Full' - origin certificate not validated.",
                    'recommendation': "Consider upgrading to 'Full (Strict)' for origin certificate validation."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: SSL mode is '{ssl_mode}'.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve SSL mode: {response.status_code}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error checking SSL mode for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error checking SSL mode: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_browser_integrity(zone_id, zone_name):
    """Check Browser Integrity Check setting"""
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/browser_check"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Medium',
                    'description': f"{zone_name}: Browser Integrity Check is disabled.",
                    'recommendation': "Enable Browser Integrity Check to detect malicious bots."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Browser Integrity Check is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'Low',
                'description': f"{zone_name}: Could not check Browser Integrity: {response.status_code}",
                'recommendation': "Verify API permissions."
            })
    except Exception as e:
        logger.error(f"Error checking Browser Integrity for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'Low',
            'description': f"{zone_name}: Error checking Browser Integrity: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_automatic_https_rewrites(zone_id, zone_name):
    """Check Automatic HTTPS Rewrites setting"""
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/automatic_https_rewrites"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Medium',
                    'description': f"{zone_name}: Automatic HTTPS Rewrites is disabled.",
                    'recommendation': "Enable Automatic HTTPS Rewrites to fix mixed content issues."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Automatic HTTPS Rewrites is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'Low',
                'description': f"{zone_name}: Could not check HTTPS Rewrites: {response.status_code}",
                'recommendation': "Verify API permissions."
            })
    except Exception as e:
        logger.error(f"Error checking HTTPS Rewrites for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'Low',
            'description': f"{zone_name}: Error checking HTTPS Rewrites: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_email_obfuscation(zone_id, zone_name):
    """Check Email Obfuscation setting"""
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/email_obfuscation"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: Email Obfuscation is disabled.",
                    'recommendation': "Enable Email Obfuscation to protect email addresses from scrapers."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Email Obfuscation is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'Info',
                'description': f"{zone_name}: Could not check Email Obfuscation: {response.status_code}",
                'recommendation': "Verify API permissions."
            })
    except Exception as e:
        logger.error(f"Error checking Email Obfuscation for {zone_id}: {str(e)}")
    return findings

def check_opportunistic_encryption(zone_id, zone_name):
    """Check Opportunistic Encryption setting"""
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/opportunistic_encryption"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: Opportunistic Encryption is disabled.",
                    'recommendation': "Enable Opportunistic Encryption for additional security."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Opportunistic Encryption is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'Info',
                'description': f"{zone_name}: Could not check Opportunistic Encryption: {response.status_code}",
                'recommendation': "Verify API permissions."
            })
    except Exception as e:
        logger.error(f"Error checking Opportunistic Encryption for {zone_id}: {str(e)}")
    return findings

def discover_entitlements(zone_id, zone_name, zone_plan):
    """Discover available SKUs and entitlements for the zone"""
    entitlements = []
    
    # Check each enterprise feature
    for feature_key, feature_info in ENTERPRISE_FEATURES.items():
        try:
            endpoint = feature_info["endpoint"].format(zone_id=zone_id)
            url = f"{BASE_URL}{endpoint}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                status = "enabled"
            elif response.status_code == 403:
                status = "unavailable"
            else:
                status = "available"
            
            entitlements.append({
                "name": feature_info["name"],
                "status": status,
                "key": feature_key
            })
        except Exception as e:
            logger.debug(f"Error checking {feature_key} for {zone_id}: {str(e)}")
            entitlements.append({
                "name": feature_info["name"],
                "status": "unknown",
                "key": feature_key
            })
    
    return entitlements

def audit_managed_rulesets_deep(zone_id, zone_name, risk_register):
    """Deep audit of managed rulesets - check individual rules against defaults"""
    findings = []
    rulesets_audit = []
    
    try:
        # Get all rulesets for the zone
        url = f"{BASE_URL}/zones/{zone_id}/rulesets"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}")
        
        if response.status_code != 200:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve rulesets for deep audit.",
                'recommendation': "Check API token permissions."
            })
            return findings, rulesets_audit
        
        rulesets = response.json().get('result', [])
        
        # Find the http_request_firewall_managed phase ruleset
        managed_phase_ruleset = None
        for rs in rulesets:
            if rs.get('phase') == 'http_request_firewall_managed':
                managed_phase_ruleset = rs
                break
        
        if not managed_phase_ruleset:
            findings.append({
                'severity': 'Critical',
                'description': f"{zone_name}: No managed WAF rules configured (http_request_firewall_managed phase missing).",
                'recommendation': "Enable Cloudflare Managed Ruleset and OWASP Core Ruleset for protection."
            })
            risk_register.add_entry(
                zone_name=zone_name,
                rule_id="managed_waf",
                rule_name="Managed WAF Configuration",
                risk_level="Critical",
                description="No managed WAF rules are configured for this zone.",
                recommendation="Deploy Cloudflare Managed Ruleset and OWASP Core Ruleset immediately."
            )
            return findings, rulesets_audit
        
        # Get the full ruleset details with rules
        ruleset_id = managed_phase_ruleset.get('id')
        url = f"{BASE_URL}/zones/{zone_id}/rulesets/{ruleset_id}"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            findings.append({
                'severity': 'Medium',
                'description': f"{zone_name}: Could not retrieve detailed ruleset configuration.",
                'recommendation': "Check API permissions for ruleset details."
            })
            return findings, rulesets_audit
        
        ruleset_details = response.json().get('result', {})
        rules = ruleset_details.get('rules', [])
        
        # Track which managed rulesets are deployed
        deployed_rulesets = {}
        for rule in rules:
            action_params = rule.get('action_parameters', {})
            if 'id' in action_params:
                ref_id = action_params['id']
                deployed_rulesets[ref_id] = {
                    'rule': rule,
                    'enabled': rule.get('enabled', True),
                    'action': rule.get('action', 'execute')
                }
        
        # Check each well-known managed ruleset
        for ruleset_id, ruleset_info in CLOUDFLARE_MANAGED_RULESETS.items():
            if ruleset_id in deployed_rulesets:
                deployment = deployed_rulesets[ruleset_id]
                rule_data = deployment['rule']
                
                # Count overrides (disabled rules)
                overrides = rule_data.get('action_parameters', {}).get('overrides', {})
                disabled_rules = []
                enabled_rules = 0
                
                # Check rule overrides
                rule_overrides = overrides.get('rules', [])
                for override in rule_overrides:
                    if override.get('enabled') is False:
                        disabled_rules.append(override.get('id', 'unknown'))
                
                # Check category overrides
                category_overrides = overrides.get('categories', [])
                for cat_override in category_overrides:
                    if cat_override.get('enabled') is False:
                        disabled_rules.append(f"Category: {cat_override.get('category', 'unknown')}")
                
                if deployment['enabled']:
                    if disabled_rules:
                        findings.append({
                            'severity': 'Medium',
                            'description': f"{zone_name}: {ruleset_info['name']} is enabled but {len(disabled_rules)} rule(s)/categories are disabled.",
                            'recommendation': f"Review disabled rules and document business justification: {', '.join(disabled_rules[:5])}{'...' if len(disabled_rules) > 5 else ''}"
                        })
                        risk_register.add_entry(
                            zone_name=zone_name,
                            rule_id=ruleset_id,
                            rule_name=ruleset_info['name'],
                            risk_level="Medium",
                            description=f"{len(disabled_rules)} rules/categories are disabled from default configuration.",
                            recommendation="Document business justification for each disabled rule."
                        )
                    else:
                        findings.append({
                            'severity': 'Compliant',
                            'description': f"{zone_name}: {ruleset_info['name']} is fully enabled with default configuration.",
                            'recommendation': "No action needed."
                        })
                else:
                    findings.append({
                        'severity': ruleset_info['severity'],
                        'description': f"{zone_name}: {ruleset_info['name']} is deployed but DISABLED.",
                        'recommendation': f"Enable this ruleset - it is recommended as a default protection."
                    })
                    risk_register.add_entry(
                        zone_name=zone_name,
                        rule_id=ruleset_id,
                        rule_name=ruleset_info['name'],
                        risk_level=ruleset_info['severity'],
                        description=f"{ruleset_info['name']} is deployed but disabled.",
                        recommendation="Enable this ruleset immediately and document reason for prior disable."
                    )
                
                rulesets_audit.append({
                    'name': ruleset_info['name'],
                    'enabled': deployment['enabled'],
                    'should_be_default': ruleset_info['default_enabled'],
                    'rules_enabled': 'All' if not disabled_rules else f"Partial ({len(disabled_rules)} disabled)",
                    'rules_disabled': len(disabled_rules),
                    'recommendation': 'Compliant' if deployment['enabled'] and not disabled_rules else 'Review Required'
                })
            else:
                # Ruleset not deployed at all
                if ruleset_info['default_enabled']:
                    findings.append({
                        'severity': ruleset_info['severity'],
                        'description': f"{zone_name}: {ruleset_info['name']} is NOT deployed (should be enabled by default).",
                        'recommendation': "Deploy this managed ruleset for baseline protection."
                    })
                    risk_register.add_entry(
                        zone_name=zone_name,
                        rule_id=ruleset_id,
                        rule_name=ruleset_info['name'],
                        risk_level=ruleset_info['severity'],
                        description=f"{ruleset_info['name']} is not deployed.",
                        recommendation="Deploy this ruleset immediately for baseline security."
                    )
                    
                    rulesets_audit.append({
                        'name': ruleset_info['name'],
                        'enabled': False,
                        'should_be_default': True,
                        'rules_enabled': 0,
                        'rules_disabled': 'N/A - Not Deployed',
                        'recommendation': 'Deploy Immediately'
                    })
    
    except Exception as e:
        logger.error(f"Error in deep ruleset audit for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'Medium',
            'description': f"{zone_name}: Error during deep ruleset audit: {str(e)}",
            'recommendation': "Check API connectivity and try again."
        })
    
    return findings, rulesets_audit

def check_page_rules(zone_id, zone_name):
    """Check Page Rules configuration"""
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/pagerules"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rules = data.get('result', [])
            
            # Check for potentially risky page rules
            for rule in rules:
                targets = rule.get('targets', [])
                actions = rule.get('actions', [])
                status = rule.get('status', 'active')
                
                for action in actions:
                    action_id = action.get('id', '')
                    action_value = action.get('value', '')
                    
                    # Flag security level bypasses
                    if action_id == 'security_level' and action_value in ['essentially_off', 'off']:
                        target_url = targets[0].get('constraint', {}).get('value', 'unknown') if targets else 'unknown'
                        findings.append({
                            'severity': 'High',
                            'description': f"{zone_name}: Page Rule disables security for {target_url}",
                            'recommendation': "Review if security bypass is necessary; consider more targeted approach."
                        })
                    
                    # Flag SSL bypass
                    if action_id == 'ssl' and action_value in ['off', 'flexible']:
                        target_url = targets[0].get('constraint', {}).get('value', 'unknown') if targets else 'unknown'
                        findings.append({
                            'severity': 'Critical',
                            'description': f"{zone_name}: Page Rule sets insecure SSL mode for {target_url}",
                            'recommendation': "Remove or modify this page rule to enforce proper encryption."
                        })
                    
                    # Flag cache everything without edge TTL
                    if action_id == 'cache_level' and action_value == 'cache_everything':
                        has_edge_ttl = any(a.get('id') == 'edge_cache_ttl' for a in actions)
                        if not has_edge_ttl:
                            findings.append({
                                'severity': 'Low',
                                'description': f"{zone_name}: 'Cache Everything' page rule without explicit Edge TTL.",
                                'recommendation': "Consider setting an explicit Edge TTL to control cache duration."
                            })
            
            if not rules:
                findings.append({
                    'severity': 'Info',
                    'description': f"{zone_name}: No Page Rules configured.",
                    'recommendation': "Page Rules can be used for URL-specific settings if needed."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: {len(rules)} Page Rule(s) configured.",
                    'recommendation': "Review page rules periodically."
                })
        else:
            findings.append({
                'severity': 'Low',
                'description': f"{zone_name}: Could not retrieve Page Rules: {response.status_code}",
                'recommendation': "Verify API permissions."
            })
    except Exception as e:
        logger.error(f"Error checking Page Rules for {zone_id}: {str(e)}")
    return findings

def check_origin_certificates(zone_id, zone_name):
    """Check Cloudflare Origin Certificates"""
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/origin_tls_client_auth"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            enabled = data.get('result', {}).get('enabled', False) if isinstance(data.get('result'), dict) else False
            if not enabled:
                findings.append({
                    'severity': 'Medium',
                    'description': f"{zone_name}: Authenticated Origin Pulls is disabled.",
                    'recommendation': "Enable Authenticated Origin Pulls for additional origin security."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Authenticated Origin Pulls is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'Info',
                'description': f"{zone_name}: Could not check Authenticated Origin Pulls: {response.status_code}",
                'recommendation': "Feature may require specific plan or permissions."
            })
    except Exception as e:
        logger.error(f"Error checking origin certs for {zone_id}: {str(e)}")
    return findings

def check_cache_settings(zone_id, zone_name):
    """Check caching configuration"""
    findings = []
    try:
        # Check cache level
        url = f"{BASE_URL}/zones/{zone_id}/settings/cache_level"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            cache_level = data['result']['value']
            findings.append({
                'severity': 'Compliant',
                'description': f"{zone_name}: Cache level is set to '{cache_level}'.",
                'recommendation': "Review cache settings match application requirements."
            })
        
        # Check browser cache TTL
        url = f"{BASE_URL}/zones/{zone_id}/settings/browser_cache_ttl"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            ttl = data['result']['value']
            if ttl < 3600:  # Less than 1 hour
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: Browser Cache TTL is {ttl} seconds (less than 1 hour).",
                    'recommendation': "Consider increasing browser cache TTL for better performance."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Browser Cache TTL is {ttl} seconds.",
                    'recommendation': "No action needed."
                })
    except Exception as e:
        logger.error(f"Error checking cache settings for {zone_id}: {str(e)}")
    return findings

def export_to_csv(zone_data, output_dir):
    """Export audit data to CSV files for client use"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Export findings
    findings_file = os.path.join(output_dir, f"findings_{timestamp}.csv")
    with open(findings_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Zone Name', 'Zone ID', 'Severity', 'Description', 'Recommendation'])
        for zone in zone_data:
            for finding in zone.get('findings', []):
                writer.writerow([
                    zone['name'],
                    zone.get('id', 'N/A'),
                    finding['severity'],
                    finding['description'],
                    finding['recommendation']
                ])
    logger.info(f"Exported findings to {findings_file}")
    
    # Export zone inventory
    inventory_file = os.path.join(output_dir, f"zone_inventory_{timestamp}.csv")
    with open(inventory_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Zone Name', 'Zone ID', 'Plan', 'Status', 'SSL Status', 'Critical', 'High', 'Medium', 'Low', 'Compliant'])
        for zone in zone_data:
            severity_counts = defaultdict(int)
            for finding in zone.get('findings', []):
                severity_counts[finding['severity']] += 1
            writer.writerow([
                zone['name'],
                zone.get('id', 'N/A'),
                zone.get('plan', 'N/A'),
                zone.get('status', 'N/A'),
                zone.get('ssl_status', 'N/A'),
                severity_counts.get('Critical', 0),
                severity_counts.get('High', 0),
                severity_counts.get('Medium', 0),
                severity_counts.get('Low', 0),
                severity_counts.get('Compliant', 0)
            ])
    logger.info(f"Exported zone inventory to {inventory_file}")
    
    # Export DNS records
    dns_file = os.path.join(output_dir, f"dns_records_{timestamp}.csv")
    with open(dns_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Zone Name', 'Record Name', 'Type', 'Content', 'Proxied', 'TTL', 'Comment'])
        for zone in zone_data:
            for record in zone.get('dns_records', []):
                if isinstance(record, dict):
                    writer.writerow([
                        zone['name'],
                        record.get('name', 'N/A'),
                        record.get('type', 'N/A'),
                        record.get('content', 'N/A'),
                        record.get('proxied', 'N/A'),
                        record.get('ttl', 'N/A'),
                        record.get('comment', '')
                    ])
    logger.info(f"Exported DNS records to {dns_file}")
    
    return {
        'findings': findings_file,
        'inventory': inventory_file,
        'dns': dns_file
    }
    # Grab all DNS records, paging through if there's a lot
    dns_records = []
    page = 1
    per_page = 100
    try:
        while True:
            url = f"{BASE_URL}/zones/{zone_id}/dns_records?page={page}&per_page={per_page}"
            response = requests.get(url, headers=headers)
            logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
            if response.status_code == 200:
                data = response.json()
                records = data.get('result', [])
                for record in records:
                    logger.debug(f"DNS Record: Type={record.get('type', 'N/A')}, Name={record.get('name', 'N/A')}, Content={record.get('content', 'N/A')}, Proxied={record.get('proxied', 'N/A')}, TTL={record.get('ttl', 'N/A')}, Comment={record.get('comment', 'None')}")
                dns_records.extend(records)
                result_info = data.get('result_info', {})
                total_pages = result_info.get('total_pages', 1)
                total_count = result_info.get('total_count', len(records))
                logger.info(f"Retrieved {len(records)} DNS records for {zone_name}, page {page}/{total_pages}, total: {total_count}")
                if page >= total_pages:
                    break
                page += 1
            else:
                logger.error(f"Failed to retrieve DNS records for {zone_name}: {response.status_code} {response.reason}")
                return f"Failed to retrieve DNS records: {response.status_code} {response.reason}"
    except Exception as e:
        logger.error(f"Error fetching DNS records for {zone_id}: {str(e)}")
        return f"Error fetching DNS records: {str(e)}"
    return dns_records

def generate_zone_pdf(zone_id, zone_name, findings, dns_records, managed_rulesets_audit=None, logpush_status=None, entitlements=None, risk_register_entries=None):
    # Building the PDF for a single zone - using reportlab for tables and text
    html_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.html"
    pdf_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.pdf"
    logger.info(f"Generating HTML and PDF for {zone_name}: {html_file}, {pdf_file}")

    try:
        # Prepare IP Access Rules data
        ip_access_rules = []
        for rule in [f for f in findings if "IP Access Rule - Target:" in f['description']]:
            try:
                parts = rule['description'].split(' - ')[1].split(', ')
                if len(parts) >= 4:
                    ip_access_rules.append({
                        'target': parts[0].split(': ')[1],
                        'value': parts[1].split(': ')[1],
                        'action': parts[2].split(': ')[1],
                        'notes': parts[3].split(': ')[1]
                    })
                else:
                    logger.warning(f"Skipping malformed IP Access Rule for {zone_name}: {rule['description']}")
            except (IndexError, KeyError) as e:
                logger.warning(f"Error parsing IP Access Rule for {zone_name}: {rule['description']}, Error: {str(e)}")

        # Prepare DNS Records data
        dns_records_data = []
        dns_records_message = "No DNS records found."
        if isinstance(dns_records, list):
            if dns_records:
                for record in dns_records:
                    content = record.get('content', 'N/A')
                    ttl = record.get('ttl', 'N/A')
                    if ttl == 1:
                        ttl = 'Auto'
                    if record.get('type') == 'MX':
                        content = f"{record.get('priority', 'N/A')} {content}"
                    elif record.get('type') == 'SRV':
                        content = f"{record.get('data', {}).get('priority', 'N/A')} {record.get('data', {}).get('target', 'N/A')}"
                    elif record.get('type') == 'NS':
                        content = record.get('content', 'N/A')
                    dns_records_data.append({
                        'name': record.get('name', 'N/A'),
                        'type': record.get('type', 'N/A'),
                        'content': content,
                        'proxied': str(record.get('proxied', False)),
                        'ttl': str(ttl),
                        'comment': str(record.get('comment', 'None'))
                    })
            else:
                dns_records_message = "No DNS records found."
        else:
            dns_records_message = dns_records
        
        # Calculate executive summary
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding['severity']] += 1
        executive_summary = {
            'critical': severity_counts.get('Critical', 0),
            'high': severity_counts.get('High', 0),
            'medium': severity_counts.get('Medium', 0),
            'low': severity_counts.get('Low', 0),
            'info': severity_counts.get('Info', 0),
            'compliant': severity_counts.get('Compliant', 0)
        }

        # Render HTML
        template = env.from_string(template_string)
        rendered_html = template.render(
            title=zone_name,
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            zone_name=zone_name,
            zone_id=zone_id,
            findings=findings,
            ip_access_rules=ip_access_rules,
            dns_records=dns_records_data,
            dns_records_message=dns_records_message,
            executive_summary=executive_summary,
            managed_rulesets_audit=managed_rulesets_audit or [],
            logpush_status=logpush_status or {},
            entitlements=entitlements or [],
            risk_register=risk_register_entries or [],
            version=VERSION
        )

        # Save HTML
        with open(html_file, 'w') as f:
            f.write(rendered_html)
        if os.path.exists(html_file):
            logger.info(f"HTML generated successfully for {zone_name}: {html_file}")
        else:
            logger.error(f"HTML file not found after generation for {zone_name}: {html_file}")

        # Generate PDF with reportlab
        doc = SimpleDocTemplate(pdf_file, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        body_style = styles['BodyText']
        pdf_severity_colors = {
            'Critical': colors.Color(0.8, 0.2, 0.2),
            'High': colors.Color(0.8, 0.4, 0.2),
            'Medium': colors.Color(0.8, 0.8, 0.2),
            'Low': colors.Color(0.2, 0.8, 0.2),
            'Compliant': colors.Color(0.2, 0.4, 0.8),
            'Info': colors.grey
        }

        elements.append(Paragraph("Cloudflare Security Audit Report", title_style))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Domain: {zone_name}", body_style))
        elements.append(Paragraph(f"Zone ID: {zone_id}", body_style))
        elements.append(Paragraph(f"Prepared by: Optiv Security", body_style))
        elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("Findings", title_style))
        if findings:
            data = [['Severity', 'Description', 'Recommendation']]
            for finding in findings:
                severity = finding['severity']
                description = Paragraph(finding['description'], cell_style)
                recommendation = Paragraph(finding['recommendation'], cell_style)
                data.append([Paragraph(severity, cell_style), description, recommendation])
            
            col_widths = [100, 200, 200]
            table = Table(data, colWidths=col_widths, splitByRow=True)
            table_styles = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
            ]
            for i, finding in enumerate(findings, 1):
                table_styles.append((
                    'BACKGROUND', (0, i), (-1, i),
                    pdf_severity_colors.get(finding['severity'], colors.beige)
                ))
            table.setStyle(TableStyle(table_styles))
            elements.append(table)
        else:
            elements.append(Paragraph("No findings available.", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("IP Access Rules", title_style))
        if ip_access_rules:
            data = [['Target', 'Value', 'Action', 'Notes']]
            for rule in ip_access_rules:
                data.append([
                    Paragraph(rule['target'], cell_style),
                    Paragraph(rule['value'], cell_style),
                    Paragraph(rule['action'], cell_style),
                    Paragraph(rule['notes'], cell_style)
                ])
            col_widths = [100, 100, 100, 100]
            table = Table(data, colWidths=col_widths, splitByRow=True)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No IP Access Rules configured.", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("DNS Records", title_style))
        if isinstance(dns_records, list):
            if dns_records:
                data = [['Record Name', 'Type', 'Content', 'Proxied', 'TTL', 'Comment']]
                for record in dns_records_data:
                    data.append([
                        Paragraph(record['name'], cell_style),
                        Paragraph(record['type'], cell_style),
                        Paragraph(record['content'], cell_style),
                        Paragraph(record['proxied'], cell_style),
                        Paragraph(record['ttl'], cell_style),
                        Paragraph(record['comment'], cell_style)
                    ])
                col_widths = [100, 80, 100, 80, 50, 100]
                table = Table(data, colWidths=col_widths, splitByRow=True)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                    ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No DNS records found.", body_style))
        else:
            elements.append(Paragraph(f"DNS Records: {dns_records}", body_style))
        elements.append(Spacer(1, 24))

        doc.build(elements)
        if os.path.exists(pdf_file):
            logger.info(f"PDF generated successfully for {zone_name}: {pdf_file}")
        else:
            logger.error(f"PDF file not found after generation for {zone_name}: {pdf_file}")

        return html_file, pdf_file
    except Exception as e:
        logger.error(f"Error generating HTML/PDF for {zone_name} ({zone_id}): {str(e)}")
        return None, None

def generate_zone_docx(zone_id, zone_name, findings, dns_records):
    # Convert HTML to DOCX - relies on pypandoc and pandoc
    html_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.html"
    docx_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.docx"
    logger.info(f"Generating DOCX for {zone_name}: {docx_file}")

    try:
        if not os.path.exists(html_file):
            logger.error(f"HTML file not found for {zone_name}: {html_file}")
            return None

        # Convert HTML to DOCX using pypandoc
        pypandoc.convert_file(
            html_file,
            'docx',
            outputfile=docx_file,
            extra_args=['--standalone']
        )

        if os.path.exists(docx_file):
            logger.info(f"DOCX generated successfully for {zone_name}: {docx_file}")
        else:
            logger.error(f"DOCX file not found after generation for {zone_name}: {docx_file}")
        
        return docx_file
    except Exception as e:
        logger.error(f"Error generating DOCX for {zone_name} ({zone_id}): {str(e)}")
        return None

def generate_pie_chart(zones_data):
    # Quick pie chart for severity counts across zones
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Compliant': 0}
    for zone in zones_data:
        for finding in zone['findings']:
            severity_counts[finding['severity']] += 1
    
    labels = [k for k, v in severity_counts.items() if v > 0]
    sizes = [v for k, v in severity_counts.items() if v > 0]
    colors_list = ['#CC3333', '#CC6633', '#3366CC', '#CCCC33', '#cccccc', '#33CC33']
    colors_list = colors_list[:len(labels)]
    
    plt.figure(figsize=(4, 4))
    plt.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%', startangle=90)
    plt.title('Severity Distribution Across All Zones')
    plt.axis('equal')
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()
    buf.seek(0)
    return buf.getvalue()

def generate_bar_chart(zones_data):
    # Bar chart for critical/high per zone - helps spot problem areas
    zone_names = [zone['name'] for zone in zones_data]
    critical_counts = []
    high_counts = []
    for zone in zones_data:
        severity_counts = {'Critical': 0, 'High': 0}
        for finding in zone['findings']:
            if finding['severity'] in severity_counts:
                severity_counts[finding['severity']] += 1
        critical_counts.append(severity_counts['Critical'])
        high_counts.append(severity_counts['High'])
    
    fig, ax = plt.subplots(figsize=(6, 4))
    bar_width = 0.35
    x = range(len(zone_names))
    ax.bar([i - bar_width/2 for i in x], critical_counts, bar_width, label='Critical', color='#CC3333')
    ax.bar([i + bar_width/2 for i in x], high_counts, bar_width, label='High', color='#CC6633')
    ax.set_xlabel('Zones')
    ax.set_ylabel('Number of Findings')
    ax.set_title('Critical and High Findings by Zone')
    ax.set_xticks(x)
    ax.set_xticklabels(zone_names, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()
    buf.seek(0)
    return buf.getvalue()

def generate_summary_docx(zones_data):
    # Summary DOCX from HTML
    html_file = "cloudflare_audit_reports/summary_audit_report.html"
    docx_file = "cloudflare_audit_reports/summary_audit_report.docx"
    logger.info(f"Generating summary DOCX: {docx_file}")
    
    try:
        if not os.path.exists(html_file):
            logger.error(f"Summary HTML file not found: {html_file}")
            return None

        # Convert HTML to DOCX using pypandoc
        pypandoc.convert_file(
            html_file,
            'docx',
            outputfile=docx_file,
            extra_args=['--standalone']
        )

        if os.path.exists(docx_file):
            logger.info(f"Summary DOCX generated successfully: {docx_file}")
        else:
            logger.error(f"Summary DOCX file not found after generation: {docx_file}")
        
        return docx_file
    except Exception as e:
        logger.error(f"Error generating summary DOCX: {str(e)}")
        return None

def generate_summary_pdf(zones_data, zone_inventory=None, risk_register_entries=None):
    # Summary PDF with charts embedded
    html_file = "cloudflare_audit_reports/summary_audit_report.html"
    pdf_file = "cloudflare_audit_reports/summary_audit_report.pdf"
    logger.info(f"Generating summary HTML and PDF: {html_file}, {pdf_file}")

    try:
        # Prepare summary data
        summary_data = []
        total_severity = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Compliant': 0}
        
        for zone in zones_data:
            zone_name = zone['name']
            findings = zone['findings']
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Compliant': 0}
            ip_access_count = len([f for f in findings if "IP Access Rule - Target:" in f['description']])
            if any("Failed to retrieve IP Access Rules" in f['description'] for f in findings):
                ip_access_count = "Failed"
            elif ip_access_count == 0:
                ip_access_count = "None"
            old_waf_status = "Enabled" if any("Legacy WAF is enabled" in f['description'] for f in findings) else "Disabled"
            if any("Failed to retrieve WAF" in f['description'] for f in findings):
                old_waf_status = "Failed"
            for finding in findings:
                severity_counts[finding['severity']] += 1
                total_severity[finding['severity']] += 1
            summary_data.append({
                'name': zone_name,
                'critical': severity_counts['Critical'],
                'high': severity_counts['High'],
                'medium': severity_counts['Medium'],
                'low': severity_counts['Low'],
                'info': severity_counts['Info'],
                'compliant': severity_counts['Compliant'],
                'ip_access_rules': ip_access_count,
                'old_waf': old_waf_status
            })

        # Generate charts
        pie_chart_bytes = generate_pie_chart(zones_data)
        bar_chart_bytes = generate_bar_chart(zones_data)
        pie_chart_data = base64.b64encode(pie_chart_bytes).decode('utf-8')
        bar_chart_data = base64.b64encode(bar_chart_bytes).decode('utf-8')
        
        # Executive summary
        executive_summary = {
            'critical': total_severity['Critical'],
            'high': total_severity['High'],
            'medium': total_severity['Medium'],
            'low': total_severity['Low'],
            'info': total_severity['Info'],
            'compliant': total_severity['Compliant']
        }

        # Render HTML
        template = env.from_string(template_string)
        rendered_html = template.render(
            title="Summary Report",
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            zones_data=summary_data,
            zone_inventory=zone_inventory or [],
            risk_register=risk_register_entries or [],
            executive_summary=executive_summary,
            total_zones=len(zones_data),
            pie_chart=f"data:image/png;base64,{pie_chart_data}",
            bar_chart=f"data:image/png;base64,{bar_chart_data}",
            version=VERSION
        )

        # Save HTML
        with open(html_file, 'w') as f:
            f.write(rendered_html)
        if os.path.exists(html_file):
            logger.info(f"Summary HTML generated successfully: {html_file}")
        else:
            logger.error(f"Summary HTML file not found after generation: {html_file}")

        # Generate PDF
        doc = SimpleDocTemplate(pdf_file, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        body_style = styles['BodyText']
        pdf_severity_colors = {
            'Critical': colors.Color(0.8, 0.2, 0.2),
            'High': colors.Color(0.8, 0.4, 0.2),
            'Medium': colors.Color(0.8, 0.8, 0.2),
            'Low': colors.Color(0.2, 0.8, 0.2),
            'Compliant': colors.Color(0.2, 0.4, 0.8),
            'Info': colors.grey
        }

        elements.append(Paragraph("Cloudflare Security Audit Summary Report", title_style))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Prepared by: Optiv Security", body_style))
        elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        elements.append(Spacer(1, 24))

        if zones_data:
            data = [['Zone Name', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Compliant', 'IP Access Rules', 'Old WAF']]
            for zone in summary_data:
                data.append([
                    Paragraph(zone['name'], cell_style),
                    Paragraph(str(zone['critical']), cell_style),
                    Paragraph(str(zone['high']), cell_style),
                    Paragraph(str(zone['medium']), cell_style),
                    Paragraph(str(zone['low']), cell_style),
                    Paragraph(str(zone['info']), cell_style),
                    Paragraph(str(zone['compliant']), cell_style),
                    Paragraph(str(zone['ip_access_rules']), cell_style),
                    Paragraph(zone['old_waf'], cell_style)
                ])
            col_widths = [100, 50, 50, 50, 50, 50, 50, 50, 50]
            table = Table(data, colWidths=col_widths, splitByRow=True)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No zones processed.", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("Severity Distribution", title_style))
        try:
            pie_chart_buffer = io.BytesIO(pie_chart_bytes)
            elements.append(Image(pie_chart_buffer, width=3*inch, height=3*inch))
            logger.debug("Pie chart embedded successfully in PDF")
        except Exception as e:
            logger.error(f"Failed to embed pie chart in PDF: {str(e)}")
            elements.append(Paragraph("Error: Pie chart could not be embedded.", body_style))

        elements.append(Spacer(1, 24))

        elements.append(Paragraph("Critical and High Findings by Zone", title_style))
        try:
            bar_chart_buffer = io.BytesIO(bar_chart_bytes)
            elements.append(Image(bar_chart_buffer, width=4*inch, height=3*inch))
            logger.debug("Bar chart embedded successfully in PDF")
        except Exception as e:
            logger.error(f"Failed to embed bar chart in PDF: {str(e)}")
            elements.append(Paragraph("Error: Bar chart could not be embedded.", body_style))

        elements.append(Spacer(1, 24))

        doc.build(elements)
        if os.path.exists(pdf_file):
            logger.info(f"Summary PDF generated successfully: {pdf_file}")
        else:
            logger.error(f"Summary PDF file not found after generation: {pdf_file}")

        return html_file, pdf_file
    except Exception as e:
        logger.error(f"Error generating summary HTML/PDF: {str(e)}")
        return None, None

def main():
    """Main audit function - enhanced with comprehensive Cloudflare best practice checks"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Cloudflare Security Audit Tool v' + VERSION)
    parser.add_argument('--output-dir', default='cloudflare_audit_reports', help='Output directory for reports')
    parser.add_argument('--csv', action='store_true', help='Export data to CSV files')
    parser.add_argument('--zones', nargs='+', help='Specific zone IDs to audit (default: all zones)')
    parser.add_argument('--skip-dns', action='store_true', help='Skip DNS record collection')
    parser.add_argument('--prepared-by', default='Security Team', help='Name to appear in "Prepared by" field')
    args = parser.parse_args()
    
    # Check environment variables
    if not CLOUDFLARE_API_TOKEN or not CLOUDFLARE_API_EMAIL:
        logger.error("CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_EMAIL not set.")
        print("\n⚠️  Please set the following environment variables:")
        print("   export CLOUDFLARE_API_TOKEN='your_token_here'")
        print("   export CLOUDFLARE_API_EMAIL='your@email.com'")
        return

    os.makedirs(args.output_dir, exist_ok=True)
    logger.info(f"Output directory: {args.output_dir}")
    
    print(f"\n{'='*60}")
    print(f"  Cloudflare Security Audit Tool v{VERSION}")
    print(f"  Comprehensive environment audit with best practices")
    print(f"{'='*60}\n")

    # Initialize risk register
    risk_register = RiskRegister()
    
    # Fetch all zones
    logger.info("Fetching zones from Cloudflare API...")
    response = requests.get(f"{BASE_URL}/zones", headers=headers)
    if response.status_code != 200:
        logger.error(f"Failed to fetch zones: {response.status_code} {response.reason}")
        print(f"❌ Failed to fetch zones. Check your API credentials.")
        return

    all_zones = response.json().get('result', [])
    
    # Filter zones if specific ones requested
    if args.zones:
        zones = [z for z in all_zones if z['id'] in args.zones or z['name'] in args.zones]
        if not zones:
            logger.error(f"No matching zones found for: {args.zones}")
            return
    else:
        zones = all_zones
    
    # Build zone inventory
    zone_inventory = []
    for z in zones:
        zone_inventory.append({
            'id': z['id'],
            'name': z['name'],
            'plan': z.get('plan', {}).get('name', 'unknown'),
            'status': z.get('status', 'unknown'),
            'ssl_status': z.get('ssl', {}).get('status', 'unknown') if z.get('ssl') else 'unknown'
        })
    
    print(f"📋 Found {len(zones)} zone(s) to audit:")
    for z in zone_inventory:
        print(f"   • {z['name']} ({z['plan']}) - {z['status']}")
    print()
    
    zones_data = []
    total_findings = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Compliant': 0}

    for i, zone in enumerate(zones, 1):
        zone_id = zone['id']
        zone_name = zone['name']
        zone_plan = zone.get('plan', {}).get('name', 'unknown')
        
        print(f"\n[{i}/{len(zones)}] Auditing: {zone_name}")
        print(f"    Zone ID: {zone_id}")
        print(f"    Plan: {zone_plan}")
        logger.info(f"Processing zone {i} of {len(zones)}: {zone_name} ({zone_id})")

        findings = []
        
        # === Core Security Checks ===
        print("    ✓ Checking TLS configuration...")
        findings.extend(check_min_tls_version(zone_id, zone_name))
        findings.extend(check_ssl_mode(zone_id, zone_name))
        
        print("    ✓ Checking security settings...")
        findings.extend(check_true_client_ip_header(zone_id, zone_name))
        findings.extend(check_security_level(zone_id, zone_name))
        findings.extend(check_always_use_https(zone_id, zone_name))
        findings.extend(check_browser_integrity(zone_id, zone_name))
        findings.extend(check_automatic_https_rewrites(zone_id, zone_name))
        findings.extend(check_email_obfuscation(zone_id, zone_name))
        findings.extend(check_opportunistic_encryption(zone_id, zone_name))
        
        print("    ✓ Checking infrastructure settings...")
        findings.extend(check_http3(zone_id, zone_name))
        findings.extend(check_dnssec(zone_id, zone_name))
        findings.extend(check_origin_certificates(zone_id, zone_name))
        
        print("    ✓ Checking bot management...")
        findings.extend(check_bot_management(zone_id, zone_name))
        
        print("    ✓ Checking WAF configuration...")
        findings.extend(check_waf(zone_id, zone_name))
        findings.extend(check_firewall_rules(zone_id, zone_name))
        findings.extend(check_managed_rules(zone_id, zone_name))
        
        # Deep managed rulesets audit
        print("    ✓ Performing deep managed rulesets audit...")
        ruleset_findings, managed_rulesets_audit = audit_managed_rulesets_deep(zone_id, zone_name, risk_register)
        findings.extend(ruleset_findings)
        
        print("    ✓ Checking rate limiting...")
        findings.extend(check_rate_limiting(zone_id, zone_name))
        
        print("    ✓ Checking IP access rules...")
        findings.extend(check_ip_access_rules(zone_id, zone_name))
        
        print("    ✓ Checking page rules...")
        findings.extend(check_page_rules(zone_id, zone_name))
        
        print("    ✓ Checking cache settings...")
        findings.extend(check_cache_settings(zone_id, zone_name))
        
        print("    ✓ Checking logpush/SIEM integration...")
        logpush_findings, logpush_status = check_logpush(zone_id, zone_name)
        findings.extend(logpush_findings)
        
        # Discover entitlements for enterprise zones
        print("    ✓ Discovering SKU entitlements...")
        entitlements = discover_entitlements(zone_id, zone_name, zone_plan)
        
        # Collect DNS records
        dns_records = []
        if not args.skip_dns:
            print("    ✓ Fetching DNS records...")
            dns_records = fetch_all_dns_records(zone_id, zone_name)
            if isinstance(dns_records, str):  # Error message
                logger.warning(f"DNS fetch returned error: {dns_records}")
                dns_records = []
        
        # Count findings
        for f in findings:
            total_findings[f['severity']] = total_findings.get(f['severity'], 0) + 1
        
        # Get risk register entries for this zone
        zone_risks = [r for r in risk_register.entries if r['zone_name'] == zone_name]

        try:
            html_file, pdf_file = generate_zone_pdf(
                zone_id, zone_name, findings, dns_records,
                managed_rulesets_audit=managed_rulesets_audit,
                logpush_status=logpush_status,
                entitlements=entitlements,
                risk_register_entries=zone_risks
            )
            docx_file = generate_zone_docx(zone_id, zone_name, findings, dns_records)
            
            if html_file and pdf_file:
                zones_data.append({
                    'name': zone_name,
                    'id': zone_id,
                    'plan': zone_plan,
                    'status': zone.get('status', 'unknown'),
                    'ssl_status': zone.get('ssl', {}).get('status', 'unknown') if zone.get('ssl') else 'unknown',
                    'findings': findings,
                    'dns_records': dns_records if isinstance(dns_records, list) else [],
                    'managed_rulesets_audit': managed_rulesets_audit,
                    'logpush_status': logpush_status,
                    'entitlements': entitlements
                })
                print(f"    📄 Reports generated: HTML, PDF" + (", DOCX" if docx_file else ""))
            else:
                logger.error(f"Skipping zone {zone_name} due to report generation failure")
        except Exception as e:
            logger.error(f"Failed to process zone {zone_name} ({zone_id}): {str(e)}")
            print(f"    ❌ Error processing zone: {str(e)}")

    # Generate summary reports
    print(f"\n{'='*60}")
    print("Generating summary reports...")
    
    try:
        html_file, pdf_file = generate_summary_pdf(zones_data, zone_inventory, risk_register.entries)
        docx_file = generate_summary_docx(zones_data)
        
        if html_file and pdf_file:
            print(f"✅ Summary HTML: {html_file}")
            print(f"✅ Summary PDF: {pdf_file}")
        if docx_file:
            print(f"✅ Summary DOCX: {docx_file}")
    except Exception as e:
        logger.error(f"Failed to generate summary reports: {str(e)}")
        print(f"❌ Error generating summary reports: {str(e)}")
    
    # Export to CSV if requested
    if args.csv:
        print("\nExporting to CSV...")
        try:
            csv_files = export_to_csv(zones_data, args.output_dir)
            print(f"✅ Findings CSV: {csv_files['findings']}")
            print(f"✅ Inventory CSV: {csv_files['inventory']}")
            print(f"✅ DNS Records CSV: {csv_files['dns']}")
        except Exception as e:
            logger.error(f"Failed to export CSV: {str(e)}")
            print(f"❌ Error exporting CSV: {str(e)}")
    
    # Export risk register
    if risk_register.entries:
        risk_file = os.path.join(args.output_dir, f"risk_register_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        risk_register.to_csv(risk_file)
        print(f"✅ Risk Register CSV: {risk_file}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("AUDIT SUMMARY")
    print(f"{'='*60}")
    print(f"Total zones audited: {len(zones_data)}")
    print(f"\nFindings by severity:")
    print(f"  🔴 Critical: {total_findings.get('Critical', 0)}")
    print(f"  🟠 High:     {total_findings.get('High', 0)}")
    print(f"  🟡 Medium:   {total_findings.get('Medium', 0)}")
    print(f"  🟢 Low:      {total_findings.get('Low', 0)}")
    print(f"  ⚪ Info:     {total_findings.get('Info', 0)}")
    print(f"  🔵 Compliant: {total_findings.get('Compliant', 0)}")
    print(f"\nRisk register entries: {len(risk_register.entries)}")
    print(f"\nReports saved to: {args.output_dir}/")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()