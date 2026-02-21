from datetime import timedelta
import json
import re
import secrets
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session, current_app

try:
    from ..models import (
        db,
        Service,
        TeamMember,
        Testimonial,
        Category,
        Post,
        ContactSubmission,
        Industry,
        SupportClient,
        SupportTicket,
        AuthRateLimitBucket,
        SecurityEvent,
    )
    from ..notifications import send_contact_notification, send_ticket_notification
    from ..utils import utc_now_naive, clean_text, escape_like, is_valid_email, normalized_ip, get_request_ip, get_page_content
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from models import (
        db,
        Service,
        TeamMember,
        Testimonial,
        Category,
        Post,
        ContactSubmission,
        Industry,
        SupportClient,
        SupportTicket,
        AuthRateLimitBucket,
        SecurityEvent,
    )
    from notifications import send_contact_notification, send_ticket_notification
    from utils import utc_now_naive, clean_text, escape_like, is_valid_email, normalized_ip, get_request_ip, get_page_content

main_bp = Blueprint('main', __name__)
REMOTE_AUTH_LIMIT = 6
REMOTE_AUTH_WINDOW_SECONDS = 300
TICKET_CREATE_LIMIT = 20
TICKET_CREATE_WINDOW_SECONDS = 3600
TICKET_CREATE_SCOPE = 'ticket_create'

TICKET_STATUS_LABELS = {
    'open': 'Open',
    'in_progress': 'In Progress',
    'waiting_customer': 'Waiting on Client',
    'resolved': 'Resolved',
    'closed': 'Closed',
}

TICKET_PRIORITY_LABELS = {
    'low': 'Low',
    'normal': 'Normal',
    'high': 'High',
    'critical': 'Critical',
}

SERVICE_SLUG_ALIASES = {
    'computer-laptop-repair': 'computer-repair',
    'server-network-repair': 'mobile-phone-repair',
    'printer-peripheral-repair': 'game-console-repair',
    'virus-malware-removal': 'device-diagnostics',
    'hardware-installation-upgrades': 'surveillance-camera-installation',
    'data-analytics-bi': 'web-development',
    'it-consulting-strategy': 'managed-it-services',
}

INDUSTRY_SLUG_ALIASES = {
    'healthcare': 'healthcare-clinics',
    'finance-banking': 'law-firms',
    'education': 'construction-field-services',
    'retail-e-commerce': 'retail-ecommerce',
    'real-estate': 'real-estate-property-management',
    'legal': 'professional-services',
    'hospitality': 'nonprofits',
}

ICON_CLASS_RE = re.compile(r"^fa-(solid|regular|brands)\s+fa-[a-z0-9-]+$")
ICON_CLASS_ALIASES = {
    'fa-ranking-star': 'fa-chart-line',
    'fa-filter-circle-dollar': 'fa-bullseye',
    'fa-radar': 'fa-crosshairs',
    'fa-siren-on': 'fa-bell',
    'fa-shield-check': 'fa-shield-halved',
}
VALID_ICON_STYLES = {'fa-solid', 'fa-regular', 'fa-brands'}
QUOTE_INTAKE_EMAIL = 'quote-intake@rightonrepair.local'
QUOTE_BUDGET_OPTIONS = {
    'under_5k': 'Under $5,000',
    '5k_15k': '$5,000 - $15,000',
    '15k_50k': '$15,000 - $50,000',
    '50k_plus': '$50,000+',
    'not_sure': 'Not sure yet',
}
QUOTE_TIMELINE_OPTIONS = {
    'asap': 'ASAP (within 2 weeks)',
    '30_days': '30 days',
    '60_days': '60 days',
    '90_plus': '90+ days',
    'planning': 'Planning phase',
}
QUOTE_CONTACT_OPTIONS = {
    'email': 'Email',
    'phone': 'Phone',
    'either': 'Either email or phone',
}
QUOTE_COMPLIANCE_OPTIONS = {
    'none': 'No formal requirement',
    'hipaa': 'HIPAA',
    'pci': 'PCI-DSS',
    'soc2': 'SOC 2',
    'other': 'Other / mixed requirements',
}
QUOTE_URGENCY_OPTIONS = {
    'normal': 'Standard planning',
    'high': 'Priority initiative',
    'critical': 'Urgent business risk',
}
CONTACT_FORM_SCOPE = 'contact_form'
QUOTE_FORM_SCOPE = 'quote_form'
PERSONAL_QUOTE_FORM_SCOPE = 'personal_quote_form'


SERVICE_PROFILES = {
    'software-development': {
        'meta_description': 'Orange County custom software development: discovery, architecture, API integration, DevOps delivery, and ongoing optimization for business operations.',
        'keywords': [
            'software development Orange County', 'custom software development', 'API integration services',
            'business automation software', 'DevOps application support', 'workflow automation'
        ],
        'intro_kicker': 'Build • Integrate • Scale',
        'board_title': 'Delivery Workflow',
        'process': [
            {'title': 'Scope', 'detail': 'Map requirements, user flows, and integrations.', 'icon': 'fa-solid fa-list-check'},
            {'title': 'Architect', 'detail': 'Define data model, API strategy, and security controls.', 'icon': 'fa-solid fa-diagram-project'},
            {'title': 'Sprint Build', 'detail': 'Ship production increments with QA at each milestone.', 'icon': 'fa-solid fa-code'},
            {'title': 'Operate', 'detail': 'Monitor, optimize, and release iterative upgrades.', 'icon': 'fa-solid fa-rocket'},
        ],
        'tools': [
            {'name': 'GitHub', 'icon': 'fa-brands fa-github'},
            {'name': 'Docker', 'icon': 'fa-brands fa-docker'},
            {'name': 'Kubernetes', 'icon': 'fa-solid fa-cubes'},
            {'name': 'AWS', 'icon': 'fa-brands fa-aws'},
            {'name': 'Microsoft Azure', 'icon': 'fa-brands fa-microsoft'},
            {'name': 'Postman', 'icon': 'fa-solid fa-code-branch'},
            {'name': 'Cloudflare', 'icon': 'fa-solid fa-shield-halved'},
            {'name': 'Datadog', 'icon': 'fa-solid fa-chart-line'},
        ],
        'deliverables': [
            {'label': 'Automation', 'value': 'Manual tasks reduced', 'icon': 'fa-solid fa-gears'},
            {'label': 'Integrations', 'value': 'CRM • ERP • Payments', 'icon': 'fa-solid fa-plug'},
            {'label': 'Reliability', 'value': 'Monitoring + alerting', 'icon': 'fa-solid fa-heart-pulse'},
        ],
        'faqs': [
            {'q': 'How do projects start?', 'a': 'We start with a short discovery workshop and convert it into a sprint plan.'},
            {'q': 'Can you integrate with existing tools?', 'a': 'Yes. We commonly connect CRM, accounting, support, and inventory systems.'},
            {'q': 'Do you provide ongoing support?', 'a': 'Yes. We provide releases, monitoring, and optimization after launch.'},
        ],
    },
    'web-development': {
        'meta_description': 'Web development for Orange County businesses focused on technical SEO, Core Web Vitals, conversion UX, analytics, and secure cloud hosting.',
        'keywords': [
            'web development Orange County', 'technical SEO services', 'Core Web Vitals optimization',
            'conversion focused websites', 'business website development'
        ],
        'intro_kicker': 'Search • Speed • Conversion',
        'board_title': 'Launch Process',
        'process': [
            {'title': 'Positioning', 'detail': 'Define offer hierarchy and search intent targets.', 'icon': 'fa-solid fa-bullseye'},
            {'title': 'Design & Build', 'detail': 'Create responsive pages with lightweight components.', 'icon': 'fa-solid fa-palette'},
            {'title': 'SEO Setup', 'detail': 'Implement metadata, schema, and internal linking.', 'icon': 'fa-solid fa-magnifying-glass-chart'},
            {'title': 'Measure', 'detail': 'Track leads, behavior, and conversion events.', 'icon': 'fa-solid fa-gauge-high'},
        ],
        'tools': [
            {'name': 'Google Analytics 4', 'icon': 'fa-solid fa-chart-column'},
            {'name': 'Google Search Console', 'icon': 'fa-solid fa-magnifying-glass'},
            {'name': 'Cloudflare', 'icon': 'fa-solid fa-cloud'},
            {'name': 'WordPress', 'icon': 'fa-brands fa-wordpress'},
            {'name': 'Webflow', 'icon': 'fa-solid fa-wand-magic-sparkles'},
            {'name': 'Lighthouse', 'icon': 'fa-solid fa-lightbulb'},
            {'name': 'Schema.org', 'icon': 'fa-solid fa-sitemap'},
            {'name': 'CDN + WAF', 'icon': 'fa-solid fa-shield'},
        ],
        'deliverables': [
            {'label': 'SEO Readiness', 'value': 'Schema + metadata + indexing', 'icon': 'fa-solid fa-chart-line'},
            {'label': 'Performance', 'value': 'Optimized Core Web Vitals', 'icon': 'fa-solid fa-bolt'},
            {'label': 'Lead Flow', 'value': 'Clear CTAs and conversion tracking', 'icon': 'fa-solid fa-bullseye'},
        ],
        'faqs': [
            {'q': 'Do you handle technical SEO?', 'a': 'Yes. Every build includes technical SEO foundations and structured metadata.'},
            {'q': 'Will the site be mobile-first?', 'a': 'Yes. Components are designed and tested for mobile and desktop.'},
            {'q': 'Can you improve our current site?', 'a': 'Yes. We can optimize existing stacks before or alongside a redesign.'},
        ],
    },
    'managed-it-services': {
        'meta_description': 'Managed IT services in Orange County with 24/7 monitoring, patching, endpoint management, backup, and strategic reporting for SMB operations.',
        'keywords': [
            'managed IT services Orange County', '24/7 IT monitoring', 'IT help desk support',
            'patch management services', 'endpoint management', 'backup and disaster recovery'
        ],
        'intro_kicker': 'Monitor • Support • Improve',
        'board_title': 'Operating Model',
        'process': [
            {'title': 'Assess', 'detail': 'Audit endpoints, networks, risks, and support volume.', 'icon': 'fa-solid fa-clipboard-check'},
            {'title': 'Standardize', 'detail': 'Apply security baselines, patching, and identity policies.', 'icon': 'fa-solid fa-sliders'},
            {'title': 'Operate 24/7', 'detail': 'Monitor alerts, resolve tickets, and escalate incidents.', 'icon': 'fa-solid fa-headset'},
            {'title': 'Review', 'detail': 'Monthly reporting and quarterly roadmap updates.', 'icon': 'fa-solid fa-chart-pie'},
        ],
        'tools': [
            {'name': 'Microsoft Intune', 'icon': 'fa-brands fa-microsoft'},
            {'name': 'Microsoft Entra ID', 'icon': 'fa-solid fa-id-badge'},
            {'name': 'Datto RMM', 'icon': 'fa-solid fa-desktop'},
            {'name': 'Veeam Backup', 'icon': 'fa-solid fa-database'},
            {'name': 'Cisco Meraki', 'icon': 'fa-solid fa-network-wired'},
            {'name': 'Cloudflare Zero Trust', 'icon': 'fa-solid fa-shield-halved'},
            {'name': 'Help Desk SLA', 'icon': 'fa-solid fa-ticket'},
            {'name': 'Patch Compliance', 'icon': 'fa-solid fa-wrench'},
        ],
        'deliverables': [
            {'label': 'Coverage', 'value': '24/7 monitoring & response', 'icon': 'fa-solid fa-clock'},
            {'label': 'Compliance', 'value': 'Patch + device policy tracking', 'icon': 'fa-solid fa-check-double'},
            {'label': 'Continuity', 'value': 'Backup and recovery readiness', 'icon': 'fa-solid fa-life-ring'},
        ],
        'faqs': [
            {'q': 'Do you support co-managed IT?', 'a': 'Yes. We can support your internal team or fully manage operations.'},
            {'q': 'How is response prioritized?', 'a': 'Critical incidents are escalated immediately, with SLA-based queueing.'},
            {'q': 'Do you provide reports?', 'a': 'Yes. We provide recurring operational and risk reporting.'},
        ],
    },
    'cybersecurity': {
        'meta_description': 'Cybersecurity services for businesses: identity controls, endpoint protection, managed detection and response, and zero trust network security.',
        'keywords': [
            'cybersecurity services Orange County', 'managed detection and response',
            'endpoint security', 'zero trust security', 'MFA deployment', 'SOC monitoring'
        ],
        'intro_kicker': 'Prevent • Detect • Respond',
        'board_title': 'Security Lifecycle',
        'process': [
            {'title': 'Risk Baseline', 'detail': 'Map exposure across identity, endpoint, and network layers.', 'icon': 'fa-solid fa-triangle-exclamation'},
            {'title': 'Control Rollout', 'detail': 'Deploy MFA, hardening, and least-privilege policies.', 'icon': 'fa-solid fa-lock'},
            {'title': '24/7 Detection', 'detail': 'Correlate alerts and investigate suspicious activity.', 'icon': 'fa-solid fa-crosshairs'},
            {'title': 'Contain & Recover', 'detail': 'Isolate threats and restore operations quickly.', 'icon': 'fa-solid fa-shield-virus'},
        ],
        'tools': [
            {'name': 'CrowdStrike Falcon', 'icon': 'fa-solid fa-crosshairs'},
            {'name': 'Microsoft Defender', 'icon': 'fa-brands fa-microsoft'},
            {'name': 'Duo MFA', 'icon': 'fa-solid fa-fingerprint'},
            {'name': 'Fortinet', 'icon': 'fa-solid fa-fire'},
            {'name': 'Prisma SASE', 'icon': 'fa-solid fa-globe'},
            {'name': 'Cloudflare SASE', 'icon': 'fa-solid fa-cloud'},
            {'name': 'XDR / MDR', 'icon': 'fa-solid fa-crosshairs'},
            {'name': 'SIEM Workflows', 'icon': 'fa-solid fa-wave-square'},
        ],
        'deliverables': [
            {'label': 'Identity Defense', 'value': 'MFA + adaptive access', 'icon': 'fa-solid fa-user-shield'},
            {'label': 'Endpoint Protection', 'value': 'EDR/XDR monitoring', 'icon': 'fa-solid fa-laptop-code'},
            {'label': 'Incident Readiness', 'value': 'Playbooks + response drills', 'icon': 'fa-solid fa-bell'},
        ],
        'faqs': [
            {'q': 'Do you offer managed security monitoring?', 'a': 'Yes. We provide continuous detection, triage, and response support.'},
            {'q': 'Can you improve our identity security?', 'a': 'Yes. We implement MFA, conditional access, and policy hardening.'},
            {'q': 'Do you support compliance-driven security?', 'a': 'Yes. We align controls to your required governance standards.'},
        ],
    },
    'cloud-solutions': {
        'meta_description': 'Cloud solutions for SMB and mid-market teams: migration planning, landing zones, governance, cost optimization, and resilient operations.',
        'keywords': [
            'cloud migration services', 'AWS Azure Google Cloud support',
            'cloud governance', 'cloud cost optimization', 'multi cloud operations'
        ],
        'intro_kicker': 'Migrate • Govern • Optimize',
        'board_title': 'Cloud Adoption Path',
        'process': [
            {'title': 'Plan', 'detail': 'Define target architecture, dependencies, and risk controls.', 'icon': 'fa-solid fa-map'},
            {'title': 'Landing Zone', 'detail': 'Deploy secure identity, networking, and logging foundations.', 'icon': 'fa-solid fa-cloud-arrow-up'},
            {'title': 'Migrate in Waves', 'detail': 'Move workloads with test and rollback checkpoints.', 'icon': 'fa-solid fa-ship'},
            {'title': 'Optimize', 'detail': 'Tune performance, cost, and resilience continuously.', 'icon': 'fa-solid fa-gauge'},
        ],
        'tools': [
            {'name': 'AWS', 'icon': 'fa-brands fa-aws'},
            {'name': 'Microsoft Azure', 'icon': 'fa-brands fa-microsoft'},
            {'name': 'Google Cloud', 'icon': 'fa-brands fa-google'},
            {'name': 'AWS Managed Services', 'icon': 'fa-solid fa-gear'},
            {'name': 'Cloudflare Connectivity', 'icon': 'fa-solid fa-cloud'},
            {'name': 'Veeam Replication', 'icon': 'fa-solid fa-arrows-rotate'},
            {'name': 'Infrastructure as Code', 'icon': 'fa-solid fa-file-code'},
            {'name': 'Cost Governance', 'icon': 'fa-solid fa-coins'},
        ],
        'deliverables': [
            {'label': 'Resilience', 'value': 'Backup + failover planning', 'icon': 'fa-solid fa-arrows-to-circle'},
            {'label': 'Security', 'value': 'Guardrails and policy checks', 'icon': 'fa-solid fa-shield-halved'},
            {'label': 'Efficiency', 'value': 'Spend visibility and rightsizing', 'icon': 'fa-solid fa-scale-balanced'},
        ],
        'faqs': [
            {'q': 'Can you support hybrid cloud?', 'a': 'Yes. We support on-prem, cloud, and hybrid operating models.'},
            {'q': 'How do you reduce migration risk?', 'a': 'We use staged waves, validation checkpoints, and rollback plans.'},
            {'q': 'Do you manage cloud after go-live?', 'a': 'Yes. We provide ongoing operations, patching, and optimization.'},
        ],
    },
    'surveillance-camera-installation': {
        'meta_description': 'Commercial surveillance camera installation including site survey, camera placement, secure remote access, retention policies, and monitoring setup.',
        'keywords': [
            'surveillance camera installation', 'commercial CCTV installation',
            'business camera systems', 'remote video monitoring', 'NVR setup'
        ],
        'intro_kicker': 'Design • Install • Monitor',
        'board_title': 'Deployment Process',
        'process': [
            {'title': 'Site Survey', 'detail': 'Map blind spots, entry points, and retention requirements.', 'icon': 'fa-solid fa-map-location-dot'},
            {'title': 'System Design', 'detail': 'Select camera types, storage, and network segmentation.', 'icon': 'fa-solid fa-drafting-compass'},
            {'title': 'Install & Test', 'detail': 'Deploy hardware, tune angles, verify alerts.', 'icon': 'fa-solid fa-screwdriver-wrench'},
            {'title': 'Handover', 'detail': 'Train staff and document access and response workflows.', 'icon': 'fa-solid fa-file-shield'},
        ],
        'tools': [
            {'name': 'UniFi Protect', 'icon': 'fa-solid fa-video'},
            {'name': 'Axis', 'icon': 'fa-solid fa-camera'},
            {'name': 'Verkada', 'icon': 'fa-solid fa-building-shield'},
            {'name': 'Meraki Cameras', 'icon': 'fa-solid fa-network-wired'},
            {'name': 'NVR Storage', 'icon': 'fa-solid fa-hard-drive'},
            {'name': 'Remote Access Policies', 'icon': 'fa-solid fa-lock'},
            {'name': 'Motion Alerts', 'icon': 'fa-solid fa-bell'},
            {'name': 'Health Monitoring', 'icon': 'fa-solid fa-heart-pulse'},
        ],
        'deliverables': [
            {'label': 'Visibility', 'value': 'Critical zones fully covered', 'icon': 'fa-solid fa-eye'},
            {'label': 'Retention', 'value': 'Policy-based storage windows', 'icon': 'fa-solid fa-clock-rotate-left'},
            {'label': 'Access', 'value': 'Secure mobile and web viewing', 'icon': 'fa-solid fa-mobile-screen'},
        ],
        'faqs': [
            {'q': 'Do you support multi-site deployments?', 'a': 'Yes. We support centralized management for multiple locations.'},
            {'q': 'Can we view cameras remotely?', 'a': 'Yes. We configure secure remote access and role-based permissions.'},
            {'q': 'Do you provide post-install support?', 'a': 'Yes. We provide health checks, updates, and incident support.'},
        ],
    },
    'data-recovery': {
        'meta_description': 'Business data recovery services with secure intake, diagnostics, recovery attempts, and verified restoration for drives and failed devices.',
        'keywords': [
            'data recovery service', 'business data recovery', 'drive failure recovery',
            'file restoration service', 'disaster recovery support'
        ],
        'intro_kicker': 'Isolate • Recover • Validate',
        'board_title': 'Recovery Workflow',
        'process': [
            {'title': 'Secure Intake', 'detail': 'Create case chain and preserve source media state.', 'icon': 'fa-solid fa-box-archive'},
            {'title': 'Diagnostics', 'detail': 'Assess media health and define recovery path.', 'icon': 'fa-solid fa-microscope'},
            {'title': 'Recovery Attempt', 'detail': 'Extract recoverable data to clean target storage.', 'icon': 'fa-solid fa-database'},
            {'title': 'Validation', 'detail': 'Verify file integrity and prioritize critical data.', 'icon': 'fa-solid fa-check-to-slot'},
        ],
        'tools': [
            {'name': 'SMART Analysis', 'icon': 'fa-solid fa-heart-pulse'},
            {'name': 'Image-Based Recovery', 'icon': 'fa-solid fa-clone'},
            {'name': 'Veeam Backup', 'icon': 'fa-solid fa-shield'},
            {'name': 'Cloud Replicas', 'icon': 'fa-solid fa-cloud-arrow-down'},
            {'name': 'Checksum Validation', 'icon': 'fa-solid fa-circle-check'},
            {'name': 'Encrypted Transfer', 'icon': 'fa-solid fa-lock'},
        ],
        'deliverables': [
            {'label': 'Critical Files', 'value': 'Priority-first restoration', 'icon': 'fa-solid fa-file-circle-check'},
            {'label': 'Security', 'value': 'Controlled handling workflow', 'icon': 'fa-solid fa-user-shield'},
            {'label': 'Continuity', 'value': 'Restore plans documented', 'icon': 'fa-solid fa-life-ring'},
        ],
        'faqs': [
            {'q': 'Can you recover failed drives?', 'a': 'In many cases yes, depending on media condition and failure type.'},
            {'q': 'How do you protect sensitive data?', 'a': 'We use controlled handling, isolated workflows, and encrypted transfer.'},
            {'q': 'Do you prioritize business-critical files?', 'a': 'Yes. We can prioritize critical folders and systems first.'},
        ],
    },
    'computer-repair': {
        'meta_description': 'Computer repair services for business devices including diagnostics, hardware replacement, OS repair, and performance stabilization.',
        'keywords': [
            'computer repair service', 'business laptop repair', 'desktop repair',
            'hardware diagnostics', 'performance optimization'
        ],
        'intro_kicker': 'Diagnose • Repair • Verify',
        'board_title': 'Repair Cycle',
        'process': [
            {'title': 'Triage', 'detail': 'Capture symptoms and run hardware + OS checks.', 'icon': 'fa-solid fa-stethoscope'},
            {'title': 'Root Cause', 'detail': 'Pinpoint failing components or software conflicts.', 'icon': 'fa-solid fa-magnifying-glass'},
            {'title': 'Repair', 'detail': 'Replace parts, remediate software, and patch.', 'icon': 'fa-solid fa-screwdriver'},
            {'title': 'Stress Test', 'detail': 'Validate stability before return to service.', 'icon': 'fa-solid fa-vial'},
        ],
        'tools': [
            {'name': 'Memory Diagnostics', 'icon': 'fa-solid fa-memory'},
            {'name': 'Disk Health Scan', 'icon': 'fa-solid fa-hard-drive'},
            {'name': 'Thermal Profiling', 'icon': 'fa-solid fa-temperature-high'},
            {'name': 'Malware Cleanup', 'icon': 'fa-solid fa-shield-virus'},
            {'name': 'Driver Remediation', 'icon': 'fa-solid fa-microchip'},
            {'name': 'System Benchmarking', 'icon': 'fa-solid fa-gauge-high'},
        ],
        'deliverables': [
            {'label': 'Reliability', 'value': 'Stable post-repair validation', 'icon': 'fa-solid fa-circle-check'},
            {'label': 'Performance', 'value': 'Boot and app speed improvements', 'icon': 'fa-solid fa-bolt'},
            {'label': 'Readiness', 'value': 'Business-use verified', 'icon': 'fa-solid fa-briefcase'},
        ],
        'faqs': [
            {'q': 'Do you repair business laptops and desktops?', 'a': 'Yes. We support business devices and office workstations.'},
            {'q': 'Can you fix slow performance?', 'a': 'Yes. We diagnose hardware, OS, and software bottlenecks.'},
            {'q': 'Do you test after repair?', 'a': 'Yes. Every repaired device goes through validation testing.'},
        ],
    },
    'mobile-phone-repair': {
        'meta_description': 'Mobile phone repair for business users including screen, battery, charging, and diagnostics with data-safe handling.',
        'keywords': [
            'mobile phone repair', 'business phone repair', 'tablet repair',
            'screen battery charging repair'
        ],
        'intro_kicker': 'Inspect • Replace • Validate',
        'board_title': 'Mobile Repair Workflow',
        'process': [
            {'title': 'Inspection', 'detail': 'Run functional checks and device diagnostics.', 'icon': 'fa-solid fa-mobile-screen'},
            {'title': 'Component Repair', 'detail': 'Replace damaged modules and connectors.', 'icon': 'fa-solid fa-sim-card'},
            {'title': 'Firmware Check', 'detail': 'Verify OS stability and update status.', 'icon': 'fa-solid fa-download'},
            {'title': 'Final QA', 'detail': 'Test charging, camera, audio, and connectivity.', 'icon': 'fa-solid fa-circle-check'},
        ],
        'tools': [
            {'name': 'Battery Health Tests', 'icon': 'fa-solid fa-battery-full'},
            {'name': 'Charging Port Diagnostics', 'icon': 'fa-solid fa-plug-circle-check'},
            {'name': 'Display Calibration', 'icon': 'fa-solid fa-display'},
            {'name': 'Data-Safe Workbench', 'icon': 'fa-solid fa-lock'},
            {'name': 'Signal Verification', 'icon': 'fa-solid fa-signal'},
            {'name': 'Accessory Validation', 'icon': 'fa-solid fa-headphones'},
        ],
        'deliverables': [
            {'label': 'Downtime', 'value': 'Fast return-to-user cycle', 'icon': 'fa-solid fa-hourglass-half'},
            {'label': 'Reliability', 'value': 'Post-repair functional checklist', 'icon': 'fa-solid fa-list-check'},
            {'label': 'Security', 'value': 'Data-aware handling process', 'icon': 'fa-solid fa-user-lock'},
        ],
        'faqs': [
            {'q': 'Do you repair business tablets too?', 'a': 'Yes. We support phones and tablets used in business workflows.'},
            {'q': 'Can you fix charging issues?', 'a': 'Yes. Charging subsystem diagnostics are part of standard intake.'},
            {'q': 'Will data be preserved?', 'a': 'We use a data-safe process and avoid unnecessary resets.'},
        ],
    },
    'game-console-repair': {
        'meta_description': 'Game console repair services including HDMI, overheating, storage, and power diagnostics with full stress testing.',
        'keywords': [
            'game console repair', 'HDMI port repair', 'console overheating repair',
            'PlayStation Xbox Nintendo repair'
        ],
        'intro_kicker': 'Test • Repair • Stress',
        'board_title': 'Console Service Workflow',
        'process': [
            {'title': 'Bench Test', 'detail': 'Validate power, display, and storage symptoms.', 'icon': 'fa-solid fa-gamepad'},
            {'title': 'Board-Level Repair', 'detail': 'Address HDMI, thermal, or power faults.', 'icon': 'fa-solid fa-screwdriver-wrench'},
            {'title': 'Thermal Service', 'detail': 'Clean cooling path and repaste as needed.', 'icon': 'fa-solid fa-fan'},
            {'title': 'Stress Validation', 'detail': 'Run extended load and connectivity checks.', 'icon': 'fa-solid fa-fire-flame-curved'},
        ],
        'tools': [
            {'name': 'HDMI Port Rework', 'icon': 'fa-solid fa-tv'},
            {'name': 'Thermal Diagnostics', 'icon': 'fa-solid fa-temperature-high'},
            {'name': 'Storage Integrity Checks', 'icon': 'fa-solid fa-hard-drive'},
            {'name': 'Power Rail Testing', 'icon': 'fa-solid fa-bolt'},
            {'name': 'Controller Pairing Tests', 'icon': 'fa-solid fa-satellite-dish'},
            {'name': 'Network Latency Checks', 'icon': 'fa-solid fa-network-wired'},
        ],
        'deliverables': [
            {'label': 'Stability', 'value': 'Extended run validation', 'icon': 'fa-solid fa-circle-check'},
            {'label': 'Thermals', 'value': 'Improved cooling performance', 'icon': 'fa-solid fa-wind'},
            {'label': 'Video Output', 'value': 'Display path restored', 'icon': 'fa-solid fa-photo-film'},
        ],
        'faqs': [
            {'q': 'Do you repair HDMI issues?', 'a': 'Yes. HDMI output and connector failures are common repair cases.'},
            {'q': 'Can overheating be resolved?', 'a': 'Yes. We service thermals and validate under sustained load.'},
            {'q': 'Do you test before return?', 'a': 'Yes. We run functional and stress tests prior to handoff.'},
        ],
    },
    'device-diagnostics': {
        'meta_description': 'Device diagnostics service to identify hidden hardware and software failures with actionable repair and upgrade recommendations.',
        'keywords': [
            'device diagnostics', 'hardware diagnostics service', 'system health assessment',
            'preventive IT maintenance'
        ],
        'intro_kicker': 'Measure • Analyze • Recommend',
        'board_title': 'Diagnostic Workflow',
        'process': [
            {'title': 'Baseline Scan', 'detail': 'Capture hardware, OS, and event-log status.', 'icon': 'fa-solid fa-file-waveform'},
            {'title': 'Deep Diagnostics', 'detail': 'Run memory, storage, thermal, and network tests.', 'icon': 'fa-solid fa-microchip'},
            {'title': 'Risk Scoring', 'detail': 'Rank failures by business impact and urgency.', 'icon': 'fa-solid fa-chart-simple'},
            {'title': 'Action Plan', 'detail': 'Provide clear repair, replace, or upgrade path.', 'icon': 'fa-solid fa-list-ol'},
        ],
        'tools': [
            {'name': 'SMART Monitoring', 'icon': 'fa-solid fa-heart-pulse'},
            {'name': 'Memory Test Suites', 'icon': 'fa-solid fa-memory'},
            {'name': 'Thermal Profiling', 'icon': 'fa-solid fa-temperature-half'},
            {'name': 'Port and NIC Checks', 'icon': 'fa-solid fa-ethernet'},
            {'name': 'Malware Risk Scan', 'icon': 'fa-solid fa-shield-virus'},
            {'name': 'Performance Baseline', 'icon': 'fa-solid fa-chart-line'},
        ],
        'deliverables': [
            {'label': 'Visibility', 'value': 'Failure points identified early', 'icon': 'fa-solid fa-eye'},
            {'label': 'Planning', 'value': 'Prioritized remediation report', 'icon': 'fa-solid fa-file-lines'},
            {'label': 'Cost Control', 'value': 'Repair vs replace clarity', 'icon': 'fa-solid fa-scale-balanced'},
        ],
        'faqs': [
            {'q': 'Is diagnostics only for broken devices?', 'a': 'No. It is also used proactively to prevent outages.'},
            {'q': 'Do we get a report?', 'a': 'Yes. We provide a concise report with priority-ranked actions.'},
            {'q': 'Can diagnostics reduce downtime?', 'a': 'Yes. Early detection helps avoid unplanned failure windows.'},
        ],
    },
    'enterprise-consultancy': {
        'meta_description': 'Enterprise IT consultancy in Orange County: technology roadmaps, infrastructure audits, vendor evaluation, digital transformation strategy, and executive advisory for growing businesses.',
        'keywords': [
            'enterprise IT consultancy Orange County', 'IT strategy consulting', 'technology roadmap planning',
            'digital transformation consulting', 'IT infrastructure audit', 'vendor evaluation services',
            'business IT advisory', 'CTO advisory Orange County', 'IT governance consulting',
        ],
        'intro_kicker': 'Assess • Advise • Transform',
        'board_title': 'Advisory Framework',
        'process': [
            {'title': 'Discovery', 'detail': 'Evaluate current infrastructure, workflows, contracts, and growth objectives.', 'icon': 'fa-solid fa-magnifying-glass-chart'},
            {'title': 'Gap Analysis', 'detail': 'Identify risks, inefficiencies, and missed opportunities across your technology stack.', 'icon': 'fa-solid fa-chart-gantt'},
            {'title': 'Strategy & Roadmap', 'detail': 'Deliver a prioritized technology roadmap with timelines, budgets, and vendor recommendations.', 'icon': 'fa-solid fa-route'},
            {'title': 'Execution Support', 'detail': 'Guide implementation, manage vendor transitions, and validate outcomes at each milestone.', 'icon': 'fa-solid fa-handshake'},
        ],
        'tools': [
            {'name': 'Microsoft 365', 'icon': 'fa-brands fa-microsoft'},
            {'name': 'Google Workspace', 'icon': 'fa-brands fa-google'},
            {'name': 'AWS', 'icon': 'fa-brands fa-aws'},
            {'name': 'Azure', 'icon': 'fa-solid fa-cloud'},
            {'name': 'Jira', 'icon': 'fa-brands fa-atlassian'},
            {'name': 'Power BI', 'icon': 'fa-solid fa-chart-pie'},
            {'name': 'Salesforce', 'icon': 'fa-brands fa-salesforce'},
            {'name': 'Slack', 'icon': 'fa-brands fa-slack'},
        ],
        'deliverables': [
            {'label': 'IT Roadmap', 'value': 'Phased transformation plan', 'icon': 'fa-solid fa-map'},
            {'label': 'Vendor Strategy', 'value': 'Objective evaluation & savings', 'icon': 'fa-solid fa-scale-balanced'},
            {'label': 'Risk Reduction', 'value': 'Governance & compliance alignment', 'icon': 'fa-solid fa-shield-halved'},
        ],
        'faqs': [
            {'q': 'Who is enterprise consultancy for?', 'a': 'Growing businesses that need strategic IT guidance without hiring a full-time CTO or IT director.'},
            {'q': 'Do you replace our existing IT team?', 'a': 'No. We complement your team by providing strategic oversight, vendor management, and roadmap planning.'},
            {'q': 'What does a typical engagement look like?', 'a': 'We start with a discovery audit, deliver a technology roadmap within 2-3 weeks, and provide ongoing advisory as needed.'},
            {'q': 'Can you help with vendor negotiations?', 'a': 'Yes. We evaluate contracts, benchmark pricing, and negotiate on your behalf to reduce costs and improve SLAs.'},
            {'q': 'How is this different from managed IT?', 'a': 'Managed IT handles day-to-day operations. Enterprise consultancy focuses on strategy, planning, and long-term technology alignment with business goals.'},
        ],
    },
}


def normalize_icon_class(icon_class, fallback='fa-solid fa-circle'):
    fallback = fallback if ICON_CLASS_RE.match(fallback) else 'fa-solid fa-circle'
    raw = clean_text(str(icon_class or ''), 120)
    if not raw:
        return fallback

    parts = raw.split()
    if len(parts) == 1 and parts[0].startswith('fa-'):
        style, glyph = 'fa-solid', parts[0]
    else:
        style = parts[0] if parts else 'fa-solid'
        glyph = parts[1] if len(parts) > 1 else ''

    if style not in VALID_ICON_STYLES:
        style = 'fa-solid'

    glyph = ICON_CLASS_ALIASES.get(glyph, glyph)
    normalized = f"{style} {glyph}".strip()
    if not ICON_CLASS_RE.match(normalized):
        return fallback
    return normalized


def normalize_icon_attr(items, fallback):
    for item in items:
        item.icon_class = normalize_icon_class(getattr(item, 'icon_class', ''), fallback)
    return items


def turnstile_enabled():
    return bool(current_app.config.get('TURNSTILE_SITE_KEY') and current_app.config.get('TURNSTILE_SECRET_KEY'))


def verify_turnstile_response():
    if not turnstile_enabled():
        return True

    token = clean_text(request.form.get('cf-turnstile-response', ''), 4096)
    if not token:
        return False

    payload = {
        'secret': current_app.config.get('TURNSTILE_SECRET_KEY'),
        'response': token,
    }
    request_ip = get_request_ip()
    if request_ip and request_ip != 'unknown':
        payload['remoteip'] = request_ip

    body = urlencode(payload).encode()
    req = Request(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    try:
        with urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
        return bool(result.get('success'))
    except Exception:
        current_app.logger.exception('Turnstile verification request failed.')
        return not current_app.config.get('TURNSTILE_ENFORCED', True)


def _cleanup_expired_buckets():
    """Periodically purge expired rate limit buckets to prevent table bloat."""
    now = utc_now_naive()
    try:
        AuthRateLimitBucket.query.filter(AuthRateLimitBucket.reset_at < now).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()


_cleanup_call_counter = 0


def get_form_rate_limit_bucket(scope, window_seconds):
    global _cleanup_call_counter
    _cleanup_call_counter += 1
    if _cleanup_call_counter % 50 == 0:
        _cleanup_expired_buckets()

    ip = get_request_ip()
    now = utc_now_naive()
    bucket = AuthRateLimitBucket.query.filter_by(scope=scope, ip=ip).first()
    if not bucket:
        bucket = AuthRateLimitBucket(
            scope=scope,
            ip=ip,
            count=0,
            reset_at=now + timedelta(seconds=window_seconds),
        )
        db.session.add(bucket)
        db.session.commit()
        return bucket
    if bucket.reset_at <= now:
        bucket.count = 0
        bucket.reset_at = now + timedelta(seconds=window_seconds)
        db.session.commit()
    return bucket


def is_form_rate_limited(scope, limit, window_seconds):
    bucket = get_form_rate_limit_bucket(scope, window_seconds)
    if bucket.count < limit:
        return False, 0
    seconds = max(1, int((bucket.reset_at - utc_now_naive()).total_seconds()))
    return True, seconds


def register_form_submission_attempt(scope, window_seconds):
    bucket = get_form_rate_limit_bucket(scope, window_seconds)
    bucket.count += 1
    db.session.commit()
    return bucket.count


def record_security_event(event_type, scope, details=''):
    try:
        event = SecurityEvent(
            event_type=clean_text(event_type, 40),
            scope=clean_text(scope, 80),
            ip=get_request_ip(),
            path=clean_text(request.path, 255) or '/',
            method=clean_text(request.method, 10) or 'GET',
            user_agent=clean_text(request.headers.get('User-Agent', ''), 300),
            details=clean_text(details, 2000),
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed to persist security event.')


def get_remote_auth_bucket():
    ip = get_request_ip()
    now = utc_now_naive()
    bucket = AuthRateLimitBucket.query.filter_by(scope='remote_auth', ip=ip).first()
    if not bucket:
        bucket = AuthRateLimitBucket(
            scope='remote_auth',
            ip=ip,
            count=0,
            reset_at=now + timedelta(seconds=REMOTE_AUTH_WINDOW_SECONDS),
        )
        db.session.add(bucket)
        db.session.commit()
        return bucket
    if bucket.reset_at <= now:
        bucket.count = 0
        bucket.reset_at = now + timedelta(seconds=REMOTE_AUTH_WINDOW_SECONDS)
        db.session.commit()
    return bucket


def is_remote_auth_limited():
    bucket = get_remote_auth_bucket()
    if bucket.count < REMOTE_AUTH_LIMIT:
        return False, 0
    seconds = max(1, int((bucket.reset_at - utc_now_naive()).total_seconds()))
    return True, seconds


def register_remote_auth_failure():
    bucket = get_remote_auth_bucket()
    bucket.count += 1
    db.session.commit()
    return bucket.count


def clear_remote_auth_failures():
    ip = get_request_ip()
    bucket = AuthRateLimitBucket.query.filter_by(scope='remote_auth', ip=ip).first()
    if bucket:
        db.session.delete(bucket)
        db.session.commit()


def get_logged_support_client():
    client_id = session.get('support_client_id')
    if not client_id:
        return None
    try:
        parsed_id = int(client_id)
    except (TypeError, ValueError):
        session.pop('support_client_id', None)
        return None
    return db.session.get(SupportClient, parsed_id)


def generate_ticket_number():
    while True:
        token = secrets.token_hex(3).upper()
        stamp = utc_now_naive().strftime('%y%m%d')
        ticket_number = f"RS-{stamp}-{token}"
        if not SupportTicket.query.filter_by(ticket_number=ticket_number).first():
            return ticket_number


def get_or_create_quote_intake_client():
    client = SupportClient.query.filter_by(email=QUOTE_INTAKE_EMAIL).first()
    if client:
        return client

    client = SupportClient(
        full_name='Quote Request Intake',
        email=QUOTE_INTAKE_EMAIL,
        company='Right On Repair',
        phone='',
    )
    client.set_password(secrets.token_urlsafe(32))
    db.session.add(client)
    db.session.commit()
    return client


def build_quote_ticket_details(payload):
    lines = [
        'Quote Intake Submission',
        f"Submitted (UTC): {utc_now_naive().strftime('%Y-%m-%d %H:%M:%S')}",
        '',
        'Requester',
        f"- Name: {payload.get('full_name') or 'Not provided'}",
        f"- Email: {payload.get('email') or 'Not provided'}",
        f"- Phone: {payload.get('phone') or 'Not provided'}",
        f"- Company: {payload.get('company') or 'Not provided'}",
        f"- Website: {payload.get('website') or 'Not provided'}",
        '',
        'Project Scope',
        f"- Project Title: {payload.get('project_title') or 'Not provided'}",
        f"- Primary Service: {payload.get('primary_service') or 'Not provided'}",
        f"- Additional Services: {payload.get('additional_services') or 'None'}",
        f"- Budget Range: {payload.get('budget_range') or 'Not provided'}",
        f"- Target Timeline: {payload.get('timeline') or 'Not provided'}",
        f"- Urgency: {payload.get('urgency') or 'Not provided'}",
        f"- Preferred Contact: {payload.get('preferred_contact') or 'Not provided'}",
        f"- Team Size: {payload.get('team_size') or 'Not provided'}",
        f"- Locations: {payload.get('location_count') or 'Not provided'}",
        f"- Compliance Requirements: {payload.get('compliance') or 'Not provided'}",
        '',
        'Business Goals',
        payload.get('business_goals') or 'Not provided',
        '',
        'Current Challenges',
        payload.get('pain_points') or 'Not provided',
        '',
        'Current Environment',
        payload.get('current_environment') or 'Not provided',
        '',
        'Integrations',
        payload.get('integrations') or 'Not provided',
        '',
        'Additional Notes',
        payload.get('additional_notes') or 'Not provided',
    ]
    return '\n'.join(lines)


def build_personal_quote_ticket_details(payload):
    lines = [
        'Personal Quote Request',
        f"Submitted (UTC): {utc_now_naive().strftime('%Y-%m-%d %H:%M:%S')}",
        '',
        'Requester',
        f"- Name: {payload.get('full_name') or 'Not provided'}",
        f"- Email: {payload.get('email') or 'Not provided'}",
        f"- Phone: {payload.get('phone') or 'Not provided'}",
        f"- Preferred Contact: {payload.get('preferred_contact') or 'Not provided'}",
        '',
        'Service Requested',
        f"- Service: {payload.get('service') or 'Not provided'}",
        '',
        'Issue Description',
        payload.get('issue_description') or 'Not provided',
        '',
        'Additional Notes',
        payload.get('additional_notes') or 'Not provided',
    ]
    return '\n'.join(lines)


def get_service_profile(service):
    # Prefer DB-stored profile_json, fall back to hardcoded SERVICE_PROFILES
    profile = {}
    if service.profile_json:
        try:
            import json as _json
            profile = _json.loads(service.profile_json)
        except (ValueError, TypeError):
            profile = {}
    if not profile:
        profile = SERVICE_PROFILES.get(service.slug, {})
    short_description = (service.description or '').strip()
    if len(short_description) > 220:
        short_description = f"{short_description[:217].rstrip()}..."
    if not short_description:
        short_description = f"{service.title} service support for Orange County businesses."

    keywords = profile.get('keywords', [
        f"{service.title} Orange County",
        f"{service.title} services",
        'business IT support',
        'Right On Repair'
    ])
    keywords = [str(k).strip() for k in keywords if str(k).strip()]

    process = profile.get('process', [
        {'title': 'Assess', 'detail': 'Review requirements and define scope.', 'icon': 'fa-solid fa-clipboard-check'},
        {'title': 'Plan', 'detail': 'Set timeline, roles, and delivery checkpoints.', 'icon': 'fa-solid fa-diagram-project'},
        {'title': 'Execute', 'detail': 'Implement and validate with quality controls.', 'icon': 'fa-solid fa-gears'},
        {'title': 'Optimize', 'detail': 'Refine outcomes based on performance data.', 'icon': 'fa-solid fa-chart-line'},
    ])
    process = [
        {
            'title': str(step.get('title', 'Step')).strip() or 'Step',
            'detail': str(step.get('detail', 'Execution step')).strip() or 'Execution step',
            'icon': normalize_icon_class(step.get('icon', ''), 'fa-solid fa-circle')
        }
        for step in process if isinstance(step, dict)
    ]

    tools = profile.get('tools', [
        {'name': 'Microsoft 365', 'icon': 'fa-brands fa-microsoft'},
        {'name': 'Cloudflare', 'icon': 'fa-solid fa-cloud'},
        {'name': 'Endpoint Monitoring', 'icon': 'fa-solid fa-desktop'},
        {'name': 'Secure Access', 'icon': 'fa-solid fa-shield-halved'},
    ])
    tools = [
        {
            'name': str(tool.get('name', 'Tool')).strip() or 'Tool',
            'icon': normalize_icon_class(tool.get('icon', ''), 'fa-solid fa-wrench')
        }
        for tool in tools if isinstance(tool, dict)
    ]

    deliverables = profile.get('deliverables', [
        {'label': 'Stability', 'value': 'Improved service reliability', 'icon': 'fa-solid fa-circle-check'},
        {'label': 'Visibility', 'value': 'Clear reporting and status tracking', 'icon': 'fa-solid fa-chart-column'},
        {'label': 'Support', 'value': 'Responsive escalation workflow', 'icon': 'fa-solid fa-headset'},
    ])
    deliverables = [
        {
            'label': str(item.get('label', 'Outcome')).strip() or 'Outcome',
            'value': str(item.get('value', 'Business impact delivered')).strip() or 'Business impact delivered',
            'icon': normalize_icon_class(item.get('icon', ''), 'fa-solid fa-bullseye')
        }
        for item in deliverables if isinstance(item, dict)
    ]

    faqs = profile.get('faqs', [
        {'q': f'What is included in {service.title.lower()}?', 'a': 'We scope your goals, implement practical solutions, and provide follow-up support.'},
        {'q': 'Can this be customized for our environment?', 'a': 'Yes. Every engagement is tailored to your infrastructure and operational priorities.'},
        {'q': 'Do you provide post-delivery support?', 'a': 'Yes. We offer ongoing support, optimization, and reporting after launch.'},
    ])
    faqs = [
        {
            'q': str(faq.get('q', 'How does this service work?')).strip() or 'How does this service work?',
            'a': str(faq.get('a', 'We tailor each engagement to your operational goals.')).strip() or 'We tailor each engagement to your operational goals.'
        }
        for faq in faqs if isinstance(faq, dict)
    ]

    return {
        'meta_description': profile.get('meta_description', short_description),
        'keywords': keywords,
        'intro_kicker': profile.get('intro_kicker', 'Plan • Deliver • Improve'),
        'board_title': profile.get('board_title', 'Service Workflow'),
        'process': process,
        'tools': tools,
        'deliverables': deliverables,
        'faqs': faqs,
    }


@main_bp.route('/')
def index():
    pro_services = normalize_icon_attr(
        Service.query.filter_by(service_type='professional', is_featured=True).order_by(Service.sort_order).all(),
        'fa-solid fa-gear'
    )
    repair_services = normalize_icon_attr(
        Service.query.filter_by(service_type='repair', is_featured=True).order_by(Service.sort_order).all(),
        'fa-solid fa-wrench'
    )
    testimonials = Testimonial.query.filter_by(is_featured=True).all()
    cb = get_page_content('home')

    pro_slugs = {service.slug for service in pro_services}
    repair_slugs = {service.slug for service in repair_services}

    def detail_or_services(slug):
        if slug in pro_slugs or slug in repair_slugs:
            return url_for('main.service_detail', slug=slug)
        return url_for('main.services')

    # Build hero cards from content blocks or use defaults
    raw_hero_cards = cb.get('hero_cards', {}).get('items', [])
    hero_cards = []
    for card in raw_hero_cards:
        slug = card.get('service_slug', '')
        if slug:
            href = detail_or_services(slug)
        else:
            href = f"{url_for('main.services')}#repair"
        hero_cards.append({
            'title': card.get('title', ''),
            'subtitle': card.get('subtitle', ''),
            'icon': card.get('icon', 'fa-solid fa-circle'),
            'color': card.get('color', 'blue'),
            'href': href,
            'aria_label': f"Open {card.get('title', '')} service page",
        })
    if not hero_cards:
        hero_cards = [
            {'title': 'Cloud', 'subtitle': 'AWS, Azure, and GCP', 'icon': 'fa-solid fa-cloud', 'color': 'blue', 'href': detail_or_services('cloud-solutions'), 'aria_label': 'Open Cloud Solutions service page'},
            {'title': 'Cybersecurity', 'subtitle': 'Threat Defense', 'icon': 'fa-solid fa-lock', 'color': 'purple', 'href': detail_or_services('cybersecurity'), 'aria_label': 'Open Cybersecurity service page'},
            {'title': 'Software & Web Development', 'subtitle': 'Full-Stack Solutions', 'icon': 'fa-solid fa-code', 'color': 'green', 'href': detail_or_services('software-development'), 'aria_label': 'Open Software & Web Development service page'},
            {'title': 'Technical Repair', 'subtitle': 'Certified Technicians', 'icon': 'fa-solid fa-laptop-medical', 'color': 'amber', 'href': f"{url_for('main.services')}#repair", 'aria_label': 'Open Technical Repair services'},
            {'title': 'Managed IT Solutions', 'subtitle': 'Proactive Support', 'icon': 'fa-solid fa-network-wired', 'color': 'cyan', 'href': detail_or_services('managed-it-services'), 'aria_label': 'Open Managed IT Solutions service page'},
            {'title': 'Enterprise Consultancy', 'subtitle': 'Strategic Advisory', 'icon': 'fa-solid fa-handshake', 'color': 'rose', 'href': detail_or_services('enterprise-consultancy'), 'aria_label': 'Open Enterprise Consultancy service page'},
        ]

    return render_template(
        'index.html',
        pro_services=pro_services,
        repair_services=repair_services,
        testimonials=testimonials,
        hero_cards=hero_cards,
        cb=cb,
    )


@main_bp.route('/about')
def about():
    team = TeamMember.query.order_by(TeamMember.sort_order).all()
    cb = get_page_content('about')
    return render_template('about.html', team=team, cb=cb)


@main_bp.route('/services')
def services():
    service_type = request.args.get('type')
    pro_services = normalize_icon_attr(
        Service.query.filter_by(service_type='professional').order_by(Service.sort_order).all(),
        'fa-solid fa-gear'
    )
    repair_services = normalize_icon_attr(
        Service.query.filter_by(service_type='repair').order_by(Service.sort_order).all(),
        'fa-solid fa-wrench'
    )
    cb = get_page_content('services')
    return render_template('services.html', pro_services=pro_services, repair_services=repair_services, active_type=service_type, cb=cb)


@main_bp.route('/services/it-services')
def services_it_track():
    return redirect(url_for('main.services', type='professional'), code=301)


@main_bp.route('/services/repair-services')
def services_repair_track():
    return redirect(f"{url_for('main.services')}#repair", code=301)


@main_bp.route('/services/<slug>')
def service_detail(slug):
    service = Service.query.filter_by(slug=slug).first()
    if service is None and slug in SERVICE_SLUG_ALIASES:
        return redirect(url_for('main.service_detail', slug=SERVICE_SLUG_ALIASES[slug]), code=301)
    if service is None:
        abort(404)
    service.icon_class = normalize_icon_class(service.icon_class, 'fa-solid fa-gear')
    service_profile = get_service_profile(service)
    return render_template('service_detail.html', service=service, service_profile=service_profile)


@main_bp.route('/blog')
def blog():
    page = request.args.get('page', 1, type=int)
    category_slug = clean_text(request.args.get('category', ''), 120)
    search = clean_text(request.args.get('q', ''), 120)

    query = Post.query.filter_by(is_published=True)

    if category_slug:
        cat = Category.query.filter_by(slug=category_slug).first()
        if cat:
            query = query.filter_by(category_id=cat.id)

    if search:
        safe_search = escape_like(search)
        query = query.filter(Post.title.ilike(f'%{safe_search}%'))

    posts = query.order_by(Post.created_at.desc()).paginate(page=page, per_page=6, error_out=False)
    categories = Category.query.all()
    return render_template('blog.html', posts=posts, categories=categories,
                           current_category=category_slug, search=search)


@main_bp.route('/blog/<slug>')
def post(slug):
    post = Post.query.filter_by(slug=slug, is_published=True).first_or_404()
    recent_posts = Post.query.filter_by(is_published=True).filter(Post.id != post.id)\
        .order_by(Post.created_at.desc()).limit(3).all()
    return render_template('post.html', post=post, recent_posts=recent_posts)


@main_bp.route('/industries')
def industries():
    all_industries = normalize_icon_attr(
        Industry.query.order_by(Industry.sort_order).all(),
        'fa-solid fa-building'
    )
    cb = get_page_content('industries')
    return render_template('industries.html', industries=all_industries, cb=cb)


@main_bp.route('/industries/<slug>')
def industry_detail(slug):
    industry = Industry.query.filter_by(slug=slug).first()
    if industry is None and slug in INDUSTRY_SLUG_ALIASES:
        return redirect(url_for('main.industry_detail', slug=INDUSTRY_SLUG_ALIASES[slug]), code=301)
    if industry is None:
        abort(404)
    industry.icon_class = normalize_icon_class(industry.icon_class, 'fa-solid fa-building')
    services = normalize_icon_attr(
        Service.query.filter_by(is_featured=True).order_by(Service.sort_order).limit(6).all(),
        'fa-solid fa-gear'
    )
    return render_template('industry_detail.html', industry=industry, services=services)


@main_bp.route('/remote-support')
def remote_support():
    portal_client = get_logged_support_client()
    services = normalize_icon_attr(Service.query.order_by(Service.title).all(), 'fa-solid fa-gear')
    tickets = []

    if portal_client:
        tickets = SupportTicket.query.filter_by(client_id=portal_client.id)\
            .order_by(SupportTicket.updated_at.desc(), SupportTicket.created_at.desc()).all()

    return render_template(
        'remote_support.html',
        portal_client=portal_client,
        services=services,
        tickets=tickets,
        ticket_status_labels=TICKET_STATUS_LABELS,
        ticket_priority_labels=TICKET_PRIORITY_LABELS,
    )


@main_bp.route('/remote-support/register', methods=['POST'])
def remote_support_register():
    limited, seconds = is_remote_auth_limited()
    if limited:
        flash(f'Too many authentication attempts. Please try again in {seconds} seconds.', 'danger')
        return redirect(url_for('main.remote_support'))

    full_name = clean_text(request.form.get('full_name', ''), 200)
    email = clean_text(request.form.get('email', ''), 200).lower()
    company = clean_text(request.form.get('company', ''), 200)
    phone = clean_text(request.form.get('phone', ''), 80)
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not full_name or not email or not password:
        register_remote_auth_failure()
        flash('Name, email, and password are required.', 'danger')
        return redirect(url_for('main.remote_support'))

    if not is_valid_email(email):
        register_remote_auth_failure()
        flash('Please provide a valid email address.', 'danger')
        return redirect(url_for('main.remote_support'))

    if password != confirm_password:
        register_remote_auth_failure()
        flash('Password confirmation does not match.', 'danger')
        return redirect(url_for('main.remote_support'))

    password_valid = len(password) >= 8 and any(c.isalpha() for c in password) and any(c.isdigit() for c in password)
    if not password_valid:
        register_remote_auth_failure()
        flash('Password must be at least 8 characters and include both letters and numbers.', 'danger')
        return redirect(url_for('main.remote_support'))

    exists = SupportClient.query.filter_by(email=email).first()
    if exists:
        register_remote_auth_failure()
        flash('An account with this email already exists. Please sign in.', 'danger')
        return redirect(url_for('main.remote_support'))

    client = SupportClient(
        full_name=full_name,
        email=email,
        company=company,
        phone=phone,
        last_login_at=utc_now_naive(),
    )
    client.set_password(password)
    db.session.add(client)
    db.session.commit()

    clear_remote_auth_failures()
    session.clear()
    session['support_client_id'] = client.id
    flash('Account created. Welcome to the remote support portal.', 'success')
    return redirect(url_for('main.remote_support'))


@main_bp.route('/remote-support/login', methods=['POST'])
def remote_support_login():
    limited, seconds = is_remote_auth_limited()
    if limited:
        flash(f'Too many failed sign-in attempts. Please try again in {seconds} seconds.', 'danger')
        return redirect(url_for('main.remote_support'))

    email = clean_text(request.form.get('email', ''), 200).lower()
    password = request.form.get('password', '')

    if not is_valid_email(email):
        register_remote_auth_failure()
        flash('Please enter a valid email address.', 'danger')
        return redirect(url_for('main.remote_support'))

    client = SupportClient.query.filter_by(email=email).first()

    if not client or not client.check_password(password):
        attempts = register_remote_auth_failure()
        remaining = max(0, REMOTE_AUTH_LIMIT - attempts)
        if remaining == 0:
            flash('Too many failed attempts. Please wait 5 minutes and try again.', 'danger')
        else:
            flash(f'Invalid email or password. {remaining} attempt(s) remaining before temporary lock.', 'danger')
        return redirect(url_for('main.remote_support'))

    clear_remote_auth_failures()
    client.last_login_at = utc_now_naive()
    db.session.commit()
    session.clear()
    session['support_client_id'] = client.id
    flash('Signed in successfully.', 'success')
    return redirect(url_for('main.remote_support'))


@main_bp.route('/remote-support/logout', methods=['POST'])
def remote_support_logout():
    session.pop('support_client_id', None)
    flash('You have been signed out.', 'success')
    return redirect(url_for('main.remote_support'))


@main_bp.route('/remote-support/tickets', methods=['POST'])
def remote_support_create_ticket():
    portal_client = get_logged_support_client()
    if not portal_client:
        flash('Please sign in to create a ticket.', 'danger')
        return redirect(url_for('main.remote_support'))

    limited, seconds = is_form_rate_limited(TICKET_CREATE_SCOPE, TICKET_CREATE_LIMIT, TICKET_CREATE_WINDOW_SECONDS)
    if limited:
        flash(f'Too many ticket submissions. Please wait {seconds} seconds and try again.', 'danger')
        return redirect(url_for('main.remote_support'))

    subject = clean_text(request.form.get('subject', ''), 300)
    service_slug = clean_text(request.form.get('service_slug', ''), 200)
    priority = clean_text(request.form.get('priority', 'normal'), 20).lower()
    details = clean_text(request.form.get('details', ''), 5000)

    if not subject or not details:
        flash('Subject and details are required.', 'danger')
        return redirect(url_for('main.remote_support'))

    valid_priorities = set(TICKET_PRIORITY_LABELS.keys())
    if priority not in valid_priorities:
        priority = 'normal'

    if service_slug and not Service.query.filter_by(slug=service_slug).first():
        service_slug = ''

    register_form_submission_attempt(TICKET_CREATE_SCOPE, TICKET_CREATE_WINDOW_SECONDS)

    ticket = SupportTicket(
        ticket_number=generate_ticket_number(),
        client_id=portal_client.id,
        subject=subject,
        service_slug=service_slug or None,
        priority=priority,
        status='open',
        details=details,
    )
    db.session.add(ticket)
    db.session.commit()
    send_ticket_notification(ticket, ticket_kind='support')

    flash(f'Ticket {ticket.ticket_number} created successfully.', 'success')
    return redirect(url_for('main.remote_support'))


@main_bp.route('/request-quote', methods=['GET', 'POST'])
def request_quote():
    services = normalize_icon_attr(Service.query.order_by(Service.service_type, Service.sort_order, Service.title).all(), 'fa-solid fa-gear')
    professional_services = [service for service in services if service.service_type == 'professional']
    repair_services = [service for service in services if service.service_type == 'repair']
    service_map = {service.slug: service for service in services}
    template_context = {
        'professional_services': professional_services,
        'repair_services': repair_services,
        'budget_options': QUOTE_BUDGET_OPTIONS,
        'timeline_options': QUOTE_TIMELINE_OPTIONS,
        'contact_options': QUOTE_CONTACT_OPTIONS,
        'compliance_options': QUOTE_COMPLIANCE_OPTIONS,
        'urgency_options': QUOTE_URGENCY_OPTIONS,
    }

    if request.method == 'POST':
        limited, seconds = is_form_rate_limited(
            QUOTE_FORM_SCOPE,
            current_app.config.get('QUOTE_FORM_LIMIT', 8),
            current_app.config.get('QUOTE_FORM_WINDOW_SECONDS', 3600),
        )
        if limited:
            record_security_event(
                'rate_limited',
                QUOTE_FORM_SCOPE,
                f"limit={current_app.config.get('QUOTE_FORM_LIMIT', 8)} window={current_app.config.get('QUOTE_FORM_WINDOW_SECONDS', 3600)}s",
            )
            flash(f'Too many quote submissions from this IP. Please wait {seconds} seconds and try again.', 'danger')
            return render_template('request_quote.html', **template_context), 429

        register_form_submission_attempt(
            QUOTE_FORM_SCOPE,
            current_app.config.get('QUOTE_FORM_WINDOW_SECONDS', 3600),
        )
        if not verify_turnstile_response():
            record_security_event('turnstile_failed', QUOTE_FORM_SCOPE, 'missing_or_invalid_turnstile_token')
            flash('Spam verification failed. Please retry and complete verification.', 'danger')
            return render_template('request_quote.html', **template_context), 400

        full_name = clean_text(request.form.get('full_name', ''), 200)
        email = clean_text(request.form.get('email', ''), 200).lower()
        phone = clean_text(request.form.get('phone', ''), 80)
        company = clean_text(request.form.get('company', ''), 200)
        website = clean_text(request.form.get('website', ''), 240)
        project_title = clean_text(request.form.get('project_title', ''), 220)
        primary_service_slug = clean_text(request.form.get('primary_service_slug', ''), 200)
        budget_range = clean_text(request.form.get('budget_range', ''), 40)
        timeline = clean_text(request.form.get('timeline', ''), 40)
        urgency = clean_text(request.form.get('urgency', 'normal'), 20).lower()
        preferred_contact = clean_text(request.form.get('preferred_contact', ''), 20)
        team_size = clean_text(request.form.get('team_size', ''), 80)
        location_count = clean_text(request.form.get('location_count', ''), 80)
        compliance = clean_text(request.form.get('compliance', 'none'), 20)
        business_goals = clean_text(request.form.get('business_goals', ''), 3000)
        pain_points = clean_text(request.form.get('pain_points', ''), 3000)
        current_environment = clean_text(request.form.get('current_environment', ''), 3000)
        integrations = clean_text(request.form.get('integrations', ''), 2500)
        additional_notes = clean_text(request.form.get('additional_notes', ''), 2500)

        additional_service_slugs = []
        for raw_slug in request.form.getlist('additional_services'):
            slug = clean_text(raw_slug, 200)
            if slug and slug not in additional_service_slugs:
                additional_service_slugs.append(slug)

        required_missing = []
        if not full_name:
            required_missing.append('full name')
        if not email:
            required_missing.append('email')
        if not primary_service_slug:
            required_missing.append('primary service')
        if not business_goals:
            required_missing.append('business goals')
        if not pain_points:
            required_missing.append('current challenges')

        if required_missing:
            flash(f"Please complete the required fields: {', '.join(required_missing)}.", 'danger')
            return render_template('request_quote.html', **template_context), 400

        if not is_valid_email(email):
            flash('Please provide a valid email address.', 'danger')
            return render_template('request_quote.html', **template_context), 400

        if primary_service_slug not in service_map:
            flash('Please select a valid primary service.', 'danger')
            return render_template('request_quote.html', **template_context), 400

        if budget_range not in QUOTE_BUDGET_OPTIONS:
            budget_range = 'not_sure'
        if timeline not in QUOTE_TIMELINE_OPTIONS:
            timeline = 'planning'
        if preferred_contact not in QUOTE_CONTACT_OPTIONS:
            preferred_contact = 'either'
        if compliance not in QUOTE_COMPLIANCE_OPTIONS:
            compliance = 'none'
        if urgency not in QUOTE_URGENCY_OPTIONS:
            urgency = 'normal'

        additional_service_slugs = [
            slug for slug in additional_service_slugs
            if slug in service_map and slug != primary_service_slug
        ]

        primary_service = service_map[primary_service_slug]
        additional_service_titles = [service_map[slug].title for slug in additional_service_slugs]
        ticket_priority = {
            'normal': 'normal',
            'high': 'high',
            'critical': 'critical',
        }.get(urgency, 'normal')

        quote_payload = {
            'full_name': full_name,
            'email': email,
            'phone': phone,
            'company': company,
            'website': website,
            'project_title': project_title,
            'primary_service': primary_service.title,
            'additional_services': ', '.join(additional_service_titles) if additional_service_titles else '',
            'budget_range': QUOTE_BUDGET_OPTIONS.get(budget_range, 'Not sure yet'),
            'timeline': QUOTE_TIMELINE_OPTIONS.get(timeline, 'Planning phase'),
            'urgency': QUOTE_URGENCY_OPTIONS.get(urgency, 'Standard planning'),
            'preferred_contact': QUOTE_CONTACT_OPTIONS.get(preferred_contact, 'Either email or phone'),
            'team_size': team_size,
            'location_count': location_count,
            'compliance': QUOTE_COMPLIANCE_OPTIONS.get(compliance, 'No formal requirement'),
            'business_goals': business_goals,
            'pain_points': pain_points,
            'current_environment': current_environment,
            'integrations': integrations,
            'additional_notes': additional_notes,
        }

        quote_client = get_or_create_quote_intake_client()
        project_subject = project_title or f"{primary_service.title} engagement"
        if company:
            ticket_subject = clean_text(f"Quote Request: {project_subject} - {company}", 300)
        else:
            ticket_subject = clean_text(f"Quote Request: {project_subject}", 300)

        ticket = SupportTicket(
            ticket_number=generate_ticket_number(),
            client_id=quote_client.id,
            subject=ticket_subject,
            service_slug=primary_service_slug,
            priority=ticket_priority,
            status='open',
            details=build_quote_ticket_details(quote_payload),
        )
        db.session.add(ticket)
        db.session.commit()
        send_ticket_notification(ticket, ticket_kind='quote')

        flash(f"Quote request received. Ticket {ticket.ticket_number} has been created for our CMS team.", 'success')
        return redirect(url_for('main.request_quote'))

    return render_template('request_quote.html', **template_context)


@main_bp.route('/request-quote/personal', methods=['GET', 'POST'])
def request_quote_personal():
    services = normalize_icon_attr(
        Service.query.order_by(Service.service_type, Service.sort_order, Service.title).all(),
        'fa-solid fa-gear',
    )
    service_map = {service.slug: service for service in services}
    professional_services = [s for s in services if s.service_type == 'professional']
    repair_services = [s for s in services if s.service_type == 'repair']
    template_context = {
        'professional_services': professional_services,
        'repair_services': repair_services,
        'contact_options': QUOTE_CONTACT_OPTIONS,
    }

    if request.method == 'POST':
        limited, seconds = is_form_rate_limited(
            PERSONAL_QUOTE_FORM_SCOPE,
            current_app.config.get('QUOTE_FORM_LIMIT', 8),
            current_app.config.get('QUOTE_FORM_WINDOW_SECONDS', 3600),
        )
        if limited:
            record_security_event(
                'rate_limited',
                PERSONAL_QUOTE_FORM_SCOPE,
                f"limit={current_app.config.get('QUOTE_FORM_LIMIT', 8)} window={current_app.config.get('QUOTE_FORM_WINDOW_SECONDS', 3600)}s",
            )
            flash(f'Too many quote submissions from this IP. Please wait {seconds} seconds and try again.', 'danger')
            return render_template('request_quote_personal.html', **template_context), 429

        register_form_submission_attempt(
            PERSONAL_QUOTE_FORM_SCOPE,
            current_app.config.get('QUOTE_FORM_WINDOW_SECONDS', 3600),
        )
        if not verify_turnstile_response():
            record_security_event('turnstile_failed', PERSONAL_QUOTE_FORM_SCOPE, 'missing_or_invalid_turnstile_token')
            flash('Spam verification failed. Please retry and complete verification.', 'danger')
            return render_template('request_quote_personal.html', **template_context), 400

        full_name = clean_text(request.form.get('full_name', ''), 200)
        email = clean_text(request.form.get('email', ''), 200).lower()
        phone = clean_text(request.form.get('phone', ''), 80)
        service_slug = clean_text(request.form.get('service_slug', ''), 200)
        preferred_contact = clean_text(request.form.get('preferred_contact', ''), 20)
        issue_description = clean_text(request.form.get('issue_description', ''), 5000)
        additional_notes = clean_text(request.form.get('additional_notes', ''), 2500)

        required_missing = []
        if not full_name:
            required_missing.append('full name')
        if not email:
            required_missing.append('email')
        if not service_slug:
            required_missing.append('service needed')
        if not preferred_contact:
            required_missing.append('preferred contact method')
        if not issue_description:
            required_missing.append('issue description')

        if required_missing:
            flash(f"Please complete the required fields: {', '.join(required_missing)}.", 'danger')
            return render_template('request_quote_personal.html', **template_context), 400

        if not is_valid_email(email):
            flash('Please provide a valid email address.', 'danger')
            return render_template('request_quote_personal.html', **template_context), 400

        if service_slug not in service_map:
            flash('Please select a valid service.', 'danger')
            return render_template('request_quote_personal.html', **template_context), 400

        if preferred_contact not in QUOTE_CONTACT_OPTIONS:
            preferred_contact = 'either'

        selected_service = service_map[service_slug]
        quote_payload = {
            'full_name': full_name,
            'email': email,
            'phone': phone,
            'preferred_contact': QUOTE_CONTACT_OPTIONS.get(preferred_contact, 'Either email or phone'),
            'service': selected_service.title,
            'issue_description': issue_description,
            'additional_notes': additional_notes,
        }

        quote_client = get_or_create_quote_intake_client()
        ticket_subject = clean_text(f"Personal Quote: {selected_service.title} - {full_name}", 300)

        ticket = SupportTicket(
            ticket_number=generate_ticket_number(),
            client_id=quote_client.id,
            subject=ticket_subject,
            service_slug=service_slug,
            priority='normal',
            status='open',
            details=build_personal_quote_ticket_details(quote_payload),
        )
        db.session.add(ticket)
        db.session.commit()
        send_ticket_notification(ticket, ticket_kind='quote')

        flash(f"Quote request received. Ticket {ticket.ticket_number} has been created. We'll be in touch soon!", 'success')
        return redirect(url_for('main.request_quote_personal'))

    return render_template('request_quote_personal.html', **template_context)


@main_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        limited, seconds = is_form_rate_limited(
            CONTACT_FORM_SCOPE,
            current_app.config.get('CONTACT_FORM_LIMIT', 12),
            current_app.config.get('CONTACT_FORM_WINDOW_SECONDS', 3600),
        )
        if limited:
            record_security_event(
                'rate_limited',
                CONTACT_FORM_SCOPE,
                f"limit={current_app.config.get('CONTACT_FORM_LIMIT', 12)} window={current_app.config.get('CONTACT_FORM_WINDOW_SECONDS', 3600)}s",
            )
            flash(f'Too many contact submissions from this IP. Please wait {seconds} seconds and try again.', 'danger')
            return redirect(url_for('main.contact'))

        register_form_submission_attempt(
            CONTACT_FORM_SCOPE,
            current_app.config.get('CONTACT_FORM_WINDOW_SECONDS', 3600),
        )
        if not verify_turnstile_response():
            record_security_event('turnstile_failed', CONTACT_FORM_SCOPE, 'missing_or_invalid_turnstile_token')
            flash('Spam verification failed. Please retry and complete verification.', 'danger')
            return redirect(url_for('main.contact'))

        name = clean_text(request.form.get('name', ''), 200)
        email = clean_text(request.form.get('email', ''), 200)
        phone = clean_text(request.form.get('phone', ''), 80)
        subject = clean_text(request.form.get('subject', ''), 300)
        message = clean_text(request.form.get('message', ''), 5000)

        if not name or not email or not message:
            flash('Name, email, and message are required.', 'danger')
            return redirect(url_for('main.contact'))
        if not is_valid_email(email):
            flash('Please provide a valid email address.', 'danger')
            return redirect(url_for('main.contact'))

        submission = ContactSubmission(
            name=name,
            email=email,
            phone=phone,
            subject=subject,
            message=message
        )
        db.session.add(submission)
        db.session.commit()
        current_app.logger.info(f'Contact submission saved: {name} <{email}>')
        result = send_contact_notification(submission)
        current_app.logger.info(f'Email notification result: {result}')
        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('main.contact'))
    cb = get_page_content('contact')
    return render_template('contact.html', cb=cb)
