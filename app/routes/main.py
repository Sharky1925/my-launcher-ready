from datetime import timedelta
from html import escape as xml_escape
import json
import re
import secrets
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session, current_app, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

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
        AcpPageDocument,
        AcpDashboardDocument,
        AcpContentType,
        AcpContentEntry,
        AcpThemeTokenSet,
        WORKFLOW_PUBLISHED,
        SUPPORT_TICKET_STATUS_OPEN,
        SUPPORT_TICKET_STATUS_LABELS,
        SUPPORT_TICKET_STAGE_LABELS,
        SUPPORT_TICKET_EVENT_CREATED,
        support_ticket_stage_for_status,
        normalize_ticket_number,
        create_support_ticket_event,
    )
    from ..notifications import send_contact_notification, send_ticket_notification
    from ..service_seo_overrides import SERVICE_RESEARCH_OVERRIDES
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
        AcpPageDocument,
        AcpDashboardDocument,
        AcpContentType,
        AcpContentEntry,
        AcpThemeTokenSet,
        WORKFLOW_PUBLISHED,
        SUPPORT_TICKET_STATUS_OPEN,
        SUPPORT_TICKET_STATUS_LABELS,
        SUPPORT_TICKET_STAGE_LABELS,
        SUPPORT_TICKET_EVENT_CREATED,
        support_ticket_stage_for_status,
        normalize_ticket_number,
        create_support_ticket_event,
    )
    from notifications import send_contact_notification, send_ticket_notification
    from service_seo_overrides import SERVICE_RESEARCH_OVERRIDES
    from utils import utc_now_naive, clean_text, escape_like, is_valid_email, normalized_ip, get_request_ip, get_page_content

main_bp = Blueprint('main', __name__)
REMOTE_AUTH_LIMIT = 6
REMOTE_AUTH_WINDOW_SECONDS = 300
TICKET_CREATE_LIMIT = 20
TICKET_CREATE_WINDOW_SECONDS = 3600
TICKET_CREATE_SCOPE = 'ticket_create'

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
AUTH_DUMMY_HASH = generate_password_hash('RightOnRepair::dummy-auth-check')


def _safe_json_loads(raw_value, fallback):
    if raw_value is None:
        return fallback
    if isinstance(raw_value, (dict, list)):
        return raw_value
    value = str(raw_value).strip()
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


SERVICE_PROFILES = {
    'software-development': {
        'meta_description': 'Custom software development in Orange County — from discovery workshops and architecture planning to API integration, agile sprint delivery, DevOps automation, and long-term application support for growing businesses.',
        'keywords': [
            'software development Orange County', 'custom software development', 'API integration services',
            'business automation software', 'DevOps application support', 'workflow automation',
            'agile software delivery', 'SaaS development Orange County', 'enterprise application development',
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
            {'name': 'GitHub', 'icon': 'fa-brands fa-github', 'desc': 'Version control and CI/CD pipelines'},
            {'name': 'Docker', 'icon': 'fa-brands fa-docker', 'desc': 'Containerized builds for consistent delivery'},
            {'name': 'Kubernetes', 'icon': 'fa-solid fa-cubes', 'desc': 'Orchestration for scalable microservices'},
            {'name': 'AWS', 'icon': 'fa-brands fa-aws', 'desc': 'Cloud infrastructure and managed services'},
            {'name': 'Microsoft Azure', 'icon': 'fa-brands fa-microsoft', 'desc': 'Enterprise cloud and identity integration'},
            {'name': 'Postman', 'icon': 'fa-solid fa-code-branch', 'desc': 'API testing and documentation workflows'},
            {'name': 'Cloudflare', 'icon': 'fa-solid fa-shield-halved', 'desc': 'Edge security, CDN, and DDoS protection'},
            {'name': 'Datadog', 'icon': 'fa-solid fa-chart-line', 'desc': 'Real-time monitoring and alerting'},
        ],
        'deliverables': [
            {'label': 'Automation', 'value': 'Manual tasks reduced', 'icon': 'fa-solid fa-gears'},
            {'label': 'Integrations', 'value': 'CRM • ERP • Payments', 'icon': 'fa-solid fa-plug'},
            {'label': 'Reliability', 'value': 'Monitoring + alerting', 'icon': 'fa-solid fa-heart-pulse'},
        ],
        'faqs': [
            {'q': 'How do custom software projects start?', 'a': 'Every engagement begins with a focused discovery workshop where we map your business requirements, user workflows, and integration needs. We then convert findings into a prioritized sprint plan with clear milestones and delivery dates.'},
            {'q': 'Can you integrate with our existing tools and platforms?', 'a': 'Yes. We routinely build integrations with CRM platforms like Salesforce and HubSpot, accounting systems like QuickBooks, support tools like Zendesk, and payment gateways. Our API-first approach ensures clean, maintainable connections.'},
            {'q': 'Do you provide ongoing support after launch?', 'a': 'Yes. Post-launch support includes proactive monitoring, performance optimization, security patching, and iterative feature releases. We treat every application as a living product, not a one-time project.'},
        ],
    },
    'web-development': {
        'meta_description': 'Professional web development in Orange County — responsive design, technical SEO, Core Web Vitals optimization, conversion-focused UX, analytics integration, and secure cloud hosting for businesses that need results.',
        'keywords': [
            'web development Orange County', 'technical SEO services', 'Core Web Vitals optimization',
            'conversion focused websites', 'business website development', 'responsive web design',
            'website redesign Orange County', 'ecommerce web development', 'landing page optimization',
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
            {'name': 'Google Analytics 4', 'icon': 'fa-solid fa-chart-column', 'desc': 'Event-based tracking and audience insights'},
            {'name': 'Google Search Console', 'icon': 'fa-solid fa-magnifying-glass', 'desc': 'Index monitoring and search performance'},
            {'name': 'Cloudflare', 'icon': 'fa-solid fa-cloud', 'desc': 'Global CDN, edge caching, and WAF'},
            {'name': 'WordPress', 'icon': 'fa-brands fa-wordpress', 'desc': 'Flexible CMS for content-driven sites'},
            {'name': 'Webflow', 'icon': 'fa-solid fa-wand-magic-sparkles', 'desc': 'Visual builder with clean code output'},
            {'name': 'Lighthouse', 'icon': 'fa-solid fa-lightbulb', 'desc': 'Performance and accessibility auditing'},
            {'name': 'Schema.org', 'icon': 'fa-solid fa-sitemap', 'desc': 'Structured data for rich search results'},
            {'name': 'CDN + WAF', 'icon': 'fa-solid fa-shield', 'desc': 'Content delivery and web application firewall'},
        ],
        'deliverables': [
            {'label': 'SEO Readiness', 'value': 'Schema + metadata + indexing', 'icon': 'fa-solid fa-chart-line'},
            {'label': 'Performance', 'value': 'Optimized Core Web Vitals', 'icon': 'fa-solid fa-bolt'},
            {'label': 'Lead Flow', 'value': 'Clear CTAs and conversion tracking', 'icon': 'fa-solid fa-bullseye'},
        ],
        'faqs': [
            {'q': 'Do you handle technical SEO as part of web development?', 'a': 'Yes. Every website we build includes technical SEO foundations — structured metadata, XML sitemaps, canonical tags, Open Graph markup, and Schema.org structured data for rich search results.'},
            {'q': 'Will the site be mobile-first and responsive?', 'a': 'Yes. All components are designed mobile-first and tested across devices and screen sizes. We optimize for Core Web Vitals to ensure fast load times and smooth interactivity on every platform.'},
            {'q': 'Can you improve our existing website without a full redesign?', 'a': 'Yes. We offer performance audits, SEO optimization, and incremental upgrades to your existing stack. Many clients see measurable improvements in speed and search rankings without a complete rebuild.'},
        ],
    },
    'managed-it-services': {
        'meta_description': 'Managed IT services in Orange County — 24/7 monitoring, help desk support, endpoint management, automated patching, backup and disaster recovery, and strategic quarterly reporting for small and mid-size businesses.',
        'keywords': [
            'managed IT services Orange County', '24/7 IT monitoring', 'IT help desk support',
            'patch management services', 'endpoint management', 'backup and disaster recovery',
            'outsourced IT support', 'co-managed IT services', 'MSP Orange County',
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
            {'name': 'Microsoft Intune', 'icon': 'fa-brands fa-microsoft', 'desc': 'Endpoint management and device compliance'},
            {'name': 'Microsoft Entra ID', 'icon': 'fa-solid fa-id-badge', 'desc': 'Identity and access management'},
            {'name': 'Datto RMM', 'icon': 'fa-solid fa-desktop', 'desc': 'Remote monitoring and management agent'},
            {'name': 'Veeam Backup', 'icon': 'fa-solid fa-database', 'desc': 'Automated backup and disaster recovery'},
            {'name': 'Cisco Meraki', 'icon': 'fa-solid fa-network-wired', 'desc': 'Cloud-managed networking and SD-WAN'},
            {'name': 'Cloudflare Zero Trust', 'icon': 'fa-solid fa-shield-halved', 'desc': 'Secure access without a VPN'},
            {'name': 'Help Desk SLA', 'icon': 'fa-solid fa-ticket', 'desc': 'Tiered ticket response with SLA tracking'},
            {'name': 'Patch Compliance', 'icon': 'fa-solid fa-wrench', 'desc': 'Automated OS and app patching schedules'},
        ],
        'deliverables': [
            {'label': 'Coverage', 'value': '24/7 monitoring & response', 'icon': 'fa-solid fa-clock'},
            {'label': 'Compliance', 'value': 'Patch + device policy tracking', 'icon': 'fa-solid fa-check-double'},
            {'label': 'Continuity', 'value': 'Backup and recovery readiness', 'icon': 'fa-solid fa-life-ring'},
        ],
        'faqs': [
            {'q': 'Do you support co-managed IT alongside internal teams?', 'a': 'Yes. We offer both fully managed and co-managed IT models. In a co-managed setup, we handle monitoring, patching, and escalation while your internal team retains control of strategic decisions and day-to-day user support.'},
            {'q': 'How are support tickets prioritized and escalated?', 'a': 'We use SLA-based prioritization with four severity tiers. Critical incidents like server outages or security breaches are escalated immediately with a 15-minute response target. Standard requests follow a structured queue with defined resolution windows.'},
            {'q': 'What kind of reports do you provide?', 'a': 'We deliver monthly operational reports covering ticket volume, resolution times, patch compliance, and device health. Quarterly business reviews include risk assessments, capacity planning, and strategic technology roadmap recommendations.'},
        ],
    },
    'cybersecurity': {
        'meta_description': 'Business cybersecurity services in Orange County — risk assessments, MFA and identity hardening, endpoint detection and response (EDR/XDR), managed SOC monitoring, zero trust network access, and incident response planning.',
        'keywords': [
            'cybersecurity services Orange County', 'managed detection and response',
            'endpoint security', 'zero trust security', 'MFA deployment', 'SOC monitoring',
            'ransomware protection', 'security risk assessment', 'SIEM managed services',
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
            {'name': 'CrowdStrike Falcon', 'icon': 'fa-solid fa-crosshairs', 'desc': 'Next-gen endpoint detection and response'},
            {'name': 'Microsoft Defender', 'icon': 'fa-brands fa-microsoft', 'desc': 'Integrated threat protection for M365'},
            {'name': 'Duo MFA', 'icon': 'fa-solid fa-fingerprint', 'desc': 'Multi-factor authentication and device trust'},
            {'name': 'Fortinet', 'icon': 'fa-solid fa-fire', 'desc': 'Next-gen firewall and network security'},
            {'name': 'Prisma SASE', 'icon': 'fa-solid fa-globe', 'desc': 'Secure access service edge for remote teams'},
            {'name': 'Cloudflare SASE', 'icon': 'fa-solid fa-cloud', 'desc': 'Zero trust connectivity and web filtering'},
            {'name': 'XDR / MDR', 'icon': 'fa-solid fa-crosshairs', 'desc': 'Extended detection with managed response'},
            {'name': 'SIEM Workflows', 'icon': 'fa-solid fa-wave-square', 'desc': 'Log correlation and automated alerting'},
        ],
        'deliverables': [
            {'label': 'Identity Defense', 'value': 'MFA + adaptive access', 'icon': 'fa-solid fa-user-shield'},
            {'label': 'Endpoint Protection', 'value': 'EDR/XDR monitoring', 'icon': 'fa-solid fa-laptop-code'},
            {'label': 'Incident Readiness', 'value': 'Playbooks + response drills', 'icon': 'fa-solid fa-bell'},
        ],
        'faqs': [
            {'q': 'Do you offer 24/7 managed security monitoring?', 'a': 'Yes. Our managed detection and response service provides continuous monitoring, alert triage, threat investigation, and guided remediation around the clock — giving your business SOC-level protection without the overhead of an in-house security team.'},
            {'q': 'How do you strengthen identity and access security?', 'a': 'We deploy multi-factor authentication (MFA), conditional access policies, and least-privilege role assignments across your environment. This closes the most common attack vector — compromised credentials — and ensures only verified users reach sensitive resources.'},
            {'q': 'Do you support compliance-driven security frameworks?', 'a': 'Yes. We align security controls to industry frameworks including NIST, CIS, HIPAA, and SOC 2. We help you document policies, implement required safeguards, and prepare for audits with evidence-ready reporting.'},
        ],
    },
    'cloud-solutions': {
        'meta_description': 'Cloud solutions for Orange County businesses — AWS, Azure, and Google Cloud migration planning, secure landing zones, governance frameworks, cost optimization, and resilient multi-cloud operations for SMB and mid-market teams.',
        'keywords': [
            'cloud migration services', 'AWS Azure Google Cloud support',
            'cloud governance', 'cloud cost optimization', 'multi cloud operations',
            'cloud solutions Orange County', 'hybrid cloud setup', 'cloud infrastructure management',
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
            {'name': 'AWS', 'icon': 'fa-brands fa-aws', 'desc': 'Scalable compute, storage, and managed services'},
            {'name': 'Microsoft Azure', 'icon': 'fa-brands fa-microsoft', 'desc': 'Enterprise cloud with M365 integration'},
            {'name': 'Google Cloud', 'icon': 'fa-brands fa-google', 'desc': 'Data analytics and Kubernetes-native platform'},
            {'name': 'AWS Managed Services', 'icon': 'fa-solid fa-gear', 'desc': 'Operational guardrails and automation'},
            {'name': 'Cloudflare Connectivity', 'icon': 'fa-solid fa-cloud', 'desc': 'Edge networking and DNS management'},
            {'name': 'Veeam Replication', 'icon': 'fa-solid fa-arrows-rotate', 'desc': 'Cross-region backup and replication'},
            {'name': 'Infrastructure as Code', 'icon': 'fa-solid fa-file-code', 'desc': 'Repeatable deployments with Terraform'},
            {'name': 'Cost Governance', 'icon': 'fa-solid fa-coins', 'desc': 'Spend alerts, rightsizing, and reserved capacity'},
        ],
        'deliverables': [
            {'label': 'Resilience', 'value': 'Backup + failover planning', 'icon': 'fa-solid fa-arrows-to-circle'},
            {'label': 'Security', 'value': 'Guardrails and policy checks', 'icon': 'fa-solid fa-shield-halved'},
            {'label': 'Efficiency', 'value': 'Spend visibility and rightsizing', 'icon': 'fa-solid fa-scale-balanced'},
        ],
        'faqs': [
            {'q': 'Can you support hybrid and multi-cloud environments?', 'a': 'Yes. We design and operate hybrid architectures that span on-premises infrastructure, private cloud, and public cloud providers. Whether you need AWS, Azure, Google Cloud, or a combination, we build a unified management layer for consistent governance and visibility.'},
            {'q': 'How do you minimize risk during cloud migration?', 'a': 'We use a phased wave-based migration approach with validation checkpoints at every stage. Each workload is tested in a staging environment before cutover, and rollback procedures are documented and rehearsed so you can revert quickly if needed.'},
            {'q': 'Do you provide ongoing cloud management after migration?', 'a': 'Yes. Post-migration services include 24/7 monitoring, automated patching, cost optimization reviews, and capacity planning. We treat cloud operations as a continuous improvement cycle — not a one-time migration event.'},
        ],
    },
    'surveillance-camera-installation': {
        'meta_description': 'Commercial surveillance camera installation in Orange County — professional site surveys, camera placement design, NVR and cloud storage setup, secure remote viewing, retention policy configuration, and ongoing system health monitoring.',
        'keywords': [
            'surveillance camera installation', 'commercial CCTV installation',
            'business camera systems', 'remote video monitoring', 'NVR setup',
            'security camera installation Orange County', 'IP camera system', 'video surveillance for business',
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
            {'name': 'UniFi Protect', 'icon': 'fa-solid fa-video', 'desc': 'Unified camera management and recording'},
            {'name': 'Axis', 'icon': 'fa-solid fa-camera', 'desc': 'Enterprise-grade IP camera hardware'},
            {'name': 'Verkada', 'icon': 'fa-solid fa-building-shield', 'desc': 'Cloud-managed cameras with analytics'},
            {'name': 'Meraki Cameras', 'icon': 'fa-solid fa-network-wired', 'desc': 'Cisco cloud-managed video surveillance'},
            {'name': 'NVR Storage', 'icon': 'fa-solid fa-hard-drive', 'desc': 'On-site recording with redundancy'},
            {'name': 'Remote Access Policies', 'icon': 'fa-solid fa-lock', 'desc': 'Role-based secure mobile and web viewing'},
            {'name': 'Motion Alerts', 'icon': 'fa-solid fa-bell', 'desc': 'AI-triggered notifications for activity zones'},
            {'name': 'Health Monitoring', 'icon': 'fa-solid fa-heart-pulse', 'desc': 'Camera uptime and connectivity checks'},
        ],
        'lead_time_diagram': [
            {'phase': 'Site Survey', 'eta': '1-2 days', 'detail': 'Onsite assessment and retention requirements.', 'icon': 'fa-solid fa-map-location-dot'},
            {'phase': 'System Design', 'eta': '2-4 days', 'detail': 'Camera map, storage plan, and network segmentation.', 'icon': 'fa-solid fa-drafting-compass'},
            {'phase': 'Installation', 'eta': '2-10 days', 'detail': 'Mounting, cabling, recorder setup, and testing.', 'icon': 'fa-solid fa-screwdriver-wrench'},
            {'phase': 'Training & Handover', 'eta': '1 day', 'detail': 'Access controls, SOPs, and operational handoff.', 'icon': 'fa-solid fa-file-shield'},
        ],
        'related_technologies': [
            'UniFi Protect', 'Axis Cameras', 'Verkada Command', 'Cisco Meraki',
            'NVR RAID Storage', 'PoE Switching', 'VLAN Segmentation', 'Cloud Archiving',
        ],
        'supported_brands': ['Axis', 'Verkada', 'Cisco Meraki', 'Ubiquiti UniFi', 'Hikvision', 'Dahua'],
        'brand_services': [
            {'brand': 'Axis / Verkada', 'services': 'Commercial IP camera deployment, retention planning, and policy tuning'},
            {'brand': 'Cisco Meraki / UniFi', 'services': 'Cloud-managed camera networking, remote access, and health monitoring'},
            {'brand': 'Hikvision / Dahua', 'services': 'NVR integration, camera hardening, and secure remote viewing controls'},
        ],
        'deliverables': [
            {'label': 'Visibility', 'value': 'Critical zones fully covered', 'icon': 'fa-solid fa-eye'},
            {'label': 'Retention', 'value': 'Policy-based storage windows', 'icon': 'fa-solid fa-clock-rotate-left'},
            {'label': 'Access', 'value': 'Secure mobile and web viewing', 'icon': 'fa-solid fa-mobile-screen'},
        ],
        'faqs': [
            {'q': 'Do you support multi-site surveillance deployments?', 'a': 'Yes. We design and deploy centrally managed camera systems across multiple business locations. A single dashboard gives you unified access to all sites with role-based permissions for managers and security staff.'},
            {'q': 'Can we view cameras remotely from a phone or browser?', 'a': 'Yes. We configure secure remote access through encrypted connections with multi-factor authentication. Authorized users can view live feeds, review recordings, and receive motion alerts from any device, anywhere.'},
            {'q': 'Do you provide ongoing support after installation?', 'a': 'Yes. Post-install services include camera health monitoring, firmware updates, storage management, and incident response support. We proactively detect offline cameras and connectivity issues before they become blind spots.'},
        ],
    },
    'data-recovery': {
        'meta_description': 'Professional data recovery services in Orange County — secure media intake, advanced drive diagnostics, file extraction from failed hardware, integrity verification, and documented chain-of-custody handling for business-critical data.',
        'keywords': [
            'data recovery service', 'business data recovery', 'drive failure recovery',
            'file restoration service', 'disaster recovery support',
            'data recovery Orange County', 'hard drive recovery', 'SSD data recovery',
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
            {'name': 'SMART Analysis', 'icon': 'fa-solid fa-heart-pulse', 'desc': 'Drive health metrics and failure prediction'},
            {'name': 'Image-Based Recovery', 'icon': 'fa-solid fa-clone', 'desc': 'Sector-level disk imaging for safe extraction'},
            {'name': 'Veeam Backup', 'icon': 'fa-solid fa-shield', 'desc': 'Enterprise backup verification and restore'},
            {'name': 'Cloud Replicas', 'icon': 'fa-solid fa-cloud-arrow-down', 'desc': 'Offsite recovery from cloud snapshots'},
            {'name': 'Checksum Validation', 'icon': 'fa-solid fa-circle-check', 'desc': 'File integrity verification after extraction'},
            {'name': 'Encrypted Transfer', 'icon': 'fa-solid fa-lock', 'desc': 'Secure handoff of recovered data'},
        ],
        'lead_time_diagram': [
            {'phase': 'Secure Intake', 'eta': '30-60 min', 'detail': 'Chain-of-custody logging and media triage.', 'icon': 'fa-solid fa-box-archive'},
            {'phase': 'Diagnostics', 'eta': '2-8 hours', 'detail': 'Failure mode analysis and recovery probability scoring.', 'icon': 'fa-solid fa-microscope'},
            {'phase': 'Recovery Execution', 'eta': '1-5 days', 'detail': 'Sector imaging, extraction, and staged restore.', 'icon': 'fa-solid fa-database'},
            {'phase': 'Integrity Validation', 'eta': '2-12 hours', 'detail': 'Checksum validation and prioritized file handoff.', 'icon': 'fa-solid fa-check-to-slot'},
        ],
        'related_technologies': [
            'SMART Diagnostics', 'Sector Imaging', 'RAID Reconstruction', 'Checksum Validation',
            'AES-256 Encrypted Transfer', 'Veeam Restore', 'Snapshot Recovery', 'Forensic Workflow',
        ],
        'supported_brands': ['Western Digital', 'Seagate', 'Samsung', 'SanDisk', 'Synology', 'QNAP', 'Apple'],
        'brand_services': [
            {'brand': 'Western Digital / Seagate', 'services': 'Mechanical drive recovery, bad-sector extraction, and integrity verification'},
            {'brand': 'Samsung / SanDisk', 'services': 'SSD and flash recovery with controller-aware diagnostics'},
            {'brand': 'Synology / QNAP', 'services': 'NAS recovery, RAID rebuild support, and business-critical file restoration'},
            {'brand': 'Apple / Dell', 'services': 'Workstation and laptop media recovery with secure data handling controls'},
        ],
        'deliverables': [
            {'label': 'Critical Files', 'value': 'Priority-first restoration', 'icon': 'fa-solid fa-file-circle-check'},
            {'label': 'Security', 'value': 'Controlled handling workflow', 'icon': 'fa-solid fa-user-shield'},
            {'label': 'Continuity', 'value': 'Restore plans documented', 'icon': 'fa-solid fa-life-ring'},
        ],
        'faqs': [
            {'q': 'Can you recover data from physically failed drives?', 'a': 'In many cases, yes. We perform sector-level imaging and use specialized tools to extract data from drives with mechanical failures, firmware corruption, or degraded flash storage. Recovery success depends on the extent of physical damage.'},
            {'q': 'How do you protect sensitive data during recovery?', 'a': 'Every recovery follows a documented chain-of-custody process. Media is handled in isolated environments, transferred over encrypted channels, and stored on access-controlled systems. We can also sign NDAs and comply with data handling regulations.'},
            {'q': 'Do you prioritize business-critical files during recovery?', 'a': 'Yes. We work with you to identify high-priority folders, databases, and application data first. Critical business files are extracted and validated before moving to secondary data, minimizing downtime for essential operations.'},
        ],
    },
    'computer-repair': {
        'meta_description': 'Business computer repair services in Orange County — hardware diagnostics, component replacement, OS troubleshooting, malware removal, performance optimization, and post-repair stress testing for laptops and desktops.',
        'keywords': [
            'computer repair service', 'business laptop repair', 'desktop repair',
            'hardware diagnostics', 'performance optimization',
            'computer repair Orange County', 'laptop screen repair', 'virus removal service',
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
            {'name': 'Memory Diagnostics', 'icon': 'fa-solid fa-memory', 'desc': 'RAM stress testing and error detection'},
            {'name': 'Disk Health Scan', 'icon': 'fa-solid fa-hard-drive', 'desc': 'SMART checks and bad sector mapping'},
            {'name': 'Thermal Profiling', 'icon': 'fa-solid fa-temperature-high', 'desc': 'CPU and GPU temperature analysis'},
            {'name': 'Malware Cleanup', 'icon': 'fa-solid fa-shield-virus', 'desc': 'Deep scan and threat removal'},
            {'name': 'Driver Remediation', 'icon': 'fa-solid fa-microchip', 'desc': 'Outdated and conflicting driver fixes'},
            {'name': 'System Benchmarking', 'icon': 'fa-solid fa-gauge-high', 'desc': 'Performance baseline and comparison'},
        ],
        'lead_time_diagram': [
            {'phase': 'Intake & Triage', 'eta': '15-45 min', 'detail': 'Capture failure symptoms and run immediate checks.', 'icon': 'fa-solid fa-stethoscope'},
            {'phase': 'Deep Diagnostics', 'eta': '1-4 hours', 'detail': 'Component testing, OS analysis, and failure isolation.', 'icon': 'fa-solid fa-magnifying-glass'},
            {'phase': 'Repair & Replacement', 'eta': 'Same day - 2 days', 'detail': 'Part replacement, OS remediation, and patching.', 'icon': 'fa-solid fa-screwdriver'},
            {'phase': 'Stress Validation', 'eta': '30-120 min', 'detail': 'CPU, memory, thermal, and workload checks before release.', 'icon': 'fa-solid fa-vial'},
        ],
        'related_technologies': [
            'SMART Disk Analytics', 'UEFI Diagnostics', 'Memory Stress Testing', 'Thermal Profiling',
            'Driver Remediation', 'Malware Forensics', 'System Benchmarking', 'Patch Baseline Enforcement',
        ],
        'supported_brands': ['Dell', 'HP', 'Lenovo', 'Apple', 'ASUS', 'Acer', 'Microsoft Surface'],
        'brand_services': [
            {'brand': 'Dell / HP / Lenovo', 'services': 'Motherboard, storage, RAM, and thermal repair with business QA testing'},
            {'brand': 'Apple', 'services': 'Mac hardware diagnostics, storage replacement, and performance remediation'},
            {'brand': 'ASUS / Acer', 'services': 'Laptop screen, keyboard, and charging subsystem repairs'},
            {'brand': 'Microsoft Surface', 'services': 'Power, boot, and thermal diagnostics with component-level triage'},
        ],
        'deliverables': [
            {'label': 'Reliability', 'value': 'Stable post-repair validation', 'icon': 'fa-solid fa-circle-check'},
            {'label': 'Performance', 'value': 'Boot and app speed improvements', 'icon': 'fa-solid fa-bolt'},
            {'label': 'Readiness', 'value': 'Business-use verified', 'icon': 'fa-solid fa-briefcase'},
        ],
        'faqs': [
            {'q': 'Do you repair business laptops and desktop workstations?', 'a': 'Yes. We service all major brands including Dell, Lenovo, HP, Apple, and custom-built desktops. Whether it is a failing hard drive, cracked screen, or motherboard issue, we diagnose and repair business devices with minimal downtime.'},
            {'q': 'Can you fix slow computer performance?', 'a': 'Yes. Slow performance often stems from failing storage, insufficient RAM, thermal throttling, or software conflicts. We run comprehensive diagnostics to identify the root cause and apply targeted fixes — from SSD upgrades to malware removal and OS optimization.'},
            {'q': 'Do you test devices after repair?', 'a': 'Yes. Every repaired device undergoes a full stress test — CPU load testing, memory validation, thermal monitoring, and application performance checks — before it is returned. This ensures the fix is stable and the device is ready for daily use.'},
        ],
    },
    'mobile-phone-repair': {
        'meta_description': 'Mobile phone and tablet repair in Orange County — screen replacement, battery service, charging port repair, data-safe diagnostics, firmware checks, and full functional QA for business and personal devices.',
        'keywords': [
            'mobile phone repair', 'business phone repair', 'tablet repair',
            'screen battery charging repair',
            'phone repair Orange County', 'iPhone repair', 'Samsung repair', 'iPad repair',
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
            {'name': 'Battery Health Tests', 'icon': 'fa-solid fa-battery-full', 'desc': 'Cycle count and capacity analysis'},
            {'name': 'Charging Port Diagnostics', 'icon': 'fa-solid fa-plug-circle-check', 'desc': 'Connector and power delivery testing'},
            {'name': 'Display Calibration', 'icon': 'fa-solid fa-display', 'desc': 'Touch accuracy and color verification'},
            {'name': 'Data-Safe Workbench', 'icon': 'fa-solid fa-lock', 'desc': 'Repair without factory reset when possible'},
            {'name': 'Signal Verification', 'icon': 'fa-solid fa-signal', 'desc': 'Cellular and Wi-Fi connectivity checks'},
            {'name': 'Accessory Validation', 'icon': 'fa-solid fa-headphones', 'desc': 'Bluetooth, audio jack, and peripheral tests'},
        ],
        'lead_time_diagram': [
            {'phase': 'Device Intake', 'eta': '15-30 min', 'detail': 'Issue confirmation, damage documentation, and estimate path.', 'icon': 'fa-solid fa-mobile-screen'},
            {'phase': 'Diagnostic Pass', 'eta': '30-90 min', 'detail': 'Battery, display, charging, and board-level testing.', 'icon': 'fa-solid fa-sim-card'},
            {'phase': 'Component Repair', 'eta': 'Same day - 2 days', 'detail': 'Screen, battery, port, or camera subsystem replacement.', 'icon': 'fa-solid fa-screwdriver-wrench'},
            {'phase': 'Functional QA', 'eta': '20-60 min', 'detail': 'Charging, signal, camera, audio, and sensor verification.', 'icon': 'fa-solid fa-circle-check'},
        ],
        'related_technologies': [
            'Battery Health Analytics', 'OLED/LCD Calibration', 'Charging Port Microscopy', 'Signal Chain Testing',
            'Firmware Integrity Checks', 'ESD-Safe Workbench', 'Data-Safe Workflow', 'Accessory Validation',
        ],
        'supported_brands': ['Apple iPhone', 'Samsung Galaxy', 'Google Pixel', 'iPad', 'Microsoft Surface', 'OnePlus'],
        'brand_services': [
            {'brand': 'Apple iPhone / iPad', 'services': 'Display, battery, charging, and camera subsystem repairs'},
            {'brand': 'Samsung Galaxy', 'services': 'OLED replacement, charging diagnostics, and board-level checks'},
            {'brand': 'Google Pixel / OnePlus', 'services': 'Battery service, port repair, and firmware stability validation'},
            {'brand': 'Microsoft Surface', 'services': 'Tablet power, display, and thermal diagnostics for field devices'},
        ],
        'deliverables': [
            {'label': 'Downtime', 'value': 'Fast return-to-user cycle', 'icon': 'fa-solid fa-hourglass-half'},
            {'label': 'Reliability', 'value': 'Post-repair functional checklist', 'icon': 'fa-solid fa-list-check'},
            {'label': 'Security', 'value': 'Data-aware handling process', 'icon': 'fa-solid fa-user-lock'},
        ],
        'faqs': [
            {'q': 'Do you repair business tablets and iPads as well?', 'a': 'Yes. We service phones and tablets from all major manufacturers including Apple, Samsung, Google, and Microsoft Surface. Business tablets used in point-of-sale, field work, or office workflows are fully supported.'},
            {'q': 'Can you fix charging port and battery issues?', 'a': 'Yes. Charging subsystem diagnostics are part of our standard intake. We test the port, cable, and battery independently to isolate the fault, then replace only the components that need repair — keeping costs predictable.'},
            {'q': 'Will my data be preserved during repair?', 'a': 'We use a data-safe repair process and avoid factory resets whenever possible. Your photos, contacts, and apps remain intact. If a reset is required, we notify you in advance so you can back up your data before we proceed.'},
        ],
    },
    'game-console-repair': {
        'meta_description': 'Game console repair services in Orange County — HDMI port repair, overheating fixes, storage upgrades, power diagnostics, thermal repaste, and extended stress testing for PlayStation, Xbox, and Nintendo systems.',
        'keywords': [
            'game console repair', 'HDMI port repair', 'console overheating repair',
            'PlayStation Xbox Nintendo repair',
            'PS5 repair Orange County', 'Xbox repair', 'Nintendo Switch repair', 'console HDMI fix',
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
            {'name': 'HDMI Port Rework', 'icon': 'fa-solid fa-tv', 'desc': 'Micro-soldering for connector replacement'},
            {'name': 'Thermal Diagnostics', 'icon': 'fa-solid fa-temperature-high', 'desc': 'Heat mapping under sustained load'},
            {'name': 'Storage Integrity Checks', 'icon': 'fa-solid fa-hard-drive', 'desc': 'SSD and HDD health verification'},
            {'name': 'Power Rail Testing', 'icon': 'fa-solid fa-bolt', 'desc': 'Voltage rail analysis on the mainboard'},
            {'name': 'Controller Pairing Tests', 'icon': 'fa-solid fa-satellite-dish', 'desc': 'Bluetooth sync and input validation'},
            {'name': 'Network Latency Checks', 'icon': 'fa-solid fa-network-wired', 'desc': 'Wi-Fi and Ethernet connectivity tests'},
        ],
        'lead_time_diagram': [
            {'phase': 'Bench Intake', 'eta': '15-45 min', 'detail': 'Power, display, and accessory symptom capture.', 'icon': 'fa-solid fa-gamepad'},
            {'phase': 'Board Diagnostics', 'eta': '1-4 hours', 'detail': 'HDMI path, power rails, thermal, and storage checks.', 'icon': 'fa-solid fa-screwdriver-wrench'},
            {'phase': 'Repair Execution', 'eta': '1-3 days', 'detail': 'Port, thermal, storage, or board-level remediation.', 'icon': 'fa-solid fa-fire-flame-curved'},
            {'phase': 'Extended Stress Test', 'eta': '2-6 hours', 'detail': 'Gameplay load, thermals, networking, and controller QA.', 'icon': 'fa-solid fa-circle-check'},
        ],
        'related_technologies': [
            'HDMI Micro-Soldering', 'Thermal Repaste', 'Power Rail Analysis', 'Storage Integrity Validation',
            'Controller Pairing QA', 'Latency Profiling', 'Cooling Path Rebuild', 'Extended Burn-In Testing',
        ],
        'supported_brands': ['Sony PlayStation', 'Microsoft Xbox', 'Nintendo Switch'],
        'brand_services': [
            {'brand': 'Sony PlayStation', 'services': 'HDMI port repair, thermal service, storage upgrades, and stress testing'},
            {'brand': 'Microsoft Xbox', 'services': 'Power diagnostics, cooling remediation, and output-path validation'},
            {'brand': 'Nintendo Switch', 'services': 'Charging, display, controller pairing, and connectivity repairs'},
        ],
        'deliverables': [
            {'label': 'Stability', 'value': 'Extended run validation', 'icon': 'fa-solid fa-circle-check'},
            {'label': 'Thermals', 'value': 'Improved cooling performance', 'icon': 'fa-solid fa-wind'},
            {'label': 'Video Output', 'value': 'Display path restored', 'icon': 'fa-solid fa-photo-film'},
        ],
        'faqs': [
            {'q': 'Can you fix HDMI port and display output issues?', 'a': 'Yes. HDMI port failure is one of the most common console repairs we handle. We use precision micro-soldering to replace damaged connectors and test the full display pipeline — from the GPU output to the HDMI port — to ensure a reliable signal.'},
            {'q': 'Can console overheating problems be resolved?', 'a': 'Yes. We disassemble the console, clean the fan and heatsink assembly, replace degraded thermal paste, and verify temperatures under sustained gaming load. This restores proper cooling and prevents thermal shutdowns or performance throttling.'},
            {'q': 'Do you stress test consoles before returning them?', 'a': 'Yes. Every repaired console runs through an extended stress test — sustained gaming load, network connectivity checks, controller pairing, and thermal monitoring. We only return the device once it passes all validation benchmarks.'},
        ],
    },
    'device-diagnostics': {
        'meta_description': 'Comprehensive device diagnostics in Orange County — hardware health assessments, storage and memory testing, thermal profiling, malware scanning, risk scoring, and prioritized repair-or-replace recommendations for business devices.',
        'keywords': [
            'device diagnostics', 'hardware diagnostics service', 'system health assessment',
            'preventive IT maintenance',
            'device diagnostics Orange County', 'computer health check', 'IT asset assessment',
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
            {'name': 'SMART Monitoring', 'icon': 'fa-solid fa-heart-pulse', 'desc': 'Predictive drive failure detection'},
            {'name': 'Memory Test Suites', 'icon': 'fa-solid fa-memory', 'desc': 'Multi-pass RAM error scanning'},
            {'name': 'Thermal Profiling', 'icon': 'fa-solid fa-temperature-half', 'desc': 'CPU and GPU heat analysis under load'},
            {'name': 'Port and NIC Checks', 'icon': 'fa-solid fa-ethernet', 'desc': 'Connectivity and throughput validation'},
            {'name': 'Malware Risk Scan', 'icon': 'fa-solid fa-shield-virus', 'desc': 'Hidden threat and rootkit detection'},
            {'name': 'Performance Baseline', 'icon': 'fa-solid fa-chart-line', 'desc': 'Benchmark scores for comparison tracking'},
        ],
        'lead_time_diagram': [
            {'phase': 'Asset Intake', 'eta': '15-45 min', 'detail': 'Device cataloging, symptom intake, and baseline capture.', 'icon': 'fa-solid fa-file-waveform'},
            {'phase': 'Deep Test Cycle', 'eta': '1-6 hours', 'detail': 'Memory, storage, thermal, and network diagnostics.', 'icon': 'fa-solid fa-microchip'},
            {'phase': 'Risk Scoring', 'eta': '30-90 min', 'detail': 'Failure probability and business-impact ranking.', 'icon': 'fa-solid fa-chart-simple'},
            {'phase': 'Action Brief', 'eta': '1-2 hours', 'detail': 'Repair, replace, and timeline recommendations delivered.', 'icon': 'fa-solid fa-list-ol'},
        ],
        'related_technologies': [
            'Hardware Health Scoring', 'SMART Predictive Analytics', 'Memory Burn-In Testing', 'Thermal Stress Profiling',
            'NIC Throughput Validation', 'Malware Forensics', 'Risk Prioritization Matrix', 'Lifecycle Planning',
        ],
        'supported_brands': ['Dell', 'HP', 'Lenovo', 'Apple', 'Microsoft', 'Samsung'],
        'brand_services': [
            {'brand': 'Dell / HP / Lenovo', 'services': 'Enterprise workstation and laptop deep diagnostics with lifecycle scoring'},
            {'brand': 'Apple', 'services': 'Mac diagnostics, thermal profiling, and performance baseline checks'},
            {'brand': 'Microsoft / Samsung', 'services': 'Tablet and hybrid-device hardware-health and connectivity analysis'},
        ],
        'deliverables': [
            {'label': 'Visibility', 'value': 'Failure points identified early', 'icon': 'fa-solid fa-eye'},
            {'label': 'Planning', 'value': 'Prioritized remediation report', 'icon': 'fa-solid fa-file-lines'},
            {'label': 'Cost Control', 'value': 'Repair vs replace clarity', 'icon': 'fa-solid fa-scale-balanced'},
        ],
        'faqs': [
            {'q': 'Is diagnostics only for devices that are already broken?', 'a': 'No. Diagnostics is equally valuable as a preventive measure. By running comprehensive health checks on devices that appear to work fine, we catch early warning signs — degrading storage, failing memory modules, or thermal issues — before they cause unexpected downtime.'},
            {'q': 'Do we receive a written diagnostic report?', 'a': 'Yes. Every diagnostic session produces a clear, prioritized report. It includes hardware health scores, identified risks ranked by business impact, and actionable recommendations for repair, replacement, or upgrade — so you can make informed decisions.'},
            {'q': 'Can proactive diagnostics actually reduce business downtime?', 'a': 'Yes. Businesses that schedule regular diagnostic cycles catch hardware failures weeks or months before they impact operations. Early detection allows you to plan replacements during maintenance windows instead of dealing with emergency outages.'},
        ],
    },
    'enterprise-consultancy': {
        'meta_description': 'Enterprise IT consultancy in Orange County — technology roadmaps, infrastructure audits, vendor evaluation and negotiation, digital transformation strategy, compliance alignment, and fractional CTO advisory for growing businesses.',
        'keywords': [
            'enterprise IT consultancy Orange County', 'IT strategy consulting', 'technology roadmap planning',
            'digital transformation consulting', 'IT infrastructure audit', 'vendor evaluation services',
            'business IT advisory', 'CTO advisory Orange County', 'IT governance consulting',
            'fractional CTO services', 'IT budget optimization',
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
            {'name': 'Microsoft 365', 'icon': 'fa-brands fa-microsoft', 'desc': 'Productivity suite licensing and governance'},
            {'name': 'Google Workspace', 'icon': 'fa-brands fa-google', 'desc': 'Collaboration platform evaluation'},
            {'name': 'AWS', 'icon': 'fa-brands fa-aws', 'desc': 'Cloud architecture and cost modeling'},
            {'name': 'Azure', 'icon': 'fa-solid fa-cloud', 'desc': 'Enterprise cloud strategy and identity'},
            {'name': 'Jira', 'icon': 'fa-brands fa-atlassian', 'desc': 'Project delivery and workflow tracking'},
            {'name': 'Power BI', 'icon': 'fa-solid fa-chart-pie', 'desc': 'Data visualization and executive dashboards'},
            {'name': 'Salesforce', 'icon': 'fa-brands fa-salesforce', 'desc': 'CRM strategy and integration planning'},
            {'name': 'Slack', 'icon': 'fa-brands fa-slack', 'desc': 'Team communication and workflow automation'},
        ],
        'deliverables': [
            {'label': 'IT Roadmap', 'value': 'Phased transformation plan', 'icon': 'fa-solid fa-map'},
            {'label': 'Vendor Strategy', 'value': 'Objective evaluation & savings', 'icon': 'fa-solid fa-scale-balanced'},
            {'label': 'Risk Reduction', 'value': 'Governance & compliance alignment', 'icon': 'fa-solid fa-shield-halved'},
        ],
        'faqs': [
            {'q': 'Who is enterprise IT consultancy designed for?', 'a': 'Growing businesses that need strategic IT guidance without hiring a full-time CTO or IT director. We serve companies from 20 to 500 employees across industries including healthcare, legal, finance, manufacturing, and professional services in Orange County.'},
            {'q': 'Do you replace our existing IT team or provider?', 'a': 'No. We complement your team by providing strategic oversight, vendor management, and technology roadmap planning. Think of us as your fractional CTO — we handle the big-picture strategy while your internal team or MSP manages daily operations.'},
            {'q': 'What does a typical consulting engagement look like?', 'a': 'We start with a 1-2 week discovery audit of your infrastructure, contracts, and workflows. Within 2-3 weeks, you receive a prioritized technology roadmap with timelines and budget estimates. Ongoing advisory is available monthly or quarterly as needed.'},
            {'q': 'Can you help negotiate vendor contracts and reduce IT costs?', 'a': 'Yes. We evaluate existing contracts, benchmark pricing against industry standards, and negotiate renewals on your behalf. Clients typically see 15-30% savings on licensing, hosting, and support agreements through our vendor optimization process.'},
            {'q': 'How is enterprise consultancy different from managed IT services?', 'a': 'Managed IT handles day-to-day operations — help desk, patching, monitoring. Enterprise consultancy focuses on strategy, planning, and long-term technology alignment with your business goals. Many clients use both services together for complete coverage.'},
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
        with urlopen(req, timeout=10) as response:  # nosec B310
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


def merge_service_profile(base_profile, override_profile):
    merged = dict(base_profile or {})
    if not isinstance(override_profile, dict):
        return merged
    for key, value in override_profile.items():
        if value in (None, '', [], {}):
            continue
        merged[key] = value
    return merged


def get_service_profile(service):
    # Prefer DB-stored profile_json, fall back to hardcoded SERVICE_PROFILES
    profile = {}
    has_custom_db_profile = False
    if service.profile_json:
        try:
            import json as _json
            loaded = _json.loads(service.profile_json)
            if isinstance(loaded, dict):
                profile = loaded
                has_custom_db_profile = True
            else:
                profile = {}
        except (ValueError, TypeError):
            profile = {}
    if not profile:
        profile = SERVICE_PROFILES.get(service.slug, {})
    if not has_custom_db_profile:
        profile = merge_service_profile(profile, SERVICE_RESEARCH_OVERRIDES.get(service.slug, {}))
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
    keyword_set = {k.lower() for k in keywords}
    local_variants = [
        f"{service.title} Irvine",
        f"{service.title} Santa Ana",
        f"{service.title} Anaheim",
    ]
    for variant in local_variants:
        if variant.lower() not in keyword_set:
            keywords.append(variant)
            keyword_set.add(variant.lower())

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
            'icon': normalize_icon_class(tool.get('icon', ''), 'fa-solid fa-wrench'),
            'desc': str(tool.get('desc', '')).strip(),
        }
        for tool in tools if isinstance(tool, dict)
    ]

    if service.service_type == 'professional':
        default_deliverables = [
            {'label': 'Coverage', 'value': 'Strategic IT delivery aligned to business goals', 'icon': 'fa-solid fa-layer-group'},
            {'label': 'Security', 'value': 'Risk-aware controls and compliance-focused execution', 'icon': 'fa-solid fa-shield-halved'},
            {'label': 'Performance', 'value': 'Reliable systems with measurable optimization gains', 'icon': 'fa-solid fa-gauge-high'},
            {'label': 'Support', 'value': 'Clear communication and accountable escalation paths', 'icon': 'fa-solid fa-headset'},
        ]
    else:
        default_deliverables = [
            {'label': 'Diagnostics', 'value': 'Root-cause analysis before any repair action', 'icon': 'fa-solid fa-stethoscope'},
            {'label': 'Turnaround', 'value': 'Fast service windows with transparent lead-time updates', 'icon': 'fa-solid fa-stopwatch'},
            {'label': 'Parts Quality', 'value': 'Verified components and precision repair workmanship', 'icon': 'fa-solid fa-microchip'},
            {'label': 'Validation', 'value': 'Post-repair stress and functional quality checks', 'icon': 'fa-solid fa-circle-check'},
        ]

    deliverables = profile.get('deliverables', default_deliverables)
    normalized_deliverables = []
    for item in deliverables:
        if not isinstance(item, dict):
            continue
        normalized_deliverables.append({
            'label': str(item.get('label', 'Outcome')).strip() or 'Outcome',
            'value': str(item.get('value', 'Business impact delivered')).strip() or 'Business impact delivered',
            'icon': normalize_icon_class(item.get('icon', ''), 'fa-solid fa-bullseye')
        })
        if len(normalized_deliverables) >= 4:
            break

    if len(normalized_deliverables) < 4:
        for fallback in default_deliverables:
            normalized_deliverables.append({
                'label': str(fallback.get('label', 'Outcome')).strip() or 'Outcome',
                'value': str(fallback.get('value', 'Business impact delivered')).strip() or 'Business impact delivered',
                'icon': normalize_icon_class(fallback.get('icon', ''), 'fa-solid fa-bullseye')
            })
            if len(normalized_deliverables) >= 4:
                break
    deliverables = normalized_deliverables[:4]

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

    meta_title = clean_text(profile.get('meta_title', ''), 140)
    if not meta_title:
        meta_title = f"{service.title} in Orange County | Right On Repair"

    positioning_badge = clean_text(profile.get('positioning_badge', ''), 90)
    if not positioning_badge:
        positioning_badge = 'Service Delivery Program'

    if service.service_type == 'professional':
        default_hero_badges = [
            {'icon': 'fa-solid fa-layer-group', 'label': 'Strategic Discovery and Planning'},
            {'icon': 'fa-solid fa-gears', 'label': 'Implementation with Quality Controls'},
            {'icon': 'fa-solid fa-chart-line', 'label': 'Continuous Optimization'},
        ]
    else:
        default_hero_badges = [
            {'icon': 'fa-solid fa-stethoscope', 'label': 'Diagnostics-First Workflow'},
            {'icon': 'fa-solid fa-screwdriver-wrench', 'label': 'Component-Level Repair Paths'},
            {'icon': 'fa-solid fa-circle-check', 'label': 'Validation Before Handoff'},
        ]

    hero_badges = profile.get('hero_badges', default_hero_badges)
    normalized_hero_badges = []
    for item in hero_badges:
        if not isinstance(item, dict):
            continue
        label = str(item.get('label', '')).strip()
        if not label:
            continue
        normalized_hero_badges.append({
            'icon': normalize_icon_class(item.get('icon', ''), 'fa-solid fa-circle'),
            'label': label,
        })
    if not normalized_hero_badges:
        normalized_hero_badges = default_hero_badges

    modules_title = clean_text(profile.get('modules_title', ''), 120)
    if not modules_title:
        modules_title = 'Specialized Service Programs'

    service_modules = profile.get('service_modules', [])
    normalized_modules = []
    for item in service_modules:
        if not isinstance(item, dict):
            continue
        title = str(item.get('title', '')).strip()
        detail = str(item.get('detail', '')).strip()
        if not title or not detail:
            continue
        normalized_modules.append({
            'title': title,
            'detail': detail,
            'icon': normalize_icon_class(item.get('icon', ''), 'fa-solid fa-circle'),
        })
    if not normalized_modules:
        normalized_modules = [
            {
                'title': step['title'],
                'detail': step['detail'],
                'icon': step['icon'],
            }
            for step in process[:4]
        ]

    issue_solution_map = profile.get('issue_solution_map', [])
    normalized_issue_solution_map = []
    for item in issue_solution_map:
        if not isinstance(item, dict):
            continue
        issue = str(item.get('issue', '')).strip()
        solution = str(item.get('solution', '')).strip()
        if not issue or not solution:
            continue
        normalized_issue_solution_map.append({
            'issue': issue,
            'solution': solution,
            'icon': normalize_icon_class(item.get('icon', ''), 'fa-solid fa-circle'),
        })
    if not normalized_issue_solution_map:
        if normalized_modules:
            for module in normalized_modules[:4]:
                normalized_issue_solution_map.append({
                    'issue': f"{module['title']} gaps creating inconsistent outcomes",
                    'solution': module['detail'],
                    'icon': module['icon'],
                })
        elif service.service_type == 'professional':
            default_issue_solution_map = [
                {
                    'issue': f"Unclear priorities and scope around {service.title.lower()} initiatives",
                    'solution': 'We define delivery scope, ownership, milestones, and success criteria before execution.',
                    'icon': 'fa-solid fa-list-check',
                },
                {
                    'issue': 'Reactive support cycles creating recurring operational disruption',
                    'solution': 'We implement proactive monitoring, escalation standards, and governance checkpoints.',
                    'icon': 'fa-solid fa-wave-square',
                },
                {
                    'issue': 'Security and compliance expectations not aligned to technology operations',
                    'solution': 'We map controls to business requirements and embed security-first delivery practices.',
                    'icon': 'fa-solid fa-shield-halved',
                },
                {
                    'issue': 'Limited visibility into outcomes, ROI, and next-step planning',
                    'solution': 'We provide measurable reporting, optimization recommendations, and strategic roadmap updates.',
                    'icon': 'fa-solid fa-chart-line',
                },
            ]
        else:
            default_issue_solution_map = [
                {
                    'issue': f"Unexpected {service.title.lower()} failures causing urgent downtime",
                    'solution': 'We run rapid intake triage and isolate root cause before selecting the repair path.',
                    'icon': 'fa-solid fa-stethoscope',
                },
                {
                    'issue': 'Inconsistent repair quality and repeat failure after service',
                    'solution': 'We use component-level diagnostics and standardized quality validation before handoff.',
                    'icon': 'fa-solid fa-screwdriver-wrench',
                },
                {
                    'issue': 'Data exposure risk during diagnostics, repair, or recovery handling',
                    'solution': 'We follow data-safe procedures, access controls, and secure transfer practices.',
                    'icon': 'fa-solid fa-user-shield',
                },
                {
                    'issue': 'No reliable estimate on turnaround and business impact',
                    'solution': 'We provide clear lead-time checkpoints and communicate status through each service phase.',
                    'icon': 'fa-solid fa-hourglass-half',
                },
            ]
        if not normalized_issue_solution_map:
            normalized_issue_solution_map = default_issue_solution_map

    narrative_title = clean_text(profile.get('narrative_title', ''), 120)
    if not narrative_title:
        narrative_title = 'Service Scope and Delivery Standards'

    seo_content_blocks = profile.get('seo_content_blocks', [])
    normalized_content_blocks = []
    for item in seo_content_blocks:
        text = str(item).strip()
        if text:
            normalized_content_blocks.append(text)
    if not normalized_content_blocks:
        normalized_content_blocks = [
            f"{service.title} engagements are scoped around operational goals, risk controls, and measurable outcomes for Orange County organizations.",
            "Each project includes a defined workflow, implementation milestones, and post-delivery review to improve reliability and long-term performance.",
        ]

    service_area_cities = profile.get('service_area_cities', [
        'Irvine', 'Santa Ana', 'Anaheim', 'Huntington Beach',
        'Newport Beach', 'Costa Mesa', 'Fullerton', 'Orange',
    ])
    service_area_cities = [str(city).strip() for city in service_area_cities if str(city).strip()]

    if service.service_type == 'professional':
        default_frameworks = ['SOC 2', 'HIPAA', 'PCI-DSS', 'NIST CSF', 'CIS Controls']
        default_proof_points = [
            {'label': 'Response Model', 'value': 'Structured triage and escalation workflows'},
            {'label': 'Local Coverage', 'value': 'Orange County onsite and remote support'},
            {'label': 'Security Posture', 'value': 'Hardening, monitoring, and policy alignment'},
            {'label': 'Roadmap Visibility', 'value': 'Prioritized recommendations and reporting'},
        ]
    else:
        default_frameworks = ['Chain-of-custody handling', 'Data-safe diagnostics', 'Quality assurance testing']
        default_proof_points = [
            {'label': 'Diagnostic Rigor', 'value': 'Root-cause analysis before repair actions'},
            {'label': 'Turnaround Focus', 'value': 'Priority workflows for business-critical devices'},
            {'label': 'Data Protection', 'value': 'Data-aware repair procedures when feasible'},
            {'label': 'Validation', 'value': 'Post-repair functional and stress test checks'},
        ]

    compliance_frameworks = profile.get('compliance_frameworks', default_frameworks)
    compliance_frameworks = [str(item).strip() for item in compliance_frameworks if str(item).strip()]

    proof_points = profile.get('proof_points', default_proof_points)
    normalized_proof_points = []
    for point in proof_points:
        if not isinstance(point, dict):
            continue
        label = str(point.get('label', 'Operational Strength')).strip() or 'Operational Strength'
        value = str(point.get('value', 'Reliable delivery with practical oversight.')).strip() or 'Reliable delivery with practical oversight.'
        normalized_proof_points.append({'label': label, 'value': value})
    if not normalized_proof_points:
        normalized_proof_points = default_proof_points

    if service.service_type == 'professional':
        default_lead_time = [
            {'phase': 'Discovery & Intake', 'eta': '1-2 days', 'detail': 'Requirements, risks, and current-state capture.', 'icon': 'fa-solid fa-magnifying-glass-chart'},
            {'phase': 'Architecture & Plan', 'eta': '2-5 days', 'detail': 'Scope, milestones, and delivery sequence finalized.', 'icon': 'fa-solid fa-diagram-project'},
            {'phase': 'Implementation', 'eta': '1-4 weeks', 'detail': 'Execution, validation, and stakeholder checkpoints.', 'icon': 'fa-solid fa-gears'},
            {'phase': 'Handover & Optimization', 'eta': '2-5 days', 'detail': 'Documentation, enablement, and continuous tuning.', 'icon': 'fa-solid fa-chart-line'},
        ]
    else:
        default_lead_time = [
            {'phase': 'Intake & Triage', 'eta': '15-60 min', 'detail': 'Device check-in, symptom review, and priority assessment.', 'icon': 'fa-solid fa-clipboard-check'},
            {'phase': 'Diagnostics', 'eta': '30-180 min', 'detail': 'Root-cause analysis and repair path selection.', 'icon': 'fa-solid fa-stethoscope'},
            {'phase': 'Repair & Recovery', 'eta': 'Same day - 3 days', 'detail': 'Component-level work, replacement, or data recovery actions.', 'icon': 'fa-solid fa-screwdriver-wrench'},
            {'phase': 'Quality Validation', 'eta': '30-120 min', 'detail': 'Stress checks, functional QA, and handoff readiness.', 'icon': 'fa-solid fa-circle-check'},
        ]

    lead_time_diagram = profile.get('lead_time_diagram', default_lead_time)
    normalized_lead_time = []
    for step in lead_time_diagram:
        if not isinstance(step, dict):
            continue
        phase = str(step.get('phase', 'Phase')).strip() or 'Phase'
        eta = str(step.get('eta', 'TBD')).strip() or 'TBD'
        detail = str(step.get('detail', 'Delivery checkpoint.')).strip() or 'Delivery checkpoint.'
        icon = normalize_icon_class(step.get('icon', ''), 'fa-solid fa-clock')
        normalized_lead_time.append({
            'phase': phase,
            'eta': eta,
            'detail': detail,
            'icon': icon,
        })
    if not normalized_lead_time:
        normalized_lead_time = default_lead_time

    related_technologies = profile.get('related_technologies', [tool.get('name', '') for tool in tools[:8]])
    normalized_technologies = []
    seen_technologies = set()
    for item in related_technologies:
        value = str(item).strip()
        key = value.lower()
        if not value or key in seen_technologies:
            continue
        normalized_technologies.append(value)
        seen_technologies.add(key)
    if not normalized_technologies:
        normalized_technologies = [tool.get('name', '') for tool in tools[:6] if tool.get('name')]

    if service.service_type == 'repair':
        default_supported_brands = ['Apple', 'Samsung', 'Dell', 'HP', 'Lenovo', 'Microsoft']
    else:
        default_supported_brands = ['Microsoft', 'Google', 'Amazon Web Services', 'Cisco', 'Dell', 'VMware']
    supported_brands = profile.get('supported_brands', default_supported_brands)
    normalized_supported_brands = []
    seen_brands = set()
    for brand in supported_brands:
        brand_name = str(brand).strip()
        brand_key = brand_name.lower()
        if not brand_name or brand_key in seen_brands:
            continue
        normalized_supported_brands.append(brand_name)
        seen_brands.add(brand_key)

    default_brand_services = []
    if service.service_type == 'repair':
        default_brand_services = [
            {'brand': 'Apple', 'services': 'Diagnostics, component repair, and post-repair QA'},
            {'brand': 'Samsung', 'services': 'Screen, battery, board-level checks, and firmware validation'},
            {'brand': 'Dell / HP / Lenovo', 'services': 'Laptop and desktop component replacement and performance tuning'},
            {'brand': 'Microsoft Surface', 'services': 'Power, charging, display, and thermal diagnostics'},
        ]
    brand_services = profile.get('brand_services', default_brand_services)
    normalized_brand_services = []
    for item in brand_services:
        if not isinstance(item, dict):
            continue
        brand = str(item.get('brand', '')).strip()
        services_text = str(item.get('services', '')).strip()
        if not brand or not services_text:
            continue
        normalized_brand_services.append({'brand': brand, 'services': services_text})

    return {
        'meta_title': meta_title,
        'meta_description': profile.get('meta_description', short_description),
        'keywords': keywords,
        'positioning_badge': positioning_badge,
        'hero_badges': normalized_hero_badges,
        'modules_title': modules_title,
        'service_modules': normalized_modules,
        'issue_solution_map': normalized_issue_solution_map,
        'narrative_title': narrative_title,
        'seo_content_blocks': normalized_content_blocks,
        'intro_kicker': profile.get('intro_kicker', 'Plan • Deliver • Improve'),
        'board_title': profile.get('board_title', 'Service Workflow'),
        'process': process,
        'tools': tools,
        'deliverables': deliverables,
        'faqs': faqs,
        'service_area_cities': service_area_cities,
        'compliance_frameworks': compliance_frameworks,
        'proof_points': normalized_proof_points,
        'lead_time_diagram': normalized_lead_time,
        'related_technologies': normalized_technologies,
        'supported_brands': normalized_supported_brands,
        'brand_services': normalized_brand_services,
    }


def get_public_base_url():
    configured = (current_app.config.get('APP_BASE_URL') or '').strip()
    if configured.startswith('http://') or configured.startswith('https://'):
        return configured.rstrip('/')
    return request.url_root.rstrip('/')


def absolute_public_url(path):
    if path.startswith('http://') or path.startswith('https://'):
        return path
    if not path.startswith('/'):
        path = f'/{path}'
    return f"{get_public_base_url()}{path}"


def format_sitemap_lastmod(dt_value):
    if not dt_value:
        return None
    return dt_value.strftime('%Y-%m-%dT%H:%M:%SZ')


def build_sitemap_entry(path, lastmod=None, changefreq='weekly', priority='0.6'):
    lines = [
        '  <url>',
        f"    <loc>{xml_escape(absolute_public_url(path))}</loc>",
    ]
    formatted_lastmod = format_sitemap_lastmod(lastmod)
    if formatted_lastmod:
        lines.append(f"    <lastmod>{formatted_lastmod}</lastmod>")
    if changefreq:
        lines.append(f"    <changefreq>{changefreq}</changefreq>")
    if priority:
        lines.append(f"    <priority>{priority}</priority>")
    lines.append('  </url>')
    return '\n'.join(lines)


@main_bp.route('/')
def index():
    pro_services = normalize_icon_attr(
        Service.query.filter_by(
            service_type='professional',
            is_featured=True,
            workflow_status=WORKFLOW_PUBLISHED,
        ).order_by(Service.sort_order).all(),
        'fa-solid fa-gear'
    )
    repair_services = normalize_icon_attr(
        Service.query.filter_by(
            service_type='repair',
            is_featured=True,
            workflow_status=WORKFLOW_PUBLISHED,
        ).order_by(Service.sort_order).all(),
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
        Service.query.filter_by(
            service_type='professional',
            workflow_status=WORKFLOW_PUBLISHED,
        ).order_by(Service.sort_order).all(),
        'fa-solid fa-gear'
    )
    repair_services = normalize_icon_attr(
        Service.query.filter_by(
            service_type='repair',
            workflow_status=WORKFLOW_PUBLISHED,
        ).order_by(Service.sort_order).all(),
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
    service = Service.query.filter_by(slug=slug, workflow_status=WORKFLOW_PUBLISHED).first()
    if service is None and slug in SERVICE_SLUG_ALIASES:
        aliased_service = Service.query.filter_by(
            slug=SERVICE_SLUG_ALIASES[slug],
            workflow_status=WORKFLOW_PUBLISHED,
        ).first()
        if aliased_service:
            return redirect(url_for('main.service_detail', slug=SERVICE_SLUG_ALIASES[slug]), code=301)
    if service is None:
        abort(404)
    service.icon_class = normalize_icon_class(service.icon_class, 'fa-solid fa-gear')
    service_profile = get_service_profile(service)
    related_services_same_type = normalize_icon_attr(
        Service.query.filter(
            Service.id != service.id,
            Service.service_type == service.service_type,
            Service.workflow_status == WORKFLOW_PUBLISHED,
        ).order_by(Service.sort_order.asc(), Service.id.asc()).limit(4).all(),
        'fa-solid fa-gear',
    )
    related_services_other_type = normalize_icon_attr(
        Service.query.filter(
            Service.id != service.id,
            Service.service_type != service.service_type,
            Service.workflow_status == WORKFLOW_PUBLISHED,
        ).order_by(Service.sort_order.asc(), Service.id.asc()).limit(2).all(),
        'fa-solid fa-wrench',
    )
    related_services = related_services_same_type + related_services_other_type

    featured_industries = normalize_icon_attr(
        Industry.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Industry.sort_order.asc(), Industry.id.asc()).limit(6).all(),
        'fa-solid fa-building',
    )

    related_posts = []
    safe_title = escape_like(service.title)
    if safe_title:
        related_posts = Post.query.filter_by(workflow_status=WORKFLOW_PUBLISHED)\
            .filter(Post.title.ilike(f'%{safe_title}%'))\
            .order_by(Post.created_at.desc())\
            .limit(3).all()
    if len(related_posts) < 3:
        existing_ids = {post.id for post in related_posts}
        fallback_posts = Post.query.filter_by(workflow_status=WORKFLOW_PUBLISHED)\
            .order_by(Post.created_at.desc())\
            .limit(6).all()
        for post in fallback_posts:
            if post.id in existing_ids:
                continue
            related_posts.append(post)
            existing_ids.add(post.id)
            if len(related_posts) >= 3:
                break

    return render_template(
        'service_detail.html',
        service=service,
        service_profile=service_profile,
        related_services=related_services,
        featured_industries=featured_industries,
        related_posts=related_posts,
    )


@main_bp.route('/blog')
def blog():
    page = request.args.get('page', 1, type=int)
    page = max(1, min(page, 1000))
    category_slug = clean_text(request.args.get('category', ''), 120)
    search = clean_text(request.args.get('q', ''), 120)

    query = Post.query.filter_by(workflow_status=WORKFLOW_PUBLISHED)

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
    post = Post.query.filter_by(slug=slug, workflow_status=WORKFLOW_PUBLISHED).first_or_404()
    recent_posts = Post.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).filter(Post.id != post.id)\
        .order_by(Post.created_at.desc()).limit(3).all()
    return render_template('post.html', post=post, recent_posts=recent_posts)


@main_bp.route('/industries')
def industries():
    all_industries = normalize_icon_attr(
        Industry.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Industry.sort_order).all(),
        'fa-solid fa-building'
    )
    cb = get_page_content('industries')
    return render_template('industries.html', industries=all_industries, cb=cb)


@main_bp.route('/industries/<slug>')
def industry_detail(slug):
    industry = Industry.query.filter_by(slug=slug, workflow_status=WORKFLOW_PUBLISHED).first()
    if industry is None and slug in INDUSTRY_SLUG_ALIASES:
        aliased_industry = Industry.query.filter_by(
            slug=INDUSTRY_SLUG_ALIASES[slug],
            workflow_status=WORKFLOW_PUBLISHED,
        ).first()
        if aliased_industry:
            return redirect(url_for('main.industry_detail', slug=INDUSTRY_SLUG_ALIASES[slug]), code=301)
    if industry is None:
        abort(404)
    industry.icon_class = normalize_icon_class(industry.icon_class, 'fa-solid fa-building')
    services = normalize_icon_attr(
        Service.query.filter_by(
            is_featured=True,
            workflow_status=WORKFLOW_PUBLISHED,
        ).order_by(Service.sort_order).limit(6).all(),
        'fa-solid fa-gear'
    )
    return render_template('industry_detail.html', industry=industry, services=services)


@main_bp.route('/remote-support')
def remote_support():
    portal_client = get_logged_support_client()
    services = normalize_icon_attr(
        Service.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Service.title).all(),
        'fa-solid fa-gear',
    )
    tickets = []
    stage_counts = {
        'pending': 0,
        'done': 0,
        'closed': 0,
    }

    if portal_client:
        tickets = SupportTicket.query.filter_by(client_id=portal_client.id)\
            .order_by(SupportTicket.updated_at.desc(), SupportTicket.created_at.desc()).all()
        for ticket in tickets:
            stage_key = support_ticket_stage_for_status(ticket.status)
            stage_counts[stage_key] = stage_counts.get(stage_key, 0) + 1

    return render_template(
        'remote_support.html',
        portal_client=portal_client,
        services=services,
        tickets=tickets,
        ticket_status_labels=SUPPORT_TICKET_STATUS_LABELS,
        ticket_priority_labels=TICKET_PRIORITY_LABELS,
        ticket_stage_labels=SUPPORT_TICKET_STAGE_LABELS,
        ticket_stage_for_status=support_ticket_stage_for_status,
        ticket_stage_counts=stage_counts,
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

    if not full_name or not email or not phone or not password:
        register_remote_auth_failure()
        flash('Name, email, phone, and password are required.', 'danger')
        return redirect(url_for('main.remote_support'))

    if not is_valid_email(email):
        register_remote_auth_failure()
        flash('Please provide a valid email address.', 'danger')
        return redirect(url_for('main.remote_support'))

    if password != confirm_password:
        register_remote_auth_failure()
        flash('Password confirmation does not match.', 'danger')
        return redirect(url_for('main.remote_support'))

    password_valid = (
        len(password) >= 10
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )
    if not password_valid:
        register_remote_auth_failure()
        flash('Password must be at least 10 characters and include uppercase, lowercase, a digit, and a special character.', 'danger')
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
    password_ok = False
    if client:
        password_ok = client.check_password(password)
    else:
        # Keep response timing closer for unknown accounts.
        check_password_hash(AUTH_DUMMY_HASH, password or '')

    if not client or not password_ok:
        attempts = register_remote_auth_failure()
        remaining = max(0, REMOTE_AUTH_LIMIT - attempts)
        if remaining == 0:
            flash('Too many failed attempts. Please wait 5 minutes and try again.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')
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


@main_bp.route('/ticket-status')
@main_bp.route('/ticket-search')
def ticket_search():
    ticket_number_input = clean_text(request.args.get('ticket_number', ''), 40)
    normalized_ticket_number = normalize_ticket_number(ticket_number_input)
    ticket = None
    ticket_stage = ''
    if normalized_ticket_number:
        ticket = SupportTicket.query.filter_by(ticket_number=normalized_ticket_number).first()
        if ticket:
            ticket_stage = support_ticket_stage_for_status(ticket.status)
    return render_template(
        'ticket_search.html',
        ticket_number_input=ticket_number_input,
        normalized_ticket_number=normalized_ticket_number,
        ticket=ticket,
        ticket_stage=ticket_stage,
        ticket_status_labels=SUPPORT_TICKET_STATUS_LABELS,
        ticket_stage_labels=SUPPORT_TICKET_STAGE_LABELS,
    )


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

    if service_slug and not Service.query.filter_by(slug=service_slug, workflow_status=WORKFLOW_PUBLISHED).first():
        service_slug = ''

    register_form_submission_attempt(TICKET_CREATE_SCOPE, TICKET_CREATE_WINDOW_SECONDS)

    ticket = SupportTicket(
        ticket_number=generate_ticket_number(),
        client_id=portal_client.id,
        subject=subject,
        service_slug=service_slug or None,
        priority=priority,
        status=SUPPORT_TICKET_STATUS_OPEN,
        details=details,
    )
    db.session.add(ticket)
    db.session.flush()
    create_support_ticket_event(
        ticket,
        SUPPORT_TICKET_EVENT_CREATED,
        'Ticket created from remote support portal.',
        actor_type='client',
        actor_name=portal_client.full_name or portal_client.email,
        actor_client_id=portal_client.id,
        status_to=ticket.status,
        stage_to=support_ticket_stage_for_status(ticket.status),
        metadata={
            'source': 'remote_support',
            'ticket_kind': 'support',
        },
    )
    db.session.commit()
    send_ticket_notification(ticket, ticket_kind='support')

    flash(f'Ticket {ticket.ticket_number} created successfully.', 'success')
    return redirect(url_for('main.remote_support'))


@main_bp.route('/request-quote', methods=['GET', 'POST'])
def request_quote():
    services = normalize_icon_attr(
        Service.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Service.service_type, Service.sort_order, Service.title).all(),
        'fa-solid fa-gear',
    )
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
        if not phone:
            required_missing.append('phone')
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
            status=SUPPORT_TICKET_STATUS_OPEN,
            details=build_quote_ticket_details(quote_payload),
        )
        db.session.add(ticket)
        db.session.flush()
        create_support_ticket_event(
            ticket,
            SUPPORT_TICKET_EVENT_CREATED,
            'Quote request converted to internal support ticket.',
            actor_type='quote_form',
            actor_name=full_name or email or 'Quote Intake',
            actor_client_id=quote_client.id,
            status_to=ticket.status,
            stage_to=support_ticket_stage_for_status(ticket.status),
            metadata={
                'source': 'request_quote',
                'ticket_kind': 'quote',
                'company': company or '',
            },
        )
        db.session.commit()
        send_ticket_notification(ticket, ticket_kind='quote')

        flash(f"Quote request received. Ticket {ticket.ticket_number} has been created for our CMS team.", 'success')
        return redirect(url_for('main.request_quote'))

    return render_template('request_quote.html', **template_context)


@main_bp.route('/request-quote/personal', methods=['GET', 'POST'])
def request_quote_personal():
    services = normalize_icon_attr(
        Service.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Service.service_type, Service.sort_order, Service.title).all(),
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
        if not phone:
            required_missing.append('phone')
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
            status=SUPPORT_TICKET_STATUS_OPEN,
            details=build_personal_quote_ticket_details(quote_payload),
        )
        db.session.add(ticket)
        db.session.flush()
        create_support_ticket_event(
            ticket,
            SUPPORT_TICKET_EVENT_CREATED,
            'Personal quote request converted to internal support ticket.',
            actor_type='quote_form',
            actor_name=full_name or email or 'Quote Intake',
            actor_client_id=quote_client.id,
            status_to=ticket.status,
            stage_to=support_ticket_stage_for_status(ticket.status),
            metadata={
                'source': 'request_quote_personal',
                'ticket_kind': 'quote',
            },
        )
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

        if not name or not email or not phone or not message:
            flash('Name, email, phone, and message are required.', 'danger')
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
        current_app.logger.info(f'Contact submission saved (id={submission.id})')
        result = send_contact_notification(submission)
        current_app.logger.info(f'Email notification result: {result}')
        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('main.contact'))
    cb = get_page_content('contact')
    return render_template('contact.html', cb=cb)


@main_bp.route('/sitemap.xml')
def sitemap_xml():
    entries = [
        build_sitemap_entry(url_for('main.index'), changefreq='weekly', priority='1.0'),
        build_sitemap_entry(url_for('main.about'), changefreq='monthly', priority='0.6'),
        build_sitemap_entry(url_for('main.services'), changefreq='weekly', priority='0.9'),
        build_sitemap_entry(url_for('main.industries'), changefreq='weekly', priority='0.8'),
        build_sitemap_entry(url_for('main.blog'), changefreq='weekly', priority='0.8'),
        build_sitemap_entry(url_for('main.request_quote'), changefreq='weekly', priority='0.7'),
        build_sitemap_entry(url_for('main.request_quote_personal'), changefreq='weekly', priority='0.6'),
        build_sitemap_entry(url_for('main.contact'), changefreq='weekly', priority='0.7'),
    ]

    try:
        services = Service.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Service.sort_order.asc(), Service.id.asc()).all()
        for service in services:
            entries.append(
                build_sitemap_entry(
                    url_for('main.service_detail', slug=service.slug),
                    lastmod=service.published_at or service.updated_at or service.created_at,
                    changefreq='monthly',
                    priority='0.8',
                )
            )

        industries = Industry.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Industry.sort_order.asc(), Industry.id.asc()).all()
        for industry in industries:
            entries.append(
                build_sitemap_entry(
                    url_for('main.industry_detail', slug=industry.slug),
                    lastmod=industry.published_at or industry.updated_at or industry.created_at,
                    changefreq='monthly',
                    priority='0.7',
                )
            )

        posts = Post.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).order_by(Post.updated_at.desc(), Post.id.desc()).all()
        for post_item in posts:
            entries.append(
                build_sitemap_entry(
                    url_for('main.post', slug=post_item.slug),
                    lastmod=post_item.updated_at or post_item.created_at,
                    changefreq='monthly',
                    priority='0.7',
                )
            )
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed to build full sitemap dynamic entries; serving core entries only.')

    xml_body = '\n'.join([
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
        *entries,
        '</urlset>',
    ])
    response = current_app.response_class(xml_body, mimetype='application/xml')
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


@main_bp.route('/robots.txt')
def robots_txt():
    sitemap_url = absolute_public_url(url_for('main.sitemap_xml'))
    body = '\n'.join([
        'User-agent: *',
        'Allow: /',
        'Disallow: /admin/',
        'Disallow: /remote-support',
        'Disallow: /remote-support/',
        'Disallow: /remote-support/register',
        'Disallow: /remote-support/tickets',
        'Disallow: /remote-support/logout',
        '',
        f'Sitemap: {sitemap_url}',
        '',
    ])
    response = current_app.response_class(body, mimetype='text/plain')
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


@main_bp.route('/api/delivery/pages/<slug>')
def acp_delivery_page(slug):
    item = AcpPageDocument.query.filter_by(slug=slug, status=WORKFLOW_PUBLISHED).first()
    if not item:
        abort(404)

    payload = {
        'id': item.id,
        'slug': item.slug,
        'title': item.title,
        'template_id': item.template_id,
        'locale': item.locale,
        'status': item.status,
        'seo': _safe_json_loads(item.seo_json, {}),
        'blocks_tree': _safe_json_loads(item.blocks_tree, {}),
        'theme_override': _safe_json_loads(item.theme_override_json, {}),
        'published_at': item.published_at.isoformat() if item.published_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
    }
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'public, max-age=120, s-maxage=300'
    return response


@main_bp.route('/api/delivery/content/<content_type_key>/<entry_key>')
def acp_delivery_content_entry(content_type_key, entry_key):
    type_key = clean_text(content_type_key, 120)
    record_key = clean_text(entry_key, 140)
    locale = clean_text(request.args.get('locale', 'en-US'), 20) or 'en-US'
    if not type_key or not record_key:
        abort(404)

    content_type = AcpContentType.query.filter_by(key=type_key, is_enabled=True).first()
    if not content_type:
        abort(404)

    item = AcpContentEntry.query.filter_by(
        content_type_id=content_type.id,
        entry_key=record_key,
        locale=locale,
        status=WORKFLOW_PUBLISHED,
    ).first()
    if not item and locale != 'en-US':
        item = AcpContentEntry.query.filter_by(
            content_type_id=content_type.id,
            entry_key=record_key,
            locale='en-US',
            status=WORKFLOW_PUBLISHED,
        ).first()
    if not item:
        abort(404)

    payload = {
        'id': item.id,
        'content_type': {
            'id': content_type.id,
            'key': content_type.key,
            'name': content_type.name,
        },
        'entry_key': item.entry_key,
        'title': item.title,
        'locale': item.locale,
        'status': item.status,
        'data': _safe_json_loads(item.data_json, {}),
        'published_at': item.published_at.isoformat() if item.published_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
    }
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'public, max-age=120, s-maxage=300'
    return response


@main_bp.route('/api/delivery/theme')
def acp_delivery_theme_default():
    return acp_delivery_theme('default')


@main_bp.route('/api/delivery/theme/<token_set_key>')
def acp_delivery_theme(token_set_key):
    key = clean_text(token_set_key, 80)
    if not key:
        abort(404)
    item = AcpThemeTokenSet.query.filter_by(
        key=key,
        status=WORKFLOW_PUBLISHED,
    ).first()
    if not item:
        abort(404)

    payload = {
        'id': item.id,
        'key': item.key,
        'name': item.name,
        'status': item.status,
        'tokens': _safe_json_loads(item.tokens_json, {}),
        'published_at': item.published_at.isoformat() if item.published_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
    }
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'public, max-age=120, s-maxage=300'
    return response


@main_bp.route('/api/delivery/dashboards/<dashboard_id>')
def acp_delivery_dashboard(dashboard_id):
    item = AcpDashboardDocument.query.filter_by(
        dashboard_id=dashboard_id,
        status=WORKFLOW_PUBLISHED,
    ).first()
    if not item:
        abort(404)

    payload = {
        'id': item.id,
        'dashboard_id': item.dashboard_id,
        'title': item.title,
        'route': item.route,
        'layout_type': item.layout_type,
        'status': item.status,
        'layout_config': _safe_json_loads(item.layout_config_json, {}),
        'widgets': _safe_json_loads(item.widgets_json, []),
        'global_filters': _safe_json_loads(item.global_filters_json, []),
        'role_visibility_rules': _safe_json_loads(item.role_visibility_json, {}),
        'published_at': item.published_at.isoformat() if item.published_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
    }
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'public, max-age=120, s-maxage=300'
    return response
