import json
import os
import secrets
from slugify import slugify

try:
    from .models import db, User, Service, TeamMember, Testimonial, Category, Post, SiteSetting, Industry, ContentBlock
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from models import db, User, Service, TeamMember, Testimonial, Category, Post, SiteSetting, Industry, ContentBlock


def seed_database():
    env_password = os.environ.get('ADMIN_PASSWORD') or ''

    # Always sync admin password with env var on startup
    if env_password:
        try:
            existing_admin = User.query.filter_by(username='admin').first()
            if existing_admin:
                existing_admin.set_password(env_password)
                db.session.commit()
        except Exception:
            db.session.rollback()

    if User.query.first():
        return

    # Admin user
    if not env_password:
        env_password = secrets.token_urlsafe(16)
        print(
            '[seed] ADMIN_PASSWORD not set. Seeded admin with a random password. '
            'Set ADMIN_PASSWORD and restart to rotate it to a known value.'
        )
    admin = User(username='admin', email='admin@example.com')
    admin.set_password(env_password)
    db.session.add(admin)

    # Site settings
    defaults = {
        'company_name': 'Right On Repair',
        'tagline': 'Orange County managed IT, cybersecurity, cloud, software, web, and technical repair services',
        'phone': '+1 (562) 542-5899',
        'email': 'info@rightonrepair.com',
        'address': '9092 Talbert Ave. Ste 4, Fountain Valley, CA 92708',
        'facebook': 'https://facebook.com',
        'twitter': 'https://twitter.com',
        'linkedin': 'https://linkedin.com',
        'meta_title': 'Right On Repair — Orange County IT Services & Computer Repair',
        'meta_description': 'Orange County IT services and technical repair: managed IT, cybersecurity, cloud migration, software and web development, surveillance setup, and same-day device repair support for local businesses.',
        'footer_text': '© 2026 Right On Repair. All rights reserved.',
    }
    for key, value in defaults.items():
        db.session.add(SiteSetting(key=key, value=value))

    # Professional IT Services (Right On catalog)
    professional_services = [
        ('Software Development', 'Custom software systems, workflow automation, and integrations designed around real operations. We build practical internal tools, portals, and APIs that reduce manual work, improve visibility, and scale with your business.', 'fa-solid fa-code', True),
        ('Web Development', 'High-performance websites and landing systems engineered for search visibility and conversion performance. We combine technical SEO, clear messaging, and responsive UX to turn traffic into qualified leads.', 'fa-solid fa-globe', True),
        ('Managed IT Services', 'Structured managed IT coverage for modern teams: monitoring, patching, helpdesk, lifecycle planning, onboarding, vendor escalation, and reporting. We keep systems stable, secure, and interruption-resistant.', 'fa-solid fa-server', True),
        ('Cybersecurity', 'Business-aligned cybersecurity with layered controls across endpoints, identity, email, and response planning. We reduce risk exposure while keeping teams productive and operations resilient.', 'fa-solid fa-shield-halved', True),
        ('Cloud Solutions', 'Cloud architecture, migration, and optimization for secure collaboration, performance, and long-term scale. We modernize your stack with measurable improvements in reliability, security, and cost control.', 'fa-solid fa-cloud', True),
        ('Surveillance Camera Installation', 'Commercial CCTV design and installation for offices, retail, warehouse, and multi-site operations. We deliver secure remote visibility, retention planning, and dependable incident-ready coverage.', 'fa-solid fa-video', True),
        ('Enterprise Consultancy', 'Strategic IT advisory for growing businesses: technology roadmaps, vendor evaluation, infrastructure audits, digital transformation planning, and executive-level guidance to align IT investments with business outcomes.', 'fa-solid fa-handshake', True),
    ]
    for i, (title, desc, icon, featured) in enumerate(professional_services):
        db.session.add(Service(
            title=title, slug=slugify(title), description=desc,
            icon_class=icon, is_featured=featured, sort_order=i,
            service_type='professional'
        ))

    # Technical Repair Services (Right On catalog)
    repair_services = [
        ('Data Recovery', 'Business-grade data recovery with secure handling, rapid triage, and transparent recoverability reporting. We recover critical files from failed, corrupted, or compromised storage while protecting chain-of-custody and confidentiality.', 'fa-solid fa-database', True),
        ('Computer Repair', 'Business-focused desktop and laptop repair including hardware remediation, software cleanup, and performance restoration. We diagnose root causes, validate stability, and return devices ready for reliable daily use.', 'fa-solid fa-laptop-medical', True),
        ('Mobile Phone Repair', 'Mobile repair for business-critical phones and tablets: screen, battery, charging port, camera, and component-level fixes. Fast, data-aware workflows keep teams connected with minimal downtime.', 'fa-solid fa-mobile-screen-button', True),
        ('Game Console Repair', 'Technical console repair for PlayStation, Xbox, and Nintendo systems, including HDMI ports, overheating issues, storage failures, and power diagnostics with post-repair stress testing.', 'fa-solid fa-gamepad', True),
        ('Device Diagnostics', 'Comprehensive diagnostics that identify hidden failures, bottlenecks, and lifecycle risks before outages occur. We deliver actionable findings for repair, upgrade, or replacement planning.', 'fa-solid fa-stethoscope', True),
    ]
    for i, (title, desc, icon, featured) in enumerate(repair_services):
        db.session.add(Service(
            title=title, slug=slugify(title), description=desc,
            icon_class=icon, is_featured=featured, sort_order=i,
            service_type='repair'
        ))

    # Team members
    team_data = [
        ('Sarah Chen', 'CEO & Founder', 'With 15+ years in technology leadership, Sarah founded Right On Repair to deliver enterprise-grade IT and dependable local support to Orange County businesses.'),
        ('Marcus Johnson', 'CTO', 'Marcus leads our engineering teams with expertise in cloud architecture, DevOps, and scalable system design.'),
        ('Emily Rodriguez', 'Head of Cybersecurity', 'Emily brings a decade of experience in cybersecurity, previously serving as a security consultant for Fortune 500 companies.'),
        ('David Park', 'Lead Developer', 'David specializes in full-stack development with a passion for clean code and modern frameworks.'),
    ]
    for i, (name, pos, bio) in enumerate(team_data):
        db.session.add(TeamMember(name=name, position=pos, bio=bio, sort_order=i))

    # Testimonials
    testimonials_data = [
        ('John Mitchell', 'Acme Corp', 'Right On Repair transformed our entire IT infrastructure. Their cloud migration was seamless and our operational costs dropped by 40%.', 5, True),
        ('Lisa Wang', 'StartupXYZ', 'The development team delivered our platform ahead of schedule. Their attention to detail and communication throughout the project was outstanding.', 5, True),
        ('Robert Garcia', 'HealthFirst Inc', 'Their cybersecurity audit uncovered vulnerabilities we never knew existed. We now feel confident about our data protection.', 5, True),
        ('Amanda Torres', 'Metro Logistics', 'When our server crashed, Right On Repair recovered all our data within 24 hours. Their repair team is incredibly skilled and responsive.', 5, True),
    ]
    for name, company, content, rating, featured in testimonials_data:
        db.session.add(Testimonial(
            client_name=name, company=company, content=content,
            rating=rating, is_featured=featured
        ))

    # Categories
    categories = ['Technology', 'Cybersecurity', 'Cloud Computing', 'Business', 'Repair & Maintenance']
    cat_objects = {}
    for name in categories:
        cat = Category(name=name, slug=slugify(name))
        db.session.add(cat)
        cat_objects[name] = cat
    db.session.flush()

    # Blog posts
    posts_data = [
        ('The Future of Cloud Computing in 2025', 'Cloud Computing',
         'Explore the emerging trends shaping cloud computing and how businesses can prepare for the next wave of innovation.',
         '<p>Cloud computing continues to evolve rapidly. In this article, we explore the key trends that will define the cloud landscape.</p><h3>Multi-Cloud Strategies</h3><p>Organizations are increasingly adopting multi-cloud approaches to avoid vendor lock-in and optimize costs. By distributing workloads across multiple providers, businesses gain flexibility and resilience.</p><h3>Edge Computing Integration</h3><p>The convergence of edge computing and cloud services is enabling faster processing and reduced latency for IoT applications and real-time analytics.</p><h3>AI-Powered Cloud Services</h3><p>Cloud providers are embedding AI and machine learning capabilities directly into their platforms, making advanced analytics accessible to organizations of all sizes.</p><p>As these trends mature, businesses that embrace cloud innovation will gain a significant competitive advantage.</p>'),
        ('Essential Cybersecurity Practices for Small Businesses', 'Cybersecurity',
         'Learn the fundamental security measures every small business should implement to protect their data and prevent costly breaches.',
         '<p>Small businesses are increasingly targeted by cybercriminals. Here are essential practices to strengthen your security posture.</p><h3>Employee Training</h3><p>Human error remains the leading cause of security breaches. Regular security awareness training helps employees recognize phishing attempts and social engineering attacks.</p><h3>Multi-Factor Authentication</h3><p>Implementing MFA across all business applications adds a critical layer of security beyond passwords alone.</p><h3>Regular Backups</h3><p>Maintain encrypted backups of critical data following the 3-2-1 rule: three copies, two different media types, one off-site location.</p><h3>Incident Response Plan</h3><p>Having a documented incident response plan ensures your team knows exactly how to react when a security event occurs.</p>'),
        ('How Digital Transformation Drives Business Growth', 'Business',
         'Discover how companies leverage technology to accelerate growth, streamline operations, and improve customer experiences.',
         '<p>Digital transformation is no longer optional—it is a strategic imperative for business survival and growth.</p><h3>Customer Experience</h3><p>Modern consumers expect seamless digital experiences. Companies that invest in digital touchpoints see higher customer satisfaction and retention rates.</p><h3>Operational Efficiency</h3><p>Automation and digital workflows eliminate manual processes, reduce errors, and free up employees to focus on high-value tasks.</p><h3>Data-Driven Decisions</h3><p>Organizations leveraging analytics platforms can make faster, more informed decisions based on real-time data rather than intuition.</p>'),
        ('Signs Your Computer Needs Professional Repair', 'Repair & Maintenance',
         'Learn to recognize the warning signs that indicate your computer needs expert attention before a minor issue becomes a major failure.',
         '<p>Computers often show warning signs before a critical failure. Recognizing these signs early can save you from data loss and costly downtime.</p><h3>Unusual Noises</h3><p>Clicking, grinding, or whirring sounds from your hard drive or fans are clear indicators of hardware wear. A clicking hard drive, in particular, requires immediate backup and professional attention.</p><h3>Frequent Crashes and Blue Screens</h3><p>Occasional crashes happen, but frequent blue screens or system freezes suggest failing RAM, overheating components, or disk corruption that needs diagnosis.</p><h3>Slow Performance</h3><p>If your computer has become significantly slower despite restarting and clearing temporary files, the issue could be a failing drive, insufficient memory, or malware infection.</p><h3>Overheating</h3><p>A laptop or desktop that runs hot to the touch likely has clogged fans, dried thermal paste, or failing cooling components. Prolonged overheating damages internal components permanently.</p>'),
    ]
    for title, cat_name, excerpt, content in posts_data:
        db.session.add(Post(
            title=title, slug=slugify(title), excerpt=excerpt,
            content=content, category_id=cat_objects[cat_name].id,
            is_published=True
        ))

    # Industries
    industries_data = [
        {
            'title': 'Healthcare Clinics',
            'icon_class': 'fa-solid fa-heart-pulse',
            'description': 'Secure, compliant IT support for medical practices, dental offices, and outpatient clinics that depend on uptime.',
            'hero_description': 'Healthcare teams need secure systems, stable performance, and rapid support during every patient interaction.',
            'challenges': 'Downtime during intake and charting|Shared workstations with weak controls|Aging clinical endpoints|EHR vendor complexity|HIPAA security pressure',
            'solutions': 'Role-based access and MFA|Endpoint hardening and patching|EHR workflow support|Backup and recovery planning|Documented escalation playbooks',
            'stats': 'Clinics Supported:120+|Target Uptime:99.9%|Critical Response:< 15min|Security Baselines:100%',
        },
        {
            'title': 'Law Firms',
            'icon_class': 'fa-solid fa-scale-balanced',
            'description': 'Confidential, resilient IT operations for legal teams handling sensitive case files and strict deadlines.',
            'hero_description': 'From document systems to secure remote access, we keep legal operations moving without compromising confidentiality.',
            'challenges': 'Case document bottlenecks|Risky file sharing practices|Unmanaged remote access|Weak backup visibility|Phishing exposure',
            'solutions': 'Access-controlled document workflows|Endpoint and identity hardening|Secure remote collaboration|Backup validation and continuity|Priority deadline support',
            'stats': 'Firms Supported:70+|Confidentiality Controls:Standardized|Urgent Escalations:Same-Day|Continuity Plans:Active',
        },
        {
            'title': 'Construction & Field Services',
            'icon_class': 'fa-solid fa-hard-hat',
            'description': 'Reliable IT for office teams and field crews that need mobile access, device uptime, and secure jobsite communication.',
            'hero_description': 'We support distributed field operations with secure mobile devices, resilient cloud access, and fast troubleshooting.',
            'challenges': 'Field device failures|Unstable office-jobsite connectivity|Inconsistent mobile security|Shared credentials|Slow incident response',
            'solutions': 'Mobile device standardization|Cloud collaboration hardening|Secure onboarding and offboarding|Priority field support|Diagnostics and lifecycle planning',
            'stats': 'Field Teams Supported:150+|Device Fleet Coverage:Multi-Site|Priority Response:Rapid|Operations Visibility:Improved',
        },
        {
            'title': 'Manufacturing',
            'icon_class': 'fa-solid fa-industry',
            'description': 'Operationally focused IT for manufacturers that require stable networks, endpoint security, and minimal production disruption.',
            'hero_description': 'We align IT priorities to production continuity, stronger security posture, and predictable maintenance outcomes.',
            'challenges': 'Production-impacting outages|Aging infrastructure|Mixed legacy and modern systems|Patch risk on live operations|Weak recovery testing',
            'solutions': 'Proactive monitoring with safe maintenance windows|Endpoint and identity hardening|Backup and recovery validation|Vendor coordination for ERP and tooling|Monthly health reporting',
            'stats': 'Plants Supported:40+|Downtime Reduction:Up to 60%|Security Posture:Improved|Recovery Confidence:Verified',
        },
        {
            'title': 'Retail & eCommerce',
            'icon_class': 'fa-solid fa-cart-shopping',
            'description': 'Customer-facing IT support for retail businesses that need reliable POS, secure payments, and always-on connectivity.',
            'hero_description': 'We help storefront and online teams reduce disruptions while protecting customer and business data.',
            'challenges': 'POS outages during peak periods|Store connectivity inconsistencies|Payment endpoint risk|Checkout device failures|Multi-location visibility gaps',
            'solutions': 'POS and network stabilization|Endpoint security controls|Store operations cloud workflows|Vendor escalation management|Backup and incident planning',
            'stats': 'Retail Clients:95+|Peak Uptime:99.9%|Incident Recovery:Faster|Location Standardization:Improved',
        },
        {
            'title': 'Professional Services',
            'icon_class': 'fa-solid fa-briefcase',
            'description': 'Scalable IT for accounting firms, agencies, consultants, and business service teams focused on productivity and security.',
            'hero_description': 'We standardize technology operations so professional teams can deliver faster while protecting client data.',
            'challenges': 'Tool sprawl and workflow friction|Manual onboarding and permissions|Weak client-data safeguards|Slow systems reducing billable output|Reactive support cycles',
            'solutions': 'Cloud collaboration standardization|Automated user lifecycle controls|Endpoint and account hardening|Proactive device support|Workflow automation opportunities',
            'stats': 'Teams Supported:120+|Onboarding Time:Reduced|Support Predictability:Improved|Security Controls:Stronger',
        },
        {
            'title': 'Nonprofits',
            'icon_class': 'fa-solid fa-hand-holding-heart',
            'description': 'Mission-focused IT support that improves reliability, controls cost, and protects donor and operational data.',
            'hero_description': 'We provide practical managed IT and security support for nonprofit teams operating with lean resources.',
            'challenges': 'Limited internal IT capacity|Aging mixed devices|Donor-data security risk|Volunteer access complexity|Backup uncertainty',
            'solutions': 'Right-sized managed coverage|Secure cloud identity and collaboration|Device standardization|Recovery readiness testing|Strategic IT planning',
            'stats': 'Organizations Supported:80+|Operational Reliability:Higher|Budget Predictability:Improved|Security Readiness:Stronger',
        },
        {
            'title': 'Real Estate & Property Management',
            'icon_class': 'fa-solid fa-building',
            'description': 'Responsive IT support for brokerages and property teams that rely on mobile operations, secure files, and fast communication.',
            'hero_description': 'From mobile agents to office teams, we keep your technology secure, fast, and available.',
            'challenges': 'Mobile device issues for agents|Fragmented file sharing|Transaction-time support delays|Weak account security|Onboarding/offboarding gaps',
            'solutions': 'Secure cloud document workflows|Mobile and office device management|Identity protection and phishing controls|Repeatable user lifecycle management|Priority troubleshooting support',
            'stats': 'Properties Supported:10K+|Transaction Stability:Improved|Agent Device Readiness:Higher|Support Response:Faster',
        },
    ]
    for i, ind in enumerate(industries_data):
        db.session.add(Industry(
            title=ind['title'], slug=slugify(ind['title']),
            description=ind['description'], icon_class=ind['icon_class'],
            hero_description=ind['hero_description'],
            challenges=ind['challenges'], solutions=ind['solutions'],
            stats=ind['stats'], sort_order=i
        ))

    # Content blocks — default page content
    content_blocks = {
        ('home', 'hero'): {
            'badge': 'Managed IT + Technical Repair for Orange County',
            'title': 'Managed IT Services & Technical Repair Services in Orange County',
            'lead': 'One local team for proactive managed IT, cybersecurity, cloud, software, and fast device repair. Your all-in-one tech and repair shop for reliable business uptime.',
        },
        ('home', 'signal_pills'): {
            'items': ['OC RESPONSE < 2H', '24/7 MONITORING', 'SECURITY-FIRST'],
        },
        ('home', 'hero_cards'): {
            'items': [
                {'title': 'Cloud', 'subtitle': 'AWS, Azure, and GCP', 'icon': 'fa-solid fa-cloud', 'color': 'blue', 'service_slug': 'cloud-solutions'},
                {'title': 'Cybersecurity', 'subtitle': 'Threat Defense', 'icon': 'fa-solid fa-lock', 'color': 'purple', 'service_slug': 'cybersecurity'},
                {'title': 'Software & Web Development', 'subtitle': 'Full-Stack Solutions', 'icon': 'fa-solid fa-code', 'color': 'green', 'service_slug': 'software-development'},
                {'title': 'Technical Repair', 'subtitle': 'Certified Technicians', 'icon': 'fa-solid fa-laptop-medical', 'color': 'amber', 'service_slug': ''},
                {'title': 'Managed IT Solutions', 'subtitle': 'Proactive Support', 'icon': 'fa-solid fa-network-wired', 'color': 'cyan', 'service_slug': 'managed-it-services'},
                {'title': 'Enterprise Consultancy', 'subtitle': 'Strategic Advisory', 'icon': 'fa-solid fa-handshake', 'color': 'rose', 'service_slug': 'enterprise-consultancy'},
            ],
        },
        ('home', 'trust_signals'): {
            'items': [
                {'label': 'Microsoft Partner', 'icon': 'fa-brands fa-microsoft'},
                {'label': 'Google Workspace', 'icon': 'fa-brands fa-google'},
                {'label': 'Microsoft 365', 'icon': 'fa-brands fa-microsoft'},
                {'label': 'AWS Cloud', 'icon': 'fa-brands fa-aws'},
                {'label': 'Microsoft Azure', 'icon': 'fa-solid fa-cloud'},
                {'label': 'Google Cloud', 'icon': 'fa-brands fa-google'},
                {'label': 'Hybrid Cloud', 'icon': 'fa-solid fa-cloud'},
                {'label': 'Disaster Recovery', 'icon': 'fa-solid fa-cloud'},
                {'label': 'SOC 2 Compliant', 'icon': 'fa-solid fa-shield-halved'},
                {'label': 'Identity & MFA', 'icon': 'fa-solid fa-shield-halved'},
                {'label': 'Microsoft Intune', 'icon': 'fa-solid fa-server'},
                {'label': 'Microsoft Entra ID', 'icon': 'fa-solid fa-shield-halved'},
                {'label': 'Patch Management', 'icon': 'fa-solid fa-server'},
                {'label': 'Datto RMM', 'icon': 'fa-solid fa-server'},
                {'label': 'Veeam Backup', 'icon': 'fa-solid fa-server'},
                {'label': 'Cloudflare Security', 'icon': 'fa-solid fa-shield-halved'},
                {'label': 'Fortinet Firewall', 'icon': 'fa-solid fa-shield-halved'},
                {'label': 'SentinelOne EDR', 'icon': 'fa-solid fa-shield-halved'},
                {'label': 'CrowdStrike Falcon', 'icon': 'fa-solid fa-shield-halved'},
                {'label': 'Cisco Meraki', 'icon': 'fa-solid fa-server'},
                {'label': 'Ubiquiti UniFi', 'icon': 'fa-solid fa-server'},
                {'label': 'VMware vSphere', 'icon': 'fa-solid fa-server'},
                {'label': 'Compliance Audits', 'icon': 'fa-solid fa-shield-halved'},
                {'label': '5-Star Rated', 'icon': 'fa-solid fa-star'},
                {'label': 'Certified Team', 'icon': 'fa-solid fa-circle-check'},
            ],
        },
        ('home', 'services_heading'): {
            'label': 'Services',
            'title': 'Everything Your Business Needs Under One Roof',
            'subtitle': 'From proactive IT management to hands-on device repairs, we handle every layer of your technology.',
        },
        ('home', 'industries_heading'): {
            'label': 'Industries',
            'title': 'Industry-Specific IT Support',
            'subtitle': 'We tailor security, support, and technology strategy to how your industry works.',
        },
        ('home', 'stats'): {
            'label': 'Results',
            'title': 'Measurable Impact for Local Businesses',
            'items': [
                {'value': '500+', 'title': 'Devices Managed', 'note': 'Across Orange County businesses'},
                {'value': '99.9%', 'title': 'Uptime Target', 'note': 'Proactive monitoring & patching'},
                {'value': '<2hr', 'title': 'Response Time', 'note': 'For critical support requests'},
                {'value': '100%', 'title': 'Local Focus', 'note': 'Orange County businesses only'},
            ],
        },
        ('home', 'how_it_works'): {
            'label': 'How It Works',
            'title': 'Get Started in Three Steps',
            'subtitle': 'From first call to full coverage, we make the process simple and transparent.',
            'items': [
                {'title': 'Free Assessment', 'description': 'We review your current systems, devices, and pain points in a 30-minute call.'},
                {'title': 'Custom Plan', 'description': 'You get a clear proposal with scope, pricing, and timeline \u2014 no guessing.'},
                {'title': 'Ongoing Support', 'description': 'We onboard your team, start monitoring, and provide proactive support.'},
            ],
        },
        ('home', 'testimonials_heading'): {
            'label': 'Testimonials',
            'title': 'Client Success Stories',
        },
        ('home', 'service_area'): {
            'label': 'Service Area',
            'title': 'IT Services Across Orange County',
            'subtitle': 'On-site and remote support for businesses throughout the region.',
            'cities': ['Anaheim', 'Irvine', 'Santa Ana', 'Huntington Beach', 'Costa Mesa', 'Fullerton', 'Orange', 'Mission Viejo', 'Newport Beach', 'Laguna Beach', 'Tustin', 'Lake Forest', 'Buena Park', 'Garden Grove', 'Westminster', 'Yorba Linda', 'San Clemente', 'Dana Point', 'Rancho Santa Margarita', 'Aliso Viejo'],
        },
        ('home', 'cta'): {
            'title': 'Ready To Fix Your IT?',
            'subtitle': 'Schedule a free consultation or call us directly. No obligations, no pressure \u2014 just a clear plan for better IT.',
            'button_text': 'Schedule a Meeting',
        },
        ('about', 'header'): {
            'title': 'About Us',
            'subtitle': 'Pioneering IT excellence since 2015.',
        },
        ('about', 'story'): {
            'label': 'Our Story',
            'title': 'Building the Future of IT',
            'text': 'Founded in 2015, Right On Repair began with a simple belief: every business deserves world-class technology. Today, we serve 500+ clients with a team of 50+ certified professionals.',
        },
        ('about', 'metrics'): {
            'items': [
                {'value': '500+', 'label': 'Local Clients'},
                {'value': '50+', 'label': 'IT Specialists'},
                {'value': '99.9%', 'label': 'Uptime SLA'},
                {'value': '24/7', 'label': 'Expert Support'},
            ],
        },
        ('about', 'milestones'): {
            'label': 'Milestones',
            'title': 'Our Journey',
            'subtitle': 'Key moments that shaped who we are today.',
            'items': [
                {'year': '2015', 'title': 'Founded', 'description': 'Started as a small IT consultancy with a vision to make enterprise technology accessible.', 'icon': 'fa-solid fa-rocket'},
                {'year': '2018', 'title': '100 Clients', 'description': 'Expanded to managed services and cybersecurity, reaching our first 100 clients.', 'icon': 'fa-solid fa-users'},
                {'year': '2021', 'title': 'Repair Division', 'description': 'Launched certified hardware repair and data recovery services.', 'icon': 'fa-solid fa-award'},
                {'year': '2024', 'title': '500+ Clients', 'description': 'Serving Orange County businesses with a team of 50+ certified professionals.', 'icon': 'fa-solid fa-globe'},
            ],
        },
        ('about', 'values'): {
            'label': 'Our Values',
            'title': 'What Drives Us',
            'items': [
                {'title': 'Innovation', 'description': 'Cutting-edge solutions for a competitive edge.', 'icon': 'fa-solid fa-lightbulb', 'color': 'blue'},
                {'title': 'Security', 'description': 'Protection embedded in every layer.', 'icon': 'fa-solid fa-shield-halved', 'color': 'purple'},
                {'title': 'Partnership', 'description': 'Long-term relationships aligned with your goals.', 'icon': 'fa-solid fa-handshake', 'color': 'green'},
                {'title': 'Excellence', 'description': 'Highest standards of quality and professionalism.', 'icon': 'fa-solid fa-medal', 'color': 'amber'},
            ],
        },
        ('about', 'cta'): {
            'title': 'Want to Join Our Team?',
            'subtitle': "We're looking for talented people who share our passion for technology.",
        },
        ('services', 'header'): {
            'title': 'Our Services',
            'subtitle': 'End-to-end technology solutions for modern businesses.',
        },
        ('services', 'professional_heading'): {
            'label': 'Professional IT',
            'title': 'Strategic Technology Solutions',
        },
        ('services', 'repair_heading'): {
            'label': 'Technical Repair',
            'title': 'Expert Repair & Recovery',
        },
        ('services', 'cta'): {
            'title': 'Need Remote Support or a Quote?',
            'subtitle': 'Choose remote assistance or request scoped pricing for your business.',
        },
        ('industries', 'header'): {
            'title': 'Industries We Serve',
            'subtitle': 'Tailored technology solutions for every sector.',
        },
        ('industries', 'grid_heading'): {
            'label': 'Sectors',
            'title': 'Technology Built for Your Industry',
            'subtitle': 'We understand the unique challenges of your sector and deliver solutions that drive results.',
        },
        ('industries', 'expertise'): {
            'label': 'Why It Matters',
            'title': 'Industry-Specific Expertise',
            'text': 'Generic IT fails. We build solutions shaped by deep industry knowledge \u2014 compliance, workflows, and growth patterns unique to your sector.',
            'items': [
                {'title': 'Compliance-First', 'description': 'HIPAA, PCI DSS, FERPA \u2014 built in, not bolted on.', 'icon': 'fa-solid fa-shield-halved'},
                {'title': 'Data-Driven', 'description': 'Analytics tailored to your industry KPIs.', 'icon': 'fa-solid fa-chart-line'},
                {'title': 'Scalable', 'description': 'Architecture that grows with your business.', 'icon': 'fa-solid fa-arrows-rotate'},
                {'title': '24/7 Support', 'description': 'Round-the-clock expert assistance.', 'icon': 'fa-solid fa-headset'},
            ],
        },
        ('industries', 'cta'): {
            'title': "Don't See Your Industry?",
            'subtitle': "We work across all sectors. Let's discuss your unique technology needs.",
        },
        ('contact', 'header'): {
            'title': 'Get in Touch',
            'subtitle': "We'd love to hear from you.",
        },
        ('contact', 'support_hours'): {
            'text': '24/7 \u2014 365 days',
        },
        ('footer', 'service_area'): {
            'description': 'On-site and remote support for businesses throughout Orange County.',
            'cities': ['Anaheim', 'Irvine', 'Santa Ana', 'Huntington Beach', 'Costa Mesa', 'Fullerton', 'Orange', 'Mission Viejo', 'Newport Beach', 'Laguna Beach', 'Tustin', 'Lake Forest'],
        },
    }
    for (page, section), data in content_blocks.items():
        db.session.add(ContentBlock(
            page=page, section=section,
            content=json.dumps(data, ensure_ascii=False),
        ))

    db.session.commit()
