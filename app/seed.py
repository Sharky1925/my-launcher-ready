import os
import secrets
from slugify import slugify

try:
    from .models import db, User, Service, TeamMember, Testimonial, Category, Post, SiteSetting, Industry
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from models import db, User, Service, TeamMember, Testimonial, Category, Post, SiteSetting, Industry


def seed_database():
    if User.query.first():
        return

    # Admin user
    admin_password = os.environ.get('ADMIN_PASSWORD')
    if not admin_password:
        admin_password = secrets.token_urlsafe(12)
        print(f"[seed] Generated initial admin password: {admin_password}")
    admin = User(username='admin', email='admin@example.com')
    admin.set_password(admin_password)
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

    db.session.commit()
