"""Content schema registry for CMS-editable page sections.

Each key is a (page, section) tuple. The value defines the admin form fields.
Field types:
  - text: single-line text input
  - textarea: multi-line text area
  - lines: textarea split/joined by newlines (stored as JSON array)
  - json: raw JSON textarea with help text
"""

CONTENT_SCHEMAS = {
    ('home', 'hero'): {
        'label': 'Homepage — Hero Section',
        'fields': [
            {'key': 'badge', 'label': 'Hero Badge Text', 'type': 'text'},
            {'key': 'title', 'label': 'Main Heading (H1)', 'type': 'text'},
            {'key': 'lead', 'label': 'Lead Paragraph', 'type': 'textarea'},
        ]
    },
    ('home', 'signal_pills'): {
        'label': 'Homepage — Signal Pills',
        'fields': [
            {'key': 'items', 'label': 'Signal Pills (one per line)', 'type': 'lines'},
        ]
    },
    ('home', 'hero_cards'): {
        'label': 'Homepage — Hero Cards',
        'fields': [
            {'key': 'items', 'label': 'Hero Cards', 'type': 'json',
             'help': 'Array of {title, subtitle, icon, color, service_slug}'}
        ]
    },
    ('home', 'trust_signals'): {
        'label': 'Homepage — Trust Signals Ticker',
        'fields': [
            {'key': 'items', 'label': 'Trust Signals', 'type': 'json',
             'help': 'Array of {label, icon}'}
        ]
    },
    ('home', 'services_heading'): {
        'label': 'Homepage — Services Section',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
        ]
    },
    ('home', 'industries_heading'): {
        'label': 'Homepage — Industries Section',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
        ]
    },
    ('home', 'stats'): {
        'label': 'Homepage — Stats Section',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'items', 'label': 'Stat Cards', 'type': 'json',
             'help': 'Array of {value, title, note}'}
        ]
    },
    ('home', 'how_it_works'): {
        'label': 'Homepage — How It Works',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
            {'key': 'items', 'label': 'Steps', 'type': 'json',
             'help': 'Array of {title, description}'}
        ]
    },
    ('home', 'service_area'): {
        'label': 'Homepage — Service Area',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
            {'key': 'cities', 'label': 'Cities (one per line)', 'type': 'lines'},
        ]
    },
    ('home', 'cta'): {
        'label': 'Homepage — Final CTA',
        'fields': [
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
            {'key': 'button_text', 'label': 'Button Text', 'type': 'text'},
        ]
    },
    ('home', 'testimonials_heading'): {
        'label': 'Homepage — Testimonials Section',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
        ]
    },
    ('about', 'header'): {
        'label': 'About — Page Header',
        'fields': [
            {'key': 'title', 'label': 'Page Title (H1)', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'text'},
        ]
    },
    ('about', 'story'): {
        'label': 'About — Our Story',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'text', 'label': 'Story Text', 'type': 'textarea'},
        ]
    },
    ('about', 'metrics'): {
        'label': 'About — Metrics',
        'fields': [
            {'key': 'items', 'label': 'Metric Cards', 'type': 'json',
             'help': 'Array of {value, label}'}
        ]
    },
    ('about', 'milestones'): {
        'label': 'About — Timeline Milestones',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'text'},
            {'key': 'items', 'label': 'Milestones', 'type': 'json',
             'help': 'Array of {year, title, description, icon}'}
        ]
    },
    ('about', 'values'): {
        'label': 'About — Company Values',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'items', 'label': 'Values', 'type': 'json',
             'help': 'Array of {title, description, icon, color}'}
        ]
    },
    ('about', 'cta'): {
        'label': 'About — CTA Section',
        'fields': [
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
        ]
    },
    ('services', 'header'): {
        'label': 'Services — Page Header',
        'fields': [
            {'key': 'title', 'label': 'Page Title', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'text'},
        ]
    },
    ('services', 'professional_heading'): {
        'label': 'Services — Professional IT Section',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
        ]
    },
    ('services', 'repair_heading'): {
        'label': 'Services — Repair Section',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
        ]
    },
    ('services', 'cta'): {
        'label': 'Services — CTA Section',
        'fields': [
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
        ]
    },
    ('industries', 'header'): {
        'label': 'Industries — Page Header',
        'fields': [
            {'key': 'title', 'label': 'Page Title', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'text'},
        ]
    },
    ('industries', 'grid_heading'): {
        'label': 'Industries — Grid Section',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
        ]
    },
    ('industries', 'expertise'): {
        'label': 'Industries — Why Industry Expertise Matters',
        'fields': [
            {'key': 'label', 'label': 'Section Label', 'type': 'text'},
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'text', 'label': 'Paragraph', 'type': 'textarea'},
            {'key': 'items', 'label': 'Feature Cards', 'type': 'json',
             'help': 'Array of {title, description, icon}'}
        ]
    },
    ('industries', 'cta'): {
        'label': 'Industries — CTA Section',
        'fields': [
            {'key': 'title', 'label': 'Heading', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'textarea'},
        ]
    },
    ('contact', 'header'): {
        'label': 'Contact — Page Header',
        'fields': [
            {'key': 'title', 'label': 'Page Title', 'type': 'text'},
            {'key': 'subtitle', 'label': 'Subtitle', 'type': 'text'},
        ]
    },
    ('contact', 'support_hours'): {
        'label': 'Contact — Support Hours',
        'fields': [
            {'key': 'text', 'label': 'Support Hours Text', 'type': 'text'},
        ]
    },
    ('footer', 'service_area'): {
        'label': 'Footer — Service Area Cities',
        'fields': [
            {'key': 'description', 'label': 'Service Area Description', 'type': 'text'},
            {'key': 'cities', 'label': 'Cities (one per line)', 'type': 'lines'},
        ]
    },
    ('global', 'topbar'): {
        'label': 'Global — Topbar Ticker Items',
        'fields': [
            {'key': 'items', 'label': 'Topbar Ticker Items', 'type': 'json',
             'help': 'Array of {text, icon} for rotating topbar messages.'},
        ]
    },
    ('global', 'cta_buttons'): {
        'label': 'Global — CTA Button Labels',
        'fields': [
            {'key': 'call_now', 'label': 'Call Now Button Text', 'type': 'text'},
            {'key': 'request_quote', 'label': 'Request Quote Button Text', 'type': 'text'},
            {'key': 'remote_support', 'label': 'Remote Support Button Text', 'type': 'text'},
            {'key': 'get_in_touch', 'label': 'Get in Touch Button Text', 'type': 'text'},
        ]
    },
    ('global', 'nav_labels'): {
        'label': 'Global — Navigation Labels',
        'fields': [
            {'key': 'it_services', 'label': 'IT Services Label', 'type': 'text'},
            {'key': 'repair_services', 'label': 'Technical Repair Services Label', 'type': 'text'},
            {'key': 'industries', 'label': 'Industries Label', 'type': 'text'},
            {'key': 'about', 'label': 'About Label', 'type': 'text'},
            {'key': 'home', 'label': 'Home Label', 'type': 'text'},
        ]
    },
    ('global', 'structured_data'): {
        'label': 'Global — Structured Data Overrides',
        'fields': [
            {'key': 'latitude', 'label': 'Latitude', 'type': 'text'},
            {'key': 'longitude', 'label': 'Longitude', 'type': 'text'},
            {'key': 'area_served', 'label': 'Area Served', 'type': 'text'},
            {'key': 'price_range', 'label': 'Price Range', 'type': 'text'},
            {'key': 'opening_hours', 'label': 'Opening Hours', 'type': 'json',
             'help': 'Array of {days: [...], opens, closes}'},
        ]
    },
    ('global', 'error_pages'): {
        'label': 'Global — Error Page Content',
        'fields': [
            {'key': '404_title', 'label': '404 Page Title', 'type': 'text'},
            {'key': '404_message', 'label': '404 Page Message', 'type': 'textarea'},
            {'key': '404_cta', 'label': '404 CTA Text', 'type': 'text'},
            {'key': '500_title', 'label': '500 Page Title', 'type': 'text'},
            {'key': '500_message', 'label': '500 Page Message', 'type': 'textarea'},
        ]
    },
}
