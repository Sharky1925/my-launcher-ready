"""Visual Site Appearance editor configuration.

Provides curated font catalog, CSS variable definitions, default theme tokens,
and conversion helpers for the /admin/appearance visual editor.
"""

import re

# ---------------------------------------------------------------------------
# Google Fonts catalog – curated popular fonts with available weights
# ---------------------------------------------------------------------------

GOOGLE_FONTS_CATALOG = {
    'Inter': [300, 400, 500, 600, 700, 800],
    'Manrope': [400, 500, 600, 700, 800],
    'Sora': [400, 500, 600, 700, 800],
    'Orbitron': [400, 500, 600, 700, 800, 900],
    'Poppins': [300, 400, 500, 600, 700, 800],
    'Roboto': [300, 400, 500, 700, 900],
    'Open Sans': [300, 400, 500, 600, 700, 800],
    'Lato': [300, 400, 700, 900],
    'Montserrat': [300, 400, 500, 600, 700, 800, 900],
    'Raleway': [300, 400, 500, 600, 700, 800],
    'Nunito': [300, 400, 500, 600, 700, 800],
    'Work Sans': [300, 400, 500, 600, 700, 800],
    'DM Sans': [400, 500, 600, 700],
    'Space Grotesk': [300, 400, 500, 600, 700],
    'Plus Jakarta Sans': [400, 500, 600, 700, 800],
    'Outfit': [300, 400, 500, 600, 700, 800],
    'Lexend': [300, 400, 500, 600, 700],
    'JetBrains Mono': [400, 500, 600, 700],
    'IBM Plex Sans': [300, 400, 500, 600, 700],
    'Figtree': [300, 400, 500, 600, 700, 800],
}

FONT_NAMES = sorted(GOOGLE_FONTS_CATALOG.keys())

# ---------------------------------------------------------------------------
# CSS variable definitions – ordered for the UI (label, group, default)
# ---------------------------------------------------------------------------

APPEARANCE_COLOR_VARS = [
    # Background & surface
    {'var': '--bg', 'label': 'Background', 'group': 'Background', 'default_dark': '#05080f', 'default_light': '#f8fafc'},
    {'var': '--surface', 'label': 'Surface', 'group': 'Background', 'default_dark': '#0e1623', 'default_light': '#ffffff'},
    {'var': '--surface-alt', 'label': 'Surface Alt', 'group': 'Background', 'default_dark': '#131d2d', 'default_light': '#f1f5f9'},
    # Text
    {'var': '--text', 'label': 'Text', 'group': 'Text', 'default_dark': '#eff7ff', 'default_light': '#0f172a'},
    {'var': '--text-muted', 'label': 'Text Muted', 'group': 'Text', 'default_dark': '#9db0c5', 'default_light': '#64748b'},
    # Border
    {'var': '--border', 'label': 'Border', 'group': 'Border', 'default_dark': 'rgba(104, 154, 255, 0.22)', 'default_light': 'rgba(15, 23, 42, 0.12)'},
    # Accent colors
    {'var': '--accent-cyan', 'label': 'Accent Primary', 'group': 'Accent', 'default_dark': '#4f7bff', 'default_light': '#3b6cf5'},
    {'var': '--accent-electric', 'label': 'Accent Electric', 'group': 'Accent', 'default_dark': '#74a0ff', 'default_light': '#5b8af5'},
    {'var': '--accent-sky', 'label': 'Accent Sky', 'group': 'Accent', 'default_dark': '#5f86ff', 'default_light': '#4a75e8'},
    # Landing accents
    {'var': '--landing-accent-a', 'label': 'Landing Accent A', 'group': 'Landing', 'default_dark': '#4f7bff', 'default_light': '#3b6cf5'},
    {'var': '--landing-accent-b', 'label': 'Landing Accent B', 'group': 'Landing', 'default_dark': '#2ecbff', 'default_light': '#0ea5e9'},
    {'var': '--landing-accent-c', 'label': 'Landing Accent C', 'group': 'Landing', 'default_dark': '#9ac4ff', 'default_light': '#7c9cf5'},
]

# ---------------------------------------------------------------------------
# Full default theme tokens
# ---------------------------------------------------------------------------

APPEARANCE_DEFAULTS = {
    'css_vars': {
        '--bg': '#05080f',
        '--surface': '#0e1623',
        '--surface-alt': '#131d2d',
        '--text': '#eff7ff',
        '--text-muted': '#9db0c5',
        '--border': 'rgba(104, 154, 255, 0.22)',
        '--accent-cyan': '#4f7bff',
        '--accent-electric': '#74a0ff',
        '--accent-sky': '#5f86ff',
        '--landing-accent-a': '#4f7bff',
        '--landing-accent-b': '#2ecbff',
        '--landing-accent-c': '#9ac4ff',
        '--radius-lg': '24px',
        '--radius-md': '18px',
        '--radius-sm': '14px',
        '--btn-radius': '999px',
        '--shadow': '0 16px 36px -20px rgba(0, 0, 0, 0.7)',
        '--shadow-lg': '0 34px 88px -34px rgba(0, 0, 0, 0.8)',
        '--shadow-soft': '0 10px 22px -14px rgba(0, 0, 0, 0.62)',
        '--shadow-strong': '0 42px 96px -38px rgba(0, 0, 0, 0.86)',
        '--gradient-main': 'linear-gradient(132deg, #10214d 0%, #305fdd 45%, #6a99ff 100%)',
        '--ease-smooth': 'cubic-bezier(0.4, 0, 0.2, 1)',
        '--transition-fast': '.2s cubic-bezier(.4,0,.2,1)',
        '--transition-base': '.3s cubic-bezier(.4,0,.2,1)',
        '--font-body': "'Manrope', -apple-system, BlinkMacSystemFont, sans-serif",
        '--font-heading': "'Sora', 'Manrope', -apple-system, sans-serif",
        '--font-slogan': "'Orbitron', 'Sora', 'Manrope', -apple-system, sans-serif",
    },
    'typography': {
        'base_font_size': '16px',
    },
    'motion': {
        'enabled': True,
        'speed': 'normal',
        'easing': 'standard',
    },
}

LIGHT_THEME_DEFAULTS = {
    'css_vars': {
        '--bg': '#f8fafc',
        '--surface': '#ffffff',
        '--surface-alt': '#f1f5f9',
        '--text': '#0f172a',
        '--text-muted': '#64748b',
        '--border': 'rgba(15, 23, 42, 0.12)',
        '--accent-cyan': '#3b6cf5',
        '--accent-electric': '#5b8af5',
        '--accent-sky': '#4a75e8',
        '--landing-accent-a': '#3b6cf5',
        '--landing-accent-b': '#0ea5e9',
        '--landing-accent-c': '#7c9cf5',
        '--radius-lg': '24px',
        '--radius-md': '18px',
        '--radius-sm': '14px',
        '--btn-radius': '999px',
        '--shadow': '0 16px 36px -20px rgba(0, 0, 0, 0.08)',
        '--shadow-lg': '0 34px 88px -34px rgba(0, 0, 0, 0.12)',
        '--shadow-soft': '0 10px 22px -14px rgba(0, 0, 0, 0.06)',
        '--shadow-strong': '0 42px 96px -38px rgba(0, 0, 0, 0.16)',
        '--gradient-main': 'linear-gradient(132deg, #dbeafe 0%, #3b82f6 45%, #60a5fa 100%)',
        '--ease-smooth': 'cubic-bezier(0.4, 0, 0.2, 1)',
        '--transition-fast': '.2s cubic-bezier(.4,0,.2,1)',
        '--transition-base': '.3s cubic-bezier(.4,0,.2,1)',
        '--font-body': "'Manrope', -apple-system, BlinkMacSystemFont, sans-serif",
        '--font-heading': "'Sora', 'Manrope', -apple-system, sans-serif",
        '--font-slogan': "'Orbitron', 'Sora', 'Manrope', -apple-system, sans-serif",
    },
    'typography': {
        'base_font_size': '16px',
    },
    'motion': {
        'enabled': True,
        'speed': 'normal',
        'easing': 'standard',
    },
}

# ---------------------------------------------------------------------------
# Shadow presets
# ---------------------------------------------------------------------------

SHADOW_PRESETS = {
    'none': {
        '--shadow': 'none',
        '--shadow-lg': 'none',
        '--shadow-soft': 'none',
        '--shadow-strong': 'none',
    },
    'subtle': {
        '--shadow': '0 8px 18px -10px rgba(0, 0, 0, 0.25)',
        '--shadow-lg': '0 16px 44px -18px rgba(0, 0, 0, 0.3)',
        '--shadow-soft': '0 5px 12px -8px rgba(0, 0, 0, 0.2)',
        '--shadow-strong': '0 20px 50px -20px rgba(0, 0, 0, 0.4)',
    },
    'normal': {
        '--shadow': '0 16px 36px -20px rgba(0, 0, 0, 0.7)',
        '--shadow-lg': '0 34px 88px -34px rgba(0, 0, 0, 0.8)',
        '--shadow-soft': '0 10px 22px -14px rgba(0, 0, 0, 0.62)',
        '--shadow-strong': '0 42px 96px -38px rgba(0, 0, 0, 0.86)',
    },
    'strong': {
        '--shadow': '0 20px 50px -16px rgba(0, 0, 0, 0.85)',
        '--shadow-lg': '0 44px 100px -30px rgba(0, 0, 0, 0.9)',
        '--shadow-soft': '0 14px 30px -10px rgba(0, 0, 0, 0.75)',
        '--shadow-strong': '0 52px 120px -32px rgba(0, 0, 0, 0.95)',
    },
}

SHADOW_PRESETS_LIGHT = {
    'none': {
        '--shadow': 'none',
        '--shadow-lg': 'none',
        '--shadow-soft': 'none',
        '--shadow-strong': 'none',
    },
    'subtle': {
        '--shadow': '0 8px 18px -10px rgba(0, 0, 0, 0.04)',
        '--shadow-lg': '0 16px 44px -18px rgba(0, 0, 0, 0.06)',
        '--shadow-soft': '0 5px 12px -8px rgba(0, 0, 0, 0.03)',
        '--shadow-strong': '0 20px 50px -20px rgba(0, 0, 0, 0.08)',
    },
    'normal': {
        '--shadow': '0 16px 36px -20px rgba(0, 0, 0, 0.08)',
        '--shadow-lg': '0 34px 88px -34px rgba(0, 0, 0, 0.12)',
        '--shadow-soft': '0 10px 22px -14px rgba(0, 0, 0, 0.06)',
        '--shadow-strong': '0 42px 96px -38px rgba(0, 0, 0, 0.16)',
    },
    'strong': {
        '--shadow': '0 20px 50px -16px rgba(0, 0, 0, 0.14)',
        '--shadow-lg': '0 44px 100px -30px rgba(0, 0, 0, 0.18)',
        '--shadow-soft': '0 14px 30px -10px rgba(0, 0, 0, 0.1)',
        '--shadow-strong': '0 52px 120px -32px rgba(0, 0, 0, 0.22)',
    },
}

# ---------------------------------------------------------------------------
# Animation presets
# ---------------------------------------------------------------------------

EASING_PRESETS = {
    'standard': 'cubic-bezier(0.4, 0, 0.2, 1)',
    'smooth': 'cubic-bezier(0.22, 1, 0.36, 1)',
    'bounce': 'cubic-bezier(0.34, 1.56, 0.64, 1)',
}

SPEED_PRESETS = {
    'fast': {'--transition-fast': '.12s', '--transition-base': '.2s'},
    'normal': {'--transition-fast': '.2s', '--transition-base': '.3s'},
    'slow': {'--transition-fast': '.35s', '--transition-base': '.5s'},
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_HEX_COLOR_RE = re.compile(r'^#[0-9a-fA-F]{3,8}$')
_RGBA_RE = re.compile(r'^rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(,\s*[\d.]+\s*)?\)$')
_CSS_SAFE_RE = re.compile(r'^[^{}<>;]{1,200}$')


def _is_valid_color(value):
    """Check if value looks like a valid CSS color (hex or rgba)."""
    v = (value or '').strip()
    if _HEX_COLOR_RE.match(v):
        return True
    if _RGBA_RE.match(v):
        return True
    return False


def _clamp_int(value, lo, hi, default):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _sanitize_font(name):
    """Return font name if it's in the catalog, else None."""
    name = (name or '').strip()
    if name in GOOGLE_FONTS_CATALOG:
        return name
    return None


# ---------------------------------------------------------------------------
# Google Fonts URL builder
# ---------------------------------------------------------------------------

def build_google_fonts_url(body_font='Manrope', heading_font='Sora', slogan_font='Orbitron'):
    """Construct a Google Fonts CSS URL from validated font selections."""
    families = set()
    for font_name in [body_font, heading_font, slogan_font]:
        font_name = (font_name or '').strip()
        if font_name and font_name in GOOGLE_FONTS_CATALOG:
            weights = GOOGLE_FONTS_CATALOG[font_name]
            weight_str = ';'.join(str(w) for w in sorted(weights))
            family = font_name.replace(' ', '+')
            families.add(f"family={family}:wght@{weight_str}")

    if not families:
        return ''

    params = '&'.join(sorted(families))
    return f"https://fonts.googleapis.com/css2?{params}&display=swap"


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def tokens_to_visual_config(tokens_dict):
    """Extract visual editor field values from a tokens_json dict.

    Returns a flat dict suitable for populating form controls.
    """
    css_vars = tokens_dict.get('css_vars', {}) if isinstance(tokens_dict, dict) else {}
    typography = tokens_dict.get('typography', {}) if isinstance(tokens_dict, dict) else {}
    motion = tokens_dict.get('motion', {}) if isinstance(tokens_dict, dict) else {}

    config = {}

    # Colors
    for cv in APPEARANCE_COLOR_VARS:
        var_name = cv['var']
        config[var_name] = css_vars.get(var_name, cv['default_dark'])

    # Radius values (extract numeric px value)
    for var_name, default in [('--radius-lg', 24), ('--radius-md', 18), ('--radius-sm', 14), ('--btn-radius', 999)]:
        raw = css_vars.get(var_name, f'{default}px')
        try:
            config[var_name] = int(str(raw).replace('px', '').strip())
        except (TypeError, ValueError):
            config[var_name] = default

    # Gradient
    config['--gradient-main'] = css_vars.get('--gradient-main', APPEARANCE_DEFAULTS['css_vars']['--gradient-main'])

    # Shadow preset detection
    current_shadow = css_vars.get('--shadow', '')
    config['shadow_preset'] = 'normal'
    for preset_name, preset_vals in SHADOW_PRESETS.items():
        if preset_vals.get('--shadow', '') == current_shadow:
            config['shadow_preset'] = preset_name
            break

    # Fonts (extract family name from CSS font stack)
    config['body_font'] = _extract_font_family(css_vars.get('--font-body', ''), 'Manrope')
    config['heading_font'] = _extract_font_family(css_vars.get('--font-heading', ''), 'Sora')
    config['slogan_font'] = _extract_font_family(css_vars.get('--font-slogan', ''), 'Orbitron')

    # Typography
    raw_size = typography.get('base_font_size', '16px')
    try:
        config['base_font_size'] = int(str(raw_size).replace('px', '').strip())
    except (TypeError, ValueError):
        config['base_font_size'] = 16

    # Motion
    config['motion_enabled'] = bool(motion.get('enabled', True))
    config['motion_speed'] = motion.get('speed', 'normal')
    if config['motion_speed'] not in SPEED_PRESETS:
        config['motion_speed'] = 'normal'
    config['motion_easing'] = motion.get('easing', 'standard')
    if config['motion_easing'] not in EASING_PRESETS:
        config['motion_easing'] = 'standard'

    return config


def _extract_font_family(css_value, default):
    """Extract the first font family name from a CSS font stack."""
    if not css_value:
        return default
    raw = str(css_value).strip()
    # Remove quotes, get first family
    first = raw.split(',')[0].strip().strip("'\"")
    if first in GOOGLE_FONTS_CATALOG:
        return first
    return default


def visual_config_to_tokens(form_data, theme_mode='dark'):
    """Convert form POST data into a validated tokens_json dict.

    Returns (tokens_dict, errors_list).
    """
    errors = []
    css_vars = {}

    # Colors
    for cv in APPEARANCE_COLOR_VARS:
        var_name = cv['var']
        value = (form_data.get(var_name) or '').strip()
        if not value:
            default_key = 'default_light' if theme_mode == 'light' else 'default_dark'
            value = cv[default_key]
        # Accept hex colors and rgba values
        if _HEX_COLOR_RE.match(value) or _RGBA_RE.match(value) or _CSS_SAFE_RE.match(value):
            css_vars[var_name] = value
        else:
            errors.append(f"Invalid color value for {cv['label']}")

    # Radius values
    css_vars['--radius-lg'] = f"{_clamp_int(form_data.get('--radius-lg'), 4, 48, 24)}px"
    css_vars['--radius-md'] = f"{_clamp_int(form_data.get('--radius-md'), 4, 30, 18)}px"
    css_vars['--radius-sm'] = f"{_clamp_int(form_data.get('--radius-sm'), 2, 20, 14)}px"
    css_vars['--btn-radius'] = f"{_clamp_int(form_data.get('--btn-radius'), 0, 999, 999)}px"

    # Gradient
    gradient = (form_data.get('--gradient-main') or '').strip()
    if gradient and _CSS_SAFE_RE.match(gradient):
        css_vars['--gradient-main'] = gradient
    else:
        defaults = LIGHT_THEME_DEFAULTS if theme_mode == 'light' else APPEARANCE_DEFAULTS
        css_vars['--gradient-main'] = defaults['css_vars']['--gradient-main']

    # Shadows
    shadow_preset = (form_data.get('shadow_preset') or 'normal').strip()
    if shadow_preset not in SHADOW_PRESETS:
        shadow_preset = 'normal'
    presets = SHADOW_PRESETS_LIGHT if theme_mode == 'light' else SHADOW_PRESETS
    css_vars.update(presets[shadow_preset])

    # Fonts
    body_font = _sanitize_font(form_data.get('body_font')) or 'Manrope'
    heading_font = _sanitize_font(form_data.get('heading_font')) or 'Sora'
    slogan_font = _sanitize_font(form_data.get('slogan_font')) or 'Orbitron'

    css_vars['--font-body'] = f"'{body_font}', -apple-system, BlinkMacSystemFont, sans-serif"
    css_vars['--font-heading'] = f"'{heading_font}', '{body_font}', -apple-system, sans-serif"
    css_vars['--font-slogan'] = f"'{slogan_font}', '{heading_font}', '{body_font}', -apple-system, sans-serif"

    # Easing
    easing_key = (form_data.get('motion_easing') or 'standard').strip()
    if easing_key not in EASING_PRESETS:
        easing_key = 'standard'
    css_vars['--ease-smooth'] = EASING_PRESETS[easing_key]

    # Speed
    speed_key = (form_data.get('motion_speed') or 'normal').strip()
    if speed_key not in SPEED_PRESETS:
        speed_key = 'normal'
    speed_vals = SPEED_PRESETS[speed_key]
    easing_func = EASING_PRESETS[easing_key]
    css_vars['--transition-fast'] = f"{speed_vals['--transition-fast']} {easing_func}"
    css_vars['--transition-base'] = f"{speed_vals['--transition-base']} {easing_func}"

    # Base font size
    base_font_size = _clamp_int(form_data.get('base_font_size'), 14, 18, 16)

    # Motion
    motion_enabled = form_data.get('motion_enabled') in ('1', 'true', 'on', True)

    tokens = {
        'css_vars': css_vars,
        'typography': {
            'base_font_size': f'{base_font_size}px',
        },
        'motion': {
            'enabled': motion_enabled,
            'speed': speed_key,
            'easing': easing_key,
        },
    }

    return tokens, errors
