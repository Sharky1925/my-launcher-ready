"""Optional Flask-WTF forms for the lightweight CMS content module.

This module is import-safe even when Flask-WTF is not installed yet.
"""

HAS_FLASK_WTF = False
CmsPageForm = None
CmsArticleForm = None

try:
    from flask_wtf import FlaskForm
    from wtforms import BooleanField, StringField, TextAreaField
    from wtforms.validators import DataRequired, Length, Optional, Regexp
except ModuleNotFoundError:  # pragma: no cover - dependency may not be installed yet
    FlaskForm = None
else:
    HAS_FLASK_WTF = True

    class _BaseCmsForm(FlaskForm):
        class Meta:
            # The project already enforces CSRF globally in app.before_request.
            csrf = False

    _slug_validator = Regexp(
        r"^[a-z0-9-]*$",
        message="Slug can only contain lowercase letters, numbers, and hyphens.",
    )

    class CmsPageForm(_BaseCmsForm):
        title = StringField("Title", validators=[DataRequired(), Length(max=200)])
        slug = StringField("Slug", validators=[Optional(), Length(max=200), _slug_validator])
        content = TextAreaField("Content", validators=[DataRequired(), Length(max=200000)])
        is_published = BooleanField("Published")

    class CmsArticleForm(_BaseCmsForm):
        title = StringField("Title", validators=[DataRequired(), Length(max=220)])
        slug = StringField("Slug", validators=[Optional(), Length(max=220), _slug_validator])
        excerpt = StringField("Excerpt", validators=[Optional(), Length(max=600)])
        content = TextAreaField("Content", validators=[DataRequired(), Length(max=200000)])
        is_published = BooleanField("Published")
