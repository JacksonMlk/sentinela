"""
Central Jinja2Templates factory that injects branding globals.
Use get_templates() in routers instead of Jinja2Templates(...) directly.
"""
from fastapi.templating import Jinja2Templates
from app.config import get_settings


def get_templates(directory: str = "app/templates") -> Jinja2Templates:
    settings = get_settings()
    templates = Jinja2Templates(directory=directory)
    templates.env.globals["product_name"] = settings.product_name
    templates.env.globals["consultancy_name"] = settings.consultancy_name
    templates.env.globals["primary_color_hex"] = settings.primary_color_hex
    templates.env.globals["accent_color_hex"] = settings.accent_color_hex
    return templates
