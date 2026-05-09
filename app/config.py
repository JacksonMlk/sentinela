from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-opus-4-7"
    admin_secret_token: str = "admin-change-me"
    # Secret key for signing session cookies (use a long random string in prod)
    session_secret: str = "change-this-session-secret-in-production"
    database_url: str = "sqlite:///./finops.db"
    app_name: str = "FinOps & Security Analyzer"
    app_env: str = "development"
    aws_default_region: str = "us-east-1"
    # Perfil AWS local (ex: SSO profile). Deixe em branco em produção com IAM Role.
    # Usa FINOPS_AWS_PROFILE para não colidir com AWS_PROFILE do shell.
    finops_aws_profile: str = ""

    # Cognito OIDC (prod) — leave empty to use ADMIN_SECRET_TOKEN locally
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""
    cognito_client_secret: str = ""
    cognito_domain: str = ""       # e.g. "hmg-guardian.auth.us-east-1.amazoncognito.com"
    cognito_redirect_uri: str = "" # e.g. "https://sentinela.yourdomain.com/admin/auth/callback"

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
