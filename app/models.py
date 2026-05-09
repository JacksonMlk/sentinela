import secrets
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, JSON
from app.database import Base


class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    company = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    aws_role_arn = Column(String(512), nullable=True)   # usado quando account_mode == "organization"
    aws_role_arns = Column(JSON, nullable=True)          # usado quando account_mode == "standalone"
    account_mode = Column(String(20), default="organization")  # "organization" | "standalone"
    aws_account_id = Column(String(50), nullable=True)
    aws_regions = Column(String(512), default="us-east-1")  # comma-separated
    access_token = Column(String(128), unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Portal visibility settings per section (True = visible, default all visible)
    visibility_settings = Column(JSON, nullable=True)

    # Scheduled analysis
    schedule_enabled = Column(Boolean, default=False)
    schedule_interval_days = Column(Integer, default=7)
    schedule_next_run = Column(DateTime, nullable=True)
    schedule_last_run = Column(DateTime, nullable=True)

    @property
    def role_arns_list(self) -> list:
        """Retorna lista de ARN strings conforme o modo configurado."""
        if self.account_mode == "standalone":
            entries = self.aws_role_arns or []
            return [e["arn"] if isinstance(e, dict) else e for e in entries]
        return [self.aws_role_arn] if self.aws_role_arn else []

    @property
    def role_accounts(self) -> list:
        """Retorna lista de dicts {arn, regions} para análise multi-conta."""
        if self.account_mode == "standalone":
            entries = self.aws_role_arns or []
            return [
                e if isinstance(e, dict) else {"arn": e, "regions": self.aws_regions or "us-east-1"}
                for e in entries
            ]
        return []

    @property
    def analysis_accounts(self) -> list:
        """Lista unificada para run_analysis_job: dicts no modo standalone, string no org."""
        if self.account_mode == "standalone":
            return self.role_accounts
        return [self.aws_role_arn] if self.aws_role_arn else []

    @property
    def primary_role_arn(self) -> str:
        """ARN principal — usado em operações de conta única (CloudTrail, Prowler)."""
        if self.account_mode == "standalone":
            entries = self.aws_role_arns or []
            first = entries[0] if entries else None
            if first:
                return first["arn"] if isinstance(first, dict) else first
            return ""
        return self.aws_role_arn or ""

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(32)


class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, nullable=False, index=True)
    report_type = Column(String(50), nullable=False)  # 'finops', 'security', 'full'
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Raw data collected from AWS
    raw_data = Column(JSON, nullable=True)

    # Claude AI analysis results
    finops_summary = Column(Text, nullable=True)
    security_summary = Column(Text, nullable=True)
    quick_wins = Column(JSON, nullable=True)       # list of quick win items
    projects = Column(JSON, nullable=True)         # list of project items
    service_suggestions = Column(JSON, nullable=True)

    # Cost metrics
    monthly_cost = Column(Float, nullable=True)
    potential_savings = Column(Float, nullable=True)
    savings_percentage = Column(Float, nullable=True)

    # Security metrics
    security_score = Column(Integer, nullable=True)
    security_label = Column(String(50), nullable=True)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)

    # FinOps structured data
    cost_by_service = Column(JSON, nullable=True)
    cost_trend = Column(JSON, nullable=True)
    rightsizing_recommendations = Column(JSON, nullable=True)
    unused_resources = Column(JSON, nullable=True)
    ri_recommendations = Column(JSON, nullable=True)

    # Security structured data
    iam_findings = Column(JSON, nullable=True)
    s3_findings = Column(JSON, nullable=True)
    network_findings = Column(JSON, nullable=True)
    encryption_findings = Column(JSON, nullable=True)
    compliance_findings = Column(JSON, nullable=True)

    # Combined FinOps + Security cross-analysis (Item 14)
    combined_analysis = Column(JSON, nullable=True)

    # Tracking: completion status per item  {quick_wins: {"0": {status, updated_at}}, projects: {...}}
    item_tracking = Column(JSON, nullable=True)

    # Prowler security posture scan (runs independently, may take 30-60 min)
    prowler_findings = Column(JSON, nullable=True)
    prowler_status = Column(String(20), nullable=True)      # pending/running/completed/failed
    prowler_started_at = Column(DateTime, nullable=True)
    prowler_completed_at = Column(DateTime, nullable=True)
