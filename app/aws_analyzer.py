"""
AWS Analyzer - collects FinOps and Security data from a customer AWS account
using STS AssumeRole with the provided ARN.
"""
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3
import json
from datetime import datetime, timedelta
from typing import Any
from botocore.exceptions import ClientError, BotoCoreError

# ---------------------------------------------------------------------------
# VERSION KNOWLEDGE BASE  (updated April 2025)
# Extended Support costs $0.12 / vCPU-hour for RDS; free for first 12 months.
# ---------------------------------------------------------------------------

_RDS_VERSION_KB: dict[str, dict[str, dict]] = {
    "mysql": {
        "5.7": {"status": "extended_support", "extended_support_started": "2024-02-29",
                "extended_support_ends": "2027-02-28",
                "extended_support_cost_note": "$0.12/vCPU-hora extra",
                "latest_major": "8.4"},
        "8.0": {"status": "approaching_eol", "standard_support_ends": "2026-04-30",
                "extended_support_starts": "2026-05-01",
                "extended_support_cost_note": "$0.12/vCPU-hora extra a partir de mai/2026",
                "latest_major": "8.4"},
        "8.4": {"status": "current", "latest_major": "8.4"},
    },
    "postgres": {
        "11": {"status": "extended_support", "extended_support_started": "2024-02-29",
               "extended_support_ends": "2027-02-28",
               "extended_support_cost_note": "$0.12/vCPU-hora extra",
               "latest_major": "17"},
        "12": {"status": "extended_support", "extended_support_started": "2025-03-01",
               "extended_support_ends": "2028-02-28",
               "extended_support_cost_note": "$0.12/vCPU-hora extra",
               "latest_major": "17"},
        "13": {"status": "approaching_eol", "standard_support_ends": "2026-02-28",
               "extended_support_starts": "2026-03-01",
               "extended_support_cost_note": "$0.12/vCPU-hora extra a partir de mar/2026",
               "latest_major": "17"},
        "14": {"status": "current", "latest_major": "17"},
        "15": {"status": "current", "latest_major": "17"},
        "16": {"status": "current", "latest_major": "17"},
        "17": {"status": "current", "latest_major": "17"},
    },
    "aurora-mysql": {
        "2": {"status": "extended_support", "extended_support_started": "2024-02-29",
              "extended_support_ends": "2027-02-28",
              "extended_support_cost_note": "$0.12/vCPU-hora extra (Aurora MySQL 2.x = MySQL 5.7)",
              "latest_major": "3 (MySQL 8.0 compat.)"},
        "3": {"status": "current", "latest_major": "3 (MySQL 8.0 compat.)"},
    },
    "aurora-postgresql": {
        "11": {"status": "extended_support", "extended_support_started": "2024-02-29",
               "extended_support_ends": "2027-02-28",
               "extended_support_cost_note": "$0.12/vCPU-hora extra",
               "latest_major": "17"},
        "12": {"status": "extended_support", "extended_support_started": "2025-03-01",
               "extended_support_ends": "2028-02-28",
               "extended_support_cost_note": "$0.12/vCPU-hora extra",
               "latest_major": "17"},
        "13": {"status": "approaching_eol", "standard_support_ends": "2026-02-28",
               "latest_major": "17"},
        "14": {"status": "current", "latest_major": "17"},
        "15": {"status": "current", "latest_major": "17"},
        "16": {"status": "current", "latest_major": "17"},
    },
    "mariadb": {
        "10.3": {"status": "extended_support", "extended_support_started": "2024-02-29",
                 "extended_support_cost_note": "$0.12/vCPU-hora extra",
                 "latest_major": "10.11"},
        "10.4": {"status": "extended_support", "extended_support_started": "2025-03-01",
                 "extended_support_cost_note": "$0.12/vCPU-hora extra",
                 "latest_major": "10.11"},
        "10.5": {"status": "approaching_eol", "standard_support_ends": "2025-10-31",
                 "latest_major": "10.11"},
        "10.6": {"status": "current", "latest_major": "10.11"},
        "10.11": {"status": "current", "latest_major": "10.11"},
    },
    "sqlserver": {
        "14.00": {"status": "extended_support", "latest_major": "16.00"},  # SQL Server 2017
        "15.00": {"status": "approaching_eol", "standard_support_ends": "2025-10-14",
                  "latest_major": "16.00"},  # SQL Server 2019
        "16.00": {"status": "current", "latest_major": "16.00"},  # SQL Server 2022
    },
}

_LAMBDA_RUNTIME_KB: dict[str, dict] = {
    "python3.13": {"status": "current", "latest": "python3.13"},
    "python3.12": {"status": "current", "latest": "python3.13"},
    "python3.11": {"status": "current", "latest": "python3.13"},
    "python3.10": {"status": "current", "latest": "python3.13"},
    "python3.9":  {"status": "deprecated", "invocations_blocked": "2025-02-14",
                   "latest": "python3.13"},
    "python3.8":  {"status": "deprecated", "invocations_blocked": "2024-10-14",
                   "latest": "python3.13"},
    "python3.7":  {"status": "deprecated", "invocations_blocked": "2023-11-14",
                   "latest": "python3.13"},
    "nodejs22.x": {"status": "current", "latest": "nodejs22.x"},
    "nodejs20.x": {"status": "current", "latest": "nodejs22.x"},
    "nodejs18.x": {"status": "deprecated", "invocations_blocked": "2025-02-28",
                   "latest": "nodejs22.x"},
    "nodejs16.x": {"status": "deprecated", "invocations_blocked": "2024-06-12",
                   "latest": "nodejs22.x"},
    "nodejs14.x": {"status": "deprecated", "invocations_blocked": "2024-03-14",
                   "latest": "nodejs22.x"},
    "java21":     {"status": "current", "latest": "java21"},
    "java17":     {"status": "current", "latest": "java21"},
    "java11":     {"status": "current", "latest": "java21"},
    "java8.al2":  {"status": "current", "latest": "java21"},
    "java8":      {"status": "deprecated", "latest": "java21"},
    "go1.x":      {"status": "deprecated", "invocations_blocked": "2024-12-31",
                   "latest": "provided.al2023"},
    "ruby3.3":    {"status": "current", "latest": "ruby3.3"},
    "ruby3.2":    {"status": "current", "latest": "ruby3.3"},
    "ruby2.7":    {"status": "deprecated", "invocations_blocked": "2024-02-14",
                   "latest": "ruby3.3"},
    "dotnet8":    {"status": "current", "latest": "dotnet8"},
    "dotnet7":    {"status": "deprecated", "latest": "dotnet8"},
    "dotnet6":    {"status": "deprecated", "invocations_blocked": "2024-08-12",
                   "latest": "dotnet8"},
    "provided.al2023": {"status": "current", "latest": "provided.al2023"},
    "provided.al2":    {"status": "current", "latest": "provided.al2023"},
}

_EKS_VERSION_KB: dict[str, dict] = {
    "1.32": {"status": "current"},
    "1.31": {"status": "current"},
    "1.30": {"status": "current"},
    "1.29": {"status": "current"},
    "1.28": {"status": "eol", "standard_support_ended": "2025-01-01"},
    "1.27": {"status": "eol", "standard_support_ended": "2024-07-01"},
    "1.26": {"status": "eol", "standard_support_ended": "2024-06-01"},
    "1.25": {"status": "eol", "standard_support_ended": "2024-05-01"},
}


def _annotate_rds_version(engine: str, engine_version: str) -> dict:
    """Returns version_info dict for an RDS instance based on engine and version."""
    if not engine or not engine_version:
        return {}
    engine_lower = engine.lower()
    parts = engine_version.split(".")

    if "sqlserver" in engine_lower:
        # SQL Server version is "major.minor.patch" — key is "major.minor" (e.g. "15.00")
        major = f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else parts[0]
        kb = _RDS_VERSION_KB.get("sqlserver", {})
    elif "aurora" in engine_lower and "mysql" in engine_lower:
        # Aurora MySQL: version like "8.0.32" or "5.7.12-log" → major is parts[0] only
        major = parts[0]
        kb = _RDS_VERSION_KB.get("aurora-mysql", {})
    elif "aurora" in engine_lower and ("postgres" in engine_lower or "pg" in engine_lower):
        major = parts[0]
        kb = _RDS_VERSION_KB.get("aurora-postgresql", {})
    elif "mysql" in engine_lower:
        # MySQL: version "5.7.44" → major key is "5.7" (two parts)
        major = f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else parts[0]
        kb = _RDS_VERSION_KB.get("mysql", {})
    elif "postgres" in engine_lower:
        # PostgreSQL: version "14.10" → major key is parts[0] = "14"
        major = parts[0]
        kb = _RDS_VERSION_KB.get("postgres", {})
    elif "mariadb" in engine_lower:
        # MariaDB: version "10.6.14" → major key is "10.6" (two parts)
        major = f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else parts[0]
        kb = _RDS_VERSION_KB.get("mariadb", {})
    else:
        return {}
    info = kb.get(major, {})
    return {"version": engine_version, **info} if info else {"version": engine_version, "status": "unknown"}


def _annotate_lambda_runtime(runtime: str) -> dict:
    """Returns version_info dict for a Lambda runtime."""
    if not runtime:
        return {}
    return _LAMBDA_RUNTIME_KB.get(runtime, {"status": "unknown", "latest": "unknown"})


def _annotate_eks_version(k8s_version: str) -> dict:
    """Returns version_info dict for an EKS cluster Kubernetes version."""
    if not k8s_version:
        return {}
    major = ".".join(k8s_version.split(".")[:2])
    return _EKS_VERSION_KB.get(major, {"status": "unknown"})


class AnalysisCancelledError(Exception):
    """Raised when a cancel event is signalled during analysis."""


def _check_cancel(cancel_event: threading.Event | None) -> None:
    """Raise AnalysisCancelledError if the cancel event has been set."""
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisCancelledError("Análise cancelada pelo usuário.")


def _base_session(region: str) -> boto3.Session:
    """
    Cria a sessão boto3 base da conta principal.
    Se AWS_PROFILE estiver configurado no .env, usa esse perfil (necessário para SSO).
    Em produção (EC2/ECS com IAM Role), deixe aws_profile em branco.
    """
    from app.config import get_settings
    profile = get_settings().finops_aws_profile
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def assume_role(role_arn: str, region: str = "us-east-1") -> dict:
    """Assume the customer's IAM role and return credentials."""
    sts = _base_session(region).client("sts")
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="FinOpsSecurityAnalyzer",
        DurationSeconds=3600,
    )
    return response["Credentials"]


def get_boto_session(credentials: dict, region: str) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


# ---------------------------------------------------------------------------
# FINOPS COLLECTORS
# ---------------------------------------------------------------------------

def collect_cost_and_usage(session: boto3.Session) -> dict:
    """Collect 12 months of cost data grouped by service."""
    ce = session.client("ce", region_name="us-east-1")
    end = datetime.utcnow().date()
    start = (end - timedelta(days=365)).replace(day=1)

    result = {"by_service": [], "daily_trend": [], "monthly_totals": []}

    try:
        # Monthly cost by service (last 6 months)
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["BlendedCost", "UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        result["by_service"] = resp.get("ResultsByTime", [])

        # Monthly totals (for trend chart)
        resp2 = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["BlendedCost"],
        )
        result["monthly_totals"] = [
            {
                "period": r["TimePeriod"]["Start"],
                "cost": float(r["Total"]["BlendedCost"]["Amount"]),
            }
            for r in resp2.get("ResultsByTime", [])
        ]

        # Cost forecast (next 30 days)
        try:
            forecast_start = str(end + timedelta(days=1))
            forecast_end = str(end + timedelta(days=31))
            fc = ce.get_cost_forecast(
                TimePeriod={"Start": forecast_start, "End": forecast_end},
                Granularity="MONTHLY",
                Metric="BLENDED_COST",
            )
            result["forecast_next_month"] = float(fc["Total"]["Amount"])
        except Exception:
            result["forecast_next_month"] = None

    except ClientError as e:
        result["error"] = str(e)

    return result


def collect_unused_resources(session: boto3.Session, regions: list[str], cancel_event=None) -> dict:
    """Find unattached EBS volumes, unused EIPs, idle load balancers, old snapshots."""
    findings = {
        "unattached_volumes": [],
        "unused_eips": [],
        "old_snapshots": [],
        "stopped_instances": [],
        "idle_load_balancers": [],
    }

    for region in regions:
        _check_cancel(cancel_event)
        try:
            ec2 = session.client("ec2", region_name=region)

            # Unattached EBS volumes
            vols = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])
            for v in vols.get("Volumes", []):
                findings["unattached_volumes"].append({
                    "region": region,
                    "volume_id": v["VolumeId"],
                    "size_gb": v["Size"],
                    "type": v["VolumeType"],
                    "created": str(v["CreateTime"]),
                    "estimated_monthly_cost": round(v["Size"] * 0.10, 2),
                })

            # Unused Elastic IPs
            addrs = ec2.describe_addresses(Filters=[{"Name": "domain", "Values": ["vpc"]}])
            for a in addrs.get("Addresses", []):
                if not a.get("AssociationId"):
                    findings["unused_eips"].append({
                        "region": region,
                        "ip": a.get("PublicIp"),
                        "allocation_id": a.get("AllocationId"),
                        "estimated_monthly_cost": 3.65,
                    })

            # Old snapshots (>90 days)
            cutoff = datetime.utcnow() - timedelta(days=90)
            snaps = ec2.describe_snapshots(OwnerIds=["self"])
            for s in snaps.get("Snapshots", []):
                snap_time = s["StartTime"].replace(tzinfo=None)
                if snap_time < cutoff:
                    findings["old_snapshots"].append({
                        "region": region,
                        "snapshot_id": s["SnapshotId"],
                        "size_gb": s["VolumeSize"],
                        "created": str(s["StartTime"]),
                        "description": s.get("Description", ""),
                        "estimated_monthly_cost": round(s["VolumeSize"] * 0.05, 2),
                    })

            # Stopped EC2 instances (>7 days)
            instances = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
            )
            for r in instances.get("Reservations", []):
                for i in r.get("Instances", []):
                    name = next(
                        (t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), "N/A"
                    )
                    findings["stopped_instances"].append({
                        "region": region,
                        "instance_id": i["InstanceId"],
                        "instance_type": i["InstanceType"],
                        "name": name,
                        "launch_time": str(i.get("LaunchTime", "")),
                    })

        except (ClientError, BotoCoreError):
            pass

        # Idle Load Balancers
        try:
            elb = session.client("elbv2", region_name=region)
            lbs = elb.describe_load_balancers()
            for lb in lbs.get("LoadBalancers", []):
                tgs = elb.describe_target_groups(LoadBalancerArn=lb["LoadBalancerArn"])
                has_healthy = False
                for tg in tgs.get("TargetGroups", []):
                    health = elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                    if any(t["TargetHealth"]["State"] == "healthy" for t in health.get("TargetHealthDescriptions", [])):
                        has_healthy = True
                        break
                if not has_healthy:
                    findings["idle_load_balancers"].append({
                        "region": region,
                        "name": lb["LoadBalancerName"],
                        "arn": lb["LoadBalancerArn"],
                        "type": lb["Type"],
                        "estimated_monthly_cost": 18.0,
                    })
        except (ClientError, BotoCoreError):
            pass

    return findings


def collect_rightsizing(session: boto3.Session) -> dict:
    """Collect Compute Optimizer rightsizing recommendations."""
    result = {"ec2": [], "rds": [], "lambda": []}
    try:
        co = session.client("compute-optimizer", region_name="us-east-1")

        # EC2 recommendations
        resp = co.get_ec2_instance_recommendations()
        for rec in resp.get("instanceRecommendations", []):
            opts = rec.get("recommendationOptions", [])
            if opts:
                best = opts[0]
                result["ec2"].append({
                    "instance_id": rec["instanceArn"].split("/")[-1],
                    "current_type": rec["currentInstanceType"],
                    "recommended_type": best.get("instanceType"),
                    "finding": rec.get("finding"),
                    "estimated_savings": best.get("estimatedMonthlySavings", {}).get("value", 0),
                    "cpu_avg": rec.get("utilizationMetrics", [{}])[0].get("value", 0) if rec.get("utilizationMetrics") else 0,
                })

        # Lambda recommendations
        try:
            lam = co.get_lambda_function_recommendations()
            for rec in lam.get("lambdaFunctionRecommendations", []):
                opts = rec.get("memorySizeRecommendationOptions", [])
                if opts:
                    result["lambda"].append({
                        "function_name": rec["functionArn"].split(":")[-1],
                        "current_memory": rec.get("currentMemorySize"),
                        "recommended_memory": opts[0].get("memorySize"),
                        "finding": rec.get("finding"),
                    })
        except Exception:
            pass

    except (ClientError, BotoCoreError) as e:
        result["error"] = str(e)

    return result


def collect_ri_recommendations(session: boto3.Session) -> dict:
    """Collect Reserved Instance and Savings Plans recommendations."""
    result = {"reserved_instances": [], "savings_plans": []}
    ce = session.client("ce", region_name="us-east-1")

    for service in ["Amazon Elastic Compute Cloud - Compute", "Amazon Relational Database Service"]:
        try:
            resp = ce.get_reservation_purchase_recommendation(
                Service=service,
                LookbackPeriodInDays="SIXTY_DAYS",
                TermInYears="ONE_YEAR",
                PaymentOption="NO_UPFRONT",
            )
            for rec in resp.get("Recommendations", []):
                details = rec.get("RecommendationDetails", [])
                for d in details[:5]:  # top 5
                    result["reserved_instances"].append({
                        "service": service,
                        "instance_type": d.get("InstanceDetails", {}).get("EC2InstanceDetails", {}).get("InstanceType", "N/A"),
                        "recommended_units": d.get("RecommendedNumberOfUnitsToPurchase", "0"),
                        "estimated_monthly_savings": float(d.get("EstimatedMonthlySavingsAmount", 0)),
                        "upfront_cost": float(d.get("UpfrontCost", 0)),
                    })
        except (ClientError, BotoCoreError):
            pass

    try:
        resp = ce.get_savings_plans_purchase_recommendation(
            SavingsPlansType="COMPUTE_SP",
            TermInYears="ONE_YEAR",
            PaymentOption="NO_UPFRONT",
            LookbackPeriodInDays="SIXTY_DAYS",
        )
        for rec in resp.get("SavingsPlansPurchaseRecommendation", {}).get("SavingsPlansPurchaseRecommendationDetails", []):
            result["savings_plans"].append({
                "hourly_commitment": float(rec.get("HourlyCommitmentToPurchase", 0)),
                "estimated_savings": float(rec.get("EstimatedMonthlySavingsAmount", 0)),
                "estimated_utilization": rec.get("EstimatedAverageUtilization", "0"),
            })
    except (ClientError, BotoCoreError):
        pass

    return result


def collect_savings_plans_coverage(session: boto3.Session) -> dict:
    """
    Coleta a cobertura e utilização REAL dos Savings Plans já comprados na conta.

    - coverage:    % do gasto EC2/Fargate/Lambda coberto por SPs existentes
    - utilization: % do compromisso de SP que está sendo realmente consumido
    - unused_commitment: valor mensal pago mas não consumido (custo desperdiçado)
    """
    ce = session.client("ce", region_name="us-east-1")
    end = datetime.utcnow().date()
    # Últimos 30 dias completos
    start = end - timedelta(days=30)
    period = {"Start": str(start), "End": str(end)}

    result = {
        "coverage": {
            "on_demand_cost_usd": 0.0,
            "covered_by_sp_usd": 0.0,
            "coverage_percentage": 0.0,
        },
        "utilization": {
            "total_commitment_usd": 0.0,
            "used_commitment_usd": 0.0,
            "unused_commitment_usd": 0.0,
            "utilization_percentage": 0.0,
        },
        "by_savings_plan": [],
    }

    # Coverage: quanto do gasto On-Demand foi coberto por SPs
    try:
        resp = ce.get_savings_plans_coverage(
            TimePeriod=period,
            Granularity="MONTHLY",
            Metrics=["SpendCoveredBySavingsPlans", "OnDemandCost", "CoveragePercentage"],
        )
        totals = resp.get("Total", {}).get("Coverage", {})
        result["coverage"]["covered_by_sp_usd"] = float(totals.get("SpendCoveredBySavingsPlans", 0) or 0)
        result["coverage"]["on_demand_cost_usd"] = float(totals.get("OnDemandCost", 0) or 0)
        result["coverage"]["coverage_percentage"] = float(totals.get("CoveragePercentage", 0) or 0)
    except (ClientError, BotoCoreError):
        pass

    # Utilization: quanto do compromisso comprado está sendo usado
    try:
        resp = ce.get_savings_plans_utilization(
            TimePeriod=period,
            Granularity="MONTHLY",
        )
        totals = resp.get("Total", {}).get("Utilization", {})
        result["utilization"]["total_commitment_usd"] = float(totals.get("TotalCommitment", 0) or 0)
        result["utilization"]["used_commitment_usd"] = float(totals.get("UsedCommitment", 0) or 0)
        result["utilization"]["unused_commitment_usd"] = float(totals.get("UnusedCommitment", 0) or 0)
        result["utilization"]["utilization_percentage"] = float(totals.get("UtilizationPercentage", 0) or 0)
    except (ClientError, BotoCoreError):
        pass

    # Detalhe por Savings Plan individual
    try:
        resp = ce.get_savings_plans_utilization_details(
            TimePeriod=period,
        )
        for sp in resp.get("SavingsPlansUtilizationDetails", [])[:10]:
            attrs = sp.get("Attributes", {})
            util = sp.get("Utilization", {})
            result["by_savings_plan"].append({
                "savings_plan_arn": attrs.get("SavingsPlansARN", ""),
                "type": attrs.get("SavingsPlansType", ""),
                "region": attrs.get("Region", ""),
                "instance_family": attrs.get("InstanceFamily", ""),
                "payment_option": attrs.get("PaymentOption", ""),
                "expiration_date": attrs.get("EndDateTime", ""),
                "total_commitment_usd": float(util.get("TotalCommitment", 0) or 0),
                "used_commitment_usd": float(util.get("UsedCommitment", 0) or 0),
                "unused_commitment_usd": float(util.get("UnusedCommitment", 0) or 0),
                "utilization_percentage": float(util.get("UtilizationPercentage", 0) or 0),
            })
    except (ClientError, BotoCoreError):
        pass

    return result


def collect_cost_by_tag(session: boto3.Session) -> dict:
    """
    Coleta custo por tags de negócio nos últimos 30 dias.
    Detecta automaticamente as tags mais populares (Environment, Project, Team, etc.)
    e retorna custo por valor de tag agrupado por serviço.
    """
    ce = session.client("ce", region_name="us-east-1")
    end = datetime.utcnow().date()
    start = end - timedelta(days=30)
    period = {"Start": str(start), "End": str(end)}

    result: dict = {
        "period": {"start": str(start), "end": str(end)},
        "tags_found": [],
        "by_tag": {},
    }

    # 1. Descobrir quais tags existem na conta
    priority_tags = ["Environment", "Project", "Team", "Application", "Cost Center",
                     "Service", "Owner", "Env", "environment", "project", "team"]
    active_tags: list[str] = []
    try:
        resp = ce.get_tags(TimePeriod=period, MaxResults=100)
        all_tags = resp.get("Tags", [])
        result["tags_found"] = all_tags
        # Priorizar tags de negócio reconhecidas; pegar até 3
        for t in priority_tags:
            if t in all_tags:
                active_tags.append(t)
            if len(active_tags) == 3:
                break
        # Se não encontrou nenhuma conhecida, pegar as 3 primeiras que existem
        if not active_tags:
            active_tags = all_tags[:3]
    except (ClientError, BotoCoreError):
        return result

    # 2. Para cada tag, custo agrupado por valor + serviço
    for tag_key in active_tags:
        tag_result: list = []
        try:
            resp = ce.get_cost_and_usage(
                TimePeriod=period,
                Granularity="MONTHLY",
                Metrics=["BlendedCost"],
                GroupBy=[
                    {"Type": "TAG", "Key": tag_key},
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                ],
            )
            # Pivot: tag_value -> [{service, cost}]
            pivot: dict = {}
            for time_result in resp.get("ResultsByTime", []):
                for group in time_result.get("Groups", []):
                    keys = group.get("Keys", [])
                    if len(keys) < 2:
                        continue
                    tag_val = keys[0].replace(f"{tag_key}$", "").strip() or "(sem tag)"
                    service  = keys[1]
                    cost     = float(group["Metrics"]["BlendedCost"]["Amount"])
                    if cost < 0.01:
                        continue
                    pivot.setdefault(tag_val, []).append({"service": service, "cost": cost})

            for tag_val, services in pivot.items():
                total = round(sum(s["cost"] for s in services), 2)
                tag_result.append({
                    "tag_value": tag_val,
                    "total_cost_usd": total,
                    "top_services": sorted(services, key=lambda x: x["cost"], reverse=True)[:5],
                })

            result["by_tag"][tag_key] = sorted(tag_result, key=lambda x: x["total_cost_usd"], reverse=True)

        except (ClientError, BotoCoreError):
            result["by_tag"][tag_key] = []

    return result


def collect_s3_costs(session: boto3.Session, cancel_event=None) -> dict:
    """Collect S3 bucket info and intelligent tiering opportunities."""
    result = {"buckets": [], "total_size_gb": 0}
    try:
        s3 = session.client("s3", region_name="us-east-1")
        buckets = s3.list_buckets().get("Buckets", [])
        cw = session.client("cloudwatch", region_name="us-east-1")

        for b in buckets[:50]:  # cap to 50
            _check_cancel(cancel_event)
            name = b["Name"]
            # Get bucket size from CloudWatch
            try:
                metrics = cw.get_metric_statistics(
                    Namespace="AWS/S3",
                    MetricName="BucketSizeBytes",
                    Dimensions=[
                        {"Name": "BucketName", "Value": name},
                        {"Name": "StorageType", "Value": "StandardStorage"},
                    ],
                    StartTime=datetime.utcnow() - timedelta(days=2),
                    EndTime=datetime.utcnow(),
                    Period=86400,
                    Statistics=["Average"],
                )
                size_bytes = metrics["Datapoints"][-1]["Average"] if metrics["Datapoints"] else 0
            except Exception:
                size_bytes = 0

            size_gb = round(size_bytes / (1024 ** 3), 2)
            result["total_size_gb"] += size_gb

            # Check lifecycle policies
            has_lifecycle = False
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=name)
                has_lifecycle = True
            except ClientError:
                pass

            # Check intelligent tiering
            has_it = False
            try:
                it = s3.list_bucket_intelligent_tiering_configurations(Bucket=name)
                has_it = bool(it.get("IntelligentTieringConfigurationList"))
            except ClientError:
                pass

            # Check versioning
            versioning = "Disabled"
            try:
                v = s3.get_bucket_versioning(Bucket=name)
                versioning = v.get("Status", "Disabled")
            except ClientError:
                pass

            result["buckets"].append({
                "name": name,
                "size_gb": size_gb,
                "has_lifecycle": has_lifecycle,
                "has_intelligent_tiering": has_it,
                "versioning": versioning,
                "estimated_monthly_cost": round(size_gb * 0.023, 2),
            })

    except (ClientError, BotoCoreError) as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# SECURITY COLLECTORS
# ---------------------------------------------------------------------------

def collect_iam_findings(session: boto3.Session, cancel_event=None) -> dict:
    """Collect IAM security findings."""
    findings = {
        "root_mfa_enabled": None,
        "users_without_mfa": [],
        "users_with_old_keys": [],
        "overprivileged_policies": [],
        "inactive_users": [],
        "password_policy": {},
    }
    try:
        iam = session.client("iam", region_name="us-east-1")

        # Account summary
        summary = iam.get_account_summary()["SummaryMap"]
        findings["root_mfa_enabled"] = bool(summary.get("AccountMFAEnabled", 0))
        findings["account_has_password_policy"] = bool(summary.get("AccountPasswordPresent", 0))

        # Password policy
        try:
            pp = iam.get_account_password_policy()
            findings["password_policy"] = pp.get("PasswordPolicy", {})
        except ClientError:
            findings["password_policy"] = {"error": "No password policy set"}

        # Users
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page["Users"])

        for user in users:
            _check_cancel(cancel_event)
            username = user["UserName"]

            # MFA check
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not mfa_devices:
                # Check if user has console access
                try:
                    iam.get_login_profile(UserName=username)
                    findings["users_without_mfa"].append(username)
                except ClientError:
                    pass

            # Old access keys (>90 days)
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key["Status"] == "Active":
                    age_days = (datetime.utcnow() - key["CreateDate"].replace(tzinfo=None)).days
                    if age_days > 90:
                        findings["users_with_old_keys"].append({
                            "user": username,
                            "key_id": key["AccessKeyId"],
                            "age_days": age_days,
                        })

            # Last activity
            try:
                cred_report = None
                try:
                    cred_report = iam.generate_credential_report()
                except Exception:
                    pass

                last_used = user.get("PasswordLastUsed")
                if last_used:
                    days_inactive = (datetime.utcnow() - last_used.replace(tzinfo=None)).days
                    if days_inactive > 90:
                        findings["inactive_users"].append({
                            "user": username,
                            "days_inactive": days_inactive,
                        })
            except Exception:
                pass

        # Policies with *:* (admin)
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    try:
                        version = iam.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy["DefaultVersionId"],
                        )
                        doc = version["PolicyVersion"]["Document"]
                        stmts = doc.get("Statement", [])
                        for stmt in stmts:
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if "*" in actions and "*" in resources and stmt.get("Effect") == "Allow":
                                findings["overprivileged_policies"].append({
                                    "policy_name": policy["PolicyName"],
                                    "policy_arn": policy["Arn"],
                                })
                                break
                    except Exception:
                        pass
        except Exception:
            pass

    except (ClientError, BotoCoreError) as e:
        findings["error"] = str(e)

    return findings


def collect_ec2_cloudwatch_metrics(session: boto3.Session, regions: list[str],
                                    cancel_event=None) -> list:
    """
    Coleta métricas reais de CPU e Network para instâncias EC2 running nos últimos 14 dias.
    Retorna lista com: instance_id, instance_type, name, cpu_avg, cpu_max,
    network_in_avg_mb, network_out_avg_mb — dados que tornam o rightsizing cirúrgico.
    """
    cw_period_seconds = 14 * 86400  # 14 dias em segundos (uma única janela de média)
    start_time = datetime.utcnow() - timedelta(days=14)
    end_time   = datetime.utcnow()

    all_instances: list = []

    for region in regions:
        _check_cancel(cancel_event)
        try:
            ec2 = session.client("ec2", region_name=region)
            cw  = session.client("cloudwatch", region_name=region)

            # Listar instâncias running
            reservations = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ).get("Reservations", [])

            instances_in_region = []
            for r in reservations:
                for i in r.get("Instances", []):
                    name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), "")
                    instances_in_region.append({
                        "instance_id":   i["InstanceId"],
                        "instance_type": i["InstanceType"],
                        "name":          name,
                        "region":        region,
                        "launch_time":   str(i.get("LaunchTime", "")),
                    })

            # Limitar a 30 instâncias por região para não estourar o rate limit
            for inst in instances_in_region[:30]:
                _check_cancel(cancel_event)
                iid = inst["instance_id"]
                dims = [{"Name": "InstanceId", "Value": iid}]

                def _get_metric(metric_name: str, stat: str) -> float:
                    try:
                        resp = cw.get_metric_statistics(
                            Namespace="AWS/EC2",
                            MetricName=metric_name,
                            Dimensions=dims,
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=cw_period_seconds,
                            Statistics=[stat],
                        )
                        points = resp.get("Datapoints", [])
                        if not points:
                            return 0.0
                        return round(points[0].get(stat, 0.0), 2)
                    except Exception:
                        return 0.0

                cpu_avg = _get_metric("CPUUtilization", "Average")
                cpu_max = _get_metric("CPUUtilization", "Maximum")
                net_in  = round(_get_metric("NetworkIn", "Average") / (1024 ** 2), 2)  # bytes → MB
                net_out = round(_get_metric("NetworkOut", "Average") / (1024 ** 2), 2)

                all_instances.append({
                    **inst,
                    "cpu_avg_pct":         cpu_avg,
                    "cpu_max_pct":         cpu_max,
                    "network_in_avg_mb":   net_in,
                    "network_out_avg_mb":  net_out,
                    "rightsizing_signal":  (
                        "overprovisioned" if cpu_avg < 10 and cpu_max < 25
                        else "underprovisioned" if cpu_avg > 80
                        else "adequate"
                    ),
                })

        except (ClientError, BotoCoreError):
            pass

    # Ordenar: primeiros os mais overprovisioned (candidatos a rightsizing)
    return sorted(all_instances, key=lambda x: x.get("cpu_avg_pct", 100))


def collect_s3_security(session: boto3.Session, cancel_event=None) -> dict:
    """Check S3 buckets for public access, encryption, logging."""
    findings = {"public_buckets": [], "unencrypted_buckets": [], "no_logging_buckets": []}
    try:
        s3 = session.client("s3", region_name="us-east-1")
        buckets = s3.list_buckets().get("Buckets", [])

        for b in buckets[:50]:
            _check_cancel(cancel_event)
            name = b["Name"]

            # Public access block
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all([
                    pab.get("BlockPublicAcls"),
                    pab.get("IgnorePublicAcls"),
                    pab.get("BlockPublicPolicy"),
                    pab.get("RestrictPublicBuckets"),
                ]):
                    findings["public_buckets"].append(name)
            except ClientError:
                findings["public_buckets"].append(name)  # No block config = potentially public

            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                findings["unencrypted_buckets"].append(name)

            # Logging
            try:
                logging_cfg = s3.get_bucket_logging(Bucket=name)
                if not logging_cfg.get("LoggingEnabled"):
                    findings["no_logging_buckets"].append(name)
            except ClientError:
                findings["no_logging_buckets"].append(name)

    except (ClientError, BotoCoreError) as e:
        findings["error"] = str(e)

    return findings


def collect_network_security(session: boto3.Session, regions: list[str], cancel_event=None) -> dict:
    """Check security groups, VPC flow logs, CloudTrail."""
    findings = {
        "open_security_groups": [],
        "vpcs_without_flow_logs": [],
        "cloudtrail_status": {},
        "regions_without_guardduty": [],
    }

    for region in regions:
        _check_cancel(cancel_event)
        try:
            ec2 = session.client("ec2", region_name=region)

            # Security groups with 0.0.0.0/0 on sensitive ports
            sgs = ec2.describe_security_groups()
            for sg in sgs.get("SecurityGroups", []):
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            if from_port in [22, 3389, 3306, 5432, 27017, 6379, 9200] or from_port == 0:
                                # Find resources attached to this SG via network interfaces
                                sg_resources = []
                                try:
                                    enis = ec2.describe_network_interfaces(
                                        Filters=[{"Name": "group-id", "Values": [sg["GroupId"]]}]
                                    ).get("NetworkInterfaces", [])
                                    for eni in enis:
                                        desc = eni.get("Description", "")
                                        attach = eni.get("Attachment", {})
                                        name_tag = next((t["Value"] for t in eni.get("TagSet", []) if t["Key"] == "Name"), "")
                                        if attach.get("InstanceId"):
                                            label = f"EC2: {name_tag or attach['InstanceId']}"
                                        elif "rds" in desc.lower():
                                            label = f"RDS: {desc.split(':')[-1][:30] if ':' in desc else desc[:30]}"
                                        elif "elb" in desc.lower() or "ELB" in desc:
                                            label = f"LB: {desc[:40]}"
                                        elif "lambda" in desc.lower():
                                            label = f"Lambda: {desc[:30]}"
                                        elif "ecs" in desc.lower():
                                            label = f"ECS: {desc[:30]}"
                                        elif desc:
                                            label = desc[:40]
                                        else:
                                            label = eni.get("NetworkInterfaceId", "eni-?")
                                        if label and label not in sg_resources:
                                            sg_resources.append(label)
                                except (ClientError, BotoCoreError):
                                    pass

                                findings["open_security_groups"].append({
                                    "region": region,
                                    "sg_id": sg["GroupId"],
                                    "sg_name": sg.get("GroupName"),
                                    "port": from_port,
                                    "protocol": perm.get("IpProtocol"),
                                    "vpc_id": sg.get("VpcId"),
                                    "sg_resources": sg_resources,
                                })

            # VPCs without flow logs
            vpcs = ec2.describe_vpcs()
            flow_logs = ec2.describe_flow_logs()
            logged_vpcs = {fl["ResourceId"] for fl in flow_logs.get("FlowLogs", [])}
            for vpc in vpcs.get("Vpcs", []):
                if vpc["VpcId"] not in logged_vpcs:
                    findings["vpcs_without_flow_logs"].append({
                        "region": region,
                        "vpc_id": vpc["VpcId"],
                        "is_default": vpc.get("IsDefault", False),
                    })

        except (ClientError, BotoCoreError):
            pass

        # GuardDuty
        try:
            gd = session.client("guardduty", region_name=region)
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                findings["regions_without_guardduty"].append(region)
        except (ClientError, BotoCoreError):
            findings["regions_without_guardduty"].append(region)

    # CloudTrail (global check)
    try:
        ct = session.client("cloudtrail", region_name="us-east-1")
        trails = ct.describe_trails(includeShadowTrails=False)
        for trail in trails.get("trailList", []):
            status = ct.get_trail_status(Name=trail["TrailARN"])
            findings["cloudtrail_status"][trail["Name"]] = {
                "is_logging": status.get("IsLogging", False),
                "multi_region": trail.get("IsMultiRegionTrail", False),
                "log_file_validation": trail.get("LogFileValidationEnabled", False),
            }
    except (ClientError, BotoCoreError):
        pass

    return findings


def collect_encryption_findings(session: boto3.Session, regions: list[str], cancel_event=None) -> dict:
    """Check encryption at rest for EC2, RDS, EBS."""
    findings = {
        "unencrypted_ebs": [],
        "unencrypted_rds": [],
        "unencrypted_ec2": [],
    }

    for region in regions:
        _check_cancel(cancel_event)
        try:
            ec2 = session.client("ec2", region_name=region)

            # Unencrypted EBS volumes
            vols = ec2.describe_volumes()
            for v in vols.get("Volumes", []):
                if not v.get("Encrypted"):
                    findings["unencrypted_ebs"].append({
                        "region": region,
                        "volume_id": v["VolumeId"],
                        "size_gb": v["Size"],
                        "state": v["State"],
                    })

        except (ClientError, BotoCoreError):
            pass

        try:
            rds = session.client("rds", region_name=region)
            instances = rds.describe_db_instances()
            for db in instances.get("DBInstances", []):
                if not db.get("StorageEncrypted"):
                    findings["unencrypted_rds"].append({
                        "region": region,
                        "db_id": db["DBInstanceIdentifier"],
                        "engine": db["Engine"],
                        "class": db["DBInstanceClass"],
                    })
        except (ClientError, BotoCoreError):
            pass

    return findings


def collect_compliance_findings(session: boto3.Session) -> dict:
    """Check AWS Config, Security Hub, Trusted Advisor findings."""
    findings = {
        "security_hub": [],
        "config_rules_failing": [],
        "trusted_advisor": [],
    }

    try:
        sh = session.client("securityhub", region_name="us-east-1")
        resp = sh.get_findings(
            Filters={
                "SeverityLabel": [
                    {"Value": "CRITICAL", "Comparison": "EQUALS"},
                    {"Value": "HIGH", "Comparison": "EQUALS"},
                ],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            },
            MaxResults=50,
        )
        for f in resp.get("Findings", []):
            findings["security_hub"].append({
                "title": f.get("Title"),
                "severity": f.get("Severity", {}).get("Label"),
                "description": f.get("Description"),
                "resource_type": f.get("Resources", [{}])[0].get("Type"),
            })
    except (ClientError, BotoCoreError):
        pass

    try:
        config = session.client("config", region_name="us-east-1")
        rules = config.describe_config_rules()
        for rule in rules.get("ConfigRules", []):
            comp = config.get_compliance_details_by_config_rule(
                ConfigRuleName=rule["ConfigRuleName"],
                ComplianceTypes=["NON_COMPLIANT"],
            )
            count = len(comp.get("EvaluationResults", []))
            if count > 0:
                findings["config_rules_failing"].append({
                    "rule": rule["ConfigRuleName"],
                    "non_compliant_resources": count,
                })
    except (ClientError, BotoCoreError):
        pass

    return findings


# ---------------------------------------------------------------------------
# VPC ENDPOINT COLLECTOR
# ---------------------------------------------------------------------------

def collect_vpc_endpoints(session: boto3.Session, regions: list[str], cancel_event=None) -> dict:
    """
    Verifica VPC Gateway Endpoints (S3 e DynamoDB) por região e VPC.
    Cruza com NAT Gateways para identificar tráfego S3/DynamoDB pago
    desnecessariamente via NAT (custo evitável — Gateway Endpoints são gratuitos).
    Também coleta breakdown de custo de Data Transfer via Cost Explorer.
    """
    result: dict = {
        "vpcs": [],
        "missing_s3_endpoint": [],
        "missing_dynamodb_endpoint": [],
        "total_data_transfer_out_usd": 0.0,
        "data_transfer_by_usagetype": [],
    }

    # Custo de data transfer do mês corrente (ou anterior) via CE
    try:
        ce = session.client("ce", region_name="us-east-1")
        end = datetime.utcnow().date()
        start = end.replace(day=1)
        if end.day <= 3:
            import calendar as _cal
            prev = end.replace(day=1) - timedelta(days=1)
            start = prev.replace(day=1)
            end = prev.replace(day=_cal.monthrange(prev.year, prev.month)[1])

        dt_resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
        )
        dt_items: list = []
        for period in dt_resp.get("ResultsByTime", []):
            for grp in period.get("Groups", []):
                usage_type = grp["Keys"][0]
                cost = float(grp["Metrics"]["UnblendedCost"]["Amount"])
                if cost < 0.01:
                    continue
                if any(kw in usage_type for kw in ["DataTransfer", "Bytes", "Transfer"]):
                    dt_items.append({"usage_type": usage_type, "cost_usd": round(cost, 2)})
                    # Contabiliza saída para internet (ex: SAE1-DataTransfer-Out-Bytes)
                    if "Out" in usage_type:
                        result["total_data_transfer_out_usd"] += cost
        dt_items.sort(key=lambda x: x["cost_usd"], reverse=True)
        result["data_transfer_by_usagetype"] = dt_items[:25]
        result["total_data_transfer_out_usd"] = round(result["total_data_transfer_out_usd"], 2)
    except (ClientError, BotoCoreError):
        pass

    for region in regions:
        _check_cancel(cancel_event)
        try:
            ec2_client = session.client("ec2", region_name=region)

            # VPCs da região
            vpcs_map = {
                v["VpcId"]: v
                for v in ec2_client.describe_vpcs().get("Vpcs", [])
            }

            # Gateway Endpoints disponíveis
            eps = ec2_client.describe_vpc_endpoints(
                Filters=[
                    {"Name": "vpc-endpoint-type", "Values": ["Gateway"]},
                    {"Name": "state", "Values": ["available"]},
                ]
            ).get("VpcEndpoints", [])

            vpc_ep_map: dict[str, set] = {}
            for ep in eps:
                svc = ep.get("ServiceName", "")
                vid = ep.get("VpcId", "")
                vpc_ep_map.setdefault(vid, set())
                if ".s3" in svc:
                    vpc_ep_map[vid].add("s3")
                elif ".dynamodb" in svc:
                    vpc_ep_map[vid].add("dynamodb")

            # NAT Gateways disponíveis por VPC
            nats = ec2_client.describe_nat_gateways(
                Filter=[{"Name": "state", "Values": ["available"]}]
            ).get("NatGateways", [])
            vpcs_with_nat = {nat["VpcId"] for nat in nats}

            for vpc_id, vpc_data in vpcs_map.items():
                eps_set = vpc_ep_map.get(vpc_id, set())
                has_nat = vpc_id in vpcs_with_nat
                has_s3 = "s3" in eps_set
                has_ddb = "dynamodb" in eps_set
                vpc_name = next(
                    (t["Value"] for t in vpc_data.get("Tags", []) if t["Key"] == "Name"),
                    vpc_id,
                )

                result["vpcs"].append({
                    "region": region,
                    "vpc_id": vpc_id,
                    "vpc_name": vpc_name,
                    "is_default": vpc_data.get("IsDefault", False),
                    "has_nat_gateway": has_nat,
                    "has_s3_gateway_endpoint": has_s3,
                    "has_dynamodb_gateway_endpoint": has_ddb,
                })

                if has_nat and not has_s3:
                    result["missing_s3_endpoint"].append({
                        "region": region,
                        "vpc_id": vpc_id,
                        "vpc_name": vpc_name,
                        "risk": "alto",
                    })
                if has_nat and not has_ddb:
                    result["missing_dynamodb_endpoint"].append({
                        "region": region,
                        "vpc_id": vpc_id,
                        "vpc_name": vpc_name,
                        "risk": "medio",
                    })

        except (ClientError, BotoCoreError):
            pass

    return result


# ---------------------------------------------------------------------------
# NAT GATEWAY COLLECTOR
# ---------------------------------------------------------------------------

def collect_nat_gateway_info(session: boto3.Session, regions: list[str],
                              cancel_event=None) -> dict:
    """NAT Gateways por região: bytes processados (14d) e custo mensal via CE."""
    result: dict = {
        "nat_gateways": [],
        "total_monthly_cost_usd": 0.0,
    }
    now = datetime.utcnow()
    end_date = now.strftime("%Y-%m-%d")
    start_30d = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    period_14d = 14 * 86400

    # Custo via Cost Explorer (usage types contendo "NatGateway")
    try:
        ce = session.client("ce", region_name="us-east-1")
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start_30d, "End": end_date},
            Granularity="MONTHLY",
            Filter={"Dimensions": {"Key": "SERVICE",
                                   "Values": ["Amazon Virtual Private Cloud"]}},
            GroupBy=[{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
            Metrics=["UnblendedCost"],
        )
        for period in resp.get("ResultsByTime", []):
            for grp in period.get("Groups", []):
                usage_type = grp.get("Keys", [""])[0]
                if "NatGateway" in usage_type:
                    result["total_monthly_cost_usd"] += float(
                        grp.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0)
                    )
    except (ClientError, BotoCoreError):
        pass

    for region in regions:
        _check_cancel(cancel_event)
        try:
            ec2 = session.client("ec2", region_name=region)
            cw  = session.client("cloudwatch", region_name=region)

            paginator = ec2.get_paginator("describe_nat_gateways")
            for page in paginator.paginate(
                Filter=[{"Name": "state", "Values": ["available"]}]
            ):
                for ngw in page.get("NatGateways", []):
                    ngw_id = ngw["NatGatewayId"]
                    name = next(
                        (t["Value"] for t in ngw.get("Tags", []) if t["Key"] == "Name"),
                        ngw_id,
                    )

                    # CloudWatch: bytes enviados ao destino (indicador de tráfego)
                    bytes_out = 0.0
                    try:
                        pts = cw.get_metric_statistics(
                            Namespace="AWS/NATGateway",
                            MetricName="BytesOutToDestination",
                            Dimensions=[{"Name": "NatGatewayId", "Value": ngw_id}],
                            StartTime=now - timedelta(days=14),
                            EndTime=now,
                            Period=period_14d,
                            Statistics=["Sum"],
                        ).get("Datapoints", [])
                        if pts:
                            bytes_out = pts[0].get("Sum", 0.0)
                    except (ClientError, BotoCoreError):
                        pass

                    result["nat_gateways"].append({
                        "region": region,
                        "nat_gateway_id": ngw_id,
                        "name": name,
                        "vpc_id": ngw.get("VpcId", ""),
                        "subnet_id": ngw.get("SubnetId", ""),
                        "bytes_out_14d_gb": round(bytes_out / (1024 ** 3), 2),
                    })
        except (ClientError, BotoCoreError):
            pass

    return result


# ---------------------------------------------------------------------------
# RDS DETAILED COLLECTOR
# ---------------------------------------------------------------------------

def collect_rds_details(session: boto3.Session, regions: list[str],
                         cancel_event=None) -> dict:
    """Inventário completo de RDS: instâncias, snapshots manuais antigos e custo mensal."""
    result: dict = {
        "instances": [],
        "manual_snapshots_old": [],
        "total_monthly_cost_usd": 0.0,
    }
    now = datetime.utcnow()
    end_date = now.strftime("%Y-%m-%d")
    start_30d = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    period_14d = 14 * 86400

    # Custo total RDS
    try:
        ce = session.client("ce", region_name="us-east-1")
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start_30d, "End": end_date},
            Granularity="MONTHLY",
            Filter={"Dimensions": {"Key": "SERVICE",
                                   "Values": ["Amazon Relational Database Service"]}},
            Metrics=["UnblendedCost"],
        )
        for period in resp.get("ResultsByTime", []):
            result["total_monthly_cost_usd"] += float(
                period.get("Total", {}).get("UnblendedCost", {}).get("Amount", 0)
            )
    except (ClientError, BotoCoreError):
        pass

    for region in regions:
        _check_cancel(cancel_event)
        try:
            rds = session.client("rds", region_name=region)
            cw  = session.client("cloudwatch", region_name=region)

            # Instâncias
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db["DBInstanceIdentifier"]

                    cpu_avg = 0.0
                    free_storage_gb: float | None = None

                    try:
                        pts = cw.get_metric_statistics(
                            Namespace="AWS/RDS",
                            MetricName="CPUUtilization",
                            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                            StartTime=now - timedelta(days=14),
                            EndTime=now,
                            Period=period_14d,
                            Statistics=["Average"],
                        ).get("Datapoints", [])
                        if pts:
                            cpu_avg = round(pts[0].get("Average", 0.0), 1)
                    except (ClientError, BotoCoreError):
                        pass

                    try:
                        pts = cw.get_metric_statistics(
                            Namespace="AWS/RDS",
                            MetricName="FreeStorageSpace",
                            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                            StartTime=now - timedelta(days=1),
                            EndTime=now,
                            Period=86400,
                            Statistics=["Average"],
                        ).get("Datapoints", [])
                        if pts:
                            free_storage_gb = round(pts[0].get("Average", 0.0) / (1024 ** 3), 1)
                    except (ClientError, BotoCoreError):
                        pass

                    allocated_gb = db.get("AllocatedStorage", 0)
                    used_gb = (
                        round(allocated_gb - free_storage_gb, 1)
                        if free_storage_gb is not None else None
                    )

                    result["instances"].append({
                        "region": region,
                        "db_id": db_id,
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "version_info": _annotate_rds_version(
                            db.get("Engine", ""), db.get("EngineVersion", "")
                        ),
                        "instance_class": db.get("DBInstanceClass"),
                        "status": db.get("DBInstanceStatus"),
                        "multi_az": db.get("MultiAZ", False),
                        "storage_type": db.get("StorageType"),
                        "allocated_storage_gb": allocated_gb,
                        "used_storage_gb": used_gb,
                        "free_storage_gb": free_storage_gb,
                        "encrypted": db.get("StorageEncrypted", False),
                        "cpu_avg_14d_pct": cpu_avg,
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                    })

            # Snapshots manuais com mais de 30 dias
            snap_paginator = rds.get_paginator("describe_db_snapshots")
            for page in snap_paginator.paginate(SnapshotType="manual"):
                for snap in page.get("DBSnapshots", []):
                    created = snap.get("SnapshotCreateTime")
                    if created:
                        age_days = (now.replace(tzinfo=None) -
                                    created.replace(tzinfo=None)).days
                        if age_days > 30:
                            result["manual_snapshots_old"].append({
                                "region": region,
                                "snapshot_id": snap["DBSnapshotIdentifier"],
                                "db_id": snap["DBInstanceIdentifier"],
                                "size_gb": snap.get("AllocatedStorage", 0),
                                "age_days": age_days,
                            })
        except (ClientError, BotoCoreError):
            pass

    return result


# ---------------------------------------------------------------------------
# LAMBDA DETAILED COLLECTOR
# ---------------------------------------------------------------------------

def collect_lambda_details(session: boto3.Session, regions: list[str],
                            cancel_event=None) -> dict:
    """Inventário de funções Lambda com métricas de invocações, duração e custo total."""
    result: dict = {
        "functions": [],
        "total_function_count": 0,
        "total_monthly_cost_usd": 0.0,
    }
    now = datetime.utcnow()
    end_date = now.strftime("%Y-%m-%d")
    start_30d = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    period_14d = 14 * 86400

    # Custo total Lambda
    try:
        ce = session.client("ce", region_name="us-east-1")
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start_30d, "End": end_date},
            Granularity="MONTHLY",
            Filter={"Dimensions": {"Key": "SERVICE", "Values": ["AWS Lambda"]}},
            Metrics=["UnblendedCost"],
        )
        for period in resp.get("ResultsByTime", []):
            result["total_monthly_cost_usd"] += float(
                period.get("Total", {}).get("UnblendedCost", {}).get("Amount", 0)
            )
    except (ClientError, BotoCoreError):
        pass

    for region in regions:
        _check_cancel(cancel_event)
        try:
            lam = session.client("lambda", region_name=region)
            cw  = session.client("cloudwatch", region_name=region)

            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    fn_name = fn["FunctionName"]
                    result["total_function_count"] += 1

                    invocations = 0
                    avg_duration_ms = 0.0
                    errors = 0

                    try:
                        pts = cw.get_metric_statistics(
                            Namespace="AWS/Lambda",
                            MetricName="Invocations",
                            Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                            StartTime=now - timedelta(days=14),
                            EndTime=now,
                            Period=period_14d,
                            Statistics=["Sum"],
                        ).get("Datapoints", [])
                        if pts:
                            invocations = int(pts[0].get("Sum", 0))
                    except (ClientError, BotoCoreError):
                        pass

                    try:
                        pts = cw.get_metric_statistics(
                            Namespace="AWS/Lambda",
                            MetricName="Duration",
                            Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                            StartTime=now - timedelta(days=14),
                            EndTime=now,
                            Period=period_14d,
                            Statistics=["Average"],
                        ).get("Datapoints", [])
                        if pts:
                            avg_duration_ms = round(pts[0].get("Average", 0.0), 1)
                    except (ClientError, BotoCoreError):
                        pass

                    try:
                        pts = cw.get_metric_statistics(
                            Namespace="AWS/Lambda",
                            MetricName="Errors",
                            Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                            StartTime=now - timedelta(days=14),
                            EndTime=now,
                            Period=period_14d,
                            Statistics=["Sum"],
                        ).get("Datapoints", [])
                        if pts:
                            errors = int(pts[0].get("Sum", 0))
                    except (ClientError, BotoCoreError):
                        pass

                    runtime = fn.get("Runtime", "unknown")
                    result["functions"].append({
                        "region": region,
                        "name": fn_name,
                        "runtime": runtime,
                        "runtime_info": _annotate_lambda_runtime(runtime),
                        "memory_mb": fn.get("MemorySize", 128),
                        "timeout_s": fn.get("Timeout", 3),
                        "last_modified": fn.get("LastModified"),
                        "invocations_14d": invocations,
                        "avg_duration_ms": avg_duration_ms,
                        "errors_14d": errors,
                        "code_size_bytes": fn.get("CodeSize", 0),
                    })
        except (ClientError, BotoCoreError):
            pass

    # Mais invocadas primeiro
    result["functions"].sort(key=lambda x: x.get("invocations_14d", 0), reverse=True)
    return result


# ---------------------------------------------------------------------------
# CONTAINERS: ECS + EKS (Item 8)
# ---------------------------------------------------------------------------

def collect_containers(session: boto3.Session, regions: list[str],
                       cancel_event=None) -> dict:
    """ECS clusters (Fargate/EC2, task/service counts) e EKS clusters (nodegroups, K8s version)."""
    result: dict = {"ecs_clusters": [], "eks_clusters": []}

    for region in regions:
        _check_cancel(cancel_event)

        # ECS
        try:
            ecs = session.client("ecs", region_name=region)
            cluster_arns = ecs.list_clusters().get("clusterArns", [])
            if cluster_arns:
                clusters = ecs.describe_clusters(
                    clusters=cluster_arns,
                    include=["SETTINGS", "STATISTICS"],
                ).get("clusters", [])
                for c in clusters:
                    result["ecs_clusters"].append({
                        "region": region,
                        "name": c["clusterName"],
                        "status": c.get("status"),
                        "running_tasks": c.get("runningTasksCount", 0),
                        "pending_tasks": c.get("pendingTasksCount", 0),
                        "active_services": c.get("activeServicesCount", 0),
                        "container_instances": c.get("registeredContainerInstancesCount", 0),
                    })
        except (ClientError, BotoCoreError):
            pass

        # EKS
        try:
            eks = session.client("eks", region_name=region)
            cluster_names = eks.list_clusters().get("clusters", [])
            for name in cluster_names:
                _check_cancel(cancel_event)
                try:
                    cluster = eks.describe_cluster(name=name)["cluster"]
                    k8s_version = cluster.get("version", "")

                    ng_names = eks.list_nodegroups(clusterName=name).get("nodegroups", [])
                    nodegroups = []
                    total_nodes = 0
                    for ng_name in ng_names[:15]:
                        try:
                            ng = eks.describe_nodegroup(
                                clusterName=name, nodegroupName=ng_name
                            )["nodegroup"]
                            desired = ng.get("scalingConfig", {}).get("desiredSize", 0)
                            total_nodes += desired
                            nodegroups.append({
                                "name": ng_name,
                                "status": ng.get("status"),
                                "instance_types": ng.get("instanceTypes", []),
                                "desired_size": desired,
                                "min_size": ng.get("scalingConfig", {}).get("minSize"),
                                "max_size": ng.get("scalingConfig", {}).get("maxSize"),
                                "ami_type": ng.get("amiType"),
                            })
                        except (ClientError, BotoCoreError):
                            pass

                    result["eks_clusters"].append({
                        "region": region,
                        "name": name,
                        "status": cluster.get("status"),
                        "kubernetes_version": k8s_version,
                        "version_info": _annotate_eks_version(k8s_version),
                        "platform_version": cluster.get("platformVersion"),
                        "nodegroups": nodegroups,
                        "total_nodes": total_nodes,
                    })
                except (ClientError, BotoCoreError):
                    pass
        except (ClientError, BotoCoreError):
            pass

    return result


# ---------------------------------------------------------------------------
# CLOUDFRONT + WAF (Item 9)
# ---------------------------------------------------------------------------

def collect_cloudfront_waf(session: boto3.Session, regions: list[str],
                            cancel_event=None) -> dict:
    """CloudFront distributions (com/sem WAF) e WAF v2 ACLs (CLOUDFRONT + REGIONAL)."""
    result: dict = {
        "distributions": [],
        "distributions_without_waf": [],
        "waf_acls": [],
    }

    # CloudFront é global — não precisa iterar regiões
    try:
        cf = session.client("cloudfront", region_name="us-east-1")
        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            items = page.get("DistributionList", {}).get("Items", [])
            for dist in items:
                waf_id = dist.get("WebACLId", "")
                has_waf = bool(waf_id)
                result["distributions"].append({
                    "id": dist["Id"],
                    "domain": dist.get("DomainName"),
                    "aliases": dist.get("Aliases", {}).get("Items", []),
                    "status": dist.get("Status"),
                    "enabled": dist.get("Enabled", False),
                    "http_version": dist.get("HttpVersion"),
                    "price_class": dist.get("PriceClass"),
                    "has_waf": has_waf,
                    "waf_id": waf_id,
                })
                if not has_waf:
                    result["distributions_without_waf"].append(dist["Id"])
    except (ClientError, BotoCoreError):
        pass

    # WAF v2 — escopo CLOUDFRONT (us-east-1 obrigatório)
    try:
        waf_cf = session.client("wafv2", region_name="us-east-1")
        resp = waf_cf.list_web_acls(Scope="CLOUDFRONT", Limit=100)
        for acl in resp.get("WebACLs", []):
            result["waf_acls"].append({
                "name": acl["Name"],
                "id": acl["Id"],
                "scope": "CLOUDFRONT",
                "description": acl.get("Description", ""),
            })
    except (ClientError, BotoCoreError):
        pass

    # WAF v2 — escopo REGIONAL (para cada região)
    for region in regions:
        _check_cancel(cancel_event)
        try:
            waf_reg = session.client("wafv2", region_name=region)
            resp = waf_reg.list_web_acls(Scope="REGIONAL", Limit=100)
            for acl in resp.get("WebACLs", []):
                result["waf_acls"].append({
                    "name": acl["Name"],
                    "id": acl["Id"],
                    "scope": f"REGIONAL/{region}",
                    "description": acl.get("Description", ""),
                })
        except (ClientError, BotoCoreError):
            pass

    return result


# ---------------------------------------------------------------------------
# TRUSTED ADVISOR (Item 10) — requer plano Business ou Enterprise
# ---------------------------------------------------------------------------

def collect_trusted_advisor(session: boto3.Session) -> dict:
    """
    Trusted Advisor checks de cost_optimizing e security.
    Requer plano de suporte Business/Enterprise — retorna erro gracioso se indisponível.
    """
    result: dict = {
        "cost_optimizing": [],
        "security": [],
        "fault_tolerance": [],
        "total_estimated_monthly_savings": 0.0,
        "error": None,
    }

    try:
        support = session.client("support", region_name="us-east-1")
        checks = support.describe_trusted_advisor_checks(language="pt")["checks"]
        relevant = [
            c for c in checks
            if c.get("category") in ("cost_optimizing", "security", "fault_tolerance")
        ]

        for check in relevant[:40]:
            _check_cancel(None)
            try:
                check_result = support.describe_trusted_advisor_check_result(
                    checkId=check["id"], language="pt"
                )["result"]

                status = check_result.get("status", "ok")
                if status not in ("warning", "error"):
                    continue

                monthly_savings = float(
                    check_result.get("categorySpecificSummary", {})
                    .get("costOptimizing", {})
                    .get("estimatedMonthlySavings", 0)
                )
                result["total_estimated_monthly_savings"] += monthly_savings

                entry = {
                    "name": check["name"],
                    "status": status,
                    "flagged_resources": check_result.get("resourcesSummary", {}).get(
                        "resourcesFlagged", 0
                    ),
                    "estimated_monthly_savings": monthly_savings,
                }

                cat = check.get("category", "")
                if cat == "cost_optimizing":
                    result["cost_optimizing"].append(entry)
                elif cat == "security":
                    result["security"].append(entry)
                elif cat == "fault_tolerance":
                    result["fault_tolerance"].append(entry)
            except (ClientError, BotoCoreError):
                pass

    except (ClientError, BotoCoreError) as e:
        result["error"] = (
            "Trusted Advisor indisponível — requer plano Business ou Enterprise. "
            f"Detalhe: {str(e)[:120]}"
        )

    return result


# ---------------------------------------------------------------------------
# COST ANOMALY DETECTION (Item 11)
# ---------------------------------------------------------------------------

def collect_cost_anomalies(session: boto3.Session) -> dict:
    """Anomalias de custo detectadas pelo AWS Cost Anomaly Detection nos últimos 30 dias."""
    ce = session.client("ce", region_name="us-east-1")
    end = datetime.utcnow().date()
    start = end - timedelta(days=30)

    result: dict = {"anomalies": [], "total_anomalous_spend": 0.0}

    try:
        resp = ce.get_anomalies(
            DateInterval={"StartDate": str(start), "EndDate": str(end)},
            TotalImpact={"NumericOperator": "GREATER_THAN", "StartValue": 1.0},
        )
        for a in resp.get("Anomalies", []):
            impact = a.get("Impact", {})
            total_impact = float(impact.get("TotalImpact", 0) or 0)
            root_causes = a.get("RootCauses", [])
            rc = root_causes[0] if root_causes else {}
            result["anomalies"].append({
                "anomaly_id": a.get("AnomalyId", ""),
                "start_date": a.get("AnomalyStartDate", ""),
                "end_date": a.get("AnomalyEndDate", ""),
                "service": rc.get("Service", ""),
                "region": rc.get("Region", ""),
                "usage_type": rc.get("UsageType", ""),
                "total_impact_usd": total_impact,
                "expected_spend": float(impact.get("TotalExpectedSpend", 0) or 0),
                "actual_spend": float(impact.get("TotalActualSpend", 0) or 0),
                "anomaly_score": float(a.get("AnomalyScore", {}).get("CurrentScore", 0)),
            })
            result["total_anomalous_spend"] += total_impact
        result["anomalies"].sort(key=lambda x: x["total_impact_usd"], reverse=True)
    except (ClientError, BotoCoreError) as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# COST BY USAGE TYPE — granularidade nível HTML (SERVICE + USAGE_TYPE)
# ---------------------------------------------------------------------------

def collect_cost_by_usage_type(session: boto3.Session) -> dict:
    """
    Coleta custo do mês corrente (ou últimos 30 dias) agrupado por SERVICE + USAGE_TYPE.
    Produz o nível de detalhe do HTML: qual usage_type específico dentro de cada serviço
    é o ofensor dominante (ex: SAE1-Multi-AZ:db.m6g.2xlarge → $879).
    """
    ce = session.client("ce", region_name="us-east-1")
    end = datetime.utcnow().date()
    # Usa o mês corrente (do dia 1 até hoje) para refletir o período atual
    start = end.replace(day=1)
    # Se estamos nos primeiros 3 dias do mês, pega o mês anterior completo
    if end.day <= 3:
        import calendar
        prev = end.replace(day=1) - timedelta(days=1)
        start = prev.replace(day=1)
        end = prev.replace(day=calendar.monthrange(prev.year, prev.month)[1])

    result: dict = {
        "period": {"start": str(start), "end": str(end)},
        "top_items": [],
        "by_service": {},
        "total_period_usd": 0.0,
    }

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[
                {"Type": "DIMENSION", "Key": "SERVICE"},
                {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
            ],
        )

        items: list = []
        for time_result in resp.get("ResultsByTime", []):
            for group in time_result.get("Groups", []):
                keys = group.get("Keys", [])
                if len(keys) < 2:
                    continue
                service = keys[0]
                usage_type = keys[1]
                cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if cost < 0.01:
                    continue
                items.append({"service": service, "usage_type": usage_type, "cost_usd": round(cost, 2)})
                result["total_period_usd"] += cost

        # Ordena por custo decrescente
        items.sort(key=lambda x: x["cost_usd"], reverse=True)
        result["top_items"] = items[:50]

        # Pivot: por serviço → lista de usage_types ordenados por custo
        by_service: dict = {}
        for item in items:
            svc = item["service"]
            by_service.setdefault(svc, []).append({
                "usage_type": item["usage_type"],
                "cost_usd": item["cost_usd"],
            })
        # Ordenar serviços por custo total e manter top 15 serviços
        svc_totals = {svc: sum(i["cost_usd"] for i in rows) for svc, rows in by_service.items()}
        top_services = sorted(svc_totals, key=lambda s: svc_totals[s], reverse=True)[:15]
        result["by_service"] = {
            svc: {"total_usd": round(svc_totals[svc], 2), "items": by_service[svc][:20]}
            for svc in top_services
        }
        result["total_period_usd"] = round(result["total_period_usd"], 2)

    except (ClientError, BotoCoreError) as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# AWS ORGANIZATIONS — contas vinculadas e custo por conta
# ---------------------------------------------------------------------------

def collect_linked_accounts(session: boto3.Session) -> dict:
    """
    Detecta se a sessão é de uma Management Account da AWS Organizations e,
    se sim, coleta as contas vinculadas com custo do mês corrente por conta.
    """
    result: dict = {
        "is_management_account": False,
        "organization_id": None,
        "accounts": [],
        "cost_by_account": [],
        "error": None,
    }

    # Verifica se é management account
    try:
        org = session.client("organizations", region_name="us-east-1")
        org_info = org.describe_organization()["Organization"]
        result["organization_id"] = org_info.get("Id")

        # Só management accounts conseguem describe_organization com sucesso
        # Confirma comparando master account id com o account atual
        sts = session.client("sts")
        caller_account = sts.get_caller_identity()["Account"]
        master_account = org_info.get("MasterAccountId", "")
        result["is_management_account"] = (caller_account == master_account)

        if not result["is_management_account"]:
            return result

        # Lista contas ativas
        paginator = org.get_paginator("list_accounts")
        accounts = []
        for page in paginator.paginate():
            for acc in page.get("Accounts", []):
                if acc.get("Status") == "ACTIVE":
                    accounts.append({
                        "account_id": acc["Id"],
                        "name": acc.get("Name", ""),
                        "email": acc.get("Email", ""),
                        "joined_date": str(acc.get("JoinedTimestamp", "")),
                    })
        result["accounts"] = accounts

    except (ClientError, BotoCoreError) as e:
        result["error"] = str(e)
        return result

    # Coleta custo por conta vinculada (últimos 30 dias)
    try:
        ce = session.client("ce", region_name="us-east-1")
        end = datetime.utcnow().date()
        start = end.replace(day=1)
        if end.day <= 3:
            import calendar
            prev = end.replace(day=1) - timedelta(days=1)
            start = prev.replace(day=1)

        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[
                {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                {"Type": "DIMENSION", "Key": "SERVICE"},
            ],
        )

        # Pivot: account_id → {service → cost}
        acc_costs: dict = {}
        for time_result in resp.get("ResultsByTime", []):
            for group in time_result.get("Groups", []):
                keys = group.get("Keys", [])
                if len(keys) < 2:
                    continue
                account_id = keys[0]
                service = keys[1]
                cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if cost < 0.01:
                    continue
                acc_costs.setdefault(account_id, {}).setdefault(service, 0)
                acc_costs[account_id][service] += cost

        # Enriquecer com nome da conta
        acc_name_map = {acc["account_id"]: acc["name"] for acc in result["accounts"]}
        cost_by_account = []
        for account_id, services in acc_costs.items():
            total = sum(services.values())
            top_services = sorted(
                [{"service": svc, "cost_usd": round(c, 2)} for svc, c in services.items()],
                key=lambda x: x["cost_usd"],
                reverse=True,
            )[:8]
            cost_by_account.append({
                "account_id": account_id,
                "account_name": acc_name_map.get(account_id, account_id),
                "total_cost_usd": round(total, 2),
                "top_services": top_services,
            })
        cost_by_account.sort(key=lambda x: x["total_cost_usd"], reverse=True)
        result["cost_by_account"] = cost_by_account

    except (ClientError, BotoCoreError) as e:
        result["cost_error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# FORECAST E ANÁLISE DE TENDÊNCIA
# ---------------------------------------------------------------------------

def collect_cost_forecast_trend(session: boto3.Session) -> dict:
    """
    Calcula a tendência de custo dos últimos 6 meses e projeta os próximos 3 meses.
    Identifica quais serviços estão crescendo e a variação mês a mês.
    """
    ce = session.client("ce", region_name="us-east-1")
    end = datetime.utcnow().date()
    start = (end - timedelta(days=180)).replace(day=1)

    result: dict = {
        "monthly_totals": [],
        "mom_changes": [],          # month-over-month %
        "avg_mom_change_pct": 0.0,
        "trend_direction": "estável",  # crescente | decrescente | estável
        "projected_next_3m": [],
        "services_growing": [],
        "services_declining": [],
        "forecast_next_month_usd": None,
        "current_month_run_rate_usd": None,
    }

    try:
        # Totais mensais dos últimos 6 meses
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )
        monthly = []
        for r in resp.get("ResultsByTime", []):
            monthly.append({
                "period": r["TimePeriod"]["Start"][:7],
                "cost_usd": round(float(r["Total"]["UnblendedCost"]["Amount"]), 2),
                "days_in_period": (
                    datetime.strptime(r["TimePeriod"]["End"], "%Y-%m-%d") -
                    datetime.strptime(r["TimePeriod"]["Start"], "%Y-%m-%d")
                ).days,
            })
        result["monthly_totals"] = monthly

        # Calcular run rate do mês corrente (extrapola dias restantes)
        if monthly:
            last = monthly[-1]
            today = end
            days_elapsed = today.day
            days_in_month = last["days_in_period"]
            if days_elapsed < days_in_month and days_elapsed > 0:
                run_rate = round(last["cost_usd"] / days_elapsed * days_in_month, 2)
                result["current_month_run_rate_usd"] = run_rate

        # Variação MoM
        if len(monthly) >= 2:
            mom_changes = []
            # Usa apenas meses completos (exclui o atual parcial)
            complete = monthly[:-1] if end.day < 25 else monthly
            for i in range(1, len(complete)):
                prev_cost = complete[i - 1]["cost_usd"]
                curr_cost = complete[i]["cost_usd"]
                if prev_cost > 0:
                    pct = round((curr_cost - prev_cost) / prev_cost * 100, 1)
                    mom_changes.append({
                        "from": complete[i - 1]["period"],
                        "to": complete[i]["period"],
                        "change_pct": pct,
                        "from_usd": prev_cost,
                        "to_usd": curr_cost,
                    })
            result["mom_changes"] = mom_changes
            if mom_changes:
                avg = round(sum(c["change_pct"] for c in mom_changes) / len(mom_changes), 1)
                result["avg_mom_change_pct"] = avg
                if avg > 5:
                    result["trend_direction"] = "crescente"
                elif avg < -3:
                    result["trend_direction"] = "decrescente"
                else:
                    result["trend_direction"] = "estável"

        # Projeção para os próximos 3 meses
        if monthly and result["avg_mom_change_pct"] != 0:
            base = result.get("current_month_run_rate_usd") or monthly[-1]["cost_usd"]
            rate = 1 + result["avg_mom_change_pct"] / 100
            projected = []
            for i in range(1, 4):
                import calendar as cal_mod
                future = end + timedelta(days=30 * i)
                projected.append({
                    "period": f"{future.year}-{future.month:02d}",
                    "projected_usd": round(base * (rate ** i), 2),
                })
            result["projected_next_3m"] = projected

        # Forecast via Cost Explorer (próximo mês)
        try:
            fc_start = str(end + timedelta(days=1))
            fc_end_date = (end + timedelta(days=31)).replace(day=1)
            fc = ce.get_cost_forecast(
                TimePeriod={"Start": fc_start, "End": str(fc_end_date)},
                Granularity="MONTHLY",
                Metric="UNBLENDED_COST",
            )
            result["forecast_next_month_usd"] = round(float(fc["Total"]["Amount"]), 2)
            # Substituir projeção linear pela do CE se disponível
            if result["projected_next_3m"]:
                result["projected_next_3m"][0]["ce_forecast_usd"] = result["forecast_next_month_usd"]
        except (ClientError, BotoCoreError):
            pass

        # Serviços crescendo/declinando (compara 2 meses completos mais recentes)
        if len(monthly) >= 3:
            try:
                prev_period = monthly[-3]["period"]
                curr_period = monthly[-2]["period"]  # Penúltimo = mais recente completo
                resp2 = ce.get_cost_and_usage(
                    TimePeriod={"Start": prev_period + "-01", "End": curr_period + "-01"},
                    Granularity="MONTHLY",
                    Metrics=["UnblendedCost"],
                    GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
                )
                prev_by_svc: dict = {}
                curr_by_svc: dict = {}
                records = resp2.get("ResultsByTime", [])
                if len(records) >= 2:
                    for grp in records[0].get("Groups", []):
                        svc = grp["Keys"][0]
                        prev_by_svc[svc] = float(grp["Metrics"]["UnblendedCost"]["Amount"])
                    for grp in records[1].get("Groups", []):
                        svc = grp["Keys"][0]
                        curr_by_svc[svc] = float(grp["Metrics"]["UnblendedCost"]["Amount"])

                    growing, declining = [], []
                    for svc in set(list(prev_by_svc.keys()) + list(curr_by_svc.keys())):
                        prev_c = prev_by_svc.get(svc, 0)
                        curr_c = curr_by_svc.get(svc, 0)
                        if prev_c < 1:
                            continue
                        diff_pct = round((curr_c - prev_c) / prev_c * 100, 1)
                        diff_usd = round(curr_c - prev_c, 2)
                        entry = {"service": svc, "change_pct": diff_pct,
                                 "change_usd": diff_usd, "current_usd": round(curr_c, 2)}
                        if diff_pct > 10 and diff_usd > 5:
                            growing.append(entry)
                        elif diff_pct < -10 and abs(diff_usd) > 5:
                            declining.append(entry)

                    result["services_growing"] = sorted(growing, key=lambda x: x["change_usd"], reverse=True)[:8]
                    result["services_declining"] = sorted(declining, key=lambda x: x["change_usd"])[:5]
            except (ClientError, BotoCoreError):
                pass

    except (ClientError, BotoCoreError) as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# MAIN COLLECTION ENTRY POINT
# ---------------------------------------------------------------------------

def run_full_analysis(role_arn: str, regions_str: str = "us-east-1",
                      cancel_event: threading.Event | None = None) -> dict:
    """
    Assume the role and collect all FinOps + Security data.
    Checks cancel_event between each collector — raises AnalysisCancelledError if set.
    """
    regions = [r.strip() for r in regions_str.split(",") if r.strip()]
    primary_region = regions[0]

    _check_cancel(cancel_event)
    credentials = assume_role(role_arn, primary_region)
    session = get_boto_session(credentials, primary_region)

    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    data: dict = {
        "account_id": account_id,
        "analyzed_regions": regions,
        "collected_at": datetime.utcnow().isoformat(),
        "is_management_account": False,
    }

    _check_cancel(cancel_event)

    # ── Phase 1: all non-regional collectors in parallel ──────────────────────
    global_collectors = {
        "cost_and_usage":       lambda: collect_cost_and_usage(session),
        "cost_by_usage_type":   lambda: collect_cost_by_usage_type(session),
        "cost_forecast_trend":  lambda: collect_cost_forecast_trend(session),
        "linked_accounts":      lambda: collect_linked_accounts(session),
        "rightsizing":          lambda: collect_rightsizing(session),
        "ri_recommendations":   lambda: collect_ri_recommendations(session),
        "savings_plans_coverage": lambda: collect_savings_plans_coverage(session),
        "cost_by_tag":          lambda: collect_cost_by_tag(session),
        "trusted_advisor":      lambda: collect_trusted_advisor(session),
        "cost_anomalies":       lambda: collect_cost_anomalies(session),
        "s3_costs":             lambda: collect_s3_costs(session, cancel_event),
        "iam_findings":         lambda: collect_iam_findings(session, cancel_event),
        "s3_security":          lambda: collect_s3_security(session, cancel_event),
        "compliance_findings":  lambda: collect_compliance_findings(session),
    }

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(fn): key for key, fn in global_collectors.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                data[key] = future.result()
            except AnalysisCancelledError:
                raise
            except Exception:
                data[key] = {}

    linked = data.get("linked_accounts", {})
    data["is_management_account"] = linked.get("is_management_account", False)

    _check_cancel(cancel_event)

    # ── Phase 2: regional collectors in parallel ───────────────────────────────
    regional_collectors = {
        "unused_resources":  lambda: collect_unused_resources(session, regions, cancel_event),
        "ec2_metrics":       lambda: collect_ec2_cloudwatch_metrics(session, regions, cancel_event),
        "nat_gateway_info":  lambda: collect_nat_gateway_info(session, regions, cancel_event),
        "vpc_endpoints":     lambda: collect_vpc_endpoints(session, regions, cancel_event),
        "rds_details":       lambda: collect_rds_details(session, regions, cancel_event),
        "lambda_details":    lambda: collect_lambda_details(session, regions, cancel_event),
        "containers":        lambda: collect_containers(session, regions, cancel_event),
        "cloudfront_waf":    lambda: collect_cloudfront_waf(session, regions, cancel_event),
        "network_security":  lambda: collect_network_security(session, regions, cancel_event),
        "encryption_findings": lambda: collect_encryption_findings(session, regions, cancel_event),
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): key for key, fn in regional_collectors.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                data[key] = future.result()
            except AnalysisCancelledError:
                raise
            except Exception:
                data[key] = {}

    return data


# ---------------------------------------------------------------------------
# Correlation engine — cross-domain FinOps × Security analysis
# ---------------------------------------------------------------------------

def detect_correlations(report) -> list[dict]:
    """
    Given a completed AnalysisReport ORM object, detect cross-domain correlations
    between cost anomalies and security findings.  Returns a list of correlation
    dicts ready to be JSON-serialised and rendered as a graph.

    Data shape notes (from real DB inspection):
    - cost_by_service: list of {"service": str, "cost": float}
    - ri_recommendations: {"reserved_instances": [...], "savings_plans": [...]}
    - unused_resources: {"unattached_volumes": [...], "unused_eips": [...], ...}
    - s3_findings: {"costs": {...}, "security": {"public_buckets": [...], ...}}
    - iam_findings: {"root_mfa_enabled": bool, "users_with_old_keys": [...], ...}
    - network_findings: {"open_security_groups": [...], "regions_without_guardduty": [...], ...}
    - encryption_findings: {"unencrypted_ebs": [...], "unencrypted_rds": [...], ...}
    """
    if report is None:
        return []

    def _sg(d, *keys, default=None):
        v = d
        for k in keys:
            if not isinstance(v, dict):
                return default
            v = v.get(k, default)
            if v is None:
                return default
        return v

    iam    = report.iam_findings        or {}
    s3     = report.s3_findings         or {}
    net    = report.network_findings    or {}
    enc    = report.encryption_findings or {}
    unused = report.unused_resources    or {}
    ri     = report.ri_recommendations  or {}

    # cost_by_service is a list of {"service": "...", "cost": ...}
    cost_list = report.cost_by_service or []
    if not isinstance(cost_list, list):
        cost_list = []

    def _svc_cost(*fragments) -> float:
        return sum(
            float(item.get("cost", 0) or 0)
            for item in cost_list
            if any(f.lower() in item.get("service", "").lower() for f in fragments)
        )

    ec2_cost = _svc_cost("elastic compute", "ec2")
    s3_cost  = _svc_cost("simple storage", "amazon s3")
    rds_cost = _svc_cost("relational database", "amazon rds")
    monthly  = float(report.monthly_cost or 0)

    correlations: list[dict] = []

    def _add(cid, severity, title, description, recommendation, fin_impact,
             src_id, src_label, src_cat, src_icon,
             tgt_id, tgt_label, tgt_cat, tgt_icon):
        correlations.append({
            "id": cid, "severity": severity,
            "title": title, "description": description,
            "recommendation": recommendation,
            "financial_impact": round(float(fin_impact or 0), 0),
            "source": {"id": src_id, "label": src_label, "category": src_cat, "icon": src_icon},
            "target": {"id": tgt_id, "label": tgt_label, "category": tgt_cat, "icon": tgt_icon},
        })

    # 1. High EC2 cost + open security groups
    open_sgs = _sg(net, "open_security_groups", default=[]) or []
    if ec2_cost > 150 and open_sgs:
        _add("ec2-open-sg", "critical",
             "EC2 de alto custo exposto por Security Group aberto",
             f"EC2 consome ${ec2_cost:.0f}/mês e {len(open_sgs)} Security Group(s) "
             f"permitem acesso 0.0.0.0/0. Recursos caros acessíveis pela internet aumentam "
             f"o risco de exploração e custos por comprometimento.",
             "Restrinja as regras de ingresso dos Security Groups e avalie Savings Plans para EC2.",
             ec2_cost * 0.15,
             "ec2-cost", f"EC2\n${ec2_cost:.0f}/mês", "finops", "💸",
             "open-sg", f"Security Groups Abertos\n{len(open_sgs)} grupo(s)", "security", "🔓")

    # 2. RI/SP savings potential + high EC2 spend
    ri_items = ri.get("reserved_instances", []) if isinstance(ri, dict) else []
    ri_savings = sum(float(x.get("estimated_monthly_savings", 0) or 0) for x in ri_items)
    if ri_savings > 50 and ec2_cost > 200:
        _add("ec2-no-ri", "high",
             f"Economia de ${ri_savings:.0f}/mês disponível com Reserved Instances",
             f"A análise identificou ${ri_savings:.0f}/mês de economia potencial com Reserved "
             f"Instances para a carga EC2 de ${ec2_cost:.0f}/mês. O uso de on-demand puro "
             f"implica custo até 72% maior que instâncias reservadas.",
             "Adquira Reserved Instances de 1 ano (no upfront) para cobrir a carga base.",
             ri_savings,
             "ec2-od", f"EC2 On-Demand\n${ec2_cost:.0f}/mês", "finops", "💰",
             "ri-opp", f"RI Disponível\n${ri_savings:.0f}/mês de economia", "finops", "📉")

    # 3. Public S3 buckets + S3 cost
    s3_sec = _sg(s3, "security", default={}) or {}
    public_buckets = s3_sec.get("public_buckets", []) or []
    if public_buckets and s3_cost > 30:
        _add("s3-public-cost", "high",
             "Buckets S3 públicos podem inflar o custo de Data Transfer",
             f"{len(public_buckets)} bucket(s) público(s) com custo S3 de ${s3_cost:.0f}/mês. "
             f"Acesso público não autorizado pode gerar transferência de dados não planejada.",
             "Bloqueie o acesso público nos buckets e habilite S3 Access Logs.",
             s3_cost * 0.30,
             "s3-public", f"Buckets Públicos\n{len(public_buckets)} bucket(s)", "security", "🪣",
             "s3-cost", f"Custo S3\n${s3_cost:.0f}/mês", "finops", "💸")

    # 4. Unencrypted EBS + EC2 workload cost
    unenc_ebs = enc.get("unencrypted_ebs", []) or []
    if unenc_ebs and ec2_cost > 80:
        _add("unenc-ebs", "medium",
             "Volumes EBS sem criptografia associados à carga EC2",
             f"{len(unenc_ebs)} volume(s) EBS não criptografado(s) suportando workloads de "
             f"${ec2_cost:.0f}/mês. Uma violação comprometeria dados e continuidade operacional.",
             "Habilite criptografia padrão de EBS na região e crie snapshots criptografados.",
             0,
             "ec2-workload", f"Workload EC2\n${ec2_cost:.0f}/mês", "infrastructure", "🖥️",
             "unenc-ebs", f"EBS Sem Criptografia\n{len(unenc_ebs)} volume(s)", "security", "🔓")

    # 5. Old IAM keys + high monthly spend
    old_keys = iam.get("users_with_old_keys", []) or []
    if old_keys and monthly > 400:
        _add("old-keys-spend", "critical",
             "Credenciais IAM antigas em conta de alto gasto",
             f"{len(old_keys)} usuário(s) com chaves de acesso com 90+ dias numa conta de "
             f"${monthly:.0f}/mês. Credenciais comprometidas podem gerar cobranças ilimitadas.",
             "Rotacione imediatamente as chaves de acesso com mais de 90 dias.",
             monthly * 0.50,
             "old-keys", f"Chaves IAM Antigas\n{len(old_keys)} usuário(s)", "security", "🔑",
             "high-spend", f"Conta de Alto Gasto\n${monthly:.0f}/mês exposto", "finops", "💰")

    # 6. No root MFA + significant spend
    root_mfa = iam.get("root_mfa_enabled", True)
    if root_mfa is False and monthly > 150:
        _add("root-no-mfa", "critical",
             "Conta root sem MFA com gasto significativo",
             f"O usuário root não tem MFA em conta com ${monthly:.0f}/mês. "
             f"Comprometimento do root dá acesso total e pode resultar em custos ilimitados.",
             "URGENTE: Ative MFA no usuário root via Console AWS → Security Credentials.",
             monthly * 2.0,
             "root-mfa", "Root Sem MFA\nRisco Máximo", "security", "🚨",
             "total-spend", f"Gasto Total Exposto\n${monthly:.0f}/mês", "finops", "💰")

    # 7. GuardDuty missing + active spend (crypto-mining risk)
    no_gd = net.get("regions_without_guardduty", []) or []
    if no_gd and monthly > 100:
        sample = ", ".join(no_gd[:3]) + ("..." if len(no_gd) > 3 else "")
        _add("no-guardduty", "high",
             f"Recursos em {len(no_gd)} região(ões) sem detecção de ameaças",
             f"Regiões {sample} têm recursos ativos mas sem GuardDuty. Ataques de "
             f"crypto-mining ou exfiltração de dados não seriam detectados a tempo.",
             "Habilite GuardDuty em todas as regiões com recursos ativos.",
             monthly * 0.10,
             "no-gd", f"Regiões Sem GuardDuty\n{len(no_gd)} região(ões)", "security", "🛡️",
             "unmonitored", "Recursos Não Monitorados\nRisco oculto", "infrastructure", "⚠️")

    # 8. Unencrypted RDS + RDS cost
    unenc_rds = enc.get("unencrypted_rds", []) or []
    if unenc_rds and rds_cost > 40:
        _add("rds-unenc", "high",
             "Banco de dados sem criptografia com custo relevante",
             f"{len(unenc_rds)} instância(s) RDS não criptografada(s) representando "
             f"${rds_cost:.0f}/mês. Dados desprotegidos expõem risco de multas LGPD/GDPR.",
             "Migre para RDS criptografado via snapshot e restauração com criptografia.",
             rds_cost * 0.20,
             "rds-cost", f"RDS\n${rds_cost:.0f}/mês", "finops", "🗄️",
             "rds-unenc", f"RDS Sem Criptografia\n{len(unenc_rds)} instância(s)", "security", "🔓")

    # 9. Unattached EBS volumes — wasted cost + data residue (key corrected to unattached_volumes)
    vols = unused.get("unattached_volumes", []) or []
    if vols:
        waste = sum(float(v.get("estimated_monthly_cost", 0) or 0) for v in vols)
        if waste > 10:
            _add("orphan-ebs", "medium",
                 "Volumes EBS não utilizados gerando custo desnecessário",
                 f"{len(vols)} volume(s) EBS não anexado(s) custando ${waste:.0f}/mês "
                 f"sem servir nenhuma aplicação. Além do desperdício, dados residuais "
                 f"em volumes não criptografados representam risco de exposição.",
                 "Delete os volumes após criar snapshots e habilite criptografia nos snapshots.",
                 waste,
                 "orphan-ebs", f"EBS Órfãos\n${waste:.0f}/mês desperdiçado", "finops", "🗑️",
                 "data-residue", "Dados Residuais\nPossível exposição", "security", "📂")

    # 10. Overprivileged IAM policies + high spend
    overpriv = iam.get("overprivileged_policies", []) or []
    if overpriv and monthly > 250:
        _add("overpriv-spend", "high",
             "Políticas IAM com permissão total em conta de alto gasto",
             f"{len(overpriv)} política(s) com permissão *:* em conta de ${monthly:.0f}/mês. "
             f"Qualquer comprometimento resulta em acesso irrestrito e custos descontrolados.",
             "Implemente princípio do menor privilégio; substitua *:* por ações específicas.",
             monthly * 0.30,
             "overpriv", f"Políticas Admin (*:*)\n{len(overpriv)} política(s)", "security", "⚠️",
             "spend-risk", f"Risco Financeiro\n${monthly:.0f}/mês em risco", "finops", "💸")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    correlations.sort(key=lambda x: sev_order.get(x["severity"], 9))
    return correlations


# ---------------------------------------------------------------------------
# CLOUDTRAIL UNAUTHORIZED RESOURCE AUDIT
# ---------------------------------------------------------------------------

_CREATION_EVENTS: set[str] = {
    # Compute
    "RunInstances", "CreateVolume", "AllocateAddress",
    "CreateSecurityGroup", "CreateVpc", "CreateSubnet",
    "CreateInternetGateway", "CreateNatGateway",
    "CreateKeyPair", "CreateImage",
    "CreateLaunchTemplate", "CreateAutoScalingGroup",
    # Load Balancing
    "CreateLoadBalancer", "CreateTargetGroup",
    # RDS / Aurora
    "CreateDBInstance", "CreateDBCluster",
    "CreateDBSubnetGroup", "CreateDBParameterGroup",
    # Lambda (versioned API name)
    "CreateFunction20150331",
    # Containers
    "CreateCluster", "CreateService",
    # Storage
    "CreateBucket", "CreateFileSystem",
    # NoSQL / Cache
    "CreateTable", "CreateCacheCluster", "CreateReplicationGroup",
    # Messaging
    "CreateQueue", "CreateTopic",
    # IaC
    "CreateStack",
    # Secrets / Keys
    "CreateKey", "CreateSecret",
    # Container Registry / Code
    "CreateRepository", "CreatePipeline", "CreateProject",
    # Search
    "CreateDomain",
    # IAM
    "CreateUser", "CreateRole", "CreatePolicy",
}


def collect_cloudtrail_unauthorized_resources(
    role_arn: str,
    regions: list[str],
    days: int = 7,
    consultant_pattern: str = "sentinela",
    log_fn=None,
) -> list[dict]:
    """
    Query CloudTrail for write events (ReadOnly=false) and return only those
    created by principals whose username/ARN does NOT contain consultant_pattern.

    Enforces 1-30 day range. Returns events sorted newest-first.
    """
    days = min(max(int(days), 1), 30)
    if log_fn:
        log_fn(f"🔍 CloudTrail: consultando {len(regions)} região(ões) ({days} dias)...")

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)

    try:
        creds = assume_role(role_arn)
    except Exception as exc:
        if log_fn:
            log_fn(f"❌ CloudTrail: falha ao assumir role — {exc}")
        raise

    pattern = consultant_pattern.lower()
    results: list[dict] = []

    for region in regions:
        if log_fn:
            log_fn(f"  📍 CloudTrail: região {region}...")
        try:
            session = get_boto_session(creds, region)
            ct = session.client("cloudtrail")
            paginator = ct.get_paginator("lookup_events")

            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": 2000, "PageSize": 50},
            )

            for page in pages:
                for event in page.get("Events", []):
                    event_name = event.get("EventName", "")

                    # Keep only creation events
                    if event_name not in _CREATION_EVENTS and not event_name.startswith("Create"):
                        continue

                    username = event.get("Username", "") or ""

                    # Parse full CloudTrail JSON for extra detail (needed for ARN check)
                    ct_raw: dict = {}
                    try:
                        ct_raw = json.loads(event.get("CloudTrailEvent", "{}") or "{}")
                    except Exception:
                        pass

                    user_identity = ct_raw.get("userIdentity") or {}
                    arn = user_identity.get("arn", "") or username

                    # Skip consultant-initiated events — check both username and full ARN
                    # (e.g. assumed-role/sentinela-login/user has pattern in ARN not username)
                    if pattern in username.lower() or pattern in arn.lower():
                        continue

                    # Skip API calls that returned an error (resource not actually created)
                    if ct_raw.get("errorCode"):
                        continue

                    resources = event.get("Resources") or []
                    resource_type = resources[0].get("ResourceType", "") if resources else ""
                    resource_name = resources[0].get("ResourceName", "") if resources else ""
                    identity_type = user_identity.get("type", "Unknown")
                    account_id = (
                        ct_raw.get("recipientAccountId", "")
                        or user_identity.get("accountId", "")
                    )

                    event_time = event.get("EventTime")
                    event_time_str = (
                        event_time.isoformat()
                        if hasattr(event_time, "isoformat")
                        else str(event_time or "")
                    )

                    results.append({
                        "event_name": event_name,
                        "event_time": event_time_str,
                        "username": username,
                        "arn": arn,
                        "identity_type": identity_type,
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "region": region,
                        "source_ip": ct_raw.get("sourceIPAddress", ""),
                        "user_agent": ct_raw.get("userAgent", ""),
                        "account_id": account_id,
                        "event_source": ct_raw.get("eventSource", ""),
                    })

        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if log_fn:
                log_fn(f"  ⚠️ CloudTrail {region}: {code}")
        except Exception as exc:
            if log_fn:
                log_fn(f"  ⚠️ CloudTrail {region}: {str(exc)[:120]}")

    results.sort(key=lambda x: x.get("event_time", ""), reverse=True)
    if log_fn:
        log_fn(f"✅ CloudTrail: {len(results)} evento(s) não autorizado(s) encontrado(s)")
    return results


# ---------------------------------------------------------------------------
# MULTI-ACCOUNT (STANDALONE) SUPPORT
# ---------------------------------------------------------------------------

def _run_single_account_analysis(
    role_arn: str,
    regions_str: str = "us-east-1",
    cancel_event: threading.Event | None = None,
) -> dict:
    """Analisa uma conta individual sem tentar descoberta via Organizations."""
    regions = [r.strip() for r in regions_str.split(",") if r.strip()]
    primary_region = regions[0]

    _check_cancel(cancel_event)
    credentials = assume_role(role_arn, primary_region)
    session = get_boto_session(credentials, primary_region)

    account_id = session.client("sts").get_caller_identity()["Account"]

    data: dict = {
        "account_id": account_id,
        "role_arn": role_arn,
        "analyzed_regions": regions,
        "collected_at": datetime.utcnow().isoformat(),
        "is_management_account": False,
    }

    _check_cancel(cancel_event)

    global_collectors = {
        "cost_and_usage":         lambda: collect_cost_and_usage(session),
        "cost_by_usage_type":     lambda: collect_cost_by_usage_type(session),
        "cost_forecast_trend":    lambda: collect_cost_forecast_trend(session),
        "rightsizing":            lambda: collect_rightsizing(session),
        "ri_recommendations":     lambda: collect_ri_recommendations(session),
        "savings_plans_coverage": lambda: collect_savings_plans_coverage(session),
        "cost_by_tag":            lambda: collect_cost_by_tag(session),
        "trusted_advisor":        lambda: collect_trusted_advisor(session),
        "cost_anomalies":         lambda: collect_cost_anomalies(session),
        "s3_costs":               lambda: collect_s3_costs(session, cancel_event),
        "iam_findings":           lambda: collect_iam_findings(session, cancel_event),
        "s3_security":            lambda: collect_s3_security(session, cancel_event),
        "compliance_findings":    lambda: collect_compliance_findings(session),
    }

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(fn): key for key, fn in global_collectors.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                data[key] = future.result()
            except AnalysisCancelledError:
                raise
            except Exception as exc:
                data[key] = {"_collection_error": str(exc)}

    _check_cancel(cancel_event)

    regional_collectors = {
        "unused_resources":    lambda: collect_unused_resources(session, regions, cancel_event),
        "ec2_metrics":         lambda: collect_ec2_cloudwatch_metrics(session, regions, cancel_event),
        "nat_gateway_info":    lambda: collect_nat_gateway_info(session, regions, cancel_event),
        "vpc_endpoints":       lambda: collect_vpc_endpoints(session, regions, cancel_event),
        "rds_details":         lambda: collect_rds_details(session, regions, cancel_event),
        "lambda_details":      lambda: collect_lambda_details(session, regions, cancel_event),
        "containers":          lambda: collect_containers(session, regions, cancel_event),
        "cloudfront_waf":      lambda: collect_cloudfront_waf(session, regions, cancel_event),
        "network_security":    lambda: collect_network_security(session, regions, cancel_event),
        "encryption_findings": lambda: collect_encryption_findings(session, regions, cancel_event),
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): key for key, fn in regional_collectors.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                data[key] = future.result()
            except AnalysisCancelledError:
                raise
            except Exception as exc:
                data[key] = {"_collection_error": str(exc)}

    return data


def _build_linked_from_standalone(accounts: list) -> dict:
    """Constrói estrutura equivalente a linked_accounts a partir de contas standalone."""
    accs = []
    cost_by_account = []

    for a in accounts:
        account_id = a.get("account_id", "")
        accs.append({"account_id": account_id, "name": account_id, "email": "", "joined_date": ""})

        monthly = a.get("cost_and_usage", {}).get("monthly_totals", [])
        total = monthly[-1].get("cost", 0) if monthly else 0

        top_services: list = []
        by_service_raw = a.get("cost_and_usage", {}).get("by_service", [])
        if by_service_raw:
            last_month = by_service_raw[-1] if by_service_raw else {}
            for g in last_month.get("Groups", [])[:8]:
                try:
                    top_services.append({
                        "service": g["Keys"][0],
                        "cost_usd": round(float(g["Metrics"]["BlendedCost"]["Amount"]), 2),
                    })
                except (KeyError, ValueError, IndexError):
                    pass
            top_services.sort(key=lambda x: x["cost_usd"], reverse=True)

        cost_by_account.append({
            "account_id": account_id,
            "account_name": account_id,
            "total_cost_usd": round(total, 2),
            "top_services": top_services[:8],
        })

    cost_by_account.sort(key=lambda x: x["total_cost_usd"], reverse=True)
    return {
        "is_management_account": False,
        "organization_id": None,
        "accounts": accs,
        "cost_by_account": cost_by_account,
        "error": None,
    }


def _merge_cost_and_usage(accounts: list) -> dict:
    """Soma custos mensais de todas as contas."""
    month_totals: dict = {}
    by_service = None

    for a in accounts:
        cau = a.get("cost_and_usage", {})
        for entry in cau.get("monthly_totals", []):
            m = entry.get("period", entry.get("month", ""))
            month_totals[m] = month_totals.get(m, 0) + entry.get("cost", 0)
        if by_service is None and cau.get("by_service"):
            by_service = cau["by_service"]

    combined_monthly = [
        {"period": m, "cost": round(c, 2)}
        for m, c in sorted(month_totals.items())
    ]
    return {"monthly_totals": combined_monthly, "by_service": by_service or []}


def _concat_lists(accounts: list, field: str) -> list:
    result: list = []
    for a in accounts:
        val = a.get(field)
        if isinstance(val, list):
            result.extend(val)
    return result


def _merge_dict_of_lists(accounts: list, field: str) -> dict:
    merged: dict = {}
    for a in accounts:
        val = a.get(field, {})
        if not isinstance(val, dict):
            continue
        for k, v in val.items():
            if k not in merged:
                merged[k] = v
            elif isinstance(v, list) and isinstance(merged[k], list):
                merged[k] = merged[k] + v
            elif isinstance(v, bool) and isinstance(merged[k], bool):
                # para flags de segurança: False (falhou) tem prioridade
                merged[k] = merged[k] and v
            elif isinstance(v, (int, float)) and isinstance(merged[k], (int, float)):
                merged[k] = merged[k] + v
    return merged


def _merge_first_or_empty(accounts: list, field: str):
    for a in accounts:
        val = a.get(field)
        if val:
            return val
    return {}


def _merge_vpc_endpoints(accounts: list) -> dict:
    """Agrega vpc_endpoints de múltiplas contas concatenando listas e somando custos."""
    merged: dict = {
        "vpcs": [],
        "missing_s3_endpoint": [],
        "missing_dynamodb_endpoint": [],
        "total_data_transfer_out_usd": 0.0,
        "data_transfer_by_usagetype": [],
    }
    seen_dt: dict[str, float] = {}
    for a in accounts:
        val = a.get("vpc_endpoints", {})
        if not isinstance(val, dict):
            continue
        merged["vpcs"].extend(val.get("vpcs", []))
        merged["missing_s3_endpoint"].extend(val.get("missing_s3_endpoint", []))
        merged["missing_dynamodb_endpoint"].extend(val.get("missing_dynamodb_endpoint", []))
        merged["total_data_transfer_out_usd"] += val.get("total_data_transfer_out_usd", 0.0)
        for item in val.get("data_transfer_by_usagetype", []):
            ut = item["usage_type"]
            seen_dt[ut] = seen_dt.get(ut, 0.0) + item["cost_usd"]
    merged["total_data_transfer_out_usd"] = round(merged["total_data_transfer_out_usd"], 2)
    merged["data_transfer_by_usagetype"] = sorted(
        [{"usage_type": k, "cost_usd": round(v, 2)} for k, v in seen_dt.items()],
        key=lambda x: x["cost_usd"], reverse=True
    )[:25]
    return merged


def _merge_accounts_data(accounts: list) -> dict:
    """Agrega dados de múltiplas contas standalone em uma estrutura unificada."""
    valid = [a for a in accounts if a.get("account_id")]
    if not valid:
        return {"error": "Todas as contas falharam na análise", "accounts_data": accounts}

    account_ids = [a["account_id"] for a in valid]
    label = account_ids[0] if len(account_ids) == 1 else f"multi ({len(account_ids)} contas)"

    merged: dict = {
        "account_mode": "standalone_multi",
        "account_id": label,
        "account_ids": account_ids,
        "analyzed_regions": valid[0].get("analyzed_regions", []),
        "collected_at": datetime.utcnow().isoformat(),
        "is_management_account": False,
        "accounts_data": valid,
        "linked_accounts": _build_linked_from_standalone(valid),
        "cost_and_usage": _merge_cost_and_usage(valid),
        "cost_anomalies": _merge_first_or_empty(valid, "cost_anomalies"),
        "ec2_metrics": _concat_lists(valid, "ec2_metrics"),
        "iam_findings": _merge_dict_of_lists(valid, "iam_findings"),
        "s3_security": _merge_dict_of_lists(valid, "s3_security"),
        "compliance_findings": _merge_dict_of_lists(valid, "compliance_findings"),
        "unused_resources": _merge_dict_of_lists(valid, "unused_resources"),
        "network_security": _merge_dict_of_lists(valid, "network_security"),
        "encryption_findings": _merge_dict_of_lists(valid, "encryption_findings"),
    }

    for field in ("cost_by_usage_type", "cost_forecast_trend", "rightsizing",
                  "ri_recommendations", "savings_plans_coverage", "trusted_advisor",
                  "s3_costs", "nat_gateway_info", "rds_details", "lambda_details",
                  "containers", "cloudfront_waf", "cost_by_tag"):
        merged[field] = _merge_first_or_empty(valid, field)

    # Merge vpc_endpoints: concatena listas, soma custo total de data transfer
    merged["vpc_endpoints"] = _merge_vpc_endpoints(valid)

    return merged


def run_multi_account_analysis(
    role_accounts: list,
    default_regions_str: str = "us-east-1",
    cancel_event: threading.Event | None = None,
) -> dict:
    """Analisa múltiplas contas standalone em paralelo e agrega os resultados.

    role_accounts: lista de dicts {"arn": ..., "regions": ...} ou strings ARN.
    """
    _check_cancel(cancel_event)

    def analyze_one(entry) -> dict:
        if isinstance(entry, dict):
            arn = entry["arn"]
            regions_str = entry.get("regions") or default_regions_str
        else:
            arn = entry
            regions_str = default_regions_str
        try:
            return _run_single_account_analysis(arn, regions_str, cancel_event)
        except AnalysisCancelledError:
            raise
        except Exception as exc:
            account_id = arn.split(":")[4] if arn.count(":") >= 4 else arn
            return {"error": str(exc), "account_id": account_id, "role_arn": arn}

    accounts_data: list = []
    with ThreadPoolExecutor(max_workers=min(len(role_accounts), 3)) as executor:
        futures = {executor.submit(analyze_one, entry): entry for entry in role_accounts}
        for future in as_completed(futures):
            _check_cancel(cancel_event)
            try:
                accounts_data.append(future.result())
            except AnalysisCancelledError:
                raise

    return _merge_accounts_data(accounts_data)
