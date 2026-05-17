"""
Extractors por seção do Assessment Report.

Cada função recebe `raw_data: dict` e retorna um dict compacto com apenas
os dados relevantes para aquela seção. Esse dict é o que vai para o prompt
do Claude no Sprint #2 — sem ruído de outros serviços.

Convenções:
- Truncar listas em no máximo 10-15 itens para não inflar o prompt.
- Sempre usar .get() com defaults para tolerar coletores ausentes.
- Retornar dict vazio {} se não houver dados relevantes (seção ficará sem contexto).
"""
from __future__ import annotations


def extract_ec2(raw_data: dict) -> dict:
    unused = raw_data.get("unused_resources", {})
    rightsizing = raw_data.get("rightsizing", {})
    ec2_metrics = raw_data.get("ec2_metrics", [])

    stopped = []
    for i in unused.get("stopped_instances", [])[:10]:
        if not isinstance(i, dict):
            continue
        stopped.append({
            "id": i.get("InstanceId", i.get("instance_id", "")),
            "type": i.get("InstanceType", i.get("instance_type", "")),
            "name": i.get("name", i.get("Name", "")),
            "stopped_since": i.get("stopped_since", i.get("days_stopped", "")),
        })

    overprovisioned = [
        m for m in ec2_metrics if m.get("rightsizing_signal") == "overprovisioned"
    ][:10]

    rs_recs = []
    for r in rightsizing.get("ec2", [])[:5]:
        if not isinstance(r, dict):
            continue
        opts = r.get("recommendationOptions", r.get("options", [{}]))
        best = opts[0] if opts else {}
        rs_recs.append({
            "instance_id": r.get("instanceArn", r.get("instance_id", "")).split("/")[-1],
            "current_type": r.get("currentInstanceType", r.get("current_type", "")),
            "recommended_type": best.get("instanceType", best.get("type", "")),
            "monthly_savings_usd": best.get("estimatedMonthlySavings", {}).get(
                "value", best.get("monthly_savings", "")
            ),
        })

    return {
        "stopped_instances": stopped,
        "stopped_count": len(unused.get("stopped_instances", [])),
        "overprovisioned_by_cloudwatch": overprovisioned,
        "rightsizing_recommendations": rs_recs,
        "unattached_volumes_count": len(unused.get("unattached_volumes", [])),
        "idle_load_balancers_count": len(unused.get("idle_load_balancers", [])),
        "old_snapshots_count": len(unused.get("old_snapshots", [])),
    }


def extract_ecs(raw_data: dict) -> dict:
    clusters = raw_data.get("containers", {}).get("ecs_clusters", [])
    result = []
    for c in clusters[:10]:
        if not isinstance(c, dict):
            continue
        result.append({
            "name": c.get("clusterName", c.get("name", "")),
            "status": c.get("status", ""),
            "running_tasks": c.get("runningTasksCount", 0),
            "container_instances": c.get("registeredContainerInstancesCount", 0),
            "settings": c.get("settings", []),
        })
    return {
        "clusters": result,
        "cluster_count": len(clusters),
    }


def extract_eks(raw_data: dict) -> dict:
    clusters = raw_data.get("containers", {}).get("eks_clusters", [])
    result = []
    for c in clusters[:10]:
        if not isinstance(c, dict):
            continue
        result.append({
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "version_status": c.get("version_info", {}).get("status", ""),
            "endpoint_public": c.get("endpoint_public", False),
            "nodegroups": [
                {
                    "name": ng.get("nodegroupName", ""),
                    "instance_types": ng.get("instanceTypes", []),
                    "desired": ng.get("scalingConfig", {}).get("desiredSize", 0),
                    "min": ng.get("scalingConfig", {}).get("minSize", 0),
                    "max": ng.get("scalingConfig", {}).get("maxSize", 0),
                }
                for ng in c.get("nodegroups", [])[:5]
            ],
        })
    return {
        "clusters": result,
        "cluster_count": len(clusters),
        "eol_clusters": [c for c in result if c.get("version_status") == "eol"],
        "public_endpoint_clusters": [c for c in result if c.get("endpoint_public")],
    }


def extract_lambda(raw_data: dict) -> dict:
    lam = raw_data.get("lambda_details", {})
    functions = lam.get("functions", [])

    idle = [f for f in functions if f.get("invocations_14d", 0) == 0][:10]
    deprecated_runtime = [
        f for f in functions
        if f.get("runtime_info", {}).get("status") == "deprecated"
    ][:10]

    return {
        "total_function_count": lam.get("total_function_count", 0),
        "total_monthly_cost_usd": lam.get("total_monthly_cost_usd", 0),
        "top_functions": functions[:10],
        "idle_functions": idle,
        "idle_count": len([f for f in functions if f.get("invocations_14d", 0) == 0]),
        "deprecated_runtime_functions": deprecated_runtime,
        "deprecated_runtime_count": len([
            f for f in functions if f.get("runtime_info", {}).get("status") == "deprecated"
        ]),
    }


def extract_rds(raw_data: dict) -> dict:
    rds = raw_data.get("rds_details", {})
    instances = rds.get("instances", [])

    extended_support = [
        i for i in instances
        if i.get("version_info", {}).get("status") == "extended_support"
    ]
    approaching_eol = [
        i for i in instances
        if i.get("version_info", {}).get("status") == "approaching_eol"
    ]
    eol = [
        i for i in instances
        if i.get("version_info", {}).get("status") == "eol"
    ]
    underused = [
        i for i in instances
        if 0 < i.get("cpu_avg_14d_pct", 100) < 10
    ]

    return {
        "instance_count": len(instances),
        "total_monthly_cost_usd": rds.get("total_monthly_cost_usd", 0),
        "instances": instances[:10],
        "extended_support": extended_support,
        "approaching_eol": approaching_eol,
        "eol_instances": eol,
        "underused_instances": underused,
        "old_manual_snapshots_count": len(rds.get("manual_snapshots_old", [])),
        "unencrypted_count": len(
            raw_data.get("encryption_findings", {}).get("unencrypted_rds", [])
        ),
    }


def extract_s3(raw_data: dict) -> dict:
    s3_costs = raw_data.get("s3_costs", {})
    s3_sec = raw_data.get("s3_security", {})

    public_names: set[str] = set()
    for b in s3_sec.get("public_buckets", []):
        if isinstance(b, dict):
            public_names.add(b.get("Name", b.get("name", b.get("bucket_name", ""))))
        elif isinstance(b, str):
            public_names.add(b)

    buckets = []
    for b in s3_costs.get("buckets", [])[:15]:
        if not isinstance(b, dict):
            continue
        name = b.get("Name", b.get("name", b.get("bucket_name", "")))
        buckets.append({
            "name": name,
            "size_gb": round(b.get("size_gb", b.get("size", 0)), 2),
            "has_lifecycle": b.get("has_lifecycle", False),
            "is_public": name in public_names,
        })

    return {
        "total_size_gb": round(s3_costs.get("total_size_gb", 0), 1),
        "bucket_count": len(s3_costs.get("buckets", [])),
        "buckets": buckets,
        "public_bucket_count": len(s3_sec.get("public_buckets", [])),
        "unencrypted_bucket_count": len(s3_sec.get("unencrypted_buckets", [])),
        "buckets_without_lifecycle": [b for b in buckets if not b["has_lifecycle"]],
        "vpc_endpoints_missing_s3": raw_data.get("vpc_endpoints", {}).get("missing_s3_endpoint", []),
    }


def extract_iam(raw_data: dict) -> dict:
    iam = raw_data.get("iam_findings", {})

    users_no_mfa = []
    for u in iam.get("users_without_mfa", [])[:10]:
        if isinstance(u, dict):
            users_no_mfa.append(u.get("UserName", u.get("username", str(u))))
        elif isinstance(u, str):
            users_no_mfa.append(u)

    users_old_keys = []
    for u in iam.get("users_with_old_keys", [])[:10]:
        if isinstance(u, dict):
            users_old_keys.append({
                "user": u.get("UserName", u.get("username", "")),
                "key_age_days": u.get("key_age_days", u.get("age_days", "")),
            })

    inactive = []
    for u in iam.get("inactive_users", [])[:10]:
        if isinstance(u, dict):
            inactive.append({
                "user": u.get("UserName", u.get("username", str(u))),
                "days_inactive": u.get("days_inactive", u.get("inactive_days", "")),
            })
        elif isinstance(u, str):
            inactive.append({"user": u})

    return {
        "root_mfa_enabled": iam.get("root_mfa_enabled"),
        "password_policy": iam.get("password_policy", {}),
        "users_without_mfa": users_no_mfa,
        "users_without_mfa_count": len(iam.get("users_without_mfa", [])),
        "users_with_old_keys": users_old_keys,
        "users_with_old_keys_count": len(iam.get("users_with_old_keys", [])),
        "inactive_users": inactive,
        "inactive_users_count": len(iam.get("inactive_users", [])),
        "overprivileged_policies": iam.get("overprivileged_policies", [])[:5],
        "overprivileged_count": len(iam.get("overprivileged_policies", [])),
    }


def extract_vpc(raw_data: dict) -> dict:
    network = raw_data.get("network_security", {})
    vpc_eps = raw_data.get("vpc_endpoints", {})

    open_sgs = []
    for sg in network.get("open_security_groups", [])[:10]:
        if not isinstance(sg, dict):
            continue
        ports = []
        for perm in sg.get("IpPermissions", sg.get("ip_permissions", [])):
            if not isinstance(perm, dict):
                continue
            port = perm.get("FromPort", perm.get("from_port", perm.get("port", "")))
            proto = perm.get("IpProtocol", perm.get("protocol", "tcp"))
            ports.append(f"{proto}/{port}")
        open_sgs.append({
            "id": sg.get("GroupId", sg.get("group_id", "")),
            "name": sg.get("GroupName", sg.get("group_name", "")),
            "open_ports": ports,
            "instance_count": sg.get("instance_count", sg.get("instances_count", 0)),
        })

    vpcs_no_flow_logs = []
    for vpc in network.get("vpcs_without_flow_logs", [])[:10]:
        if isinstance(vpc, dict):
            vpcs_no_flow_logs.append({
                "id": vpc.get("VpcId", vpc.get("vpc_id", "")),
                "cidr": vpc.get("CidrBlock", vpc.get("cidr", "")),
            })
        elif isinstance(vpc, str):
            vpcs_no_flow_logs.append({"id": vpc})

    return {
        "open_security_groups": open_sgs,
        "open_sg_count": len(network.get("open_security_groups", [])),
        "vpcs_without_flow_logs": vpcs_no_flow_logs,
        "vpcs_without_flow_logs_count": len(network.get("vpcs_without_flow_logs", [])),
        "regions_without_guardduty": network.get("regions_without_guardduty", []),
        "cloudtrail_status": network.get("cloudtrail_status", {}),
        "vpcs_total": len(vpc_eps.get("vpcs", [])),
        "missing_s3_endpoint": vpc_eps.get("missing_s3_endpoint", []),
        "missing_dynamodb_endpoint": vpc_eps.get("missing_dynamodb_endpoint", []),
        "data_transfer_out_usd": vpc_eps.get("total_data_transfer_out_usd", 0),
    }


def extract_nat_gateway(raw_data: dict) -> dict:
    nat = raw_data.get("nat_gateway_info", {})
    gateways = []
    for gw in nat.get("nat_gateways", [])[:10]:
        if not isinstance(gw, dict):
            continue
        gateways.append({
            "id": gw.get("NatGatewayId", gw.get("id", "")),
            "vpc_id": gw.get("VpcId", gw.get("vpc_id", "")),
            "monthly_cost_usd": gw.get("monthly_cost_usd", 0),
            "bytes_processed_14d": gw.get("bytes_processed_14d", 0),
        })
    return {
        "nat_gateway_count": len(nat.get("nat_gateways", [])),
        "total_monthly_cost_usd": nat.get("total_monthly_cost_usd", 0),
        "gateways": gateways,
        "vpc_endpoints_missing_dynamodb": raw_data.get("vpc_endpoints", {}).get(
            "missing_dynamodb_endpoint", []
        ),
    }


def extract_encryption(raw_data: dict) -> dict:
    enc = raw_data.get("encryption_findings", {})
    unused = raw_data.get("unused_resources", {})

    unencrypted_ebs = []
    for vol in enc.get("unencrypted_ebs", [])[:10]:
        if not isinstance(vol, dict):
            continue
        unencrypted_ebs.append({
            "id": vol.get("VolumeId", vol.get("volume_id", "")),
            "size_gb": vol.get("Size", vol.get("size_gb", 0)),
            "az": vol.get("AvailabilityZone", vol.get("az", "")),
        })

    unencrypted_rds = []
    for db in enc.get("unencrypted_rds", [])[:10]:
        if not isinstance(db, dict):
            continue
        unencrypted_rds.append({
            "id": db.get("DBInstanceIdentifier", db.get("db_id", str(db))),
            "engine": db.get("Engine", db.get("engine", "")),
        })

    unattached = []
    for vol in unused.get("unattached_volumes", [])[:10]:
        if not isinstance(vol, dict):
            continue
        vol_type = vol.get("VolumeType", vol.get("type", "gp2"))
        size = vol.get("Size", vol.get("size_gb", 0))
        rate = 0.08 if vol_type == "gp3" else 0.10
        unattached.append({
            "id": vol.get("VolumeId", vol.get("volume_id", "")),
            "size_gb": size,
            "type": vol_type,
            "az": vol.get("AvailabilityZone", vol.get("az", "")),
            "estimated_monthly_cost_usd": round(float(size or 0) * rate, 2),
        })

    return {
        "unencrypted_ebs": unencrypted_ebs,
        "unencrypted_ebs_count": len(enc.get("unencrypted_ebs", [])),
        "unencrypted_rds": unencrypted_rds,
        "unencrypted_rds_count": len(enc.get("unencrypted_rds", [])),
        "unattached_volumes": unattached,
        "unattached_volumes_count": len(unused.get("unattached_volumes", [])),
    }


def extract_cloudfront_waf(raw_data: dict) -> dict:
    cf = raw_data.get("cloudfront_waf", {})
    distributions = []
    for d in cf.get("distributions", [])[:10]:
        if not isinstance(d, dict):
            continue
        distributions.append({
            "id": d.get("Id", ""),
            "domain": d.get("DomainName", ""),
            "has_waf": bool(d.get("WebACLId", "")),
        })
    return {
        "distribution_count": len(cf.get("distributions", [])),
        "distributions": distributions,
        "distributions_without_waf_count": len(cf.get("distributions_without_waf", [])),
        "waf_acl_count": len(cf.get("waf_acls", [])),
    }


def extract_savings_plans(raw_data: dict) -> dict:
    sp_cov = raw_data.get("savings_plans_coverage", {})
    ri_recs = raw_data.get("ri_recommendations", {})

    return {
        "coverage_pct": sp_cov.get("coverage", {}).get("coverage_percentage", 0),
        "on_demand_not_covered_usd": sp_cov.get("coverage", {}).get("on_demand_cost_usd", 0),
        "utilization_pct": sp_cov.get("utilization", {}).get("utilization_percentage", 0),
        "unused_commitment_usd": sp_cov.get("utilization", {}).get("unused_commitment_usd", 0),
        "active_plans": sp_cov.get("by_savings_plan", [])[:5],
        "ri_recommendations": ri_recs.get("reserved_instances", [])[:5],
        "sp_recommendations": ri_recs.get("savings_plans", [])[:3],
    }


def extract_compliance(raw_data: dict) -> dict:
    comp = raw_data.get("compliance_findings", {})
    sh_findings = comp.get("security_hub", [])

    critical = [
        f for f in sh_findings
        if isinstance(f, dict) and f.get("Severity", {}).get("Label") == "CRITICAL"
    ][:5]
    high = [
        f for f in sh_findings
        if isinstance(f, dict) and f.get("Severity", {}).get("Label") == "HIGH"
    ][:5]

    return {
        "security_hub_total": len(sh_findings),
        "critical_count": len([
            f for f in sh_findings
            if isinstance(f, dict) and f.get("Severity", {}).get("Label") == "CRITICAL"
        ]),
        "high_count": len([
            f for f in sh_findings
            if isinstance(f, dict) and f.get("Severity", {}).get("Label") == "HIGH"
        ]),
        "critical_findings": critical,
        "high_findings": high,
        "config_rules_failing": comp.get("config_rules_failing", [])[:10],
        "config_rules_failing_count": len(comp.get("config_rules_failing", [])),
    }


# ---------------------------------------------------------------------------
# Dispatcher — usado no Sprint #2 para chamar o extractor certo pelo slug
# ---------------------------------------------------------------------------

_EXTRACTOR_MAP: dict[str, callable] = {
    "ec2": extract_ec2,
    "ecs": extract_ecs,
    "eks": extract_eks,
    "lambda": extract_lambda,
    "rds": extract_rds,
    "s3": extract_s3,
    "iam": extract_iam,
    "vpc": extract_vpc,
    "nat_gateway": extract_nat_gateway,
    "encryption": extract_encryption,
    "cloudfront_waf": extract_cloudfront_waf,
    "savings_plans": extract_savings_plans,
    "compliance": extract_compliance,
}


def get_extractor(slug: str) -> callable:
    """Retorna a função extractor para o slug dado. Lança KeyError se não existir."""
    return _EXTRACTOR_MAP[slug]
