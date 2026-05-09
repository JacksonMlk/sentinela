"""
AI Analyzer — Anthropic Claude SDK for AWS FinOps & Security analysis.
Uses prompt caching on the system instruction to reduce latency and cost.
"""
import json
import time
from datetime import datetime
import anthropic
from app.config import get_settings

settings = get_settings()

SYSTEM_PROMPT = """Você é um arquiteto de soluções AWS sênior da consultoria.
Responda sempre em Português do Brasil.
Nomes de serviços AWS sempre em inglês (Security Hub, GuardDuty, Savings Plans, etc.).
Nunca invente dados — use apenas as informações fornecidas.
Quando solicitado, retorne APENAS JSON válido, sem texto antes ou depois do JSON."""


# ---------------------------------------------------------------------------
# DATA SANITIZATION
# ---------------------------------------------------------------------------

_NOISE_KEYS = frozenset({
    "ResponseMetadata", "RequestId", "HostId", "HTTPStatusCode",
    "HTTPHeaders", "RetryAttempts", "RequestCharged",
    "BucketKeyEnabled", "SSECustomerAlgorithm", "ServerSideEncryption",
    "ContentType", "ETag", "ContentLength", "AcceptRanges",
})


def _sanitize(obj, _depth: int = 0):
    if _depth > 8:
        return str(obj)[:300]
    if isinstance(obj, dict):
        return {
            k: _sanitize(v, _depth + 1)
            for k, v in obj.items()
            if k not in _NOISE_KEYS
            and v is not None
            and v != ""
            and v != {}
            and v != []
        }
    if isinstance(obj, list):
        return [_sanitize(item, _depth + 1) for item in obj[:50]]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj


# ---------------------------------------------------------------------------
# HELPERS — extraem dados ricos com nomes/IDs reais dos recursos
# ---------------------------------------------------------------------------

def _extract_sg_details(open_sgs: list) -> list:
    result = []
    for sg in open_sgs[:10]:
        if not isinstance(sg, dict):
            continue
        entry = {
            "id": sg.get("GroupId", sg.get("group_id", "")),
            "nome": sg.get("GroupName", sg.get("group_name", "")),
            "portas_abertas": [],
            "instancias_associadas": sg.get("instance_count", sg.get("instances_count", 0)),
        }
        for perm in sg.get("IpPermissions", sg.get("ip_permissions", [])):
            if not isinstance(perm, dict):
                continue
            port = perm.get("FromPort", perm.get("from_port", perm.get("port", "")))
            proto = perm.get("IpProtocol", perm.get("protocol", "tcp"))
            entry["portas_abertas"].append(f"{proto}/{port}")
        if not entry["portas_abertas"] and sg.get("port"):
            entry["portas_abertas"].append(str(sg["port"]))
        result.append(entry)
    return result


def _extract_vpc_details(vpcs_without_flow_logs: list) -> list:
    result = []
    for vpc in vpcs_without_flow_logs[:10]:
        if isinstance(vpc, dict):
            result.append({
                "id": vpc.get("VpcId", vpc.get("vpc_id", "")),
                "nome": vpc.get("name", vpc.get("Name", "")),
                "cidr": vpc.get("CidrBlock", vpc.get("cidr", "")),
            })
        elif isinstance(vpc, str):
            result.append({"id": vpc, "nome": "", "cidr": ""})
    return result


def _extract_ebs_details(volumes: list) -> list:
    result = []
    for vol in volumes[:10]:
        if not isinstance(vol, dict):
            continue
        size = vol.get("Size", vol.get("size_gb", vol.get("size", 0)))
        vol_type = vol.get("VolumeType", vol.get("volume_type", vol.get("type", "gp2")))
        rate = 0.08 if vol_type == "gp3" else 0.10
        cost = round(float(size or 0) * rate, 2)
        result.append({
            "id": vol.get("VolumeId", vol.get("volume_id", "")),
            "tamanho_gb": size,
            "tipo": vol_type,
            "custo_mensal_estimado_usd": cost,
            "az": vol.get("AvailabilityZone", vol.get("az", "")),
            "criado_em": vol.get("CreateTime", vol.get("created_at", "")),
        })
    return result


def _extract_iam_users(users: list, key: str = "UserName") -> list:
    result = []
    for u in users[:10]:
        if isinstance(u, dict):
            result.append({
                "usuario": u.get(key, u.get("username", u.get("user", str(u)))),
                "dias_desde_ultimo_uso": u.get("days_inactive", u.get("inactive_days", "")),
                "key_age_days": u.get("key_age_days", u.get("age_days", "")),
                "access_keys_ativas": u.get("access_key_count", u.get("keys_count", "")),
                "politicas": u.get("policies", u.get("attached_policies", [])),
            })
        elif isinstance(u, str):
            result.append({"usuario": u})
    return result


def _extract_s3_details(buckets: list, public_buckets: list) -> list:
    public_names = set()
    for b in public_buckets:
        if isinstance(b, dict):
            public_names.add(b.get("Name", b.get("name", b.get("bucket_name", ""))))
        elif isinstance(b, str):
            public_names.add(b)

    result = []
    for b in buckets[:20]:
        if not isinstance(b, dict):
            continue
        name = b.get("Name", b.get("name", b.get("bucket_name", "")))
        size = round(b.get("size_gb", b.get("size", b.get("SizeGB", 0))), 2)
        result.append({
            "nome": name,
            "tamanho_gb": size,
            "tem_lifecycle": b.get("has_lifecycle", b.get("lifecycle", False)),
            "acesso_publico": name in public_names,
        })
    return result


def _extract_snapshots(snapshots: list) -> list:
    result = []
    for s in snapshots[:10]:
        if not isinstance(s, dict):
            continue
        result.append({
            "id": s.get("SnapshotId", s.get("snapshot_id", "")),
            "tamanho_gb": s.get("VolumeSize", s.get("size_gb", s.get("size", 0))),
            "criado_em": s.get("StartTime", s.get("created_at", s.get("start_time", ""))),
            "descricao": s.get("Description", s.get("description", "")),
        })
    return result


def _extract_stopped_ec2(instances: list) -> list:
    result = []
    for i in instances[:10]:
        if not isinstance(i, dict):
            continue
        result.append({
            "id": i.get("InstanceId", i.get("instance_id", "")),
            "tipo": i.get("InstanceType", i.get("instance_type", "")),
            "nome": i.get("name", i.get("Name", "")),
            "parada_ha": i.get("stopped_since", i.get("days_stopped", "")),
        })
    return result


def _extract_rightsizing(recs: list) -> list:
    result = []
    for r in recs[:5]:
        if not isinstance(r, dict):
            continue
        opts = r.get("recommendationOptions", r.get("options", [{}]))
        recommended = opts[0] if opts else {}
        result.append({
            "instance_id": r.get("instanceArn", r.get("instance_id", "")).split("/")[-1],
            "tipo_atual": r.get("currentInstanceType", r.get("current_type", "")),
            "tipo_recomendado": recommended.get("instanceType", recommended.get("type", "")),
            "economia_mensal_usd": recommended.get("estimatedMonthlySavings", {}).get("value",
                                   recommended.get("monthly_savings", "")),
        })
    return result


# ---------------------------------------------------------------------------
# ANTHROPIC CLIENT + CALL WITH CACHING
# ---------------------------------------------------------------------------

def _client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=settings.anthropic_api_key)


def _call(prompt: str, max_tokens: int = 16000) -> dict:
    """
    Calls Claude with the analysis prompt.
    System prompt is cached (ephemeral) to reduce latency on repeated calls.
    Extracts JSON from the response text.
    """
    client = _client()
    model = settings.anthropic_model
    last_exc: Exception | None = None

    for attempt in range(3):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.content[0].text
            stop_reason = response.stop_reason

            usage = response.usage
            print(f"[claude] attempt={attempt+1} stop={stop_reason} "
                  f"in={usage.input_tokens} out={usage.output_tokens} "
                  f"cache_read={getattr(usage, 'cache_read_input_tokens', 0)} "
                  f"cache_created={getattr(usage, 'cache_creation_input_tokens', 0)}")

            if stop_reason == "max_tokens":
                raise ValueError(
                    f"Resposta truncada pelo limite de tokens ({max_tokens}). "
                    "Reduza o prompt ou aumente max_tokens."
                )

            # Extract JSON from response (Claude may wrap in markdown)
            start = text.find("{")
            end = text.rfind("}") + 1
            if start == -1 or end == 0:
                raise ValueError("Nenhum JSON encontrado na resposta do Claude.")
            return json.loads(text[start:end])

        except json.JSONDecodeError as exc:
            last_exc = exc
            print(f"⚠ Erro de parsing JSON (tentativa {attempt + 1}): {exc}")
            if attempt < 2:
                time.sleep(5)
                continue
            raise
        except anthropic.RateLimitError as exc:
            last_exc = exc
            wait = 30 * (2 ** attempt)
            print(f"⏳ Rate limit atingido. Aguardando {wait}s...")
            time.sleep(wait)
            continue
        except Exception as exc:
            last_exc = exc
            raise

    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ANALYSIS FUNCTIONS
# ---------------------------------------------------------------------------

def analyze_finops(raw_data: dict) -> dict:
    monthly_totals = raw_data.get("cost_and_usage", {}).get("monthly_totals", [])
    sp_coverage = raw_data.get("savings_plans_coverage", {})
    ec2_metrics = raw_data.get("ec2_metrics", [])
    nat_gws = raw_data.get("nat_gateway_info", {})
    vpc_eps = raw_data.get("vpc_endpoints", {})
    rds = raw_data.get("rds_details", {})
    lam = raw_data.get("lambda_details", {})
    containers = raw_data.get("containers", {})
    ta = raw_data.get("trusted_advisor", {})
    anomalies = raw_data.get("cost_anomalies", {})
    usage_by_type = raw_data.get("cost_by_usage_type", {})
    linked_accounts = raw_data.get("linked_accounts", {})
    forecast = raw_data.get("cost_forecast_trend", {})

    overprovisioned = [
        m for m in ec2_metrics
        if m.get("rightsizing_signal") == "overprovisioned"
    ][:10]

    idle_lambdas = [
        f for f in lam.get("functions", [])
        if f.get("invocations_14d", 0) == 0
    ][:10]

    rds_underused = [
        db for db in rds.get("instances", [])
        if 0 < db.get("cpu_avg_14d_pct", 100) < 10
    ]

    unused = raw_data.get("unused_resources", {})
    tag_data = raw_data.get("cost_by_tag", {}).get("by_tag", {})
    tags_found = raw_data.get("cost_by_tag", {}).get("tags_found", [])

    summary = _sanitize({
        "account_id": raw_data.get("account_id"),
        "is_management_account": raw_data.get("is_management_account", False),
        "monthly_costs_last_6": monthly_totals[-6:],
        "forecast_next_month": raw_data.get("cost_and_usage", {}).get("forecast_next_month"),

        # --- NOVO: análise de tendência e forecast ---
        "cost_trend_analysis": forecast,

        # --- NOVO: breakdown por conta (Organizations) ---
        "linked_accounts": linked_accounts,

        # --- NOVO: custo por UsageType (granularidade do HTML) ---
        "cost_by_usage_type_top30": usage_by_type.get("top_items", [])[:30],
        "cost_by_service_with_usagetype": usage_by_type.get("by_service", {}),

        "unused_resources": {
            "unattached_volumes_count": len(unused.get("unattached_volumes", [])),
            "unused_eips_count": len(unused.get("unused_eips", [])),
            "old_snapshots_count": len(unused.get("old_snapshots", [])),
            "stopped_instances_count": len(unused.get("stopped_instances", [])),
            "idle_load_balancers_count": len(unused.get("idle_load_balancers", [])),
            "top_volumes": unused.get("unattached_volumes", [])[:5],
            "top_eips": unused.get("unused_eips", [])[:5],
        },
        "rightsizing_ec2_top5": raw_data.get("rightsizing", {}).get("ec2", [])[:5],
        "ec2_overprovisioned_by_cloudwatch": overprovisioned,
        "ri_recommendations_top5": raw_data.get("ri_recommendations", {}).get("reserved_instances", [])[:5],
        "savings_plans_recommendations_top3": raw_data.get("ri_recommendations", {}).get("savings_plans", [])[:3],
        "savings_plans_existing": {
            "coverage_percentage": sp_coverage.get("coverage", {}).get("coverage_percentage", 0),
            "on_demand_cost_not_covered_usd": sp_coverage.get("coverage", {}).get("on_demand_cost_usd", 0),
            "utilization_percentage": sp_coverage.get("utilization", {}).get("utilization_percentage", 0),
            "unused_commitment_usd_monthly": sp_coverage.get("utilization", {}).get("unused_commitment_usd", 0),
            "plans": sp_coverage.get("by_savings_plan", [])[:5],
        },
        "cost_by_tag": {
            "tags_found": tags_found,
            "by_tag": tag_data,
            "tagging_coverage_note": (
                f"Tags ativas: {', '.join(tags_found[:5]) if tags_found else 'nenhuma encontrada'}"
            ),
        },
        "nat_gateway": {
            "count": len(nat_gws.get("nat_gateways", [])),
            "total_monthly_cost_usd": nat_gws.get("total_monthly_cost_usd", 0),
            "gateways": nat_gws.get("nat_gateways", [])[:10],
        },
        "vpc_endpoints": {
            "vpcs_total": len(vpc_eps.get("vpcs", [])),
            "missing_s3_endpoint": vpc_eps.get("missing_s3_endpoint", []),
            "missing_dynamodb_endpoint": vpc_eps.get("missing_dynamodb_endpoint", []),
            "total_data_transfer_out_usd": vpc_eps.get("total_data_transfer_out_usd", 0),
            "data_transfer_by_usagetype": vpc_eps.get("data_transfer_by_usagetype", [])[:15],
            "vpcs_detail": vpc_eps.get("vpcs", []),
        },
        "rds": {
            "instance_count": len(rds.get("instances", [])),
            "total_monthly_cost_usd": rds.get("total_monthly_cost_usd", 0),
            "instances": rds.get("instances", [])[:10],
            "underused_instances": rds_underused,
            "old_manual_snapshots_count": len(rds.get("manual_snapshots_old", [])),
        },
        "lambda": {
            "total_function_count": lam.get("total_function_count", 0),
            "total_monthly_cost_usd": lam.get("total_monthly_cost_usd", 0),
            "top_10_by_invocations": lam.get("functions", [])[:10],
            "idle_functions_count": len(idle_lambdas),
        },
        "containers": {
            "ecs_cluster_count": len(containers.get("ecs_clusters", [])),
            "ecs_clusters": containers.get("ecs_clusters", [])[:5],
            "eks_cluster_count": len(containers.get("eks_clusters", [])),
            "eks_clusters": containers.get("eks_clusters", [])[:5],
        },
        "trusted_advisor": {
            "cost_optimizing": ta.get("cost_optimizing", [])[:10],
            "total_estimated_monthly_savings": ta.get("total_estimated_monthly_savings", 0),
            "available": ta.get("error") is None,
        },
        "cost_anomalies": {
            "count": len(anomalies.get("anomalies", [])),
            "total_anomalous_spend_usd": anomalies.get("total_anomalous_spend", 0),
            "top_anomalies": anomalies.get("anomalies", [])[:5],
            "available": anomalies.get("error") is None,
        },
        "s3": {
            "total_gb": raw_data.get("s3_costs", {}).get("total_size_gb", 0),
            "buckets_without_lifecycle": sum(
                1 for b in raw_data.get("s3_costs", {}).get("buckets", [])
                if not b.get("has_lifecycle")
            ),
        },
    })

    prompt = f"""Você é um especialista sênior em FinOps da consultoria.
Analise os dados financeiros desta conta AWS e retorne EXATAMENTE o JSON abaixo.
Todos os textos em Português do Brasil. Nomes de serviços AWS sempre em inglês.
Baseie cada afirmação nos dados reais fornecidos — sem generalidades.

═══════════════════════════════════════════════════════════════
DADOS DISPONÍVEIS — USE TODOS PARA ANÁLISE ESPECÍFICA
═══════════════════════════════════════════════════════════════

NÍVEL DE DETALHE ESPERADO (imite o exemplo abaixo):
  Serviço: Amazon EC2 — Custo: $1.826
  ├─ SAE1-BoxUsage:m6a.xlarge [sem SP] ............ $1.040
  ├─ SAE1-DataTransfer-Out-Bytes .................. $291
  ├─ BoxUsage:t2.xlarge [geração antiga] .......... $196
  Ação: Adquirir Compute Savings Plan 3 anos No Upfront ($1,20–1,40/h) → economia: $700–900/mês

cost_by_usage_type_top30: linhas de custo com granularidade UsageType — USE para identificar o ofensor exato dentro de cada serviço.
cost_by_service_with_usagetype: dicionário serviço → lista de usage_types ordenados por custo.

linked_accounts: se is_management_account=true, mostra breakdown por conta vinculada.

cost_trend_analysis: tendência dos últimos 6 meses, variação mês a mês, projeção e diagnóstico de quais serviços estão crescendo.

ec2_overprovisioned_by_cloudwatch: instâncias com CPU avg < 10% e max < 25% (últimos 14 dias).
savings_plans_existing: cobertura e utilização REAL dos Savings Plans comprados.
cost_by_tag: custo por tag de negócio; sem tags = pontuação baixa em Tagging.
nat_gateway: NAT Gateways, custo mensal e bytes processados.
vpc_endpoints: VPC Gateway Endpoints (S3, DynamoDB) — quais VPCs têm/não têm, custo total de data transfer, breakdown por usage type.
rds: instâncias RDS com CPU avg, storage, snapshots manuais antigos, e version_info.
lambda: funções com invocações/duração/erros, funções ociosas, runtime_info.
containers: clusters ECS e EKS com nodegroups e versão K8s.
trusted_advisor: checks de cost_optimizing com economia estimada.
cost_anomalies: anomalias detectadas pelo AWS nos últimos 30 dias.

═══════════════════════════════════════════════════════════════
ANÁLISE DE TENDÊNCIA E FORECAST (OBRIGATÓRIO)
═══════════════════════════════════════════════════════════════
Analise cost_trend_analysis e monthly_costs_last_6:
- A tendência é crescente, estável ou decrescente? Qual o % de variação mês a mês?
- Quais serviços estão puxando o crescimento? (use cost_by_usage_type para identificar)
- Se a tendência continuar, qual será o custo em 3 meses?
- Classifique: "alerta" (>15% crescimento), "atenção" (5-15%), "estável" (<5%), "otimizando" (queda)

═══════════════════════════════════════════════════════════════
ANÁLISE DE VERSÃO (CRÍTICO)
═══════════════════════════════════════════════════════════════
Cada instância RDS tem version_info.status (current | approaching_eol | extended_support | eol).
Cada função Lambda tem runtime_info.status (current | deprecated).
Cada cluster EKS tem version_info.status (current | eol).
Para itens NÃO "current": cite versão atual, latest, custo extra estimado.

═══════════════════════════════════════════════════════════════
MATURITY MODEL (OBRIGATÓRIO — 5 dimensões)
═══════════════════════════════════════════════════════════════
Crawl (0-3), Walk (4-6), Run (7-10).
- Tagging: baseado em cost_by_tag.tags_found
- Rightsizing: baseado em ec2_overprovisioned e rds.underused_instances
- Commitment Coverage: baseado em savings_plans_existing.coverage_percentage
- Waste Elimination: baseado em unused_resources
- Governance: baseado em trusted_advisor, cost_anomalies

═══════════════════════════════════════════════════════════════
ANÁLISE DE DATA TRANSFER (OBRIGATÓRIO SE HOUVER CUSTO > $10)
═══════════════════════════════════════════════════════════════
Use vpc_endpoints.data_transfer_by_usagetype para identificar os tipos de tráfego.
Correlacione com vpc_endpoints.missing_s3_endpoint e missing_dynamodb_endpoint.

REGRAS DE DIAGNÓSTICO (aplique em ordem):
1. Se vpc_endpoints.missing_s3_endpoint não está vazio E há custo de DataTransfer-Out-Bytes:
   → PROVÁVEL CAUSA: tráfego S3 saindo pelo NAT/internet em vez de usar Gateway Endpoint gratuito.
   → Cite cada VPC afetada (vpc_id, região). Gateway Endpoint S3 custa $0 — é quick win imediato.

2. Se vpc_endpoints.missing_dynamodb_endpoint não está vazio E há custo de DataTransfer:
   → Tráfego DynamoDB pode estar passando pelo NAT. Adicionar Gateway Endpoint DynamoDB ($0).

3. Se usage_type contém "Regional-Bytes" ou "APN1-DataTransfer" (cross-AZ/cross-region):
   → Tráfego cross-AZ ou cross-region — investigar arquitetura (consolidar AZs, usar cache).

4. Se nat_gateway.total_monthly_cost_usd > $30 E há missing_s3_endpoint:
   → NAT caro + sem endpoint S3 é combinação clássica. Estimar economia: uma parte significativa
      do custo NAT pode ser eliminada com Gateway Endpoints.

5. Se cost_by_service_with_usagetype tem "CloudFront" com DataTransfer alto:
   → Avaliar se origem está no S3 com acesso direto (sem OAC/OAI) causando double-billing.

Regras de especificidade:
- Cite db_id, function name, usage_type, account_id sempre que relevante
- Mencione % de CPU real para EC2 e RDS com baixa utilização
- Se nat_gateway.total_monthly_cost_usd > 50, analise custo vs uso
- Cite o ofensor dominante dentro de cada serviço usando usage_type

Retorne este JSON (todos os campos obrigatórios):

{{
  "executive_summary": "3-4 frases sobre o estado financeiro real. Cite custo atual, projeção, tendência e os 2 maiores problemas com dados concretos (usage type, $ e recurso).",
  "total_potential_savings": 0.0,
  "savings_breakdown": {{
    "unused_resources": 0.0,
    "rightsizing": 0.0,
    "commitments": 0.0,
    "storage": 0.0,
    "version_upgrade": 0.0
  }},
  "cost_health_score": 0,
  "cost_health_label": "Crítico|Ruim|Regular|Bom|Excelente",
  "top_services_to_optimize": ["serviço1", "serviço2", "serviço3"],

  "cost_trend": {{
    "status": "alerta|atenção|estável|otimizando",
    "variacao_mom_pct": 0.0,
    "custo_medio_ultimos_3m": 0.0,
    "projecao_3_meses_usd": 0.0,
    "servicos_crescendo": [
      {{
        "servico": "Nome do serviço",
        "usage_type_ofensor": "UsageType específico",
        "crescimento_pct": 0.0,
        "custo_atual_usd": 0.0
      }}
    ],
    "diagnostico": "Parágrafo explicando por que os custos estão se comportando assim, com dados concretos de usage_type e contas."
  }},

  "service_breakdown": [
    {{
      "servico": "Nome do serviço AWS",
      "custo_periodo_usd": 0.0,
      "custo_mensal_projetado_usd": 0.0,
      "percentual_do_total": 0.0,
      "severidade": "critico|alto|medio|baixo",
      "ofensor_principal": "UsageType específico que domina o custo",
      "ofensor_custo_usd": 0.0,
      "conta_principal": "account_id ou nome da conta (se Organizations)",
      "itens_usage_type": [
        {{"usage_type": "...", "cost_usd": 0.0, "flag": "sem RI|sem SP|geração antiga|idle|"}}
      ],
      "acao_recomendada": "Ação específica com economia estimada em $",
      "economia_estimada_usd": 0.0
    }}
  ],

  "data_transfer_analysis": {{
    "total_data_transfer_out_usd": 0.0,
    "diagnostico": "Explicação da causa raiz do data transfer: origem do tráfego (EC2→internet, NAT→S3 sem endpoint, cross-AZ, cross-region). Cite usage_types e valores concretos.",
    "causa_provavel": "sem_endpoint_s3|sem_endpoint_dynamodb|cross_az|cross_region|saida_internet|multiplas|nao_aplicavel",
    "vpcs_sem_s3_endpoint": [],
    "vpcs_sem_dynamodb_endpoint": [],
    "recomendacoes": [
      {{
        "acao": "Descrição da ação (ex: Criar VPC Gateway Endpoint para S3 na vpc-xxx em sa-east-1)",
        "economia_estimada_usd": 0.0,
        "esforco": "baixo|medio|alto",
        "custo_endpoint": "$0 (Gateway Endpoints são gratuitos)"
      }}
    ]
  }},

  "maturity_model": {{
    "overall_maturity": "Crawl|Walk|Run",
    "overall_score": 0,
    "dimensions": {{
      "tagging": {{"score": 0, "level": "Crawl|Walk|Run", "justification": "Baseada nos dados reais"}},
      "rightsizing": {{"score": 0, "level": "Crawl|Walk|Run", "justification": "Baseada nos dados reais"}},
      "commitment_coverage": {{"score": 0, "level": "Crawl|Walk|Run", "justification": "Baseada nos dados reais"}},
      "waste_elimination": {{"score": 0, "level": "Crawl|Walk|Run", "justification": "Baseada nos dados reais"}},
      "governance": {{"score": 0, "level": "Crawl|Walk|Run", "justification": "Baseada nos dados reais"}}
    }},
    "next_step": "A ação mais importante e específica para avançar de nível"
  }},

  "version_analysis": [
    {{
      "resource_type": "RDS|Lambda|EKS",
      "resource_id": "identificador",
      "current_version": "versão atual",
      "latest_version": "versão mais recente",
      "status": "extended_support|approaching_eol|deprecated|eol",
      "extended_support_active": true,
      "extended_support_cost_note": "ex: $0.12/vCPU-hora extra",
      "estimated_extra_cost_monthly_usd": 0.0,
      "upgrade_urgency": "imediato|planejado|monitorar",
      "upgrade_note": "Recomendação específica"
    }}
  ],

  "cost_anomalies_found": [
    {{
      "service": "Nome do serviço AWS",
      "start_date": "YYYY-MM-DD",
      "total_impact_usd": 0.0,
      "expected_spend": 0.0,
      "actual_spend": 0.0,
      "descricao": "O que aconteceu, qual serviço e qual o impacto"
    }}
  ],

  "quick_wins": [
    {{
      "title": "Título específico com dado real (usage_type ou resource ID)",
      "description": "Descrição com resource ID, tipo, valor em $",
      "category": "compute|storage|network|database|commitments|version_upgrade|anomaly|other",
      "estimated_savings_monthly": 0.0,
      "effort_hours": 0,
      "risk": "low|medium|high",
      "steps": ["passo 1", "passo 2"],
      "aws_cli_command": "comando aws cli opcional"
    }}
  ],

  "projects": [
    {{
      "title": "Título do projeto",
      "description": "Descrição com impacto financeiro real em $",
      "category": "compute|storage|network|database|architecture|commitments|version_upgrade",
      "estimated_savings_monthly": 0.0,
      "effort_weeks": 0,
      "risk": "low|medium|high",
      "business_value": "Valor de negócio além do custo",
      "steps": ["passo 1", "passo 2", "passo 3"]
    }}
  ],

  "service_suggestions": [
    {{
      "current_service": "Serviço atual",
      "suggested_service": "Serviço AWS sugerido",
      "reason": "Por que trocar, com dado concreto de custo",
      "estimated_savings_percentage": 0,
      "migration_complexity": "low|medium|high"
    }}
  ],

  "tagging_compliance_note": "Nota sobre conformidade de tagging com base nos dados de cost_by_tag"
}}

DADOS AWS:
{json.dumps(summary, indent=2, default=str)}"""

    return _call(prompt, max_tokens=16000)


def analyze_security(raw_data: dict) -> dict:
    cf_waf = raw_data.get("cloudfront_waf", {})
    containers = raw_data.get("containers", {})
    ta = raw_data.get("trusted_advisor", {})
    rds = raw_data.get("rds_details", {})
    lam = raw_data.get("lambda_details", {})

    rds_version_issues = [
        db for db in rds.get("instances", [])
        if db.get("version_info", {}).get("status") in ("extended_support", "approaching_eol", "eol")
    ]
    lambda_version_issues = [
        f for f in lam.get("functions", [])
        if f.get("runtime_info", {}).get("status") == "deprecated"
    ]
    eks_version_issues = [
        c for c in containers.get("eks_clusters", [])
        if c.get("version_info", {}).get("status") in ("eol",)
    ]

    summary = _sanitize({
        "account_id": raw_data.get("account_id"),
        "is_management_account": raw_data.get("is_management_account", False),
        "linked_accounts": raw_data.get("linked_accounts", {}),
        "iam": {
            "root_mfa_enabled": raw_data.get("iam_findings", {}).get("root_mfa_enabled"),
            "users_without_mfa": raw_data.get("iam_findings", {}).get("users_without_mfa", []),
            "users_with_old_keys_top10": raw_data.get("iam_findings", {}).get("users_with_old_keys", [])[:10],
            "overprivileged_policies": raw_data.get("iam_findings", {}).get("overprivileged_policies", []),
            "inactive_users_top10": raw_data.get("iam_findings", {}).get("inactive_users", [])[:10],
            "password_policy": raw_data.get("iam_findings", {}).get("password_policy", {}),
        },
        "s3": {
            "public_buckets": raw_data.get("s3_security", {}).get("public_buckets", []),
            "unencrypted_buckets": raw_data.get("s3_security", {}).get("unencrypted_buckets", []),
        },
        "network": {
            "open_security_groups_top10": raw_data.get("network_security", {}).get("open_security_groups", [])[:10],
            "vpcs_without_flow_logs": raw_data.get("network_security", {}).get("vpcs_without_flow_logs", []),
            "cloudtrail_status": raw_data.get("network_security", {}).get("cloudtrail_status", {}),
            "regions_without_guardduty": raw_data.get("network_security", {}).get("regions_without_guardduty", []),
        },
        "encryption": {
            "unencrypted_ebs_count": len(raw_data.get("encryption_findings", {}).get("unencrypted_ebs", [])),
            "unencrypted_rds": raw_data.get("encryption_findings", {}).get("unencrypted_rds", []),
        },
        "cloudfront_waf": {
            "distribution_count": len(cf_waf.get("distributions", [])),
            "distributions_without_waf": cf_waf.get("distributions_without_waf", []),
            "waf_acl_count": len(cf_waf.get("waf_acls", [])),
            "waf_acls": cf_waf.get("waf_acls", [])[:10],
        },
        "containers_security": {
            "eks_clusters": containers.get("eks_clusters", [])[:5],
            "ecs_clusters": containers.get("ecs_clusters", [])[:5],
        },
        "version_issues": {
            "rds_extended_support_or_eol": rds_version_issues,
            "lambda_deprecated_runtimes": lambda_version_issues,
            "eks_eol_versions": eks_version_issues,
        },
        "trusted_advisor_security": ta.get("security", [])[:10],
        "compliance": {
            "security_hub_findings_top10": raw_data.get("compliance_findings", {}).get("security_hub", [])[:10],
            "config_rules_failing_top10": raw_data.get("compliance_findings", {}).get("config_rules_failing", [])[:10],
        },
    })

    prompt = f"""Você é um especialista sênior em segurança AWS da consultoria.
Analise os dados de segurança desta conta AWS e retorne EXATAMENTE o JSON abaixo.
Todos os textos em Português do Brasil. Nomes de serviços AWS sempre em inglês.
Baseie cada afirmação nos dados reais — sem generalidades.

ANÁLISE OBRIGATÓRIA DE VERSÕES (inclua em findings e quick_wins):
- version_issues.rds_extended_support_or_eol: instâncias RDS em versões com suporte pago ou EOL
- version_issues.lambda_deprecated_runtimes: funções Lambda com runtime deprecated
- version_issues.eks_eol_versions: clusters EKS com Kubernetes fora de suporte
- cloudfront_waf.distributions_without_waf: distribuições CloudFront sem WAF
- trusted_advisor_security: achados do Trusted Advisor

Para cada version_issue:
- Cite o resource ID, versão atual e versão mais recente
- Classifique a severidade: "critical" se deprecated/eol, "high" se extended_support, "medium" se approaching_eol
- Mencione datas concretas

Retorne este JSON:

{{
  "executive_summary": "2-3 frases sobre a postura de segurança. Cite os riscos mais críticos com dados concretos.",
  "security_score": 0,
  "security_label": "Crítico|Ruim|Regular|Bom|Excelente",
  "critical_findings_count": 0,
  "high_findings_count": 0,
  "medium_findings_count": 0,
  "low_findings_count": 0,
  "findings": [
    {{
      "id": "unique-id",
      "title": "Título específico em PT-BR",
      "description": "Descrição com resource ID e dado real",
      "severity": "critical|high|medium|low",
      "category": "iam|s3|network|encryption|compliance|monitoring|versioning|waf",
      "affected_resources": ["resource-id-1"],
      "risk_description": "O que pode acontecer se não corrigir",
      "remediation": "Como corrigir com passos concretos",
      "quick_fix": true
    }}
  ],
  "quick_wins": [
    {{
      "title": "Título em PT-BR",
      "description": "Descrição com resource ID",
      "severity": "critical|high|medium",
      "effort_hours": 0,
      "steps": ["passo 1", "passo 2"],
      "aws_cli_command": "comando opcional"
    }}
  ],
  "projects": [
    {{
      "title": "Título do projeto em PT-BR",
      "description": "Descrição",
      "category": "iam|network|encryption|compliance|architecture|versioning|waf",
      "severity": "critical|high|medium",
      "effort_weeks": 0,
      "business_impact": "Impacto de negócio",
      "steps": ["passo 1", "passo 2"]
    }}
  ],
  "compliance_notes": {{
    "cis_benchmark": "Nota sobre conformidade CIS AWS Benchmark",
    "well_architected": "Nota sobre AWS Well-Architected Framework — Security Pillar"
  }},
  "positive_findings": ["Coisas que a conta está fazendo bem"]
}}

DADOS DE SEGURANÇA AWS:
{json.dumps(summary, indent=2, default=str)}"""

    return _call(prompt, max_tokens=16000)


def generate_assessment_narrative(raw_data: dict, finops_analysis: dict) -> dict:
    iam        = raw_data.get("iam_findings", {})
    network    = raw_data.get("network_security", {})
    encryption = raw_data.get("encryption_findings", {})
    compliance = raw_data.get("compliance_findings", {})
    s3_costs   = raw_data.get("s3_costs", {})
    s3_sec     = raw_data.get("s3_security", {})
    unused     = raw_data.get("unused_resources", {})
    ri_recs    = raw_data.get("ri_recommendations", {})
    cost_data  = raw_data.get("cost_and_usage", {})
    rightsizing = raw_data.get("rightsizing", {})
    sp_coverage = raw_data.get("savings_plans_coverage", {})
    ec2_metrics = raw_data.get("ec2_metrics", [])
    cost_by_tag = raw_data.get("cost_by_tag", {})
    nat_gws    = raw_data.get("nat_gateway_info", {})
    rds        = raw_data.get("rds_details", {})
    lam        = raw_data.get("lambda_details", {})

    sh_findings = compliance.get("security_hub", [])
    sh_critical = [f for f in sh_findings if isinstance(f, dict) and
                   f.get("Severity", {}).get("Label") == "CRITICAL"][:5]
    sh_high     = [f for f in sh_findings if isinstance(f, dict) and
                   f.get("Severity", {}).get("Label") == "HIGH"][:5]

    summary = _sanitize({
        "account_id": raw_data.get("account_id"),
        "analyzed_regions": raw_data.get("analyzed_regions", []),
        "is_management_account": raw_data.get("is_management_account", False),
        "linked_accounts": raw_data.get("linked_accounts", {}),
        "cost_trend": finops_analysis.get("cost_trend", {}),

        "iam": {
            "root_mfa_enabled": iam.get("root_mfa_enabled"),
            "password_policy": iam.get("password_policy", {}),
            "users_without_mfa": _extract_iam_users(iam.get("users_without_mfa", [])),
            "users_with_old_keys": _extract_iam_users(iam.get("users_with_old_keys", [])),
            "inactive_users": _extract_iam_users(iam.get("inactive_users", [])),
            "overprivileged_policies": iam.get("overprivileged_policies", [])[:5],
        },
        "vpc_e_rede": {
            "security_groups_criticos": _extract_sg_details(network.get("open_security_groups", [])),
            "vpcs_sem_flow_logs": _extract_vpc_details(network.get("vpcs_without_flow_logs", [])),
            "regioes_sem_guardduty": network.get("regions_without_guardduty", []),
            "cloudtrail": network.get("cloudtrail_status", {}),
        },
        "ebs": {
            "volumes_nao_anexados": _extract_ebs_details(unused.get("unattached_volumes", [])),
            "volumes_sem_criptografia": _extract_ebs_details(encryption.get("unencrypted_ebs", [])),
        },
        "s3": {
            "buckets": _extract_s3_details(s3_costs.get("buckets", []), s3_sec.get("public_buckets", [])),
            "total_gb": round(s3_costs.get("total_size_gb", 0), 1),
        },
        "ec2_paradas": _extract_stopped_ec2(unused.get("stopped_instances", [])),
        "snapshots_antigos": _extract_snapshots(unused.get("old_snapshots", [])),
        "rightsizing": _extract_rightsizing(rightsizing.get("ec2", [])),
        "savings_plans": {
            "planos_ativos": ri_recs.get("savings_plans", [])[:3],
            "recomendacoes_ri": ri_recs.get("reserved_instances", [])[:3],
        },
        "savings_plans_coverage": {
            "coverage_pct": sp_coverage.get("coverage", {}).get("coverage_percentage", 0),
            "on_demand_nao_coberto_usd": sp_coverage.get("coverage", {}).get("on_demand_cost_usd", 0),
            "utilization_pct": sp_coverage.get("utilization", {}).get("utilization_percentage", 0),
            "compromisso_nao_usado_usd_mensal": sp_coverage.get("utilization", {}).get("unused_commitment_usd", 0),
            "planos_individuais": sp_coverage.get("by_savings_plan", [])[:3],
        },
        "ec2_overprovisioned": [
            m for m in ec2_metrics if m.get("rightsizing_signal") == "overprovisioned"
        ][:8],
        "custo_por_tag": cost_by_tag.get("by_tag", {}),
        "nat_gateway": {
            "count": len(nat_gws.get("nat_gateways", [])),
            "total_monthly_cost_usd": nat_gws.get("total_monthly_cost_usd", 0),
            "gateways": nat_gws.get("nat_gateways", [])[:8],
        },
        "rds": {
            "instance_count": len(rds.get("instances", [])),
            "total_monthly_cost_usd": rds.get("total_monthly_cost_usd", 0),
            "instances": rds.get("instances", [])[:8],
            "old_manual_snapshots": rds.get("manual_snapshots_old", [])[:5],
        },
        "lambda": {
            "total_function_count": lam.get("total_function_count", 0),
            "total_monthly_cost_usd": lam.get("total_monthly_cost_usd", 0),
            "top_functions": lam.get("functions", [])[:8],
            "idle_functions": [
                f for f in lam.get("functions", []) if f.get("invocations_14d", 0) == 0
            ][:8],
        },
        "custo_e_uso": {
            "totais_ultimos_3_meses": cost_data.get("monthly_totals", [])[-3:],
            "top_servicos_por_custo": cost_data.get("by_service", [])[:10],
            "previsao_proximo_mes": cost_data.get("forecast_next_month"),
        },
        "compliance": {
            "security_hub_total": len(sh_findings),
            "security_hub_criticos": [f.get("Title", str(f)) if isinstance(f, dict) else str(f) for f in sh_critical],
            "security_hub_altos": [f.get("Title", str(f)) if isinstance(f, dict) else str(f) for f in sh_high],
            "config_rules_falhando": len(compliance.get("config_rules_failing", [])),
        },
        "finops_resumo": {
            "executive_summary": finops_analysis.get("executive_summary", ""),
            "economia_potencial_usd": finops_analysis.get("total_potential_savings", 0),
            "cost_health_score": finops_analysis.get("cost_health_score", 0),
            "cost_health_label": finops_analysis.get("cost_health_label", ""),
            "breakdown_economia": finops_analysis.get("savings_breakdown", {}),
            "top_servicos_otimizar": finops_analysis.get("top_services_to_optimize", []),
        },
    })

    prompt = f"""Você é um arquiteto de soluções AWS sênior da consultoria.
Gere um Assessment Report de arquitetura cloud em Português do Brasil.

════════════════════════════════════════════
REGRAS DE ESTILO — LEIA COM ATENÇÃO
════════════════════════════════════════════

TOM E PROFUNDIDADE:
- Escreva como um especialista que analisou a conta pessoalmente.
- Cada bullet deve contar uma história completa: O QUE + ONDE (recurso/ID) + POR QUE importa + QUAL o risco ou impacto.
- PROIBIDO bullets de uma linha com apenas um fato ("MFA desabilitado: sim").
- PROIBIDO linguagem genérica sem dado concreto.

EXEMPLOS CORRETO vs ERRADO:
  ❌ ERRADO:  "Security Groups com portas abertas: 2"
  ✅ CORRETO: "Identificados os Security Groups sg-0abc (porta 22 → 0.0.0.0/0) e sg-0def (porta 3306 → 0.0.0.0/0), expondo SSH e banco de dados diretamente à internet."

  ❌ ERRADO:  "Volumes EBS não anexados: 2"
  ✅ CORRETO: "Identificados 2 volumes EBS não anexados — vol-0abc (50 GB, gp2, $5/mês) e vol-0def (100 GB, gp3, $8/mês) — totalizando $13/mês em custo desnecessário."

════════════════════════════════════════════
ESTRUTURA OBRIGATÓRIA
════════════════════════════════════════════
1. Escopo / 2. Cenário Atual / 3. Melhorias / 4. Recomendações de Serviços /
5. Considerações Gerais / 6. Pain Points / 7. Oportunidades / 8. Referências

Nomes de serviços AWS sempre em inglês. Todo texto descritivo em PT-BR.
PROIBIDO adicionar seções fora da lista acima.

════════════════════════════════════════════
DADOS AWS COLETADOS
════════════════════════════════════════════
{json.dumps(summary, indent=2, default=str)}

════════════════════════════════════════════
RETORNE EXATAMENTE ESTE JSON
════════════════════════════════════════════

{{
  "cenario_atual": {{
    "intro": "Parágrafo de 3-4 linhas com ID da conta, principais serviços, vulnerabilidades críticas.",
    "vulnerabilidades_criticas": ["Vulnerabilidade 1 com recurso e risco específico", "Vulnerabilidade 2"],
    "arquitetura": "Parágrafo descrevendo topologia atual com dados reais."
  }},
  "camadas": {{
    "computacao": null, "dados_cache": null, "seguranca_waf": null,
    "seguranca_hub": null, "seguranca_guardduty": null, "rede": null,
    "iam": null, "ebs": null, "cloudwatch": null, "snapshots": null,
    "savings_plans": null, "s3": null
  }},
  "melhorias": {{
    "computacao": null, "dados_cache": null, "seguranca_waf": null,
    "rede": null, "iam": null, "ebs": null, "s3": null
  }},
  "landing_zone": {{
    "usar_organizations": false,
    "contas": [
      {{"nome": "Conta Management", "funcao_principal": "...", "recursos_comuns": ["..."], "beneficio": "..."}},
      {{"nome": "Conta Network", "funcao_principal": "...", "recursos_comuns": ["..."], "beneficio": "..."}},
      {{"nome": "Conta Development", "funcao_principal": "...", "recursos_comuns": ["..."], "beneficio": "..."}},
      {{"nome": "Conta Production", "funcao_principal": "...", "recursos_comuns": ["..."], "beneficio": "..."}}
    ],
    "otimizacao_governanca": null
  }},
  "outros_servicos": [
    {{"nome": "AWS Backup", "intro": "Análise do estado atual de backup.", "bullets": ["Bullet específico 1", "Bullet 2"]}}
  ],
  "consideracoes": {{
    "introducao": "Parágrafo resumindo pontos de melhoria com referência a achados concretos.",
    "organizacao_governanca": ["Bullet específico.", "Segundo bullet."],
    "vpc": ["Bullet sobre VPC.", "Segundo bullet."],
    "seguranca": ["Bullet sobre segurança.", "Segundo bullet."],
    "acesso": ["Bullet sobre acesso/IAM.", "Segundo bullet."],
    "performance_finops": ["Bullet sobre custo/performance.", "Segundo bullet."]
  }},
  "pain_points": ["Ação crítica imediata com recurso e risco concreto", "Segunda ação"],
  "oportunidades": ["Projeto de modernização com ganho esperado", "Segunda oportunidade"]
}}

INSTRUÇÃO FINAL: Para cada campo null em camadas/melhorias — se há dados reais → substitua por:
{{"titulo": "Nome da Camada", "bullets": ["Bullet rico.", "Segundo bullet."]}}
Se não há dados suficientes → mantenha null."""

    return _call(prompt, max_tokens=16000)


def generate_combined_analysis(finops_analysis: dict, security_analysis: dict, raw_data: dict) -> dict:
    rds = raw_data.get("rds_details", {})
    ec2_metrics = raw_data.get("ec2_metrics", [])
    lam = raw_data.get("lambda_details", {})
    cf_waf = raw_data.get("cloudfront_waf", {})

    overprovisioned_ec2 = [
        m for m in ec2_metrics if m.get("rightsizing_signal") == "overprovisioned"
    ][:5]
    underused_rds = [
        db for db in rds.get("instances", []) if 0 < db.get("cpu_avg_14d_pct", 100) < 10
    ][:5]
    sec_findings = security_analysis.get("findings", [])
    critical_high_findings = [
        f for f in sec_findings if f.get("severity") in ("critical", "high")
    ][:8]

    summary = _sanitize({
        "is_management_account": raw_data.get("is_management_account", False),
        "linked_accounts_summary": raw_data.get("linked_accounts", {}).get("accounts", [])[:5],
        "finops": {
            "score": finops_analysis.get("cost_health_score", 0),
            "label": finops_analysis.get("cost_health_label", ""),
            "potential_savings_usd": finops_analysis.get("total_potential_savings", 0),
            "savings_breakdown": finops_analysis.get("savings_breakdown", {}),
            "cost_trend": finops_analysis.get("cost_trend", {}),
            "service_breakdown": finops_analysis.get("service_breakdown", [])[:5],
            "version_issues": finops_analysis.get("version_analysis", [])[:5],
            "anomalies": finops_analysis.get("cost_anomalies_found", [])[:3],
            "maturity_model": finops_analysis.get("maturity_model", {}),
        },
        "security": {
            "score": security_analysis.get("security_score", 0),
            "label": security_analysis.get("security_label", ""),
            "critical": security_analysis.get("critical_findings_count", 0),
            "high": security_analysis.get("high_findings_count", 0),
            "medium": security_analysis.get("medium_findings_count", 0),
            "top_findings": critical_high_findings,
        },
        "recursos_caros": {
            "ec2_overprovisioned": overprovisioned_ec2,
            "rds_underused": underused_rds,
            "cloudfront_sem_waf": cf_waf.get("distributions_without_waf", [])[:5],
        },
        "quick_wins_finops_top3": finops_analysis.get("quick_wins", [])[:3],
        "quick_wins_security_top3": security_analysis.get("quick_wins", [])[:3],
    })

    prompt = f"""Você é um especialista sênior em AWS da consultoria.
Analise os dados COMBINADOS de FinOps e Segurança desta conta AWS.

OBJETIVO PRINCIPAL: Identificar recursos que são SIMULTANEAMENTE caros E inseguros —
esses têm prioridade máxima por representar risco financeiro E de segurança.

Exemplo de prioridade máxima: instância EC2 oversized (CPU avg 3%, custo alto) com porta 22
aberta para 0.0.0.0/0 = desperdício de dinheiro + superfície de ataque crítica.

DADOS:
{json.dumps(summary, indent=2, default=str)}

Retorne EXATAMENTE este JSON em Português do Brasil:

{{
  "resumo_executivo": "3-4 frases combinando custo, segurança e tendência. Cite valores concretos e impacto para o negócio.",
  "score_combinado": 0,
  "nivel_maturidade": "Inicial|Em Desenvolvimento|Definido|Gerenciado|Otimizando",
  "matriz_prioridades": [
    {{
      "rank": 1,
      "titulo": "Título específico com dado real (resource ID ou usage_type)",
      "tipo": "finops|segurança|ambos",
      "impacto": "crítico|alto|médio",
      "custo_mensal_usd": 0.0,
      "risco_descricao": "O risco de segurança concreto (se aplicável)",
      "custo_descricao": "O custo ou desperdício concreto em $ (se aplicável)",
      "descricao": "Descrição completa com resource IDs, valores e riscos — mínimo 2 frases",
      "proximos_passos": ["Passo 1 acionável", "Passo 2"]
    }}
  ],
  "proximas_acoes": [
    "Ação 1 imediata e específica (quem faz o quê em quanto tempo)",
    "Ação 2",
    "Ação 3"
  ]
}}

Gere no mínimo 5 itens na matriz_prioridades. Priorize recursos que aparecem em AMBAS as análises."""

    return _call(prompt, max_tokens=16000)
