"""
Catálogo declarativo de seções possíveis no Assessment Report.

Cada entrada tem:
- slug: chave única (usada como key em Assessment.secoes_servicos).
- title: título que aparece no DOCX como heading da seção.
- applicable(raw_data): True se essa seção deve aparecer para esse cliente.
- extractor: nome (string) da função em extractors.py que extrai os dados dessa seção.

A ORDEM da lista é a ordem em que as seções aparecem no DOCX.

Princípio: o catálogo decide o que existe ANTES de chamar o LLM.
O LLM nunca recebe dados de serviço que o cliente não tem — então não
tem como inventar uma seção EKS para cliente sem EKS.
"""
from typing import Callable, TypedDict


class SectionSpec(TypedDict):
    slug: str
    title: str
    applicable: Callable[[dict], bool]
    extractor: str  # nome da função em app.assessment.extractors


SECTIONS_CATALOG: list[SectionSpec] = [
    {
        "slug": "ec2",
        "title": "Camada de Computação – EC2",
        "applicable": lambda raw: bool(
            raw.get("ec2_metrics")
            or raw.get("unused_resources", {}).get("stopped_instances")
            or any(
                "EC2" in str(item.get("usage_type", ""))
                for item in raw.get("cost_by_usage_type", {}).get("top_items", [])
            )
        ),
        "extractor": "extract_ec2",
    },
    {
        "slug": "ecs",
        "title": "Camada de Computação – ECS",
        "applicable": lambda raw: bool(raw.get("containers", {}).get("ecs_clusters")),
        "extractor": "extract_ecs",
    },
    {
        "slug": "eks",
        "title": "Camada de Computação – EKS",
        "applicable": lambda raw: bool(raw.get("containers", {}).get("eks_clusters")),
        "extractor": "extract_eks",
    },
    {
        "slug": "lambda",
        "title": "Camada de Computação – Lambda",
        "applicable": lambda raw: bool(
            raw.get("lambda_details", {}).get("total_function_count")
            or raw.get("lambda_details", {}).get("functions")
        ),
        "extractor": "extract_lambda",
    },
    {
        "slug": "rds",
        "title": "Banco de Dados – RDS",
        "applicable": lambda raw: bool(raw.get("rds_details", {}).get("instances")),
        "extractor": "extract_rds",
    },
    {
        "slug": "s3",
        "title": "Armazenamento – S3",
        "applicable": lambda raw: bool(
            raw.get("s3_costs", {}).get("buckets")
            or raw.get("s3_findings", {})
        ),
        "extractor": "extract_s3",
    },
    {
        "slug": "iam",
        "title": "Identidade e Acesso – IAM",
        "applicable": lambda raw: bool(raw.get("iam_findings")),
        "extractor": "extract_iam",
    },
    {
        "slug": "vpc",
        "title": "Rede – VPC e Security Groups",
        "applicable": lambda raw: bool(
            raw.get("network_security")
            or raw.get("vpc_endpoints")
        ),
        "extractor": "extract_vpc",
    },
    {
        "slug": "nat_gateway",
        "title": "Rede – NAT Gateway",
        "applicable": lambda raw: bool(
            raw.get("nat_gateway_info", {}).get("nat_gateways")
        ),
        "extractor": "extract_nat_gateway",
    },
    {
        "slug": "encryption",
        "title": "Criptografia e Proteção de Dados",
        "applicable": lambda raw: bool(
            raw.get("encryption_findings", {}).get("unencrypted_ebs")
            or raw.get("encryption_findings", {}).get("unencrypted_rds")
            or raw.get("unused_resources", {}).get("unattached_volumes")
        ),
        "extractor": "extract_encryption",
    },
    {
        "slug": "cloudfront_waf",
        "title": "Entrega de Conteúdo – CloudFront e WAF",
        "applicable": lambda raw: bool(raw.get("cloudfront_waf", {}).get("distributions")),
        "extractor": "extract_cloudfront_waf",
    },
    {
        "slug": "savings_plans",
        "title": "FinOps – Savings Plans e Reserved Instances",
        "applicable": lambda raw: bool(
            raw.get("savings_plans_coverage")
            or raw.get("ri_recommendations", {}).get("reserved_instances")
            or raw.get("ri_recommendations", {}).get("savings_plans")
        ),
        "extractor": "extract_savings_plans",
    },
    {
        "slug": "compliance",
        "title": "Conformidade – Security Hub e Config",
        "applicable": lambda raw: bool(
            raw.get("compliance_findings", {}).get("security_hub")
            or raw.get("compliance_findings", {}).get("config_rules_failing")
        ),
        "extractor": "extract_compliance",
    },
]


def get_applicable_sections(raw_data: dict) -> list[SectionSpec]:
    """Retorna apenas as seções aplicáveis para o raw_data fornecido, em ordem de catálogo."""
    return [s for s in SECTIONS_CATALOG if s["applicable"](raw_data)]
