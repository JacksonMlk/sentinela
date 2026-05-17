"""
Pydantic schemas para o Assessment Report.

A estrutura espelha as seções do documento final que será gerado:
- Cada serviço analisado vira uma `ServiceSection` em `Assessment.secoes_servicos`,
  indexada pelo slug do catálogo (ex: "ecs", "rds").
- Seções globais (escopo, landing zone, considerações, pain points, oportunidades)
  ficam em campos dedicados do `Assessment`.
"""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Literal


Severity = Literal["critical", "high", "medium", "low", "info"]


class GuideListItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    severity: Optional[Severity] = None


class ServiceSection(BaseModel):
    """
    Uma subseção de serviço dentro de 'Cenário Atual'.
    Ex: ECS, EKS, RDS, IAM, S3, VPC, etc.
    """
    model_config = ConfigDict(extra="forbid")
    presente: bool = True
    intro: str = Field(..., description="Parágrafo introdutório de 2-3 frases descrevendo o estado atual.")
    seguranca: list[str] = Field(default_factory=list, description="Bullets sobre achados de segurança.")
    arquitetura: list[str] = Field(default_factory=list, description="Bullets sobre topologia/arquitetura.")
    guide_list: list[GuideListItem] = Field(default_factory=list, description="Checklist de boas práticas.")
    melhorias: list[str] = Field(default_factory=list, description="Recomendações acionáveis.")


class ContaLandingZone(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nome: str
    funcao_principal: str
    recursos_comuns: list[str] = Field(default_factory=list)
    beneficio: str = ""


class LandingZone(BaseModel):
    model_config = ConfigDict(extra="forbid")
    usar_organizations: bool = False
    contas: list[ContaLandingZone] = Field(default_factory=list)
    otimizacao_governanca: list[str] = Field(default_factory=list)


class ConsideracoesGerais(BaseModel):
    model_config = ConfigDict(extra="forbid")
    introducao: str = ""
    organizacao_governanca: list[str] = Field(default_factory=list)
    vpc: list[str] = Field(default_factory=list)
    seguranca: list[str] = Field(default_factory=list)
    acesso: list[str] = Field(default_factory=list)
    performance_finops: list[str] = Field(default_factory=list)


class AccountSections(BaseModel):
    """Seções de serviço de uma conta AWS (usado em modo multi-conta)."""
    model_config = ConfigDict(extra="forbid")
    account_id: str
    account_label: str  # e.g. "PROD – 011528294225"
    sections: dict[str, ServiceSection] = Field(default_factory=dict)


class Assessment(BaseModel):
    """Estrutura completa do Assessment Report."""
    model_config = ConfigDict(extra="forbid")
    escopo_intro: str = ""
    cenario_intro: str = ""
    vulnerabilidades_criticas: list[str] = Field(default_factory=list)
    arquitetura_atual: str = ""
    # Multi-account: seções agrupadas por conta (preferred when accounts_data present)
    secoes_por_conta: list[AccountSections] = Field(default_factory=list)
    # Single-account fallback: chave = slug do catálogo, valor = conteúdo da seção
    secoes_servicos: dict[str, ServiceSection] = Field(default_factory=dict)
    landing_zone: Optional[LandingZone] = None
    consideracoes: ConsideracoesGerais = Field(default_factory=ConsideracoesGerais)
    pain_points: list[str] = Field(default_factory=list)
    oportunidades: list[str] = Field(default_factory=list)
