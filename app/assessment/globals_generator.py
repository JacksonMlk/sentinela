"""
Geração dos campos globais do Assessment.
"""
import json
import logging
import time
from typing import Optional

import anthropic
from pydantic import ValidationError

from app.assessment.prompts import SYSTEM_PROMPT_GLOBALS, USER_PROMPT_GLOBALS_TEMPLATE
from app.assessment.schemas import ServiceSection, LandingZone, ConsideracoesGerais
from app.assessment.section_generator import _client, _extract_json, _violates_brand
from app.config import get_settings

logger = logging.getLogger(__name__)


def generate_globals(
    raw_data: dict,
    sections: dict[str, ServiceSection],
    finops_analysis: Optional[dict] = None,
    max_retries: int = 3,
) -> dict:
    """
    Generate the global narrative fields of the Assessment.
    On failure, returns defaults instead of raising.
    """
    settings = get_settings()
    model = settings.anthropic_model
    client = _client()

    sections_summary = {
        slug: {
            "intro": s.intro,
            "seguranca_count": len(s.seguranca),
            "melhorias_count": len(s.melhorias),
            "top_seguranca": s.seguranca[:2],
            "top_melhorias": s.melhorias[:2],
        }
        for slug, s in sections.items()
    }

    raw_summary = {
        "account_id": raw_data.get("account_id"),
        "is_management_account": raw_data.get("is_management_account", False),
        "analyzed_regions": raw_data.get("analyzed_regions", []),
        "monthly_cost": raw_data.get("cost_and_usage", {}).get("monthly_totals", [])[-1:],
        "cost_trend": (finops_analysis or {}).get("cost_trend", {}),
        "iam": {
            "root_mfa_enabled": raw_data.get("iam_findings", {}).get("root_mfa_enabled"),
            "users_without_mfa_count": len(raw_data.get("iam_findings", {}).get("users_without_mfa", [])),
        },
        "linked_accounts_count": len(raw_data.get("linked_accounts", {}).get("accounts", []) or []),
        "finops_summary": (finops_analysis or {}).get("executive_summary", ""),
        "potential_savings_usd": (finops_analysis or {}).get("total_potential_savings", 0),
    }

    base_prompt = USER_PROMPT_GLOBALS_TEMPLATE.format(
        raw_data_json=json.dumps(raw_summary, separators=(",", ":"), default=str),
        sections_summary_json=json.dumps(sections_summary, separators=(",", ":"), default=str),
    )

    defaults = {
        "escopo_intro": "",
        "cenario_intro": "",
        "vulnerabilidades_criticas": [],
        "arquitetura_atual": "",
        "consideracoes": ConsideracoesGerais(),
        "landing_zone": None,
        "pain_points": [],
        "oportunidades": [],
    }

    correction_note = ""

    for attempt in range(max_retries):
        prompt = base_prompt + correction_note

        try:
            response = client.messages.create(
                model=model,
                max_tokens=4000,
                system=[{
                    "type": "text",
                    "text": SYSTEM_PROMPT_GLOBALS,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.content[0].text

            offender = _violates_brand(text)
            if offender:
                correction_note = (
                    f"\n\n<correction>\nMencionou termo proibido '{offender}'. "
                    f"Reescreva sem nomes de marcas.\n</correction>"
                )
                continue

            raw = _extract_json(text)
            consideracoes = ConsideracoesGerais.model_validate(raw.get("consideracoes") or {})
            landing_zone_raw = raw.get("landing_zone")
            landing_zone = LandingZone.model_validate(landing_zone_raw) if landing_zone_raw else None

            return {
                "escopo_intro": raw.get("escopo_intro", "") or "",
                "cenario_intro": raw.get("cenario_intro", "") or "",
                "vulnerabilidades_criticas": list(raw.get("vulnerabilidades_criticas") or []),
                "arquitetura_atual": raw.get("arquitetura_atual", "") or "",
                "consideracoes": consideracoes,
                "landing_zone": landing_zone,
                "pain_points": list(raw.get("pain_points") or []),
                "oportunidades": list(raw.get("oportunidades") or []),
            }

        except (json.JSONDecodeError, ValidationError) as e:
            logger.warning(f"[globals] attempt {attempt+1} failed: {e}")
            correction_note = (
                f"\n\n<correction>\nValidação falhou: {str(e)[:300]}. "
                f"Corrija e retorne apenas campos do schema.\n</correction>"
            )
        except anthropic.RateLimitError:
            wait = 30 * (2 ** attempt)
            time.sleep(wait)
        except Exception as e:
            logger.error(f"[globals] unexpected error attempt {attempt+1}: {e}")

    logger.error("[globals] all retries failed — returning defaults")
    return defaults
