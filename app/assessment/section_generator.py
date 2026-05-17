"""
Geração de UMA ServiceSection via Claude com validação Pydantic + retry + anti-brand
+ injeção de few-shot quando disponível.
"""
import json
import logging
import time
from typing import Optional

import anthropic
from pydantic import ValidationError

from app.assessment.fewshot_loader import load_fewshot
from app.assessment.prompts import SYSTEM_PROMPT_SECTION, USER_PROMPT_SECTION_TEMPLATE
from app.assessment.schemas import ServiceSection
from app.config import get_settings

logger = logging.getLogger(__name__)


def _client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=get_settings().anthropic_api_key)


def _extract_json(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError("Nenhum JSON encontrado na resposta.")
    return json.loads(text[start:end])


def _violates_brand(text: str) -> Optional[str]:
    """Returns offending term if text contains a blocked brand."""
    settings = get_settings()
    lower = text.lower()
    for term in settings.brand_blocklist_list():
        if term and term in lower:
            return term
    return None


def _build_fewshot_block(slug: str) -> str:
    """Returns the <example_section> block or empty string if no few-shot exists."""
    example = load_fewshot(slug)
    if not example:
        return ""
    return (
        "\n\n<example_section>\n"
        "Este é um exemplo do estilo, profundidade e estrutura esperados (de outro cliente).\n"
        "Imite o padrão, mas NÃO copie resource IDs nem frases literais.\n\n"
        f"{json.dumps(example, ensure_ascii=False, indent=2)}\n"
        "</example_section>"
    )


def generate_section(
    slug: str,
    title: str,
    section_data: dict,
    max_retries: int = 3,
) -> Optional[ServiceSection]:
    """
    Generate a single ServiceSection via Claude.
    Loads few-shot from disk when available.
    Retries with error feedback on JSON/validation/brand failures.
    Returns None if all retries exhausted.
    """
    if not section_data:
        logger.info(f"[section:{slug}] extractor returned empty — skipping")
        return None

    settings = get_settings()
    model = settings.anthropic_model
    client = _client()

    fewshot_block = _build_fewshot_block(slug)
    base_prompt = USER_PROMPT_SECTION_TEMPLATE.format(
        section_title=title,
        fewshot_block=fewshot_block,
        section_data_json=json.dumps(section_data, separators=(",", ":"), default=str),
    )

    correction_note = ""

    for attempt in range(max_retries):
        prompt = base_prompt + correction_note

        try:
            response = client.messages.create(
                model=model,
                max_tokens=3000,
                system=[{
                    "type": "text",
                    "text": SYSTEM_PROMPT_SECTION,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.content[0].text
            stop_reason = response.stop_reason

            usage = response.usage
            logger.info(
                f"[section:{slug}] attempt={attempt+1} stop={stop_reason} "
                f"in={usage.input_tokens} out={usage.output_tokens} "
                f"fewshot={'yes' if fewshot_block else 'no'}"
            )

            if stop_reason == "max_tokens":
                correction_note = (
                    "\n\n<correction>\nSua resposta foi TRUNCADA. "
                    "Seja mais conciso (menos bullets, mais densos).\n</correction>"
                )
                continue

            offender = _violates_brand(text)
            if offender:
                correction_note = (
                    f"\n\n<correction>\nSua resposta mencionou o termo proibido "
                    f"'{offender}'. Reescreva sem nomes de marcas ou consultorias.\n</correction>"
                )
                continue

            raw = _extract_json(text)
            raw.setdefault("presente", True)

            section = ServiceSection.model_validate(raw)
            return section

        except json.JSONDecodeError as e:
            logger.warning(f"[section:{slug}] JSON parse failed attempt {attempt+1}: {e}")
            correction_note = (
                f"\n\n<correction>\nSua resposta NÃO era JSON válido. Erro: {e}. "
                f"Retorne APENAS um objeto JSON.\n</correction>"
            )
        except ValidationError as e:
            logger.warning(f"[section:{slug}] Pydantic validation failed attempt {attempt+1}: {e}")
            errors_summary = "; ".join(
                f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}"
                for err in e.errors()[:5]
            )
            correction_note = (
                f"\n\n<correction>\nValidação do schema falhou: {errors_summary}. "
                f"Corrija e retorne apenas campos do schema.\n</correction>"
            )
        except anthropic.RateLimitError:
            wait = 30 * (2 ** attempt)
            logger.warning(f"[section:{slug}] rate limit, sleeping {wait}s")
            time.sleep(wait)
        except Exception as e:
            logger.error(f"[section:{slug}] unexpected error attempt {attempt+1}: {e}")
            correction_note = ""

    logger.error(f"[section:{slug}] all {max_retries} attempts failed — skipping")
    return None
