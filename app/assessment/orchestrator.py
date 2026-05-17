"""
Orquestrador top-level: produz um Assessment validado a partir de raw_data.
Paraleliza chamadas Claude por seção (ThreadPoolExecutor, max_workers=4).

Modo multi-conta: quando raw_data contém accounts_data[], gera seções por
conta separadamente e retorna Assessment.secoes_por_conta preenchido.
Modo single-conta: comportamento original com Assessment.secoes_servicos.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from app.assessment.extractors import get_extractor
from app.assessment.globals_generator import generate_globals
from app.assessment.schemas import Assessment, AccountSections, ConsideracoesGerais
from app.assessment.section_generator import generate_section
from app.assessment.sections_catalog import get_applicable_sections

logger = logging.getLogger(__name__)


def _generate_sections_for_raw(raw_data: dict, max_workers: int) -> dict:
    """
    Generate all applicable ServiceSections for a single account's raw_data.
    Returns dict[slug, ServiceSection]. Failed sections are skipped silently.
    """
    applicable = get_applicable_sections(raw_data)
    section_results: dict = {}

    if not applicable:
        return section_results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_slug: dict = {}
        for spec in applicable:
            try:
                extractor_fn = get_extractor(spec["slug"])
            except KeyError:
                logger.warning(f"[assessment] no extractor for slug={spec['slug']}")
                continue

            section_data = extractor_fn(raw_data)
            if not section_data:
                logger.info(f"[assessment] empty data for {spec['slug']} — skipping")
                continue

            future = executor.submit(
                generate_section,
                spec["slug"],
                spec["title"],
                section_data,
            )
            future_to_slug[future] = spec["slug"]

        for future in as_completed(future_to_slug):
            slug = future_to_slug[future]
            try:
                section = future.result()
                if section is not None:
                    section_results[slug] = section
            except Exception as e:
                logger.error(f"[assessment] section {slug} raised: {e}")

    return section_results


def _build_account_label(account: dict) -> str:
    """Build a readable label like 'PROD – 011528294225' from account data."""
    account_id = account.get("account_id", "?")
    # Use alias if available in linked_accounts summary
    alias = account.get("account_alias") or account.get("name") or ""
    if alias:
        return f"{alias} – {account_id}"
    return account_id


def generate_assessment(
    raw_data: dict,
    finops_analysis: Optional[dict] = None,
    max_workers: int = 4,
) -> Assessment:
    """
    Top-level: produces a validated Assessment from raw_data.

    Multi-account (accounts_data present with >1 accounts):
        Generates sections per account → Assessment.secoes_por_conta.

    Single-account:
        Generates flat sections → Assessment.secoes_servicos (original behavior).

    Never raises — always returns an Assessment (possibly partial).
    """
    accounts_data = [
        acc for acc in raw_data.get("accounts_data", [])
        if not acc.get("error")  # skip accounts that failed collection
    ]
    is_multi_account = len(accounts_data) > 1

    # ── Multi-account path ──────────────────────────────────────────────────
    if is_multi_account:
        logger.info(f"[assessment] multi-account mode — {len(accounts_data)} accounts")
        secoes_por_conta: list[AccountSections] = []
        all_sections_summary: dict = {}

        for account in accounts_data:
            account_id = account.get("account_id", "?")
            account_label = _build_account_label(account)
            logger.info(f"[assessment] generating sections for account {account_id}")

            sections = _generate_sections_for_raw(account, max_workers)
            logger.info(f"[assessment] account {account_id} sections: {list(sections.keys())}")

            secoes_por_conta.append(AccountSections(
                account_id=account_id,
                account_label=account_label,
                sections=sections,
            ))
            # merge into summary for globals (prefix to avoid key collision)
            for slug, section in sections.items():
                all_sections_summary[f"{account_id[:6]}_{slug}"] = section

        try:
            globals_data = generate_globals(raw_data, all_sections_summary, finops_analysis)
        except Exception as e:
            logger.error(f"[assessment] globals generation failed: {e}")
            globals_data = _default_globals()

        return Assessment(
            escopo_intro=globals_data["escopo_intro"],
            cenario_intro=globals_data["cenario_intro"],
            vulnerabilidades_criticas=globals_data["vulnerabilidades_criticas"],
            arquitetura_atual=globals_data["arquitetura_atual"],
            secoes_por_conta=secoes_por_conta,
            secoes_servicos={},
            landing_zone=globals_data["landing_zone"],
            consideracoes=globals_data["consideracoes"],
            pain_points=globals_data["pain_points"],
            oportunidades=globals_data["oportunidades"],
        )

    # ── Single-account path (original behavior) ─────────────────────────────
    logger.info("[assessment] single-account mode")
    section_results = _generate_sections_for_raw(raw_data, max_workers)
    logger.info(f"[assessment] sections generated: {list(section_results.keys())}")

    try:
        globals_data = generate_globals(raw_data, section_results, finops_analysis)
    except Exception as e:
        logger.error(f"[assessment] globals generation failed: {e}")
        globals_data = _default_globals()

    return Assessment(
        escopo_intro=globals_data["escopo_intro"],
        cenario_intro=globals_data["cenario_intro"],
        vulnerabilidades_criticas=globals_data["vulnerabilidades_criticas"],
        arquitetura_atual=globals_data["arquitetura_atual"],
        secoes_por_conta=[],
        secoes_servicos=section_results,
        landing_zone=globals_data["landing_zone"],
        consideracoes=globals_data["consideracoes"],
        pain_points=globals_data["pain_points"],
        oportunidades=globals_data["oportunidades"],
    )


def _default_globals() -> dict:
    return {
        "escopo_intro": "",
        "cenario_intro": "",
        "vulnerabilidades_criticas": [],
        "arquitetura_atual": "",
        "consideracoes": ConsideracoesGerais(),
        "landing_zone": None,
        "pain_points": [],
        "oportunidades": [],
    }
