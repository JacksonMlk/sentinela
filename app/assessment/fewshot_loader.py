"""
Carrega arquivos JSON de few-shot do diretório app/assessment/fewshot/.
Retorna None silenciosamente se o arquivo não existe ou é inválido.
"""
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

FEWSHOT_DIR = Path(__file__).parent / "fewshot"


@lru_cache(maxsize=32)
def load_fewshot(slug: str) -> Optional[dict]:
    """
    Loads a JSON few-shot file for the given slug.
    Cached to avoid re-reading disk on every section generation.
    Returns None if file is missing or invalid.
    """
    path = FEWSHOT_DIR / f"{slug}.json"
    if not path.is_file():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load fewshot for {slug}: {e}")
        return None
