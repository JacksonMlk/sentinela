"""
Prowler runner — executes `prowler aws` as a subprocess and stores findings in DB.
Requires prowler installed: pip install prowler  (or system package)
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

_PROWLER_CMD = shutil.which("prowler") or "prowler"

# Severity mapping from Prowler OCSF format (severity_id → label)
_OCSF_SEV: dict[int, str] = {
    0: "informational",
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

# In-memory tracker: client_id -> {"status": ..., "started_at": ..., "report_id": ...}
_active_prowler: dict[int, dict] = {}
_prowler_lock = threading.Lock()


def prowler_available() -> bool:
    return shutil.which("prowler") is not None


def get_prowler_state(client_id: int) -> dict | None:
    with _prowler_lock:
        return _active_prowler.get(client_id)


def run_prowler_background(
    client_id: int,
    report_id: int,
    role_arn: str,
    regions: list[str],
    db_session_factory,
) -> None:
    """Launch a Prowler scan in a daemon thread."""
    with _prowler_lock:
        if client_id in _active_prowler and _active_prowler[client_id].get("status") == "running":
            return  # already running
        _active_prowler[client_id] = {
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "report_id": report_id,
        }

    t = threading.Thread(
        target=_prowler_job,
        args=(client_id, report_id, role_arn, regions, db_session_factory),
        daemon=True,
        name=f"prowler-{client_id}",
    )
    t.start()


def _prowler_job(
    client_id: int,
    report_id: int,
    role_arn: str,
    regions: list[str],
    db_session_factory,
) -> None:
    db = db_session_factory()
    try:
        from app.models import AnalysisReport

        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if not report:
            return

        report.prowler_status = "running"
        report.prowler_started_at = datetime.utcnow()
        db.commit()

        with tempfile.TemporaryDirectory(prefix="prowler_") as tmpdir:
            cmd = [
                _PROWLER_CMD, "aws",
                "--role", role_arn,
                "--output-formats", "json-ocsf",
                "--output-directory", tmpdir,
                "--no-banner",
                "--quiet",
            ]
            if regions:
                cmd += ["-f", ",".join(regions)]

            logger.info(f"Prowler starting for client {client_id}: {' '.join(cmd[:6])}...")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=7200,  # 2h max
            )

            logger.info(f"Prowler finished (rc={proc.returncode}) for client {client_id}")

            findings = _parse_output(tmpdir)

        # Refresh report from DB before writing results
        db.expire_all()
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if report:
            report.prowler_findings = findings
            report.prowler_status = "completed"
            report.prowler_completed_at = datetime.utcnow()
            db.commit()

        with _prowler_lock:
            _active_prowler[client_id] = {
                "status": "completed",
                "report_id": report_id,
                "started_at": _active_prowler.get(client_id, {}).get("started_at"),
            }

    except subprocess.TimeoutExpired:
        logger.warning(f"Prowler timeout for client {client_id}")
        db.expire_all()
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if report:
            report.prowler_status = "failed"
            report.prowler_findings = {"error": "Timeout — scan excedeu 2 horas"}
            db.commit()
        with _prowler_lock:
            _active_prowler[client_id] = {"status": "failed", "report_id": report_id}

    except Exception as exc:
        logger.exception(f"Prowler job failed for client {client_id}: {exc}")
        try:
            db.expire_all()
            report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
            if report:
                report.prowler_status = "failed"
                report.prowler_findings = {"error": str(exc)[:500]}
                db.commit()
        except Exception:
            pass
        with _prowler_lock:
            _active_prowler[client_id] = {"status": "failed", "report_id": report_id}

    finally:
        db.close()


def _parse_output(output_dir: str) -> dict:
    """Parse prowler JSON-OCSF output into {critical: [...], high: [...], ...}."""
    buckets: dict[str, list] = {
        "critical": [], "high": [], "medium": [], "low": [], "informational": [],
    }

    json_file = _find_json(output_dir)
    if not json_file:
        logger.warning("Prowler: no JSON output file found in %s", output_dir)
        return buckets

    try:
        with open(json_file, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as exc:
        logger.warning("Prowler: failed to parse JSON: %s", exc)
        return buckets

    items = raw if isinstance(raw, list) else raw.get("findings", [])
    for item in items:
        sev_id = item.get("severity_id", 0)
        severity = _OCSF_SEV.get(sev_id, "informational")

        status = (item.get("status_code") or item.get("status") or "").upper()
        if status not in ("FAIL", "FAILED"):
            continue

        finding_obj = item.get("finding") or {}
        remediation = (item.get("remediation") or {})

        resource = item.get("resources") or [{}]
        resource = resource[0] if isinstance(resource, list) and resource else resource

        buckets[severity].append({
            "title": finding_obj.get("title") or item.get("description") or "—",
            "description": item.get("message") or item.get("description") or "—",
            "resource_type": resource.get("type", ""),
            "resource_uid": resource.get("uid", ""),
            "region": item.get("region") or (item.get("cloud") or {}).get("region", ""),
            "remediation": remediation.get("desc", "") or remediation.get("recommendation", ""),
            "check_id": finding_obj.get("uid", "") or item.get("check_id", ""),
        })

    return buckets


def _find_json(directory: str) -> str | None:
    for fname in os.listdir(directory):
        if fname.endswith(".ocsf.json") or fname.endswith(".json"):
            return os.path.join(directory, fname)
    # recurse one level (prowler creates subdirectory)
    for entry in os.scandir(directory):
        if entry.is_dir():
            found = _find_json(entry.path)
            if found:
                return found
    return None
