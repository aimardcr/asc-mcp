import importlib
import logging

from asc_mcp.service import AndroidAnalysisService, diff_artifacts


def initialize_worker() -> None:
    for name in (
        "json",
        "multiprocessing",
        "urllib.request",
        "http.client",
        "email.message",
        "tempfile",
        "bz2",
        "lzma",
        "shutil",
        "random",
        "androguard.core.apk",
    ):
        importlib.import_module(name)
    from loguru import logger

    logger.remove()
    logging.getLogger("androguard").disabled = True


def execute(operation: str, payload: dict) -> dict:
    if operation == "diff":
        return diff_artifacts(**payload)
    path = payload.pop("artifact_path")
    artifact_type = payload.pop("artifact_type")
    capabilities = payload.pop("capabilities")
    max_workers = payload.pop("max_workers", 4)
    service = AndroidAnalysisService(
        path,
        artifact_type=artifact_type,
        capabilities=capabilities,
        max_workers=max_workers,
    )
    handler = getattr(service, operation, None)
    if handler is None or operation.startswith("_"):
        raise ValueError("Unknown analysis operation")
    return handler(**payload)
