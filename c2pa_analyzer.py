"""Isolated adapter for the official c2pa-python Reader API."""

from __future__ import annotations

import importlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
MAX_C2PA_JSON_BYTES = 512_000


def _limited(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "[maximum nesting reached]"
    if isinstance(value, dict):
        return {
            str(key)[:120]: _limited(item, depth + 1)
            for key, item in list(value.items())[:100]
            if not any(secret in str(key).lower() for secret in ("private_key", "token", "password"))
        }
    if isinstance(value, list):
        return [_limited(item, depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:2_000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:2_000]


def _validation_buckets(value: Any) -> dict[str, list[Any]]:
    results: dict[str, list[Any]] = {
        "success": [],
        "failure": [],
        "informational": [],
        "unclassified": [],
    }
    status_names = {
        "success": "success",
        "successful": "success",
        "failure": "failure",
        "failures": "failure",
        "error": "failure",
        "errors": "failure",
        "informational": "informational",
        "info": "informational",
    }

    def visit(item: Any, status: str | None = None) -> None:
        if isinstance(item, dict):
            if status is not None and "code" in item:
                results[status].append(_limited(item))
                return
            for key, child in item.items():
                child_status = status_names.get(str(key).lower(), status)
                visit(child, child_status)
        elif isinstance(item, list):
            for child in item:
                visit(child, status)
        elif item is not None:
            results[status or "unclassified"].append(_limited(item))

    visit(value)
    return results


def _validation_codes(results: list[Any]) -> set[str]:
    codes: set[str] = set()
    for result in results:
        if isinstance(result, dict) and isinstance(result.get("code"), str):
            codes.add(result["code"])
    return codes


def analyze_c2pa(path: Path) -> dict[str, Any]:
    """Read and validate embedded credentials with the official SDK."""
    try:
        sdk = importlib.import_module("c2pa")
    except (ImportError, OSError) as exc:
        logger.warning("C2PA SDK unavailable: %s", type(exc).__name__)
        return {"status": "UNAVAILABLE", "reason": "The C2PA SDK is unavailable."}

    try:
        settings = sdk.Settings.from_dict({"verify": {"remote_manifest_fetch": False}})
        context_manager = sdk.Context(settings)
        with context_manager as context:
            try:
                with sdk.Reader(str(path), context=context) as reader:
                    raw_store = reader.json()
            except Exception as exc:
                reader_error = exc
            else:
                reader_error = None
    except Exception as exc:
        logger.warning("C2PA SDK initialization failed: %s", type(exc).__name__)
        return {
            "status": "UNAVAILABLE",
            "reason": f"The C2PA SDK could not initialize ({type(exc).__name__}).",
        }

    if reader_error is not None:
        exc = reader_error
        logger.info("C2PA Reader did not return a report: %s", type(exc).__name__)
        message = str(exc).lower()
        exception_name = type(exc).__name__.lower()
        if (
            "manifestnotfound" in exception_name
            or any(marker in message for marker in ("manifest not found", "no manifest", "no c2pa"))
        ):
            return {
                "status": "NOT DETECTED",
                "credential": "NOT DETECTED",
                "reason": "The C2PA SDK did not find an embedded manifest.",
                "remote_retrieval": "DISABLED",
            }
        return {
            "status": "INCONCLUSIVE",
            "credential": "NOT VERIFIED",
            "reason": f"The SDK could not produce a manifest report ({type(exc).__name__}).",
        }

    if not isinstance(raw_store, str) or len(raw_store.encode("utf-8")) > MAX_C2PA_JSON_BYTES:
        return {"status": "INCONCLUSIVE", "reason": "The manifest report exceeded the size limit."}
    try:
        store = json.loads(raw_store)
    except json.JSONDecodeError as exc:
        logger.info("C2PA Reader returned malformed JSON: %s", type(exc).__name__)
        return {
            "status": "INCONCLUSIVE",
            "reason": "The C2PA SDK returned malformed manifest JSON.",
        }

    if not isinstance(store, dict):
        return {"status": "INCONCLUSIVE", "reason": "The C2PA manifest report has an unexpected shape."}

    active_name = store.get("active_manifest")
    validation_status = store.get("validation_status")
    validation_issues = store.get("validation_results", store.get("validation_issues"))
    if validation_issues is None:
        validation_issues = validation_status
    validation = _validation_buckets(validation_issues)
    if not active_name:
        if validation["failure"]:
            return {
                "status": "INVALID",
                "credential": "PRESENT",
                "active_manifest": None,
                "validation_status": _limited(validation_status),
                "validation_issues": validation["failure"],
                "remote_retrieval": "DISABLED",
                "limitation": "SDK validation errors do not prove that the image itself is fake.",
            }
        if validation["unclassified"]:
            return {
                "status": "INCONCLUSIVE",
                "credential": "NOT VERIFIED",
                "active_manifest": None,
                "validation_status": _limited(validation_status),
                "validation_issues": [],
                "unclassified_validation_results": validation["unclassified"],
                "remote_retrieval": "DISABLED",
            }
        return {
            "status": "NOT DETECTED",
            "credential": "NOT DETECTED",
            "active_manifest": None,
            "manifests": [],
            "validation_issues": [],
            "remote_retrieval": "DISABLED",
        }

    manifests = store.get("manifests")
    manifests = manifests if isinstance(manifests, dict) else {}
    active = manifests.get(active_name, {})
    active = active if isinstance(active, dict) else {}
    if validation["failure"]:
        status = "INVALID"
    else:
        status = "PRESENT"

    signature = active.get("signature_info", active.get("signature", {}))
    signature = signature if isinstance(signature, dict) else {}
    successful_codes = _validation_codes(validation["success"])
    failure_codes = _validation_codes(validation["failure"])
    signature_integrity = (
        "VERIFIED"
        if "claimSignature.validated" in successful_codes
        else "INVALID"
        if "claimSignature.validated" in failure_codes
        else "NOT VERIFIED"
    )
    certificate_trust = (
        "VERIFIED"
        if "signingCredential.trusted" in successful_codes
        else "NOT TRUSTED (SDK reported a validation failure)"
        if "signingCredential.trusted" in failure_codes
        else "NOT VERIFIED"
    )
    return {
        "status": status,
        "credential": "PRESENT",
        "active_manifest": active_name,
        "manifest_title": active.get("title"),
        "claim_generator": active.get("claim_generator"),
        "claim_generator_info": _limited(active.get("claim_generator_info", [])),
        "signature_issuer": signature.get("issuer"),
        "signature_timestamp": signature.get("time", signature.get("timestamp")),
        "signature_integrity": signature_integrity,
        "certificate_trust": certificate_trust,
        "signer_identity": "NOT VERIFIED",
        "signature": _limited(signature),
        "assertions": _limited(active.get("assertions", [])),
        "ingredients": _limited(active.get("ingredients", [])),
        "validation_status": _limited(validation_status),
        "validation_issues": validation["failure"],
        "validation_successes": validation["success"],
        "validation_informational": validation["informational"],
        "unclassified_validation_results": validation["unclassified"],
        "manifests": _limited(manifests),
        "remote_retrieval": "DISABLED",
        "limitation": (
            "A parsed manifest is not by itself proof of signature integrity, certificate trust, "
            "or signer identity. See SDK validation results above."
        ),
    }
