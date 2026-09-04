"""Development-only authenticated HTTP adapter for the authoritative ledger.

This module owns transport validation and identity-v1 encoding only.  Claim,
lease, fence, recovery, and state-transition decisions remain in ActionLedger.
It intentionally has no provider execution or language-specific client API.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import ipaddress
import json
import math
import os
import re
import socket
import stat
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mycelium.action_ledger import ActionLedger
from mycelium.decision import Decision
from mycelium.ledger_storage import FileLedgerStorage
from mycelium.outcome_emit import FileOutcomeStorage, OutcomeEmitter
from mycelium.transition import (
    RetryPermission,
    SideEffectBoundary,
    SideEffectClass,
    ToolCapability,
    ToolTransitionBinding,
)

PROTOCOL_VERSION = "1.0"
IDENTITY_VERSION = "1"
CANONICALIZATION_VERSION = "jcs-1"
MAX_PREIMAGE_BYTES = 65536
MAX_BODY_BYTES = 1024 * 1024
MAX_PATH_BYTES = 1024
TOKEN_BYTES = 43  # base64url encoding of 256 random bits


def openapi_document() -> dict[str, Any]:
    """Return the small, language-neutral OpenAPI description for this adapter."""
    paths = {
        "/health": {
            "get": {"security": [], "responses": {"200": {"description": "Process health"}}}
        },
        "/v1/openapi.json": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "This OpenAPI document"}},
            }
        },
        "/v1/capabilities": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Capabilities"}},
            }
        },
        "/v1/identities/derive": {
            "post": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Derived identity"}},
            }
        },
        "/v1/effects/claim": {
            "post": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Claim disposition"}},
            }
        },
    }
    for action in ("renew", "boundary", "provider-reference", "reconcile", "complete", "fail"):
        paths[f"/v1/effects/{{effect_id}}/{action}"] = {
            "post": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Ledger projection"}},
            }
        }
    paths["/v1/effects/{effect_id}"] = {
        "get": {
            "security": [{"bearerAuth": []}],
            "responses": {"200": {"description": "Ledger projection"}},
        }
    }
    for path_item in paths.values():
        if "post" in path_item:
            path_item["post"]["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/JsonObject"}
                    }
                },
            }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Mycelium Development Sidecar",
            "version": PROTOCOL_VERSION,
            "description": (
                "Development-only, loopback-only JSON adapter. It makes no "
                "exactly-once or hostile-client guarantee."
            ),
        },
        "servers": [{"url": "http://127.0.0.1"}],
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "JsonObject": {"type": "object", "additionalProperties": True},
                "Error": {
                    "type": "object",
                    "required": [
                        "code",
                        "message",
                        "retryable",
                        "state_may_have_changed",
                        "effect_may_have_happened",
                    ],
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                        "retryable": {"type": "boolean"},
                        "state_may_have_changed": {"type": "boolean"},
                        "effect_may_have_happened": {"type": "boolean"},
                        "caller_action_required": {"type": "boolean"},
                    },
                }
            },
        },
        "x-stable-error-codes": [
            "INVALID_REQUEST",
            "INVALID_JSON",
            "DUPLICATE_OBJECT_KEY",
            "REQUEST_TOO_LARGE",
            "RESPONSE_TOO_LARGE",
            "NOT_FOUND",
            "AUTHENTICATION_REQUIRED",
            "AUTHENTICATION_INVALID",
            "TENANT_MISMATCH",
            "APPLICATION_MISMATCH",
            "IDENTITY_REQUIRED",
            "EFFECT_ID_MISMATCH",
            "UNSUPPORTED_IDENTITY_VERSION",
            "UNSUPPORTED_CANONICALIZATION_VERSION",
            "IDENTITY_PREIMAGE_TOO_LARGE",
            "UNSUPPORTED_VALUE_TYPE",
            "NON_FINITE_NUMBER",
            "NON_CANONICAL_NUMBER",
            "INTEGER_OUT_OF_RANGE",
            "INVALID_UNICODE",
            "NON_CANONICAL_DECIMAL",
            "INVALID_DECIMAL",
            "INVALID_URL",
            "OWNER_REQUIRED",
            "FENCE_REQUIRED",
            "ACTIVE_OWNER",
            "STALE_FENCE",
            "LEASE_LOST",
            "INVALID_TRANSITION",
            "POLICY_DENIED",
            "RECONCILIATION_UNAVAILABLE",
            "INTERNAL_PROTOCOL_ERROR",
        ],
        "paths": paths,
    }


class SidecarError(ValueError):
    """Safe protocol error with a stable code and HTTP status."""

    def __init__(self, code: str, message: str, *, status: int = 400, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.retryable = retryable


def _effect_path_segment(value: str) -> str:
    try:
        decoded = urllib.parse.unquote(value, errors="strict")
    except UnicodeDecodeError as exc:
        raise SidecarError("INVALID_REQUEST", "effect ID path is invalid") from exc
    if "/" in decoded or "\\" in decoded:
        raise SidecarError("INVALID_REQUEST", "effect ID path is invalid")
    return decoded


def _validate_structure(value: Any, *, depth: int = 0) -> None:
    if depth > 100:
        raise SidecarError("UNSUPPORTED_VALUE_TYPE", "JSON nesting is too deep")
    if isinstance(value, list):
        if len(value) > 10000:
            raise SidecarError("UNSUPPORTED_VALUE_TYPE", "JSON array is too large")
        for item in value:
            _validate_structure(item, depth=depth + 1)
    elif isinstance(value, dict):
        if len(value) > 1000:
            raise SidecarError("UNSUPPORTED_VALUE_TYPE", "JSON object is too large")
        for key, item in value.items():
            if len(key.encode("utf-8", "strict")) > 1024:
                raise SidecarError("UNSUPPORTED_VALUE_TYPE", "JSON key is too large")
            _validate_structure(item, depth=depth + 1)


def _validate_unicode(value: Any) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SidecarError("INVALID_UNICODE", "string is not valid Unicode") from exc
    elif isinstance(value, list):
        for item in value:
            _validate_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode(key)
            _validate_unicode(item)


def _jcs(value: Any) -> str:
    """Serialize the jcs-1 JSON value subset without language fallbacks."""
    _validate_unicode(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SidecarError("NON_FINITE_NUMBER", "non-finite numbers are not supported")
        raise SidecarError("NON_CANONICAL_NUMBER", "floating-point values are not supported")
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise SidecarError("INTEGER_OUT_OF_RANGE", "integer is outside the safe range")
    if isinstance(value, dict):
        ordered = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_jcs(key) + ":" + _jcs(value[key]) for key in ordered) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if value is None or isinstance(value, (bool, int, str)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    raise SidecarError("UNSUPPORTED_VALUE_TYPE", "identity contains an unsupported value")


def derive_identity_v1(preimage: dict[str, Any]) -> tuple[str, str]:
    """Return canonical identity JSON and the engine-derived identity-v1 ID."""
    fields = {
        "application_id",
        "business_request_id",
        "canonicalization_version",
        "destination",
        "execution_scope",
        "identity_version",
        "input",
        "tenant_id",
        "tool_contract_version",
        "tool_id",
    }
    if set(preimage) != fields:
        raise SidecarError("IDENTITY_REQUIRED", "identity-v1 requires its exact preimage fields")
    for key in fields - {"destination", "execution_scope", "input"}:
        if (
            not isinstance(preimage[key], str)
            or not preimage[key].strip()
            or len(preimage[key].encode()) > 1024
        ):
            raise SidecarError("IDENTITY_REQUIRED", f"{key} must be a non-empty identifier")
    if preimage["identity_version"] != IDENTITY_VERSION:
        raise SidecarError("UNSUPPORTED_IDENTITY_VERSION", "only identity version 1 is supported")
    if preimage["canonicalization_version"] != CANONICALIZATION_VERSION:
        raise SidecarError("UNSUPPORTED_CANONICALIZATION_VERSION", "only jcs-1 is supported")
    if not isinstance(preimage["execution_scope"], dict):
        raise SidecarError("IDENTITY_REQUIRED", "execution_scope must be an object")
    if preimage["destination"] is not None and not isinstance(preimage["destination"], dict):
        raise SidecarError("IDENTITY_REQUIRED", "destination must be an object or null")
    _validate_structure(preimage)
    canonical = _jcs(preimage)
    encoded = canonical.encode("utf-8")
    if len(encoded) > MAX_PREIMAGE_BYTES:
        raise SidecarError("IDENTITY_PREIMAGE_TOO_LARGE", "canonical identity exceeds 64 KiB")
    digest = hashlib.sha256(b"mycelium.effect.v1\n" + encoded).hexdigest()
    return canonical, f"mycelium:effect:v1:{digest}"


def _validate_typed_values(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _validate_typed_values(item)
    elif isinstance(value, dict):
        marker = value.get("$type")
        if marker in {"decimal", "url"}:
            profile = value.get("profile")
            if profile != f"{marker}-1":
                raise SidecarError("INVALID_" + marker.upper(), f"unsupported {marker} profile")
            if set(value) - {"$type", "profile", "value"} or not isinstance(
                value.get("value"), str
            ):
                raise SidecarError("INVALID_" + marker.upper(), f"invalid {marker} value")
            text = value["value"]
            if marker == "decimal":
                import re

                if len(text) > 40 or not re.fullmatch(
                    r"(?:(?:0|[1-9][0-9]*|-[1-9][0-9]*)(?:\.[0-9]{0,17}[1-9])?|-0\.[0-9]{0,17}[1-9])",
                    text,
                ):
                    raise SidecarError("NON_CANONICAL_DECIMAL", "decimal is not in decimal-1 form")
                if len(text.replace("-", "").replace(".", "")) > 38:
                    raise SidecarError("NON_CANONICAL_DECIMAL", "decimal exceeds 38 digits")
            else:
                _validate_url(text)
        for item in value.values():
            _validate_typed_values(item)


def _validate_url(value: str) -> None:
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SidecarError("INVALID_URL", "URL contains controls or is empty")
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise SidecarError("INVALID_URL", "URL syntax is invalid") from exc
    scheme_end = value.find(":")
    if scheme_end <= 0 or value[:scheme_end] != value[:scheme_end].lower():
        raise SidecarError("INVALID_URL", "URL scheme must be lowercase")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.fragment:
        raise SidecarError("INVALID_URL", "URL must be an absolute HTTP(S) URL without fragment")
    if parsed.username is not None or parsed.password is not None:
        raise SidecarError("INVALID_URL", "URL credentials are prohibited")
    try:
        host = parsed.hostname
        if not host or any(ord(char) > 127 for char in host):
            raise ValueError
        parsed.port
    except ValueError as exc:
        raise SidecarError("INVALID_URL", "URL host or port is invalid") from exc
    netloc_end = len(value)
    for delimiter in "/?#":
        position = value.find(delimiter, scheme_end + 3)
        if position >= 0:
            netloc_end = min(netloc_end, position)
    raw_netloc = value[scheme_end + 3 : netloc_end]
    raw_host = raw_netloc.rsplit("@", 1)[-1]
    if raw_host.startswith("["):
        raw_host = raw_host[1:].split("]", 1)[0]
    elif raw_host.count(":") == 1:
        raw_host = raw_host.rsplit(":", 1)[0]
    if raw_host != raw_host.lower():
        raise SidecarError("INVALID_URL", "URL scheme and DNS host must be lowercase")
    normalized = value.replace(parsed.scheme, parsed.scheme.lower(), 1)
    if parsed.scheme != parsed.scheme.lower():
        raise SidecarError("INVALID_URL", "URL scheme and DNS host must be lowercase")
    if normalized != value:
        raise SidecarError("INVALID_URL", "URL is not in url-1 form")


def _read_token_file(path: str | os.PathLike[str]) -> str:
    token_path = Path(path)
    try:
        info = token_path.lstat()
    except OSError as exc:
        raise ValueError("cannot read sidecar token file") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("sidecar token file must be a regular owner-only file")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("sidecar token file must be owned by the current user")
    try:
        raw = token_path.read_bytes()
        token = raw.decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("sidecar token file must contain ASCII") from exc
    if token.endswith("\n"):
        token = token[:-1]
        if token.endswith("\r"):
            token = token[:-1]
    if (
        not token
        or any(char.isspace() for char in token)
        or not re.fullmatch(r"(?:[A-Za-z0-9_-]{43}|[0-9a-fA-F]{64})", token)
    ):
        raise ValueError("sidecar token must be 43 base64url or 64 hexadecimal characters")
    return token


@dataclass(frozen=True)
class SidecarConfig:
    host: str
    port: int
    tenant_id: str
    application_id: str
    token: str
    ledger_path: Path
    outcome_path: Path
    protocol_version: str = PROTOCOL_VERSION
    identity_namespace: str = "identity-v1"
    body_limit: int = MAX_BODY_BYTES
    legacy_inspection: bool = False

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("sidecar host must be a literal loopback address") from exc
        if not address.is_loopback:
            raise ValueError("sidecar host must resolve exclusively to loopback")
        if not self.tenant_id or not self.application_id:
            raise ValueError("tenant_id and application_id are required")
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError("only protocol version 1.0 is supported")
        if self.identity_namespace != "identity-v1":
            raise ValueError("only identity-v1 namespace is supported")
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if not 1 <= self.body_limit <= 16 * MAX_BODY_BYTES:
            raise ValueError("body_limit is outside the development limit")
        try:
            self.token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("token must be ASCII") from exc
        if not re.fullmatch(r"(?:[A-Za-z0-9_-]{43}|[0-9a-fA-F]{64})", self.token):
            raise ValueError("token must be 43 base64url or 64 hexadecimal characters")

    @classmethod
    def from_yaml(cls, path: str | os.PathLike[str]) -> SidecarConfig:
        import yaml

        config_path = Path(path)
        if not config_path.is_absolute():
            raise ValueError("sidecar config path must be absolute")
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError("invalid sidecar configuration") from exc
        if not isinstance(data, dict) or data.get("kind") != "mycelium-sidecar":
            raise ValueError("sidecar config kind must be mycelium-sidecar")
        token_file = data.get("bearer_token_file")
        if not isinstance(token_file, str) or not Path(token_file).is_absolute():
            raise ValueError("bearer_token_file must be an absolute path")
        ledger = data.get("ledger")
        outcome = data.get("outcome_storage")
        if (
            not isinstance(ledger, dict)
            or ledger.get("type") != "file"
            or not isinstance(ledger.get("path"), str)
        ):
            raise ValueError("a file ledger path is required for the prototype")
        if (
            not isinstance(outcome, dict)
            or outcome.get("type") != "file"
            or not isinstance(outcome.get("path"), str)
        ):
            raise ValueError("a file outcome path is required for the prototype")
        if not Path(ledger["path"]).is_absolute() or not Path(outcome["path"]).is_absolute():
            raise ValueError("ledger and outcome paths must be absolute")
        values = data.get("server", {})
        if not isinstance(values, dict):
            raise ValueError("server configuration must be an object")
        return cls(
            host=values.get("host", "127.0.0.1"),
            port=int(values.get("port", 0)),
            tenant_id=data.get("tenant_id", ""),
            application_id=data.get("application_id", ""),
            token=_read_token_file(token_file),
            ledger_path=Path(ledger["path"]),
            outcome_path=Path(outcome["path"]),
            protocol_version=data.get("protocol_version", PROTOCOL_VERSION),
            identity_namespace=data.get("identity_namespace", ""),
            body_limit=int(data.get("request_body_limit", MAX_BODY_BYTES)),
            legacy_inspection=bool(data.get("legacy_inspection", False)),
        )


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    application_id: str
    capabilities: frozenset[str]
    principal_type: str = "development-token"
    audit_id: str = "sidecar-local"


def _identity_body(body: dict[str, Any], principal: Principal) -> dict[str, Any]:
    for key, expected in (
        ("tenant_id", principal.tenant_id),
        ("application_id", principal.application_id),
    ):
        if body.get(key) != expected:
            raise SidecarError(
                "TENANT_MISMATCH" if key == "tenant_id" else "APPLICATION_MISMATCH",
                f"{key} is not bound to this sidecar",
                status=403,
            )
    required = (
        "application_id",
        "business_request_id",
        "canonicalization_version",
        "destination",
        "execution_scope",
        "identity_version",
        "input",
        "tenant_id",
        "tool_contract_version",
        "tool_id",
    )
    missing = [key for key in required if key not in body]
    if missing:
        raise SidecarError("IDENTITY_REQUIRED", "missing identity fields: " + ",".join(missing))
    _validate_typed_values(body["input"])
    return {key: body[key] for key in required}


def _projection(entry: Any) -> dict[str, Any]:
    data = entry.to_dict()
    return {
        "effect_id": data.get("effect_id"),
        "effect_state": entry.resolved_effect_state().value,
        "terminal_outcome": data.get("terminal_outcome"),
        "owner_id": data.get("owner"),
        "lease": {
            "leased_until": data.get("lease_until"),
            "last_heartbeat_at": data.get("last_heartbeat_at"),
        },
        "fence": data.get("fence"),
        "provider_boundary": data.get("side_effect_boundary"),
        "provider_operation_ref": data.get("external_operation_ref"),
        "result": data.get("result"),
        "decision": data.get("decision"),
        "error": data.get("error"),
    }


class SidecarService:
    """Thin protocol adapter over one existing ActionLedger."""

    def __init__(
        self, ledger: ActionLedger, config: SidecarConfig, outcome: OutcomeEmitter | None = None
    ):
        self.ledger, self.config = ledger, config
        self.principal = Principal(
            config.tenant_id,
            config.application_id,
            frozenset({"effects", "identity", "capabilities"}),
        )
        self.outcome = outcome

    def _emit(self, entry: Any, event: str) -> None:
        if self.outcome is None:
            return
        try:
            self.outcome.emit_event(
                tool=entry.tool,
                request_id=entry.request_id,
                event=event,
                terminal_outcome=entry.terminal_outcome,
                side_effect_boundary=entry.side_effect_boundary,
                owner=entry.owner,
            )
        except Exception:
            return

    def _identity(self, body: dict[str, Any]) -> tuple[str, str]:
        canonical, effect_id = derive_identity_v1(_identity_body(body, self.principal))
        expected = body.get("expected_effect_id", body.get("effect_id"))
        if expected is not None and expected != effect_id:
            raise SidecarError(
                "EFFECT_ID_MISMATCH", "expected effect ID does not match engine derivation"
            )
        return canonical, effect_id

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "protocol_version": self.config.protocol_version}

    def capabilities(self) -> dict[str, Any]:
        return {
            "protocol_version": self.config.protocol_version,
            "identity_namespace": self.config.identity_namespace,
            "capabilities": sorted(self.principal.capabilities),
            "operations": [
                "derive_identity",
                "claim_effect",
                "inspect_effect",
                "renew_lease",
                "record_boundary",
                "attach_provider_reference",
                "reconcile",
                "complete_effect",
                "fail_effect",
                "request_reconciliation",
            ],
            "development_only": True,
        }

    def derive(self, body: dict[str, Any]) -> dict[str, Any]:
        canonical, effect_id = self._identity(body)
        return {
            "protocol_version": self.config.protocol_version,
            "effect_id": effect_id,
            "canonical_json": canonical,
            "canonical_bytes": len(canonical.encode()),
            "identity_namespace": self.config.identity_namespace,
        }

    @staticmethod
    def _binding(body: dict[str, Any]) -> ToolTransitionBinding:
        return ToolTransitionBinding.for_tool(
            agent_id="sidecar",
            policy_version="sidecar-development",
            side_effect_class=SideEffectClass.IRREVERSIBLE,
            retry_permission=RetryPermission.MANUAL_RECONCILIATION_REQUIRED,
            capability=ToolCapability.BLIND,
        )

    def claim(self, body: dict[str, Any]) -> dict[str, Any]:
        _, effect_id = self._identity(body)
        decision_raw = body.get("decision")
        if decision_raw is not None:
            try:
                decision = Decision.from_dict(decision_raw)
            except (TypeError, ValueError) as exc:
                raise SidecarError("INVALID_REQUEST", "invalid decision evidence") from exc
        else:
            decision = None
        try:
            entry = self.ledger.claim_side_effecting(
                effect_id,
                str(body["tool_id"]),
                (),
                {
                    "canonical_input": body["input"],
                    "business_request_id": body["business_request_id"],
                    "tenant_id": self.config.tenant_id,
                    "application_id": self.config.application_id,
                },
                self._binding(body),
                lease_ttl=body.get("lease_ttl"),
                poll_timeout=0,
                _effect_id=effect_id,
            )
            if (
                decision is not None
                and entry.decision is None
                and entry.resolved_effect_state().value == "INTENDED"
            ):
                entry = self.ledger.record_decision(
                    effect_id,
                    decision.to_dict(),
                    expected_owner=entry.owner,
                    expected_fence=entry.fence,
                )
        except SidecarError:
            raise
        except Exception as exc:
            code = (
                "ACTIVE_OWNER"
                if "in-flight" in str(exc).lower()
                else "POLICY_DENIED"
                if decision is not None and not decision.allowed
                else "INVALID_TRANSITION"
            )
            raise SidecarError(
                code, "claim was not authorized", status=409, retryable=code == "ACTIVE_OWNER"
            ) from exc
        result = _projection(entry)
        state = result["effect_state"]
        if state == "COMMITTED":
            disposition = "RETURN_STORED_RESULT"
        elif state == "UNKNOWN":
            disposition = "UNKNOWN"
        elif state == "ABORTED":
            disposition = "TERMINAL_ABORTED"
        elif decision is None:
            disposition = "RECORD_DECISION"
        elif not decision.allowed:
            disposition = "DENIED"
        elif state == "ATTEMPTING":
            disposition = "EXECUTE"
        else:
            disposition = "WAIT_FOR_OWNER"
        self._emit(entry, "sidecar_claim")
        return {
            "protocol_version": self.config.protocol_version,
            "disposition": disposition,
            **result,
        }

    def effect_command(
        self, operation: str, body: dict[str, Any], effect_id: str
    ) -> dict[str, Any]:
        _, derived = self._identity(body)
        if derived != effect_id:
            raise SidecarError("EFFECT_ID_MISMATCH", "path effect ID does not match identity")
        if operation == "reconcile":
            if self.ledger.get(effect_id) is None:
                raise SidecarError("NOT_FOUND", "effect not found", status=404)
            try:
                entry = self.ledger.claim_side_effecting(
                    effect_id,
                    str(body["tool_id"]),
                    (),
                    {
                        "canonical_input": body["input"],
                        "business_request_id": body["business_request_id"],
                        "tenant_id": self.config.tenant_id,
                        "application_id": self.config.application_id,
                    },
                    self._binding(body),
                    poll_timeout=0,
                    _effect_id=effect_id,
                )
            except Exception as exc:
                raise SidecarError(
                    "RECONCILIATION_UNAVAILABLE",
                    "reconciliation could not resolve the effect",
                    status=409,
                ) from exc
            self._emit(entry, "sidecar_reconciliation")
            return {
                "protocol_version": self.config.protocol_version,
                "reconciliation": "authoritative-engine-result",
                **_projection(entry),
            }
        entry = self.ledger.get(effect_id)
        if entry is None or (
            entry.kwargs.get("tenant_id") != self.config.tenant_id
            or entry.kwargs.get("application_id") != self.config.application_id
        ):
            raise SidecarError("NOT_FOUND", "effect not found", status=404)
        owner, fence = body.get("owner_id"), body.get("fence")
        if not isinstance(owner, str) or not owner or len(owner.encode()) > 1024:
            raise SidecarError("OWNER_REQUIRED", "owner_id is required", status=400)
        if isinstance(fence, bool) or not isinstance(fence, int) or fence <= 0:
            raise SidecarError("FENCE_REQUIRED", "a positive fence is required", status=400)
        try:
            if operation == "renew":
                entry = self.ledger.renew_lease(
                    effect_id,
                    expected_fence=fence,
                    _expected_owner=owner,
                    lease_ttl=body.get("lease_ttl"),
                )
            elif operation == "boundary":
                entry = self.ledger.advance_boundary(
                    effect_id,
                    SideEffectBoundary(body["boundary"]),
                    expected_owner=owner,
                    expected_fence=fence,
                )
            elif operation == "provider-reference":
                entry = self.ledger.attach_external_operation_ref(
                    effect_id,
                    str(body["provider_operation_ref"]),
                    expected_owner=owner,
                    expected_fence=fence,
                )
            elif operation == "complete":
                entry = self.ledger.complete(
                    effect_id, body.get("result"), expected_fence=fence, _expected_owner=owner
                )
            elif operation == "fail":
                boundary = body.get("boundary", "not_crossed")
                entry = self.ledger.fail(
                    effect_id,
                    RuntimeError("safe failure reported by host"),
                    failed_after_effect=boundary != "not_crossed",
                    expected_fence=fence,
                    _expected_owner=owner,
                )
            else:
                raise SidecarError("INVALID_REQUEST", "unknown effect operation")
        except SidecarError:
            raise
        except Exception as exc:
            message = str(exc).lower()
            code = (
                "STALE_FENCE"
                if "fence" in message or "owner" in message
                else "LEASE_LOST"
                if "lease" in message
                else "INVALID_TRANSITION"
            )
            raise SidecarError(code, "ledger rejected the fenced operation", status=409) from exc
        self._emit(entry, "sidecar_" + operation.replace("-", "_"))
        return {"protocol_version": self.config.protocol_version, **_projection(entry)}


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MyceliumSidecar/0"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10.0)

    def _service(self) -> SidecarService:
        return self.server.service  # type: ignore[attr-defined]

    def _auth(self, required: bool = True) -> None:
        if not required:
            return
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise SidecarError("AUTHENTICATION_REQUIRED", "bearer token required", status=401)
        if not hmac.compare_digest(header[7:], self._service().config.token):
            raise SidecarError("AUTHENTICATION_INVALID", "invalid bearer token", status=401)

    def _reply(self, payload: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_BODY_BYTES:
            raw = json.dumps(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "error": {
                        "code": "RESPONSE_TOO_LARGE",
                        "message": "response exceeds the development limit",
                        "retryable": False,
                        "caller_action_required": True,
                        "state_may_have_changed": True,
                        "effect_may_have_happened": True,
                    },
                },
                separators=(",", ":"),
            ).encode("utf-8")
            status = 413
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, exc: SidecarError) -> None:
        uncertain = {
            "ACTIVE_OWNER",
            "STALE_FENCE",
            "LEASE_LOST",
            "INVALID_TRANSITION",
            "RECONCILIATION_UNAVAILABLE",
            "INTERNAL_PROTOCOL_ERROR",
        }
        state_changed = exc.code in uncertain
        effect_may_have_happened = exc.code in {
            "ACTIVE_OWNER",
            "STALE_FENCE",
            "LEASE_LOST",
            "INVALID_TRANSITION",
            "RECONCILIATION_UNAVAILABLE",
            "INTERNAL_PROTOCOL_ERROR",
        }
        self._reply(
            {
                "protocol_version": PROTOCOL_VERSION,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "retryable": exc.retryable,
                    "caller_action_required": not exc.retryable,
                    "state_may_have_changed": state_changed,
                    "effect_may_have_happened": effect_may_have_happened,
                },
            },
            exc.status,
        )

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = urllib.parse.urlsplit(self.path).path
            if len(path.encode()) > MAX_PATH_BYTES:
                raise SidecarError("INVALID_REQUEST", "path is too long")
            self._auth(path != "/health")
            if path == "/health":
                self._reply(self._service().health())
                return
            if path == "/v1/capabilities":
                self._reply(self._service().capabilities())
                return
            if path == "/v1/openapi.json":
                self._reply(openapi_document())
                return
            if path.startswith("/v1/effects/"):
                effect_id = _effect_path_segment(path.rsplit("/", 1)[-1])
                if not effect_id.startswith("mycelium:effect:v1:"):
                    raise SidecarError("NOT_FOUND", "effect not found", status=404)
                entry = self._service().ledger.get(effect_id)
                if entry is None:
                    raise SidecarError("NOT_FOUND", "effect not found", status=404)
                if (
                    entry.kwargs.get("tenant_id") != self._service().config.tenant_id
                    or entry.kwargs.get("application_id")
                    != self._service().config.application_id
                ):
                    raise SidecarError("NOT_FOUND", "effect not found", status=404)
                self._reply({"protocol_version": PROTOCOL_VERSION, **_projection(entry)})
                return
            raise SidecarError("NOT_FOUND", "endpoint not found", status=404)
        except SidecarError as exc:
            self._error(exc)
        except Exception:
            self._error(
                SidecarError("INTERNAL_PROTOCOL_ERROR", "internal protocol error", status=500)
            )

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._auth()
            if self.headers.get_content_type() != "application/json":
                raise SidecarError(
                    "INVALID_REQUEST", "Content-Type must be application/json", status=415
                )
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError as exc:
                raise SidecarError("INVALID_REQUEST", "invalid Content-Length") from exc
            limit = self._service().config.body_limit
            if length < 0 or length > limit:
                raise SidecarError(
                    "REQUEST_TOO_LARGE", "request body exceeds configured limit", status=413
                )
            raw = self.rfile.read(length)

            def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, value in items:
                    if key in result:
                        raise SidecarError("DUPLICATE_OBJECT_KEY", "duplicate JSON object key")
                    result[key] = value
                return result

            try:
                body = json.loads(raw, object_pairs_hook=pairs)
            except SidecarError:
                raise
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SidecarError("INVALID_JSON", "invalid JSON request") from exc
            if not isinstance(body, dict):
                raise SidecarError("INVALID_REQUEST", "JSON object required")
            _validate_structure(body)
            path = urllib.parse.urlsplit(self.path).path
            if path == "/v1/identities/derive":
                result = self._service().derive(body)
                status = 200
            elif path == "/v1/effects/claim":
                result = self._service().claim(body)
                status = 200
            elif path.startswith("/v1/effects/"):
                parts = path.strip("/").split("/")
                if len(parts) != 4:
                    raise SidecarError("NOT_FOUND", "endpoint not found", status=404)
                result = self._service().effect_command(
                    parts[3], body, _effect_path_segment(parts[2])
                )
                status = 200
            else:
                raise SidecarError("NOT_FOUND", "endpoint not found", status=404)
            self._reply(result, status)
        except SidecarError as exc:
            self._error(exc)
        except Exception:
            self._error(
                SidecarError("INTERNAL_PROTOCOL_ERROR", "internal protocol error", status=500)
            )

    def log_message(self, format: str, *args: Any) -> None:
        return


class SidecarServer(http.server.ThreadingHTTPServer):
    """HTTP server that can only bind to a validated loopback address."""

    def __init__(self, service: SidecarService):
        if not service.config.host:
            raise ValueError("sidecar host is required")
        if ":" in service.config.host:
            self.address_family = socket.AF_INET6
            address = (service.config.host, service.config.port, 0, 0)
        else:
            address = (service.config.host, service.config.port)
        super().__init__(address, _Handler)
        self.service = service


def build_service(config: SidecarConfig) -> SidecarService:
    ledger = ActionLedger(
        storage=FileLedgerStorage(config.ledger_path), unclassified_policy="strict"
    )
    outcome = OutcomeEmitter(config.application_id, FileOutcomeStorage(config.outcome_path))
    return SidecarService(ledger, config, outcome)


def serve_config(config: SidecarConfig) -> None:
    server = SidecarServer(build_service(config))
    print(
        f"Mycelium sidecar listening on http://{config.host}:{server.server_port} "
        "(development-only)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def serve_in_thread(service: SidecarService) -> tuple[SidecarServer, threading.Thread]:
    server = SidecarServer(service)
    thread = threading.Thread(target=server.serve_forever, name="mycelium-sidecar", daemon=True)
    thread.start()
    return server, thread
