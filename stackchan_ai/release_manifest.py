from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION = 1
COMPONENT_NAMES = ("computer", "mobile", "firmware", "assets")

_TOP_LEVEL_FIELDS = {
    "schemaVersion",
    "releaseVersion",
    "publishedAt",
    "components",
    "signature",
}
_COMPONENT_FIELDS = {"version", "size", "sha256", "url", "compatibility"}
_COMPATIBILITY_FIELDS = {"minimumCurrentVersion", "maximumCurrentVersion"}
_SIGNATURE_FIELDS = {"algorithm", "keyId", "value"}
_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PUBLISHED_AT_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_PUBLIC_KEY_CONFIG_FIELDS = {"schemaVersion", "keys"}
_PUBLIC_KEY_FIELDS = {"keyId", "algorithm", "publicKeyPem"}
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_PUBLIC_KEY_CONFIG_BYTES = 64 * 1024


class ReleaseManifestError(ValueError):
    pass


class ReleaseManifestSignatureError(ReleaseManifestError):
    pass


class ReleaseManifestCompatibilityError(ReleaseManifestError):
    pass


def generate_release_manifest(
    *,
    release_version: str,
    components: Mapping[str, Mapping[str, Any]],
    private_key_pem: bytes | str,
    key_id: str,
    published_at: str,
) -> dict[str, Any]:
    _parse_semver(release_version, "releaseVersion")
    _validate_published_at(published_at)
    _validate_key_id(key_id)
    validated_components = _validate_components(components)
    private_key = _load_private_key(private_key_pem)

    unsigned = {
        "schemaVersion": SCHEMA_VERSION,
        "releaseVersion": release_version,
        "publishedAt": published_at,
        "components": validated_components,
    }
    signature = private_key.sign(_canonical_json(unsigned))
    return {
        **unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "keyId": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_release_manifest(
    manifest: bytes | str | Mapping[str, Any],
    *,
    public_key_config: str | os.PathLike[str],
    current_versions: Mapping[str, str],
) -> dict[str, Any]:
    document = _parse_manifest_document(manifest)
    normalized = _validate_manifest_document(document)
    signature = normalized["signature"]
    public_key = _load_public_key(public_key_config, signature["keyId"])
    try:
        signature_bytes = base64.b64decode(signature["value"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ReleaseManifestSignatureError(
            "manifest signature is not valid base64"
        ) from exc
    if len(signature_bytes) != 64:
        raise ReleaseManifestSignatureError("manifest signature has an invalid length")

    unsigned = dict(normalized)
    unsigned.pop("signature")
    try:
        public_key.verify(signature_bytes, _canonical_json(unsigned))
    except InvalidSignature as exc:
        raise ReleaseManifestSignatureError(
            "manifest signature verification failed"
        ) from exc

    _validate_current_versions(normalized["components"], current_versions)
    return normalized


def _parse_manifest_document(
    manifest: bytes | str | Mapping[str, Any],
) -> dict[str, Any]:
    if isinstance(manifest, Mapping):
        try:
            encoded = _canonical_json(manifest)
        except (TypeError, ValueError) as exc:
            raise ReleaseManifestError("manifest must be valid JSON") from exc
    elif isinstance(manifest, str):
        try:
            encoded = manifest.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ReleaseManifestError("manifest must be UTF-8 JSON") from exc
    elif isinstance(manifest, bytes):
        encoded = manifest
    else:
        raise ReleaseManifestError("manifest must be a JSON object")
    if len(encoded) > _MAX_MANIFEST_BYTES:
        raise ReleaseManifestError("manifest exceeds the size limit")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("manifest must be UTF-8 JSON") from exc
    document = _strict_json_loads(text, "manifest")
    if not isinstance(document, dict):
        raise ReleaseManifestError("manifest must be a JSON object")
    return document


def _validate_manifest_document(document: Mapping[str, Any]) -> dict[str, Any]:
    unknown_fields = set(document) - _TOP_LEVEL_FIELDS
    missing_fields = _TOP_LEVEL_FIELDS - set(document)
    if unknown_fields:
        raise ReleaseManifestError(
            f"manifest has unknown field: {sorted(unknown_fields)[0]}"
        )
    if missing_fields:
        raise ReleaseManifestError(
            f"manifest is missing field: {sorted(missing_fields)[0]}"
        )
    if (
        isinstance(document["schemaVersion"], bool)
        or document["schemaVersion"] != SCHEMA_VERSION
    ):
        raise ReleaseManifestError(f"schemaVersion must be {SCHEMA_VERSION}")

    release_version = document["releaseVersion"]
    _parse_semver(release_version, "releaseVersion")
    published_at = document["publishedAt"]
    _validate_published_at(published_at)
    components = _validate_components(document["components"])
    signature = _validate_signature(document["signature"])
    return {
        "schemaVersion": SCHEMA_VERSION,
        "releaseVersion": release_version,
        "publishedAt": published_at,
        "components": components,
        "signature": signature,
    }


def _validate_signature(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ReleaseManifestError("signature must be an object")
    unknown_fields = set(value) - _SIGNATURE_FIELDS
    missing_fields = _SIGNATURE_FIELDS - set(value)
    if unknown_fields:
        raise ReleaseManifestError(
            f"signature has unknown field: {sorted(unknown_fields)[0]}"
        )
    if missing_fields:
        raise ReleaseManifestError(
            f"signature is missing field: {sorted(missing_fields)[0]}"
        )
    if value["algorithm"] != "Ed25519":
        raise ReleaseManifestError("signature algorithm must be Ed25519")
    _validate_key_id(value["keyId"])
    if not isinstance(value["value"], str) or not value["value"]:
        raise ReleaseManifestError("signature value must be base64 text")
    return {
        "algorithm": "Ed25519",
        "keyId": value["keyId"],
        "value": value["value"],
    }


def _load_public_key(
    config_path: str | os.PathLike[str], key_id: str
) -> Ed25519PublicKey:
    if not isinstance(config_path, (str, os.PathLike)):
        raise ReleaseManifestError("public key config path must be explicit")
    path = Path(config_path)
    try:
        if path.stat().st_size > _MAX_PUBLIC_KEY_CONFIG_BYTES:
            raise ReleaseManifestError("public key config exceeds the size limit")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReleaseManifestError("public key config could not be loaded") from exc

    config = _strict_json_loads(text, "public key config")
    if not isinstance(config, dict):
        raise ReleaseManifestError("public key config must be a JSON object")
    unknown_fields = set(config) - _PUBLIC_KEY_CONFIG_FIELDS
    missing_fields = _PUBLIC_KEY_CONFIG_FIELDS - set(config)
    if (
        unknown_fields
        or missing_fields
        or config.get("schemaVersion") != SCHEMA_VERSION
    ):
        raise ReleaseManifestError("public key config schema is invalid")
    keys = config["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
        raise ReleaseManifestError("public key config keys must be a non-empty list")

    selected: Mapping[str, Any] | None = None
    seen_key_ids: set[str] = set()
    for entry in keys:
        if not isinstance(entry, Mapping) or set(entry) != _PUBLIC_KEY_FIELDS:
            raise ReleaseManifestError("public key config key schema is invalid")
        entry_key_id = entry["keyId"]
        _validate_key_id(entry_key_id)
        if entry_key_id in seen_key_ids:
            raise ReleaseManifestError("public key config contains a duplicate keyId")
        seen_key_ids.add(entry_key_id)
        if entry["algorithm"] != "Ed25519" or not isinstance(
            entry["publicKeyPem"], str
        ):
            raise ReleaseManifestError("public key config key schema is invalid")
        if entry_key_id == key_id:
            selected = entry
    if selected is None:
        raise ReleaseManifestError(f"manifest references unknown trusted key: {key_id}")

    try:
        public_key = serialization.load_pem_public_key(
            selected["publicKeyPem"].encode("ascii")
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ReleaseManifestError(
            "trusted key is not a valid Ed25519 public key"
        ) from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReleaseManifestError("trusted key is not a valid Ed25519 public key")
    return public_key


def _validate_current_versions(
    components: Mapping[str, Mapping[str, Any]],
    current_versions: Mapping[str, str],
) -> None:
    if not isinstance(current_versions, Mapping) or set(current_versions) != set(
        COMPONENT_NAMES
    ):
        raise ReleaseManifestCompatibilityError(
            "current_versions must contain exactly computer, mobile, firmware, and assets"
        )
    for name in COMPONENT_NAMES:
        current = _parse_semver(current_versions[name], f"current_versions.{name}")
        target = _parse_semver(
            components[name]["version"], f"components.{name}.version"
        )
        if _compare_semver(target, current) < 0:
            raise ReleaseManifestCompatibilityError(
                f"{name} downgrade from {current_versions[name]} to "
                f"{components[name]['version']} is not allowed"
            )
        compatibility = components[name]["compatibility"]
        minimum = _parse_semver(
            compatibility["minimumCurrentVersion"],
            f"components.{name}.compatibility.minimumCurrentVersion",
        )
        maximum = _parse_semver(
            compatibility["maximumCurrentVersion"],
            f"components.{name}.compatibility.maximumCurrentVersion",
        )
        if (
            _compare_semver(current, minimum) < 0
            or _compare_semver(current, maximum) > 0
        ):
            raise ReleaseManifestCompatibilityError(
                f"installed {name} version {current_versions[name]} is incompatible"
            )


def _strict_json_loads(text: str, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseManifestError(f"{label} has duplicate field: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ReleaseManifestError(f"{label} contains invalid number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except ReleaseManifestError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ReleaseManifestError(f"{label} must be valid JSON") from exc


def _validate_components(
    components: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(components, Mapping) or set(components) != set(COMPONENT_NAMES):
        raise ReleaseManifestError(
            "components must contain exactly computer, mobile, firmware, and assets"
        )

    validated: dict[str, dict[str, Any]] = {}
    for name in COMPONENT_NAMES:
        component = components[name]
        if not isinstance(component, Mapping):
            raise ReleaseManifestError(f"components.{name} must be an object")
        unknown_fields = set(component) - _COMPONENT_FIELDS
        missing_fields = _COMPONENT_FIELDS - set(component)
        if unknown_fields:
            raise ReleaseManifestError(
                f"components.{name} has unknown field: {sorted(unknown_fields)[0]}"
            )
        if missing_fields:
            raise ReleaseManifestError(
                f"components.{name} is missing field: {sorted(missing_fields)[0]}"
            )

        version = component["version"]
        _parse_semver(version, f"components.{name}.version")
        size = component["size"]
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size < 2**63:
            raise ReleaseManifestError(
                f"components.{name}.size must be a positive integer"
            )
        sha256 = component["sha256"]
        if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256):
            raise ReleaseManifestError(
                f"components.{name}.sha256 must be a lowercase SHA-256 digest"
            )
        url = component["url"]
        _validate_artifact_url(url, f"components.{name}.url")
        compatibility = _validate_compatibility(
            component["compatibility"], f"components.{name}.compatibility"
        )
        validated[name] = {
            "version": version,
            "size": size,
            "sha256": sha256,
            "url": url,
            "compatibility": compatibility,
        }
    return validated


def _validate_compatibility(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ReleaseManifestError(f"{field} must be an object")
    unknown_fields = set(value) - _COMPATIBILITY_FIELDS
    missing_fields = _COMPATIBILITY_FIELDS - set(value)
    if unknown_fields:
        raise ReleaseManifestError(
            f"{field} has unknown field: {sorted(unknown_fields)[0]}"
        )
    if missing_fields:
        raise ReleaseManifestError(
            f"{field} is missing field: {sorted(missing_fields)[0]}"
        )

    minimum = value["minimumCurrentVersion"]
    maximum = value["maximumCurrentVersion"]
    minimum_version = _parse_semver(minimum, f"{field}.minimumCurrentVersion")
    maximum_version = _parse_semver(maximum, f"{field}.maximumCurrentVersion")
    if _compare_semver(minimum_version, maximum_version) > 0:
        raise ReleaseManifestError(f"{field} compatibility range is inverted")
    return {
        "minimumCurrentVersion": minimum,
        "maximumCurrentVersion": maximum,
    }


def _validate_artifact_url(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(char) < 0x20 for char in value)
    ):
        raise ReleaseManifestError(f"{field} must be an HTTPS URL")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
    except ValueError as exc:
        raise ReleaseManifestError(f"{field} must be an HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or username is not None
        or password is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ReleaseManifestError(f"{field} must be an HTTPS URL")

    decoded_path = parsed.path
    for _ in range(16):
        next_path = unquote(decoded_path)
        if next_path == decoded_path:
            break
        decoded_path = next_path
    else:
        raise ReleaseManifestError(f"{field} must not contain path traversal")
    if "\\" in decoded_path or any(
        segment in {".", ".."} for segment in decoded_path.split("/")
    ):
        raise ReleaseManifestError(f"{field} must not contain path traversal")


def _parse_semver(
    value: Any, field: str
) -> tuple[int, int, int, tuple[str, ...] | None]:
    if not isinstance(value, str):
        raise ReleaseManifestError(f"{field} must be a semantic version")
    match = _SEMVER_PATTERN.fullmatch(value)
    if match is None:
        raise ReleaseManifestError(f"{field} must be a semantic version")
    prerelease_text = match.group(4)
    prerelease = tuple(prerelease_text.split(".")) if prerelease_text else None
    if prerelease and any(
        identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")
        for identifier in prerelease
    ):
        raise ReleaseManifestError(f"{field} must be a semantic version")
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease


def _compare_semver(
    left: tuple[int, int, int, tuple[str, ...] | None],
    right: tuple[int, int, int, tuple[str, ...] | None],
) -> int:
    if left[:3] != right[:3]:
        return -1 if left[:3] < right[:3] else 1
    left_pre, right_pre = left[3], right[3]
    if left_pre is None or right_pre is None:
        if left_pre is right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_id, right_id in zip(left_pre, right_pre):
        if left_id == right_id:
            continue
        left_numeric, right_numeric = left_id.isdigit(), right_id.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_id) < int(right_id) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_id < right_id else 1
    if len(left_pre) == len(right_pre):
        return 0
    return -1 if len(left_pre) < len(right_pre) else 1


def _validate_published_at(value: Any) -> None:
    if not isinstance(value, str) or not _PUBLISHED_AT_PATTERN.fullmatch(value):
        raise ReleaseManifestError("publishedAt must be a UTC RFC 3339 timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseManifestError(
            "publishedAt must be a UTC RFC 3339 timestamp"
        ) from exc


def _validate_key_id(value: Any) -> None:
    if not isinstance(value, str) or not _KEY_ID_PATTERN.fullmatch(value):
        raise ReleaseManifestError("keyId is invalid")


def _load_private_key(value: bytes | str) -> Ed25519PrivateKey:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise ReleaseManifestError(
            "private_key_pem must contain an Ed25519 private key"
        )
    try:
        private_key = serialization.load_pem_private_key(value, password=None)
    except (TypeError, ValueError) as exc:
        raise ReleaseManifestError(
            "private_key_pem must contain an Ed25519 private key"
        ) from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ReleaseManifestError(
            "private_key_pem must contain an Ed25519 private key"
        )
    return private_key


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
