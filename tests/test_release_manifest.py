import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


COMPONENT_NAMES = ("computer", "mobile", "firmware", "assets")


def _private_key_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _components(version="2.0.0"):
    return {
        name: {
            "version": version,
            "size": 1024 + index,
            "sha256": f"{index + 1:02x}" * 32,
            "url": f"https://updates.example.com/stackchan/{name}-{version}.bin",
            "compatibility": {
                "minimumCurrentVersion": "1.0.0",
                "maximumCurrentVersion": version,
            },
        }
        for index, name in enumerate(COMPONENT_NAMES)
    }


def _public_key_config(tmp_path, private_key, key_id="official-2026"):
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    path = tmp_path / "release-public-keys.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "keys": [
                    {
                        "keyId": key_id,
                        "algorithm": "Ed25519",
                        "publicKeyPem": public_key_pem,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _signed_manifest(private_key, components=None):
    from stackchan_ai.release_manifest import generate_release_manifest

    return generate_release_manifest(
        release_version="2.0.0",
        components=components or _components(),
        private_key_pem=_private_key_pem(private_key),
        key_id="official-2026",
        published_at="2026-07-22T08:30:00Z",
    )


def _resign_manifest(manifest, private_key):
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    payload = json.dumps(
        unsigned,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "keyId": "official-2026",
        "value": base64.b64encode(private_key.sign(payload)).decode("ascii"),
    }
    return manifest


def _current_versions(version="2.0.0"):
    return {name: version for name in COMPONENT_NAMES}


def test_generate_release_manifest_signs_all_four_components():
    from stackchan_ai.release_manifest import generate_release_manifest

    private_key = Ed25519PrivateKey.generate()
    manifest = generate_release_manifest(
        release_version="2.0.0",
        components=_components(),
        private_key_pem=_private_key_pem(private_key),
        key_id="official-2026",
        published_at="2026-07-22T08:30:00Z",
    )

    assert set(manifest) == {
        "schemaVersion",
        "releaseVersion",
        "publishedAt",
        "components",
        "signature",
    }
    assert manifest["schemaVersion"] == 1
    assert manifest["releaseVersion"] == "2.0.0"
    assert set(manifest["components"]) == set(COMPONENT_NAMES)
    assert manifest["signature"]["algorithm"] == "Ed25519"
    assert manifest["signature"]["keyId"] == "official-2026"

    signature = base64.b64decode(manifest["signature"]["value"], validate=True)
    unsigned = dict(manifest)
    unsigned.pop("signature")
    payload = json.dumps(
        unsigned,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    private_key.public_key().verify(signature, payload)


@pytest.mark.parametrize(
    "version",
    ["2", "v2.0.0", "02.0.0", "2.0.0-01", "2.0", "2.0.0+"],
)
def test_generate_release_manifest_rejects_invalid_semantic_versions(version):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        generate_release_manifest,
    )

    with pytest.raises(ReleaseManifestError, match="semantic version"):
        generate_release_manifest(
            release_version=version,
            components=_components(),
            private_key_pem=_private_key_pem(Ed25519PrivateKey.generate()),
            key_id="official-2026",
            published_at="2026-07-22T08:30:00Z",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://updates.example.com/stackchan/firmware.bin",
        "file:///tmp/firmware.bin",
        "https://updates.example.com/stackchan/../private.bin",
        "https://updates.example.com/stackchan/%2e%2e/private.bin",
        "https://updates.example.com/stackchan/%252e%252e/private.bin",
        "https://updates.example.com/stackchan/%252525252e%252525252e/private.bin",
        "https://updates.example.com/stackchan\\..\\private.bin",
        "https://[broken/firmware.bin",
    ],
)
def test_generate_release_manifest_rejects_non_https_and_traversal_urls(url):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        generate_release_manifest,
    )

    components = _components()
    components["firmware"]["url"] = url

    with pytest.raises(ReleaseManifestError, match="HTTPS|traversal"):
        generate_release_manifest(
            release_version="2.0.0",
            components=components,
            private_key_pem=_private_key_pem(Ed25519PrivateKey.generate()),
            key_id="official-2026",
            published_at="2026-07-22T08:30:00Z",
        )


def test_generate_release_manifest_rejects_missing_or_unknown_fields():
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        generate_release_manifest,
    )

    private_key_pem = _private_key_pem(Ed25519PrivateKey.generate())
    missing_component = _components()
    missing_component.pop("assets")
    with pytest.raises(ReleaseManifestError, match="components"):
        generate_release_manifest(
            release_version="2.0.0",
            components=missing_component,
            private_key_pem=private_key_pem,
            key_id="official-2026",
            published_at="2026-07-22T08:30:00Z",
        )

    unknown_field = _components()
    unknown_field["computer"]["notes"] = "not signed schema"
    with pytest.raises(ReleaseManifestError, match="unknown field"):
        generate_release_manifest(
            release_version="2.0.0",
            components=unknown_field,
            private_key_pem=private_key_pem,
            key_id="official-2026",
            published_at="2026-07-22T08:30:00Z",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("size", 0, "size"),
        ("size", True, "size"),
        ("sha256", "AA" * 32, "SHA-256"),
        ("sha256", "00" * 31, "SHA-256"),
    ],
)
def test_generate_release_manifest_validates_artifact_metadata(field, value, message):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        generate_release_manifest,
    )

    components = _components()
    components["mobile"][field] = value

    with pytest.raises(ReleaseManifestError, match=message):
        generate_release_manifest(
            release_version="2.0.0",
            components=components,
            private_key_pem=_private_key_pem(Ed25519PrivateKey.generate()),
            key_id="official-2026",
            published_at="2026-07-22T08:30:00Z",
        )


def test_generate_release_manifest_rejects_an_inverted_compatibility_range():
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        generate_release_manifest,
    )

    components = _components()
    components["assets"]["compatibility"] = {
        "minimumCurrentVersion": "2.0.0",
        "maximumCurrentVersion": "1.9.9",
    }

    with pytest.raises(ReleaseManifestError, match="compatibility"):
        generate_release_manifest(
            release_version="2.0.0",
            components=components,
            private_key_pem=_private_key_pem(Ed25519PrivateKey.generate()),
            key_id="official-2026",
            published_at="2026-07-22T08:30:00Z",
        )


def test_verify_release_manifest_accepts_a_valid_signed_json_document(tmp_path):
    from stackchan_ai.release_manifest import verify_release_manifest

    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key)

    verified = verify_release_manifest(
        json.dumps(manifest).encode("utf-8"),
        public_key_config=_public_key_config(tmp_path, private_key),
        current_versions=_current_versions(),
    )

    assert verified == manifest
    assert verified is not manifest


def test_verify_release_manifest_rejects_unsigned_and_tampered_documents(tmp_path):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        ReleaseManifestSignatureError,
        verify_release_manifest,
    )

    private_key = Ed25519PrivateKey.generate()
    key_config = _public_key_config(tmp_path, private_key)
    unsigned = _signed_manifest(private_key)
    unsigned.pop("signature")
    with pytest.raises(ReleaseManifestError, match="signature"):
        verify_release_manifest(
            unsigned,
            public_key_config=key_config,
            current_versions=_current_versions(),
        )

    tampered = _signed_manifest(private_key)
    tampered["components"]["firmware"]["size"] += 1
    with pytest.raises(ReleaseManifestSignatureError, match="signature"):
        verify_release_manifest(
            tampered,
            public_key_config=key_config,
            current_versions=_current_versions(),
        )


@pytest.mark.parametrize(
    ("location", "field"),
    [
        ("top", "notes"),
        ("component", "filename"),
        ("compatibility", "channel"),
        ("signature", "certificate"),
    ],
)
def test_verify_release_manifest_rejects_unknown_fields(tmp_path, location, field):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        verify_release_manifest,
    )

    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key)
    if location == "top":
        manifest[field] = "unexpected"
    elif location == "component":
        manifest["components"]["computer"][field] = "unexpected"
    elif location == "compatibility":
        manifest["components"]["computer"]["compatibility"][field] = "unexpected"
    else:
        manifest["signature"][field] = "unexpected"

    with pytest.raises(ReleaseManifestError, match="unknown field"):
        verify_release_manifest(
            manifest,
            public_key_config=_public_key_config(tmp_path, private_key),
            current_versions=_current_versions(),
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://updates.example.com/stackchan/mobile.bin",
        "https://updates.example.com/stackchan/%2e%2e/mobile.bin",
    ],
)
def test_verify_release_manifest_revalidates_signed_artifact_urls(tmp_path, url):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        verify_release_manifest,
    )

    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key)
    manifest["components"]["mobile"]["url"] = url
    _resign_manifest(manifest, private_key)

    with pytest.raises(ReleaseManifestError, match="HTTPS|traversal"):
        verify_release_manifest(
            manifest,
            public_key_config=_public_key_config(tmp_path, private_key),
            current_versions=_current_versions(),
        )


def test_verify_release_manifest_rejects_downgrades(tmp_path):
    from stackchan_ai.release_manifest import (
        ReleaseManifestCompatibilityError,
        verify_release_manifest,
    )

    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key)
    current_versions = _current_versions()
    current_versions["firmware"] = "2.0.1"

    with pytest.raises(ReleaseManifestCompatibilityError, match="downgrade"):
        verify_release_manifest(
            manifest,
            public_key_config=_public_key_config(tmp_path, private_key),
            current_versions=current_versions,
        )


def test_verify_release_manifest_rejects_incompatible_installed_versions(tmp_path):
    from stackchan_ai.release_manifest import (
        ReleaseManifestCompatibilityError,
        verify_release_manifest,
    )

    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key)
    current_versions = _current_versions()
    current_versions["assets"] = "0.9.9"

    with pytest.raises(ReleaseManifestCompatibilityError, match="incompatible"):
        verify_release_manifest(
            manifest,
            public_key_config=_public_key_config(tmp_path, private_key),
            current_versions=current_versions,
        )


def test_verify_release_manifest_requires_an_explicit_known_public_key(tmp_path):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        verify_release_manifest,
    )

    signing_key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(signing_key)

    with pytest.raises(ReleaseManifestError, match="public key config"):
        verify_release_manifest(
            manifest,
            public_key_config=tmp_path / "missing.json",
            current_versions=_current_versions(),
        )
    with pytest.raises(ReleaseManifestError, match="trusted key"):
        verify_release_manifest(
            manifest,
            public_key_config=_public_key_config(tmp_path, other_key, "other-key"),
            current_versions=_current_versions(),
        )


def test_verify_release_manifest_rejects_duplicate_json_keys(tmp_path):
    from stackchan_ai.release_manifest import (
        ReleaseManifestError,
        verify_release_manifest,
    )

    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key)
    document = json.dumps(manifest)
    duplicate = document.replace(
        '"schemaVersion": 1,', '"schemaVersion": 1, "schemaVersion": 1,', 1
    )

    with pytest.raises(ReleaseManifestError, match="duplicate field"):
        verify_release_manifest(
            duplicate,
            public_key_config=_public_key_config(tmp_path, private_key),
            current_versions=_current_versions(),
        )
