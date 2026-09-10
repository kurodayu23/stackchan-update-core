import hashlib
import struct

import pytest

import stackchan_ai.firmware_ota as ota


def asset_image() -> bytes:
    name = b"face.bin\0".ljust(32, b"\0")
    payload = b"ZZ\0\0"
    table = struct.pack("<32sIIHH", name, 2, 0, 0, 0)
    body = table + payload
    header = struct.pack("<III", 1, sum(body) & 0xFFFF, len(body))
    return header + body


def test_stage_accepts_a_valid_asset_image_and_exposes_safe_metadata():
    store = ota.AssetArtifactStore()
    content = asset_image()

    artifact = store.stage("screen-assets.bin", content, version="2.0.0")

    assert artifact.version == "2.0.0"
    assert artifact.size == len(content)
    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert artifact.content == content
    assert artifact.public_summary() == {
        "id": artifact.id,
        "filename": "screen-assets.bin",
        "version": "2.0.0",
        "size": len(content),
        "sha256": artifact.sha256,
        "createdAt": artifact.created_at,
    }
    assert "content=" not in repr(artifact)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"bad", "too small"),
        (asset_image()[:-1], "length"),
        (asset_image()[:-2] + b"xx", "checksum"),
    ],
)
def test_stage_rejects_malformed_asset_images(content, message):
    with pytest.raises(ota.AssetValidationError, match=message):
        ota.AssetArtifactStore().stage("assets.bin", content, version="2.0.0")


def test_asset_store_enforces_partition_size_and_short_lived_tickets():
    with pytest.raises(ValueError, match="asset slot"):
        ota.AssetArtifactStore(max_size=ota.ASSET_SLOT_SIZE + 1)

    store = ota.AssetArtifactStore(ticket_ttl_seconds=30)
    artifact = store.stage("assets.bin", asset_image(), version="2.0.0")
    ticket = store.issue_ticket(artifact.id, now=1000)

    assert store.resolve_ticket(artifact.id, ticket, now=1029.9) is artifact
    assert store.resolve_ticket(artifact.id, ticket, now=1030) is None


@pytest.mark.parametrize("version", ["", "2", "2.0", "v2.0.0", "2.0.0\n"])
def test_asset_store_requires_a_strict_three_part_version(version):
    with pytest.raises(ota.AssetValidationError, match="version"):
        ota.AssetArtifactStore().stage("assets.bin", asset_image(), version=version)
