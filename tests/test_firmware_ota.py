import hashlib

import pytest

import stackchan_ai.firmware_ota as ota
from stackchan_ai.firmware_ota import (
    MIN_FIRMWARE_SIZE,
    OTA_SLOT_SIZE,
    FirmwareArtifactStore,
)


def _firmware_image(version: str = "1.4.4", *, size: int = MIN_FIRMWARE_SIZE) -> bytes:
    image = bytearray(size)
    image[0] = 0xE9
    encoded_version = version.encode("ascii")
    image[0x30 : 0x30 + len(encoded_version)] = encoded_version
    return bytes(image)


def test_stage_accepts_an_esp_bin_and_exposes_only_safe_metadata():
    content = _firmware_image()
    store = FirmwareArtifactStore()

    artifact = store.stage("stack-chan.bin", content)

    assert artifact.filename == "stack-chan.bin"
    assert artifact.version == "1.4.4"
    assert artifact.size == len(content)
    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert artifact.content == content
    assert store.get(artifact.id) is artifact
    assert store.latest() is artifact
    assert artifact.public_summary() == {
        "id": artifact.id,
        "filename": "stack-chan.bin",
        "version": "1.4.4",
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "createdAt": artifact.created_at,
    }
    assert not hasattr(artifact, "path")
    assert "token" not in repr(artifact).lower()
    assert "content=" not in repr(artifact)


def test_stage_rejects_non_bin_uploads():
    store = FirmwareArtifactStore()

    with pytest.raises(ota.FirmwareValidationError, match=r"\.bin"):
        store.stage("stack-chan.zip", _firmware_image())


def test_stage_enforces_minimum_and_configured_maximum_size():
    store = FirmwareArtifactStore(max_size=MIN_FIRMWARE_SIZE + 16)

    with pytest.raises(ota.FirmwareValidationError, match="too small"):
        store.stage("tiny.bin", _firmware_image(size=MIN_FIRMWARE_SIZE - 1))
    with pytest.raises(ota.FirmwareValidationError, match="OTA slot"):
        store.stage("large.bin", _firmware_image(size=MIN_FIRMWARE_SIZE + 17))

    assert store.stage(
        "exact-limit.bin", _firmware_image(size=MIN_FIRMWARE_SIZE + 16)
    ).size == MIN_FIRMWARE_SIZE + 16


def test_store_cannot_raise_the_hardware_ota_slot_limit():
    with pytest.raises(ValueError, match="OTA slot"):
        FirmwareArtifactStore(max_size=OTA_SLOT_SIZE + 1)


def test_stage_rejects_an_invalid_esp_image_magic_byte():
    content = bytearray(_firmware_image())
    content[0] = 0x00

    with pytest.raises(ota.FirmwareValidationError, match="ESP image"):
        FirmwareArtifactStore().stage("not-esp.bin", content)


@pytest.mark.parametrize(
    "version_bytes",
    [b"\0" * 32, b"\xff" + b"\0" * 31, b"1.4.4\n" + b"\0" * 26],
    ids=["blank", "non-ascii", "control-character"],
)
def test_stage_rejects_a_missing_or_non_ascii_app_version(version_bytes):
    content = bytearray(_firmware_image())
    content[0x30:0x50] = version_bytes

    with pytest.raises(ota.FirmwareValidationError, match="version"):
        FirmwareArtifactStore().stage("bad-version.bin", content)


def test_stage_reads_exactly_32_version_bytes_and_discards_submitted_paths():
    version = "v" * 32
    content = bytearray(_firmware_image(version))
    content[0x50:0x55] = b"LEAK!"

    artifact = FirmwareArtifactStore().stage(
        r"C:\private\releases\STACK-CHAN.BIN", content
    )

    assert artifact.version == version
    assert artifact.filename == "STACK-CHAN.BIN"
    assert "private" not in repr(artifact)


def test_staging_identical_content_does_not_overwrite_existing_metadata():
    content = _firmware_image()
    store = FirmwareArtifactStore()

    original = store.stage("original.bin", content)
    repeated = store.stage("renamed.bin", content)

    assert repeated is original
    assert store.get(original.id) is original
    assert store.latest() is original
    assert original.filename == "original.bin"


def test_staging_a_new_build_with_the_same_version_retains_both_artifacts():
    first_content = bytearray(_firmware_image("1.4.4"))
    second_content = bytearray(first_content)
    second_content[-1] = 1
    store = FirmwareArtifactStore()

    first = store.stage("first.bin", first_content)
    second = store.stage("second.bin", second_content)

    assert first.id != second.id
    assert store.get(first.id) is first
    assert store.get(second.id) is second
    assert store.latest() is second


def test_ticket_is_high_entropy_and_resolves_only_before_expiry():
    store = FirmwareArtifactStore(ticket_ttl_seconds=30)
    artifact = store.stage("stack-chan.bin", _firmware_image())

    first_ticket = store.issue_ticket(artifact.id, now=1_000.0)
    second_ticket = store.issue_ticket(artifact.id, now=1_000.0)

    assert len(first_ticket) >= 43
    assert first_ticket != second_ticket
    assert store.resolve_ticket(artifact.id, first_ticket, now=1_029.9) is artifact
    assert store.resolve_ticket(artifact.id, first_ticket, now=1_029.9) is artifact
    assert store.resolve_ticket(artifact.id, "wrong-ticket", now=1_029.9) is None
    assert store.resolve_ticket(artifact.id, first_ticket, now=1_030.0) is None
    assert first_ticket not in repr(artifact)
    assert first_ticket not in repr(artifact.public_summary())


def test_ticket_cannot_be_issued_for_an_unknown_artifact():
    store = FirmwareArtifactStore()

    with pytest.raises(KeyError, match="unknown firmware artifact"):
        store.issue_ticket("missing", now=1_000.0)


@pytest.mark.parametrize("ttl", [0, -1, 3601])
def test_ticket_lifetime_must_remain_short(ttl):
    with pytest.raises(ValueError, match="ticket_ttl_seconds"):
        FirmwareArtifactStore(ticket_ttl_seconds=ttl)
