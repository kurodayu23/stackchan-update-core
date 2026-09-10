from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import struct
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from threading import RLock
from typing import Any


MIN_FIRMWARE_SIZE = 0x10000
OTA_SLOT_SIZE = 0x460000
ASSET_SLOT_SIZE = 0x360000
MIN_ASSET_SIZE = 12 + 44 + 2
MAX_TICKET_TTL_SECONDS = 3600


class FirmwareValidationError(ValueError):
    pass


class AssetValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FirmwareArtifact:
    id: str
    filename: str
    version: str
    size: int
    sha256: str
    created_at: float
    content: bytes = field(repr=False)

    def public_summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "filename": self.filename,
            "version": self.version,
            "size": self.size,
            "sha256": self.sha256,
            "createdAt": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class AssetArtifact:
    id: str
    filename: str
    version: str
    size: int
    sha256: str
    created_at: float
    content: bytes = field(repr=False)

    def public_summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "filename": self.filename,
            "version": self.version,
            "size": self.size,
            "sha256": self.sha256,
            "createdAt": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class _TicketRecord:
    token_digest: bytes = field(repr=False)
    expires_at: float


class FirmwareArtifactStore:
    def __init__(
        self,
        max_size: int = OTA_SLOT_SIZE,
        ticket_ttl_seconds: int = 900,
    ) -> None:
        if max_size < MIN_FIRMWARE_SIZE:
            raise ValueError("max_size cannot be smaller than the minimum firmware size")
        if max_size > OTA_SLOT_SIZE:
            raise ValueError("max_size cannot exceed the hardware OTA slot size")
        if not 1 <= ticket_ttl_seconds <= MAX_TICKET_TTL_SECONDS:
            raise ValueError(
                f"ticket_ttl_seconds must be between 1 and {MAX_TICKET_TTL_SECONDS}"
            )
        self._max_size = max_size
        self._ticket_ttl_seconds = ticket_ttl_seconds
        self._artifacts: dict[str, FirmwareArtifact] = {}
        self._latest_id: str | None = None
        self._tickets: dict[str, list[_TicketRecord]] = {}
        self._lock = RLock()

    def stage(self, filename: str, content: bytes) -> FirmwareArtifact:
        safe_filename = PurePosixPath(filename.replace("\\", "/")).name
        if not safe_filename.lower().endswith(".bin"):
            raise FirmwareValidationError("firmware upload must use a .bin filename")
        immutable_content = bytes(content)
        if len(immutable_content) < MIN_FIRMWARE_SIZE:
            raise FirmwareValidationError("firmware image is too small")
        if len(immutable_content) > self._max_size:
            raise FirmwareValidationError("firmware image exceeds the OTA slot size")
        if immutable_content[0] != 0xE9:
            raise FirmwareValidationError("firmware is not an ESP image")

        encoded_version = immutable_content[0x30:0x50].split(b"\0", 1)[0]
        try:
            decoded_version = encoded_version.decode("ascii")
        except UnicodeDecodeError as exc:
            raise FirmwareValidationError("firmware app version must be ASCII") from exc
        if not decoded_version.isprintable():
            raise FirmwareValidationError("firmware app version contains control characters")
        version = decoded_version.strip()
        if not version:
            raise FirmwareValidationError("firmware app version is missing")

        sha256 = hashlib.sha256(immutable_content).hexdigest()
        with self._lock:
            existing = self._artifacts.get(sha256)
            if existing is not None:
                self._latest_id = existing.id
                return existing
            artifact = FirmwareArtifact(
                id=sha256,
                filename=safe_filename,
                version=version,
                size=len(immutable_content),
                sha256=sha256,
                created_at=time.time(),
                content=immutable_content,
            )
            self._artifacts[artifact.id] = artifact
            self._latest_id = artifact.id
            return artifact

    def get(self, artifact_id: str) -> FirmwareArtifact | None:
        with self._lock:
            return self._artifacts.get(artifact_id)

    def latest(self) -> FirmwareArtifact | None:
        with self._lock:
            if self._latest_id is None:
                return None
            return self._artifacts[self._latest_id]

    def issue_ticket(self, artifact_id: str, *, now: float | None = None) -> str:
        issued_at = time.time() if now is None else float(now)
        with self._lock:
            if artifact_id not in self._artifacts:
                raise KeyError("unknown firmware artifact")
            token = secrets.token_urlsafe(32)
            token_digest = hashlib.sha256(token.encode("ascii")).digest()
            record = _TicketRecord(
                token_digest=token_digest,
                expires_at=issued_at + self._ticket_ttl_seconds,
            )
            self._tickets.setdefault(artifact_id, []).append(record)
            return token

    def resolve_ticket(
        self,
        artifact_id: str,
        token: str,
        *,
        now: float | None = None,
    ) -> FirmwareArtifact | None:
        if not isinstance(token, str):
            return None
        checked_at = time.time() if now is None else float(now)
        candidate_digest = hashlib.sha256(token.encode("utf-8")).digest()
        with self._lock:
            records = self._tickets.get(artifact_id, ())
            valid_records: list[_TicketRecord] = []
            matched = False
            for record in records:
                is_match = hmac.compare_digest(record.token_digest, candidate_digest)
                if checked_at < record.expires_at:
                    valid_records.append(record)
                    matched = matched or is_match
            if valid_records:
                self._tickets[artifact_id] = valid_records
            else:
                self._tickets.pop(artifact_id, None)
            if not matched:
                return None
            return self._artifacts.get(artifact_id)


class AssetArtifactStore(FirmwareArtifactStore):
    def __init__(
        self,
        max_size: int = ASSET_SLOT_SIZE,
        ticket_ttl_seconds: int = 900,
    ) -> None:
        if max_size < MIN_ASSET_SIZE:
            raise ValueError("max_size cannot be smaller than the minimum asset image")
        if max_size > ASSET_SLOT_SIZE:
            raise ValueError("max_size cannot exceed the hardware asset slot size")
        super().__init__(max_size=max_size, ticket_ttl_seconds=ticket_ttl_seconds)

    def stage(self, filename: str, content: bytes, *, version: str) -> AssetArtifact:
        safe_filename = PurePosixPath(filename.replace("\\", "/")).name
        if not safe_filename.lower().endswith(".bin"):
            raise AssetValidationError("asset upload must use a .bin filename")
        if not isinstance(version, str) or re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version) is None:
            raise AssetValidationError("asset version must use major.minor.patch")

        immutable_content = bytes(content)
        if len(immutable_content) < MIN_ASSET_SIZE:
            raise AssetValidationError("asset image is too small")
        if len(immutable_content) > self._max_size:
            raise AssetValidationError("asset image exceeds the asset slot size")
        stored_files, stored_checksum, stored_length = struct.unpack_from("<III", immutable_content)
        if stored_files == 0 or stored_length != len(immutable_content) - 12:
            raise AssetValidationError("asset image length is invalid")

        body = immutable_content[12:]
        if sum(body) & 0xFFFF != stored_checksum:
            raise AssetValidationError("asset image checksum is invalid")
        table_size = stored_files * 44
        if table_size > stored_length:
            raise AssetValidationError("asset image table is invalid")
        data_size = stored_length - table_size
        for index in range(stored_files):
            name, asset_size, asset_offset, _, _ = struct.unpack_from(
                "<32sIIHH", immutable_content, 12 + index * 44
            )
            if b"\0" not in name or asset_offset > data_size or asset_size > data_size - asset_offset:
                raise AssetValidationError("asset image table is invalid")
            if data_size - asset_offset - asset_size < 2:
                raise AssetValidationError("asset image table is invalid")
            data_offset = 12 + table_size + asset_offset
            if immutable_content[data_offset : data_offset + 2] != b"ZZ":
                raise AssetValidationError("asset image payload is invalid")

        sha256 = hashlib.sha256(immutable_content).hexdigest()
        with self._lock:
            existing = self._artifacts.get(sha256)
            if existing is not None:
                self._latest_id = existing.id
                return existing
            artifact = AssetArtifact(
                id=sha256,
                filename=safe_filename,
                version=version,
                size=len(immutable_content),
                sha256=sha256,
                created_at=time.time(),
                content=immutable_content,
            )
            self._artifacts[artifact.id] = artifact
            self._latest_id = artifact.id
            return artifact
