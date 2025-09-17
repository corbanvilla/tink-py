#!/usr/bin/env python3
"""Run the most common Tink primitives using the pip-installed distribution."""

from __future__ import annotations

import datetime
import importlib.util
import io
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


def _has_pip_tink(candidate_path: Sequence[str]) -> bool:
    original = sys.path[:]
    try:
        sys.path[:] = list(candidate_path)
        return importlib.util.find_spec("tink") is not None
    finally:
        sys.path[:] = original


def _sanitize_sys_path() -> None:
    """Remove the repository root from ``sys.path`` when pip Tink is available."""

    script_path = Path(__file__).resolve()
    repo_root = str(script_path.parents[1])
    sanitized: List[str] = []
    for entry in sys.path:
        if not entry:
            continue
        normalized = entry.rstrip(os.sep)
        if normalized == repo_root:
            continue
        sanitized.append(entry)

    if _has_pip_tink(sanitized):
        sys.path[:] = sanitized
        return

    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


_sanitize_sys_path()

import tink  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import aead  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import daead  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import hybrid  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import jwt  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import mac  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import signature  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position
from tink import streaming_aead  # type: ignore  # noqa: E402  pylint: disable=wrong-import-position


@dataclass
class PrimitiveResult:
    primitive: str
    detail: str
    elapsed_ms: float
    note: str


def _format_row(row: Sequence[str], widths: Sequence[int]) -> str:
    return " | ".join(cell.ljust(width) for cell, width in zip(row, widths))


def _render_table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    widths = [len(header) for header in headers]
    normalized_rows: List[List[str]] = []
    for row in rows:
        normalized = [str(cell) for cell in row]
        normalized_rows.append(normalized)
        for idx, cell in enumerate(normalized):
            widths[idx] = max(widths[idx], len(cell))

    header_line = _format_row(headers, widths)
    separator = "-+-".join("-" * width for width in widths)
    body = [_format_row(row, widths) for row in normalized_rows]
    return "\n".join([header_line, separator, *body])


def _format_bytes(length: int) -> str:
    if length < 1024:
        return f"{length} B"
    if length < 1024 ** 2:
        return f"{length / 1024:.1f} KiB"
    return f"{length / (1024 ** 2):.1f} MiB"


def _register_in_memory_kms(key_uri: str) -> aead.Aead:
    aead.register()
    remote_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    remote_aead = remote_handle.primitive(aead.Aead)

    class _InMemoryKmsClient(tink.KmsClient):
        def __init__(self, uri: str, wrapped: aead.Aead):
            self._uri = uri
            self._wrapped = wrapped

        def does_support(self, uri: str) -> bool:
            return uri == self._uri

        def get_aead(self, uri: str) -> aead.Aead:
            if uri != self._uri:
                raise tink.TinkError(f"Unsupported key URI: {uri}")
            return self._wrapped

    tink.register_kms_client(_InMemoryKmsClient(key_uri, remote_aead))
    return remote_aead


def _run_aead() -> PrimitiveResult:
    aead.register()
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    primitive = keyset_handle.primitive(aead.Aead)
    associated_data = b"benchmark"
    plaintext = b"standard AEAD payload"
    start = time.perf_counter()
    ciphertext = primitive.encrypt(plaintext, associated_data)
    decrypted = primitive.decrypt(ciphertext, associated_data)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if decrypted != plaintext:
        raise AssertionError("AEAD decryption mismatch")
    return PrimitiveResult(
        primitive="AEAD",
        detail="AES256_GCM",
        elapsed_ms=elapsed_ms,
        note=f"{_format_bytes(len(plaintext))} -> {_format_bytes(len(ciphertext))}",
    )


def _run_streaming_aead() -> PrimitiveResult:
    streaming_aead.register()
    key_template = streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB
    keyset_handle = tink.new_keyset_handle(key_template)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
    associated_data = b"stream"
    plaintext = (b"0123456789abcdef" * 4096)
    ciphertext_buffer = io.BytesIO()
    start = time.perf_counter()
    with primitive.new_encrypting_stream(ciphertext_buffer, associated_data) as enc:
        enc.write(plaintext)
    ciphertext = ciphertext_buffer.getvalue()
    with primitive.new_decrypting_stream(io.BytesIO(ciphertext), associated_data) as dec:
        decrypted = dec.read()
    elapsed_ms = (time.perf_counter() - start) * 1000
    if decrypted != plaintext:
        raise AssertionError("Streaming AEAD decryption mismatch")
    return PrimitiveResult(
        primitive="Streaming AEAD",
        detail="AES256_GCM_HKDF_1MB",
        elapsed_ms=elapsed_ms,
        note=f"{_format_bytes(len(plaintext))} -> {_format_bytes(len(ciphertext))}",
    )


def _run_deterministic_aead() -> PrimitiveResult:
    daead.register()
    key_template = daead.deterministic_aead_key_templates.AES256_SIV
    keyset_handle = tink.new_keyset_handle(key_template)
    primitive = keyset_handle.primitive(daead.DeterministicAead)
    associated_data = b"deterministic"
    plaintext = b"message"
    start = time.perf_counter()
    ciphertext1 = primitive.encrypt_deterministically(plaintext, associated_data)
    ciphertext2 = primitive.encrypt_deterministically(plaintext, associated_data)
    decrypted = primitive.decrypt_deterministically(ciphertext1, associated_data)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if decrypted != plaintext:
        raise AssertionError("Deterministic AEAD decryption mismatch")
    if ciphertext1 != ciphertext2:
        raise AssertionError("Deterministic AEAD mismatch")
    return PrimitiveResult(
        primitive="Deterministic AEAD",
        detail="AES256_SIV",
        elapsed_ms=elapsed_ms,
        note=f"ciphertext length {len(ciphertext1)} bytes",
    )


def _run_envelope_aead() -> PrimitiveResult:
    aead.register()
    kms_uri = f"in-memory-kms://{uuid.uuid4()}"
    _register_in_memory_kms(kms_uri)
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=kms_uri,
        dek_template=aead.aead_key_templates.AES256_GCM,
    )
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    associated_data = b"envelope"
    plaintext = b"kms envelope payload"
    start = time.perf_counter()
    ciphertext = primitive.encrypt(plaintext, associated_data)
    decrypted = primitive.decrypt(ciphertext, associated_data)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if decrypted != plaintext:
        raise AssertionError("Envelope AEAD decryption mismatch")
    return PrimitiveResult(
        primitive="KMS Envelope AEAD",
        detail="AES256_GCM under in-memory KMS",
        elapsed_ms=elapsed_ms,
        note=f"ciphertext length {len(ciphertext)} bytes",
    )


def _run_hybrid() -> PrimitiveResult:
    hybrid.register()
    key_template = hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
    private_handle = tink.new_keyset_handle(key_template)
    public_handle = private_handle.public_keyset_handle()
    encryptor = public_handle.primitive(hybrid.HybridEncrypt)
    decryptor = private_handle.primitive(hybrid.HybridDecrypt)
    context_info = b"context"
    plaintext = b"hybrid payload"
    start = time.perf_counter()
    ciphertext = encryptor.encrypt(plaintext, context_info)
    decrypted = decryptor.decrypt(ciphertext, context_info)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if decrypted != plaintext:
        raise AssertionError("Hybrid encryption mismatch")
    return PrimitiveResult(
        primitive="Hybrid Encryption",
        detail="ECIES P256 + AES128_GCM",
        elapsed_ms=elapsed_ms,
        note=f"ciphertext length {len(ciphertext)} bytes",
    )


def _run_mac() -> PrimitiveResult:
    mac.register()
    key_template = mac.mac_key_templates.HMAC_SHA256_128BITTAG
    keyset_handle = tink.new_keyset_handle(key_template)
    primitive = keyset_handle.primitive(mac.Mac)
    data = b"mac payload"
    start = time.perf_counter()
    tag = primitive.compute_mac(data)
    primitive.verify_mac(tag, data)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return PrimitiveResult(
        primitive="MAC",
        detail="HMAC_SHA256_128BITTAG",
        elapsed_ms=elapsed_ms,
        note=f"tag length {len(tag)} bytes",
    )


def _run_signature() -> PrimitiveResult:
    signature.register()
    key_template = signature.signature_key_templates.ED25519
    private_handle = tink.new_keyset_handle(key_template)
    public_handle = private_handle.public_keyset_handle()
    signer = private_handle.primitive(signature.PublicKeySign)
    verifier = public_handle.primitive(signature.PublicKeyVerify)
    message = b"signature payload"
    start = time.perf_counter()
    signature_value = signer.sign(message)
    verifier.verify(signature_value, message)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return PrimitiveResult(
        primitive="Digital Signature",
        detail="ED25519",
        elapsed_ms=elapsed_ms,
        note=f"signature length {len(signature_value)} bytes",
    )


def _run_jwt() -> PrimitiveResult:
    jwt.register_jwt_signature()
    keyset_handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    signer = keyset_handle.primitive(jwt.JwtPublicKeySign)
    public_handle = keyset_handle.public_keyset_handle()
    verifier = public_handle.primitive(jwt.JwtPublicKeyVerify)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        audiences=["audience"],
        expiration=now + datetime.timedelta(minutes=5),
        issued_at=now,
        not_before=now,
        subject="demo",
    )
    start = time.perf_counter()
    token = signer.sign_and_encode(raw_jwt)
    validator = jwt.new_validator(expected_audience="audience")
    verified_jwt = verifier.verify_and_decode(token, validator)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if verified_jwt.subject() != "demo":
        raise AssertionError("JWT verification mismatch")
    return PrimitiveResult(
        primitive="JWT",
        detail="ES256",
        elapsed_ms=elapsed_ms,
        note=f"token length {len(token)} characters",
    )


def _run_kms_encrypted_keyset() -> PrimitiveResult:
    aead.register()
    kms_uri = f"in-memory-kms://{uuid.uuid4()}"
    remote_aead = _register_in_memory_kms(kms_uri)
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    associated_data = "keyset demo"
    start = time.perf_counter()
    serialized = tink.json_proto_keyset_format.serialize_encrypted(
        keyset_handle, remote_aead, associated_data
    )
    recovered_handle = tink.json_proto_keyset_format.parse_encrypted(
        serialized, remote_aead, associated_data
    )
    primitive = recovered_handle.primitive(aead.Aead)
    ciphertext = primitive.encrypt(b"kms encrypted keyset", b"ad")
    decrypted = primitive.decrypt(ciphertext, b"ad")
    elapsed_ms = (time.perf_counter() - start) * 1000
    if decrypted != b"kms encrypted keyset":
        raise AssertionError("KMS encrypted keyset mismatch")
    return PrimitiveResult(
        primitive="KMS-Encrypted Primitive",
        detail="AES128_GCM keyset",
        elapsed_ms=elapsed_ms,
        note=f"encrypted keyset length {len(serialized)} characters",
    )


def main() -> None:
    results = [
        _run_aead(),
        _run_streaming_aead(),
        _run_deterministic_aead(),
        _run_envelope_aead(),
        _run_hybrid(),
        _run_mac(),
        _run_signature(),
        _run_jwt(),
        _run_kms_encrypted_keyset(),
    ]
    headers = ("Primitive", "Details", "Elapsed (ms)", "Notes")
    rows = (
        (result.primitive, result.detail, f"{result.elapsed_ms:.3f}", result.note)
        for result in results
    )
    print("Most common Tink primitives demo\n")
    print(_render_table(headers, rows))


if __name__ == "__main__":
    main()
