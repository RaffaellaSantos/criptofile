"""Testes unitários das primitivas criptográficas (AES-256-GCM, RSA-OAEP, SHA-256)."""

import hashlib
import io
import os

import pytest
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from app.utils import cryptography_utils as cu
from app.utils.cryptography_utils import (
    NONCE_SIZE,
    TAG_SIZE,
    decrypt_stream,
    decrypt_with_kek,
    encrypt_stream,
    encrypt_with_kek,
    generate_dek,
    generate_priv_pub_key,
    reencrypt_stream,
    sha256_bytes,
    sha256_file,
    unwrap_dek_with_private_key,
    wrap_dek_with_public_key,
)


@pytest.fixture(scope="module")
def rsa_pair():
    """Par RSA-2048 gerado uma única vez (a geração é lenta)."""
    return generate_priv_pub_key()


@pytest.fixture
def kek():
    return bytearray(generate_dek())


# DEK e SHA-256 ------------------------------------------------------------ #
def test_dek_has_256_bits_and_is_random():
    deks = {generate_dek() for _ in range(10)}
    assert len(deks) == 10
    assert all(len(dek) == 32 for dek in deks)


def test_sha256_bytes_matches_hashlib():
    data = b"dados secretos"
    assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()


def test_sha256_file_matches_in_memory_hash(tmp_path):
    # Conteúdo maior que o bloco de leitura (1 MiB) exercita a leitura em partes.
    data = bytes(range(256)) * (5 * 1024)  # 1,25 MiB
    path = tmp_path / "grande.bin"
    path.write_bytes(data)
    assert sha256_file(str(path)) == sha256_bytes(data)


def test_sha256_detects_single_bit_change():
    data = b"dados secretos"
    altered = bytes([data[0] ^ 0x01]) + data[1:]
    assert sha256_bytes(data) != sha256_bytes(altered)


# AES-256-GCM com a KEK ---------------------------------------------------- #
def test_encrypt_with_kek_roundtrip(kek):
    data = b"chave privada em PEM"
    assert decrypt_with_kek(encrypt_with_kek(data, kek), kek) == data


def test_encrypt_with_kek_layout_is_nonce_tag_ciphertext(kek):
    data = b"x" * 50
    blob = encrypt_with_kek(data, kek)
    assert len(blob) == NONCE_SIZE + TAG_SIZE + len(data)
    assert data not in blob


def test_same_plaintext_produces_different_ciphertexts(kek):
    """Nonce aleatório por cifragem: o mesmo conteúdo nunca gera o mesmo blob."""
    data = b"mesmo conteudo"
    first, second = encrypt_with_kek(data, kek), encrypt_with_kek(data, kek)
    assert first != second
    assert first[:NONCE_SIZE] != second[:NONCE_SIZE]


def test_decrypt_with_wrong_kek_fails(kek):
    blob = encrypt_with_kek(b"segredo", kek)
    with pytest.raises(ValueError):
        decrypt_with_kek(blob, bytearray(generate_dek()))


@pytest.mark.parametrize("position", [0, NONCE_SIZE, NONCE_SIZE + TAG_SIZE])
def test_decrypt_detects_tampering_in_any_part(kek, position):
    """Alterar nonce, tag ou ciphertext invalida a tag GCM."""
    blob = bytearray(encrypt_with_kek(b"segredo", kek))
    blob[position] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_with_kek(bytes(blob), kek)


def test_decrypt_of_truncated_blob_fails(kek):
    blob = encrypt_with_kek(b"segredo", kek)
    with pytest.raises(ValueError):
        decrypt_with_kek(blob[:-1], kek)


# RSA-2048 com OAEP -------------------------------------------------------- #
def test_generated_keys_are_pem_rsa_2048(rsa_pair):
    priv, pub = rsa_pair
    assert priv.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert RSA.import_key(pub).size_in_bits() == 2048


def test_wrap_and_unwrap_dek_roundtrip(rsa_pair):
    priv, pub = rsa_pair
    dek = generate_dek()
    wrapped = wrap_dek_with_public_key(dek, pub)
    assert wrapped != dek
    assert len(wrapped) == 256  # tamanho do módulo RSA-2048
    assert unwrap_dek_with_private_key(wrapped, priv) == dek


def test_oaep_wrapping_is_randomized(rsa_pair):
    _, pub = rsa_pair
    dek = generate_dek()
    assert wrap_dek_with_public_key(dek, pub) != wrap_dek_with_public_key(dek, pub)


def test_unwrap_with_other_private_key_fails(rsa_pair):
    _, pub = rsa_pair
    other_priv, _ = generate_priv_pub_key()
    wrapped = wrap_dek_with_public_key(generate_dek(), pub)
    with pytest.raises(ValueError):
        unwrap_dek_with_private_key(wrapped, other_priv)


def test_unwrap_of_tampered_dek_fails(rsa_pair):
    priv, pub = rsa_pair
    wrapped = bytearray(wrap_dek_with_public_key(generate_dek(), pub))
    wrapped[-1] ^= 0xFF
    with pytest.raises(ValueError):
        unwrap_dek_with_private_key(bytes(wrapped), priv)


def test_invalid_public_key_is_rejected():
    with pytest.raises(ValueError):
        wrap_dek_with_public_key(generate_dek(), b"-----BEGIN PUBLIC KEY-----\nlixo\n")


def test_new_wraps_use_oaep_sha256(rsa_pair):
    """O OAEP padrão (SHA-1) não abre um envolvimento novo: ele usa SHA-256."""
    priv, pub = rsa_pair
    wrapped = wrap_dek_with_public_key(generate_dek(), pub)
    with pytest.raises(ValueError):
        PKCS1_OAEP.new(RSA.import_key(priv)).decrypt(wrapped)
    assert PKCS1_OAEP.new(RSA.import_key(priv), hashAlgo=SHA256).decrypt(wrapped)


def test_legacy_sha1_wrapped_dek_still_unwraps(rsa_pair):
    """DEKs envolvidas antes da troca para SHA-256 continuam legíveis."""
    priv, pub = rsa_pair
    dek = generate_dek()
    legacy = PKCS1_OAEP.new(RSA.import_key(pub)).encrypt(dek)
    assert unwrap_dek_with_private_key(legacy, priv) == dek


# Processamento em blocos (streaming) -------------------------------------- #
@pytest.fixture
def small_chunks(monkeypatch):
    """Blocos de 16 bytes: exercita vários blocos com conteúdos pequenos."""
    monkeypatch.setattr(cu, "CHUNK_SIZE", 16)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 100])
def test_stream_roundtrip_across_chunk_boundaries(kek, small_chunks, size):
    data = os.urandom(size)
    enc = io.BytesIO()
    digest = encrypt_stream(io.BytesIO(data), enc, kek)

    out = io.BytesIO()
    assert decrypt_stream(io.BytesIO(enc.getvalue()), out, kek) == digest
    assert out.getvalue() == data
    assert digest == sha256_bytes(data)


def test_stream_format_is_compatible_with_in_memory_format(kek, small_chunks):
    """Arquivos .enc gravados antes do streaming (encrypt_with_kek) continuam
    abrindo, e o inverso também vale."""
    data = os.urandom(70)
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(encrypt_with_kek(data, kek)), out, kek)
    assert out.getvalue() == data

    enc = io.BytesIO()
    encrypt_stream(io.BytesIO(data), enc, kek)
    assert decrypt_with_kek(enc.getvalue(), kek) == data


def test_stream_respects_existing_prefix(kek):
    """A tag é gravada na posição certa quando há um cabeçalho antes (file_id)."""
    enc = io.BytesIO()
    enc.write(b"P" * 36)
    encrypt_stream(io.BytesIO(b"conteudo"), enc, kek)
    assert decrypt_with_kek(enc.getvalue()[36:], kek) == b"conteudo"


def test_decrypt_stream_without_destination_only_verifies(kek):
    enc = io.BytesIO()
    digest = encrypt_stream(io.BytesIO(b"conteudo"), enc, kek)
    assert decrypt_stream(io.BytesIO(enc.getvalue()), None, kek) == digest


@pytest.mark.parametrize("position", [0, NONCE_SIZE, NONCE_SIZE + TAG_SIZE, -1])
def test_decrypt_stream_detects_tampering(kek, small_chunks, position):
    enc = io.BytesIO()
    encrypt_stream(io.BytesIO(os.urandom(50)), enc, kek)
    blob = bytearray(enc.getvalue())
    blob[position] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_stream(io.BytesIO(bytes(blob)), None, kek)


def test_decrypt_stream_rejects_truncated_header(kek):
    with pytest.raises(ValueError, match="truncado"):
        decrypt_stream(io.BytesIO(b"curto"), None, kek)


def test_stream_reads_in_bounded_chunks(kek, small_chunks):
    """Nunca lê o arquivo inteiro de uma vez: a memória não cresce com o tamanho."""
    sizes = []

    class SpyReader(io.BytesIO):
        def read(self, size=-1):
            sizes.append(size)
            return super().read(size)

    encrypt_stream(SpyReader(os.urandom(200)), io.BytesIO(), kek)
    assert sizes and all(0 < size <= 16 for size in sizes)


def test_reencrypt_stream_switches_key(kek, small_chunks):
    data = os.urandom(90)
    old = io.BytesIO()
    digest = encrypt_stream(io.BytesIO(data), old, kek)
    new_key = bytearray(generate_dek())

    new = io.BytesIO()
    assert reencrypt_stream(io.BytesIO(old.getvalue()), new, kek, new_key) == digest
    assert decrypt_with_kek(new.getvalue(), new_key) == data
    with pytest.raises(ValueError):
        decrypt_with_kek(new.getvalue(), kek)


def test_reencrypt_stream_detects_tampered_source(kek):
    old = io.BytesIO()
    encrypt_stream(io.BytesIO(b"conteudo"), old, kek)
    blob = bytearray(old.getvalue())
    blob[-1] ^= 0xFF
    with pytest.raises(ValueError):
        reencrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), kek, generate_dek())
