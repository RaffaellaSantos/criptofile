import hashlib
from typing import BinaryIO

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

NONCE_SIZE = 12
TAG_SIZE = 16
# Arquivos são processados em blocos: o uso de memória é constante,
# independentemente do tamanho do arquivo.
CHUNK_SIZE = 1024 * 1024


def generate_dek() -> bytes:
    """Gera uma DEK (Data Encryption Key) AES-256 aleatória por arquivo."""
    return get_random_bytes(32)


def sha256_bytes(data: bytes) -> str:
    """Hash SHA-256 (hex) do conteúdo em memória."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(file_path: str) -> str:
    """Hash SHA-256 (hex) do conteúdo de um arquivo em disco."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as plain_file:
        for chunk in iter(lambda: plain_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encrypt_with_kek(data: bytes, kek: bytearray) -> bytes:
    """Encripta dados (como a chave privada) usando AES-GCM e a KEK da sessão."""
    nonce = get_random_bytes(12)
    cipher = AES.new(bytes(kek), AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Formato do arquivo: Nonce (12 bytes) + Tag (16 bytes) + Ciphertext
    return nonce + tag + ciphertext


def decrypt_with_kek(encrypted_data: bytes, kek: bytearray) -> bytes:
    """Desencripta os dados lidos do disco usando a KEK da sessão."""
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = AES.new(bytes(kek), AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_stream(src: BinaryIO, dst: BinaryIO, key: bytes | bytearray) -> str:
    """Cifra `src` em `dst` com AES-256-GCM, em blocos, e devolve o SHA-256 do
    texto claro.

    Mesmo formato de `encrypt_with_kek` (Nonce + Tag + Ciphertext). A tag só
    é conhecida no fim: o espaço dela é reservado e preenchido ao final.
    """
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
    digest = hashlib.sha256()
    tag_offset = dst.tell() + NONCE_SIZE
    dst.write(nonce + bytes(TAG_SIZE))
    for chunk in iter(lambda: src.read(CHUNK_SIZE), b""):
        digest.update(chunk)
        dst.write(cipher.encrypt(chunk))
    end = dst.tell()
    dst.seek(tag_offset)
    dst.write(cipher.digest())
    dst.seek(end)
    return digest.hexdigest()


def decrypt_stream(src: BinaryIO, dst: BinaryIO | None, key: bytes | bytearray) -> str:
    """Decifra `src` (Nonce + Tag + Ciphertext) em `dst`, em blocos, e devolve
    o SHA-256 do texto claro. Com `dst=None` apenas confere.

    A tag GCM só é validada ao final (ValueError se não conferir): o que foi
    escrito em `dst` até lá NÃO é confiável e deve ser descartado pelo chamador.
    """
    header = src.read(NONCE_SIZE + TAG_SIZE)
    if len(header) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Cabeçalho AES-GCM truncado.")
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=header[:NONCE_SIZE])
    digest = hashlib.sha256()
    for chunk in iter(lambda: src.read(CHUNK_SIZE), b""):
        plain = cipher.decrypt(chunk)
        digest.update(plain)
        if dst is not None:
            dst.write(plain)
    cipher.verify(header[NONCE_SIZE:])
    return digest.hexdigest()


def reencrypt_stream(
    src: BinaryIO, dst: BinaryIO, old_key: bytes | bytearray, new_key: bytes | bytearray
) -> str:
    """Troca a chave de um conteúdo cifrado sem materializar o texto claro em
    disco nem em memória. Levanta ValueError se a tag antiga não conferir
    (nesse caso `dst` deve ser descartado). Devolve o SHA-256 do texto claro."""
    header = src.read(NONCE_SIZE + TAG_SIZE)
    if len(header) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Cabeçalho AES-GCM truncado.")
    old = AES.new(bytes(old_key), AES.MODE_GCM, nonce=header[:NONCE_SIZE])
    nonce = get_random_bytes(NONCE_SIZE)
    new = AES.new(bytes(new_key), AES.MODE_GCM, nonce=nonce)
    digest = hashlib.sha256()
    tag_offset = dst.tell() + NONCE_SIZE
    dst.write(nonce + bytes(TAG_SIZE))
    for chunk in iter(lambda: src.read(CHUNK_SIZE), b""):
        plain = old.decrypt(chunk)
        digest.update(plain)
        dst.write(new.encrypt(plain))
    old.verify(header[NONCE_SIZE:])
    end = dst.tell()
    dst.seek(tag_offset)
    dst.write(new.digest())
    dst.seek(end)
    return digest.hexdigest()


def generate_priv_pub_key() -> tuple[bytes, bytes]:
    """Gera as chaves públicas e privadas do usuário"""
    key = RSA.generate(2048)
    priv_key, pub_key = key.export_key(), key.publickey().export_key()
    return priv_key, pub_key


def public_key_of(priv_key: bytes) -> bytes:
    """Chave pública (PEM) correspondente a uma chave privada RSA."""
    return RSA.import_key(priv_key).publickey().export_key()


def wrap_dek_with_public_key(dek: bytes, pub_key: bytes) -> bytes:
    """Envolve a DEK com RSA-OAEP usando a chave pública do usuário alvo.

    Usada quando o alvo da cifragem não é o próprio usuário da sessão
    (a KEK do destinatário nunca é conhecida pelo remetente).
    """
    public_rsa = RSA.import_key(pub_key)
    return PKCS1_OAEP.new(public_rsa, hashAlgo=SHA256).encrypt(dek)


def unwrap_dek_with_private_key(wrapped_dek: bytes, priv_key: bytes) -> bytes:
    """Reverte o envolvimento RSA-OAEP da DEK com a chave privada do usuário.

    DEKs novas usam OAEP com SHA-256; as envolvidas antes dessa mudança usam
    o padrão do PyCryptodome (SHA-1) e continuam legíveis. Um hash errado faz
    o OAEP falhar de forma determinística, então a segunda tentativa só
    ocorre para envolvimentos legados (ou inválidos, que falham nas duas).
    """
    priv_key_rsa = RSA.import_key(priv_key)
    try:
        return PKCS1_OAEP.new(priv_key_rsa, hashAlgo=SHA256).decrypt(wrapped_dek)
    except ValueError:
        return PKCS1_OAEP.new(priv_key_rsa).decrypt(wrapped_dek)
