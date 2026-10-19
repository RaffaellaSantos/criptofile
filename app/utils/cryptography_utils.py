import hashlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


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

def generate_priv_pub_key() -> tuple[bytes, bytes]:
    """Gera as chaves públicas e privadas do usuário"""
    key = RSA.generate(2048)
    priv_key, pub_key = key.export_key(), key.publickey().export_key()
    return priv_key, pub_key

def wrap_dek_with_public_key(dek: bytes, pub_key: bytes) -> bytes:
    """Envolve a DEK com RSA-OAEP usando a chave pública do usuário alvo.

    Usada quando o alvo da cifragem não é o próprio usuário da sessão
    (a KEK do destinatário nunca é conhecida pelo remetente).
    """
    public_rsa = RSA.import_key(pub_key)
    return PKCS1_OAEP.new(public_rsa).encrypt(dek)

def unwrap_dek_with_private_key(wrapped_dek: bytes, priv_key: bytes) -> bytes:
    """Reverte o envolvimento RSA-OAEP da DEK com a chave privada do usuário."""
    priv_key_rsa = RSA.import_key(priv_key)
    return PKCS1_OAEP.new(priv_key_rsa).decrypt(wrapped_dek)
