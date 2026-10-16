import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


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

def encrypt(file_path: str, pub_key: bytes) -> str:
    """Criptografa o arquivo utilizando a chave pública"""
    with open(file_path, 'rb') as enc_file:
        data_enc = enc_file.read()

    public_rsa = RSA.import_key(pub_key)
    session_key = get_random_bytes(32)

    chips_rsa = PKCS1_OAEP.new(public_rsa)
    enc_session_key = chips_rsa.encrypt(session_key)

    chips_aes = AES.new(session_key, AES.MODE_GCM)
    chips_text, tag = chips_aes.encrypt_and_digest(data_enc)
    
    out_path = f"{file_path}.enc"
    with open(out_path, 'wb') as file_encrypted:
        file_encrypted.writelines((enc_session_key, chips_aes.nonce, tag, chips_text))
    os.remove(file_path)
    return out_path

def decrypt(file_path: str, priv_key: bytes) -> str:
    """Descriptografa o arquivo utilizando a chave privada"""

    priv_key_rsa = RSA.import_key(priv_key)
    with open(file_path, 'rb') as file_encrypted:
        enc_session_key = file_encrypted.read(priv_key_rsa.size_in_bytes())
        nonce = file_encrypted.read(16)
        tag = file_encrypted.read(16)
        ciphertext = file_encrypted.read()

    chips_rsa = PKCS1_OAEP.new(priv_key_rsa)
    session_key = chips_rsa.decrypt(enc_session_key)

    chips_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    data = chips_aes.decrypt_and_verify(ciphertext, tag)
    
    out_path = file_path[:-4] if file_path.endswith('.enc') else f"{file_path}.dec"
    with open(out_path, 'wb') as file_decrypted:
        file_decrypted.write(data)
    os.remove(file_path)
    return out_path
