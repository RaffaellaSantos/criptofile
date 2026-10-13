import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

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
        for x in (enc_session_key, chips_aes.nonce, tag, chips_text):
            file_encrypted.write(x)
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
